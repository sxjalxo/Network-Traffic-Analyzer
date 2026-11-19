#!/usr/bin/env python3
"""
Network Traffic Analyzer
------------------------
Captures live packets (or reads a .pcap file), breaks traffic down by protocol,
flags suspicious ports and simple traffic anomalies, and writes a report.

Usage:
    python analyzer.py --read capture.pcap
    python analyzer.py --iface "Wi-Fi" --count 200        (needs Administrator)
    python analyzer.py --read capture.pcap --out report.md --csv packets.csv
"""

import argparse
import csv
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime

from scapy.all import rdpcap, sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

# Ports that are commonly abused or should not normally appear on a LAN.
SUSPICIOUS_PORTS = {
    21:    ("FTP", "Cleartext file transfer - credentials sent unencrypted"),
    23:    ("Telnet", "Cleartext remote login - credentials sent unencrypted"),
    69:    ("TFTP", "No authentication - often used to pull malware or configs"),
    135:   ("MSRPC", "Common lateral-movement and worm target"),
    139:   ("NetBIOS", "Legacy Windows file sharing - information disclosure"),
    445:   ("SMB", "Ransomware / EternalBlue lateral movement target"),
    1433:  ("MSSQL", "Database exposed - brute force target"),
    3306:  ("MySQL", "Database exposed - brute force target"),
    3389:  ("RDP", "Remote desktop - top brute force / ransomware entry point"),
    4444:  ("Metasploit", "Default Meterpreter reverse-shell port"),
    5555:  ("ADB / backdoor", "Android Debug Bridge or known backdoor port"),
    5900:  ("VNC", "Remote desktop, often unauthenticated"),
    6667:  ("IRC", "Classic botnet command-and-control channel"),
    8080:  ("HTTP-alt", "Proxy or unmanaged web service"),
    31337: ("Elite / BackOrifice", "Historic backdoor port"),
}

WELL_KNOWN = {
    20: "FTP-data", 22: "SSH", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP",
    443: "HTTPS", 465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
}

# Anomaly thresholds (documented in the README so they can be justified)
PORT_SCAN_THRESHOLD = 15     # distinct destination ports from one source
HOST_SWEEP_THRESHOLD = 15    # distinct destination hosts from one source
SYN_FLOOD_MIN_SYNS = 20      # minimum SYNs before the ratio check applies
SYN_FLOOD_RATIO = 3.0        # SYNs sent vs SYN-ACKs received
ICMP_FLOOD_THRESHOLD = 50    # ICMP echo requests from one source
LARGE_PACKET_BYTES = 1400    # unusually large packets
EPHEMERAL_START = 49152      # ports at or above this are client-side ports

CLEARTEXT_PORTS = (21, 23, 80, 110, 143)
HIGH_RISK_PORTS = (21, 23, 445, 3389, 4444, 6667, 31337)


def service_name(port):
    """Return a human-readable service name for a port number."""
    if port in SUSPICIOUS_PORTS:
        return SUSPICIOUS_PORTS[port][0]
    return WELL_KNOWN.get(port, "unknown")


# ---------------------------------------------------------------------------
# Capture / load
# ---------------------------------------------------------------------------

def load_packets(args):
    """Read packets from a pcap file, or sniff them live."""
    if args.read:
        if not os.path.exists(args.read):
            sys.exit("[!] File not found: " + args.read)
        print("[*] Reading packets from " + args.read + " ...")
        return rdpcap(args.read)

    iface = args.iface or "(default)"
    print("[*] Capturing " + str(args.count) + " packets on interface " + iface + " ...")
    print("[*] Live capture needs Administrator rights and Npcap installed.")
    try:
        pkts = sniff(iface=args.iface, count=args.count,
                     timeout=args.timeout, filter=args.bpf or None)
    except PermissionError:
        sys.exit("[!] Permission denied. Run this terminal as Administrator.")
    except Exception as exc:
        sys.exit("[!] Capture failed: " + str(exc))

    if args.save:
        wrpcap(args.save, pkts)
        print("[*] Saved raw capture to " + args.save)
    return pkts


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyse(packets):
    """Walk every packet once and collect statistics plus anomaly evidence."""
    stats = {
        "total": len(packets),
        "bytes": 0,
        "start": None,
        "end": None,
        "protocols": Counter(),
        "talkers_src": Counter(),
        "talkers_dst": Counter(),
        "dst_ports": Counter(),
        "conversations": Counter(),
        "non_ip": 0,
    }

    scan_ports = defaultdict(set)      # source -> set of destination ports
    scan_hosts = defaultdict(set)      # source -> set of destination hosts
    syn_count = Counter()
    synack_count = Counter()
    icmp_echo = Counter()
    large_packets = []
    rows = []

    for pkt in packets:
        ts = float(pkt.time)
        if stats["start"] is None:
            stats["start"] = ts
            stats["end"] = ts
        else:
            stats["start"] = min(stats["start"], ts)
            stats["end"] = max(stats["end"], ts)
        stats["bytes"] += len(pkt)

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
        else:
            stats["non_ip"] += 1
            stats["protocols"]["Non-IP (ARP / other)"] += 1
            continue

        stats["talkers_src"][src] += 1
        stats["talkers_dst"][dst] += 1
        scan_hosts[src].add(dst)

        proto = "Other-IP"
        sport = None
        dport = None
        flags = ""

        if TCP in pkt:
            tcp = pkt[TCP]
            sport = int(tcp.sport)
            dport = int(tcp.dport)
            flags = str(tcp.flags)
            name = service_name(dport)
            proto = "TCP" if name == "unknown" else "TCP/" + name
            stats["dst_ports"][dport] += 1
            # Only a new connection attempt counts as scan evidence. A server
            # replying from port 443 to many ephemeral client ports is normal
            # and must not be mistaken for a scanner.
            if "S" in flags and "A" not in flags:
                syn_count[src] += 1
                scan_ports[src].add(dport)
            if "S" in flags and "A" in flags:
                synack_count[dst] += 1

        elif UDP in pkt:
            udp = pkt[UDP]
            sport = int(udp.sport)
            dport = int(udp.dport)
            name = service_name(dport)
            proto = "UDP" if name == "unknown" else "UDP/" + name
            stats["dst_ports"][dport] += 1
            # Replies land on high ephemeral ports, so ignore those as evidence.
            if dport < EPHEMERAL_START:
                scan_ports[src].add(dport)

        elif ICMP in pkt:
            proto = "ICMP"
            if int(pkt[ICMP].type) == 8:
                icmp_echo[src] += 1

        stats["protocols"][proto] += 1
        stats["conversations"][(src, dst, proto)] += 1

        if len(pkt) > LARGE_PACKET_BYTES:
            large_packets.append((src, dst, len(pkt)))

        rows.append({
            "time": datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
            "src": src,
            "dst": dst,
            "protocol": proto,
            "src_port": sport if sport is not None else "",
            "dst_port": dport if dport is not None else "",
            "flags": flags,
            "length": len(pkt),
        })

    findings = detect_findings(stats, scan_ports, scan_hosts, syn_count,
                               synack_count, icmp_echo, large_packets)
    return stats, rows, findings


def detect_findings(stats, scan_ports, scan_hosts, syn_count,
                    synack_count, icmp_echo, large_packets):
    """Turn the collected evidence into severity-ranked findings."""
    findings = []

    # 1. Suspicious destination ports seen in the capture
    for port, count in stats["dst_ports"].most_common():
        if port in SUSPICIOUS_PORTS:
            name, why = SUSPICIOUS_PORTS[port]
            severity = "HIGH" if port in HIGH_RISK_PORTS else "MEDIUM"
            findings.append({
                "severity": severity,
                "title": "Traffic to suspicious port " + str(port) + " (" + name + ")",
                "detail": str(count) + " packet(s) sent to port " + str(port) + ". " + why,
                "recommend": "Confirm whether port " + str(port) + " is required. Block it "
                             "at the firewall or move the service to an encrypted equivalent.",
            })

    # 2. Vertical port scan: one source, many ports
    for src in sorted(scan_ports):
        ports = scan_ports[src]
        if len(ports) >= PORT_SCAN_THRESHOLD:
            findings.append({
                "severity": "HIGH",
                "title": "Possible port scan from " + src,
                "detail": src + " contacted " + str(len(ports)) + " distinct destination "
                          "ports (threshold " + str(PORT_SCAN_THRESHOLD) + "). This is "
                          "typical of reconnaissance before an attack.",
                "recommend": "Verify the host is an authorised scanner. If not, isolate it "
                             "and review it for compromise.",
            })

    # 3. Horizontal sweep: one source, many hosts
    for src in sorted(scan_hosts):
        hosts = scan_hosts[src]
        if len(hosts) >= HOST_SWEEP_THRESHOLD:
            findings.append({
                "severity": "MEDIUM",
                "title": "Possible host sweep from " + src,
                "detail": src + " contacted " + str(len(hosts)) + " distinct hosts "
                          "(threshold " + str(HOST_SWEEP_THRESHOLD) + ").",
                "recommend": "Check whether this is a monitoring tool. Otherwise treat it "
                             "as network reconnaissance.",
            })

    # 4. SYN flood / half-open connections
    for src in sorted(syn_count):
        syns = syn_count[src]
        acks = synack_count.get(src, 0)
        if syns >= SYN_FLOOD_MIN_SYNS and (acks == 0 or syns / max(acks, 1) >= SYN_FLOOD_RATIO):
            findings.append({
                "severity": "HIGH",
                "title": "SYN flood / half-open connections from " + src,
                "detail": str(syns) + " SYN packets but only " + str(acks) + " SYN-ACK "
                          "replies, so the TCP handshakes are not completing.",
                "recommend": "Enable SYN cookies and rate limiting, and investigate the source.",
            })

    # 5. ICMP echo flood
    for src in sorted(icmp_echo):
        count = icmp_echo[src]
        if count >= ICMP_FLOOD_THRESHOLD:
            findings.append({
                "severity": "MEDIUM",
                "title": "ICMP echo flood from " + src,
                "detail": str(count) + " ICMP echo requests from a single source "
                          "(threshold " + str(ICMP_FLOOD_THRESHOLD) + ").",
                "recommend": "Rate-limit ICMP at the gateway and confirm it is not a ping sweep.",
            })

    # 6. Cleartext credential-bearing protocols
    cleartext = [p for p in stats["dst_ports"] if p in CLEARTEXT_PORTS]
    if cleartext:
        listed = ", ".join(service_name(p) + "(" + str(p) + ")" for p in sorted(cleartext))
        findings.append({
            "severity": "MEDIUM",
            "title": "Cleartext protocols in use",
            "detail": "Traffic observed on: " + listed + ". Data and credentials on these "
                      "protocols travel unencrypted and can be read by anyone on the path.",
            "recommend": "Migrate to the SSH / HTTPS / IMAPS equivalents.",
        })

    # 7. Unusually large packets
    if large_packets:
        biggest = max(large_packets, key=lambda x: x[2])
        findings.append({
            "severity": "LOW",
            "title": str(len(large_packets)) + " unusually large packet(s)",
            "detail": "Largest was " + str(biggest[2]) + " bytes from " + biggest[0] +
                      " to " + biggest[1] + " (threshold " + str(LARGE_PACKET_BYTES) +
                      " bytes). Can indicate bulk transfer or data exfiltration.",
            "recommend": "Confirm the transfer is an expected backup or upload.",
        })

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: order[f["severity"]])
    return findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def build_report(stats, findings, source):
    """Build the Markdown report."""
    lines = []
    add = lines.append

    duration = (stats["end"] - stats["start"]) if stats["start"] else 0.0
    add("# Network Traffic Analysis Report")
    add("")
    add("- **Generated:** " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    add("- **Source:** " + source)
    add("- **Packets analysed:** " + str(stats["total"]))
    add("- **Total bytes:** " + format(stats["bytes"], ","))
    add("- **Capture duration:** " + format(duration, ".2f") + " seconds")
    add("")

    high = sum(1 for f in findings if f["severity"] == "HIGH")
    med = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")
    add("## 1. Summary")
    add("")
    add("Findings: **" + str(high) + " High**, **" + str(med) + " Medium**, **" +
        str(low) + " Low**.")
    add("")

    add("## 2. Protocol Breakdown")
    add("")
    add("| Protocol | Packets | Share |")
    add("|---|---:|---:|")
    for proto, count in stats["protocols"].most_common():
        pct = count / stats["total"] * 100 if stats["total"] else 0
        add("| " + proto + " | " + str(count) + " | " + format(pct, ".1f") + "% |")
    add("")

    add("## 3. Top Talkers")
    add("")
    add("| Source IP | Packets sent |")
    add("|---|---:|")
    for ip, count in stats["talkers_src"].most_common(10):
        add("| " + ip + " | " + str(count) + " |")
    add("")
    add("| Destination IP | Packets received |")
    add("|---|---:|")
    for ip, count in stats["talkers_dst"].most_common(10):
        add("| " + ip + " | " + str(count) + " |")
    add("")

    add("## 4. Top Destination Ports")
    add("")
    add("| Port | Service | Packets | Flagged |")
    add("|---|---|---:|---|")
    for port, count in stats["dst_ports"].most_common(15):
        flag = "YES" if port in SUSPICIOUS_PORTS else ""
        add("| " + str(port) + " | " + service_name(port) + " | " + str(count) +
            " | " + flag + " |")
    add("")

    add("## 5. Top Conversations")
    add("")
    add("| Source | Destination | Protocol | Packets |")
    add("|---|---|---|---:|")
    for key, count in stats["conversations"].most_common(10):
        src, dst, proto = key
        add("| " + src + " | " + dst + " | " + proto + " | " + str(count) + " |")
    add("")

    add("## 6. Findings")
    add("")
    if not findings:
        add("No suspicious ports or traffic anomalies were detected in this capture.")
        add("")
    else:
        for i, f in enumerate(findings, 1):
            add("### " + str(i) + ". [" + f["severity"] + "] " + f["title"])
            add("")
            add("- **Observation:** " + f["detail"])
            add("- **Recommendation:** " + f["recommend"])
            add("")

    add("## 7. Detection Thresholds Used")
    add("")
    add("- Port scan: " + str(PORT_SCAN_THRESHOLD) + "+ distinct destination ports from one source")
    add("- Host sweep: " + str(HOST_SWEEP_THRESHOLD) + "+ distinct destination hosts from one source")
    add("- SYN flood: " + str(SYN_FLOOD_MIN_SYNS) + "+ SYNs with a SYN:SYN-ACK ratio of " +
        str(SYN_FLOOD_RATIO) + " or higher")
    add("- ICMP flood: " + str(ICMP_FLOOD_THRESHOLD) + "+ echo requests from one source")
    add("- Large packet: over " + str(LARGE_PACKET_BYTES) + " bytes")
    add("")
    return "\n".join(lines)


def print_console(stats, findings):
    """Print a short summary to the terminal."""
    print("")
    print("=" * 64)
    print(" NETWORK TRAFFIC ANALYSIS ".center(64, "="))
    print("=" * 64)
    print(" Packets: " + str(stats["total"]) + "   Bytes: " + format(stats["bytes"], ","))
    print("-" * 64)
    print(" PROTOCOL BREAKDOWN")
    for proto, count in stats["protocols"].most_common(10):
        pct = count / stats["total"] * 100 if stats["total"] else 0
        bar = "#" * int(pct / 3)
        print("   " + proto.ljust(20) + str(count).rjust(6) + "  " +
              format(pct, "5.1f") + "% " + bar)
    print("-" * 64)
    print(" TOP TALKERS")
    for ip, count in stats["talkers_src"].most_common(5):
        print("   " + ip.ljust(22) + str(count).rjust(6) + " packets sent")
    print("-" * 64)
    print(" TOP DESTINATION PORTS")
    for port, count in stats["dst_ports"].most_common(8):
        flag = "  <-- SUSPICIOUS" if port in SUSPICIOUS_PORTS else ""
        print("   " + str(port).ljust(6) + service_name(port).ljust(18) +
              str(count).rjust(6) + flag)
    print("-" * 64)
    print(" FINDINGS (" + str(len(findings)) + ")")
    if not findings:
        print("   None - no suspicious ports or anomalies detected.")
    for f in findings:
        print("   [" + f["severity"].ljust(6) + "] " + f["title"])
    print("=" * 64)


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "time", "src", "dst", "protocol", "src_port", "dst_port", "flags", "length"])
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Simple network traffic analyzer")
    parser.add_argument("--read", help="read packets from a .pcap file")
    parser.add_argument("--iface", help="interface name for live capture")
    parser.add_argument("--count", type=int, default=200,
                        help="packets to capture (default 200)")
    parser.add_argument("--timeout", type=int, default=60,
                        help="live capture timeout in seconds")
    parser.add_argument("--bpf", help="capture filter, for example 'tcp port 80'")
    parser.add_argument("--save", help="save the live capture to this .pcap file")
    parser.add_argument("--out", default="report.md",
                        help="report output file (default report.md)")
    parser.add_argument("--csv", help="also write per-packet details to this CSV file")
    args = parser.parse_args()

    packets = load_packets(args)
    if not packets:
        sys.exit("[!] No packets to analyse.")

    stats, rows, findings = analyse(packets)
    print_console(stats, findings)

    source = args.read or ("live capture on " + (args.iface or "default interface"))
    report = build_report(stats, findings, source)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(report)
    print("")
    print("[*] Report written to " + args.out)

    if args.csv:
        write_csv(args.csv, rows)
        print("[*] Packet details written to " + args.csv)


if __name__ == "__main__":
    main()
