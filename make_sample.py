#!/usr/bin/env python3
"""
Sample traffic generator
------------------------
Builds a small .pcap file containing normal traffic plus a few planted
anomalies, so the analyzer can be demonstrated without Administrator
rights or a live network. Nothing is sent on the network - the packets
are only written to a file.

Usage:
    python make_sample.py                    -> writes sample.pcap
    python make_sample.py --out demo.pcap
"""

import argparse
import random
import time

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

LAN = "192.168.1."
GATEWAY = "192.168.1.1"
DNS_SERVER = "192.168.1.1"
INTERNET = ["93.184.216.34", "142.250.183.14", "151.101.1.69", "104.18.32.47"]

# Fixed MAC addresses. Without these, Scapy tries to resolve a real MAC via
# ARP for every packet, which is slow and needs a live network.
MAC_A = "aa:bb:cc:11:11:11"
MAC_B = "aa:bb:cc:22:22:22"


def eth():
    return Ether(src=MAC_A, dst=MAC_B)


def stamp(pkt, t):
    pkt.time = t
    return pkt


def build():
    pkts = []
    t = time.time()
    random.seed(7)

    workstations = [LAN + str(n) for n in (10, 11, 12, 13, 14)]

    # --- 1. Normal web browsing: HTTPS to the internet -------------------
    for i in range(60):
        src = random.choice(workstations)
        dst = random.choice(INTERNET)
        sport = random.randint(49152, 65535)
        t += 0.05
        pkts.append(stamp(eth() / IP(src=src, dst=dst) /
                          TCP(sport=sport, dport=443, flags="S"), t))
        t += 0.02
        pkts.append(stamp(eth() / IP(src=dst, dst=src) /
                          TCP(sport=443, dport=sport, flags="SA"), t))
        t += 0.02
        pkts.append(stamp(eth() / IP(src=src, dst=dst) /
                          TCP(sport=sport, dport=443, flags="A") /
                          Raw(b"x" * random.randint(100, 600)), t))

    # --- 2. Normal DNS lookups -------------------------------------------
    for i in range(25):
        src = random.choice(workstations)
        t += 0.04
        pkts.append(stamp(eth() / IP(src=src, dst=DNS_SERVER) /
                          UDP(sport=random.randint(49152, 65535), dport=53) /
                          Raw(b"\x00" * 40), t))
        t += 0.01
        pkts.append(stamp(eth() / IP(src=DNS_SERVER, dst=src) /
                          UDP(sport=53, dport=49152) / Raw(b"\x00" * 60), t))

    # --- 3. Normal plain HTTP to an internal server ----------------------
    for i in range(12):
        src = random.choice(workstations)
        t += 0.06
        pkts.append(stamp(eth() / IP(src=src, dst=LAN + "50") /
                          TCP(sport=random.randint(49152, 65535), dport=80, flags="PA") /
                          Raw(b"GET /index.html HTTP/1.1\r\nHost: intranet\r\n\r\n"), t))

    # --- 4. ANOMALY: port scan from a rogue host -------------------------
    # One source touching many ports on one target = classic recon.
    scanner = LAN + "99"
    target = LAN + "50"
    for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                 1433, 3306, 3389, 5900, 8080, 8443]:
        t += 0.01
        pkts.append(stamp(eth() / IP(src=scanner, dst=target) /
                          TCP(sport=random.randint(40000, 50000),
                              dport=port, flags="S"), t))

    # --- 5. ANOMALY: Telnet session (cleartext credentials) --------------
    for i in range(6):
        t += 0.3
        pkts.append(stamp(eth() / IP(src=LAN + "12", dst=LAN + "60") /
                          TCP(sport=51000, dport=23, flags="PA") /
                          Raw(b"login: admin\r\n"), t))

    # --- 6. ANOMALY: SMB traffic to an external address -------------------
    for i in range(8):
        t += 0.2
        pkts.append(stamp(eth() / IP(src=LAN + "13", dst="198.51.100.77") /
                          TCP(sport=52000 + i, dport=445, flags="PA") /
                          Raw(b"\xffSMB" + b"\x00" * 60), t))

    # --- 7. ANOMALY: reverse shell to port 4444 ---------------------------
    for i in range(5):
        t += 0.4
        pkts.append(stamp(eth() / IP(src=LAN + "14", dst="203.0.113.9") /
                          TCP(sport=53000, dport=4444, flags="PA") /
                          Raw(b"whoami\n"), t))

    # --- 8. ANOMALY: SYN flood with no replies ----------------------------
    flooder = "203.0.113.55"
    for i in range(40):
        t += 0.005
        pkts.append(stamp(eth() / IP(src=flooder, dst=GATEWAY) /
                          TCP(sport=random.randint(1024, 65535),
                              dport=80, flags="S"), t))

    # --- 9. ANOMALY: ICMP ping sweep across the subnet --------------------
    for n in range(1, 61):
        t += 0.01
        pkts.append(stamp(eth() / IP(src=scanner, dst=LAN + str(n)) /
                          ICMP(type=8), t))

    # --- 10. ANOMALY: one oversized packet (possible exfiltration) --------
    t += 0.5
    pkts.append(stamp(eth() / IP(src=LAN + "11", dst="198.51.100.200") /
                      TCP(sport=54000, dport=443, flags="PA") /
                      Raw(b"D" * 1460), t))

    return pkts


def main():
    parser = argparse.ArgumentParser(description="Generate a sample .pcap file")
    parser.add_argument("--out", default="sample.pcap", help="output file name")
    args = parser.parse_args()

    pkts = build()
    wrpcap(args.out, pkts)
    print("[*] Wrote " + str(len(pkts)) + " packets to " + args.out)
    print("[*] Now run:  python analyzer.py --read " + args.out)


if __name__ == "__main__":
    main()
