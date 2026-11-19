# Network Traffic Analyzer

A Python tool that captures network packets (or reads a saved `.pcap` file),
breaks the traffic down by protocol, flags suspicious ports and traffic
anomalies, and writes a findings report.

Built with **Scapy**, and compatible with **Wireshark** / **tshark** capture files.

---

## 1. Objectives covered

| Objective | How this project meets it |
|---|---|
| Packet capture and protocol analysis | Live capture via Scapy, or reads any `.pcap` from Wireshark. Classifies every packet into TCP / UDP / ICMP and names the service behind each port. |
| Identifying suspicious ports and traffic anomalies | 15 known-bad ports flagged, plus 6 behavioural detections (port scan, host sweep, SYN flood, ICMP flood, cleartext protocols, oversized packets). |
| Hands-on use of industry-standard tools | Scapy for capture and dissection, Wireshark / Npcap for verification, `.pcap` as the interchange format. |
| Documentation and reporting of findings | Generates a Markdown report with protocol tables, top talkers, severity-ranked findings and a recommendation per finding, plus a per-packet CSV. |

---

## 2. Files

| File | Purpose |
|---|---|
| `analyzer.py` | The analyzer. Captures or reads packets, detects issues, writes the report. |
| `make_sample.py` | Generates `sample.pcap` with normal traffic plus planted anomalies, so the tool can be demonstrated without Administrator rights. |
| `sample.pcap` | The generated demo capture (380 packets). |
| `report.md` | Example output report. |
| `packets.csv` | Example per-packet export (opens in Excel). |
| `requirements.txt` | The one dependency. |

---

## 3. Setup

```bash
pip install -r requirements.txt
```

For **live capture on Windows** you also need [Npcap](https://npcap.com/)
(it ships with Wireshark) and an Administrator terminal.

---

## 4. How to run

### Option A — demo with the sample capture (no admin needed)

```bash
python make_sample.py
```

```bash
python analyzer.py --read sample.pcap --csv packets.csv
```

### Option B — live capture (Administrator terminal)

List your interface names first:

```bash
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

Then capture 200 packets:

```bash
python analyzer.py --iface "Wi-Fi" --count 200 --save mycapture.pcap
```

### Option C — analyse a capture you took in Wireshark

Capture in Wireshark, save as `.pcap` (not `.pcapng`), then:

```bash
python analyzer.py --read yourfile.pcap
```

### All options

| Flag | Meaning |
|---|---|
| `--read FILE` | Analyse an existing `.pcap` instead of capturing |
| `--iface NAME` | Interface to capture on |
| `--count N` | Number of packets to capture (default 200) |
| `--timeout N` | Stop capturing after N seconds (default 60) |
| `--bpf FILTER` | Capture filter, e.g. `"tcp port 80"` |
| `--save FILE` | Save the live capture to a `.pcap` |
| `--out FILE` | Report filename (default `report.md`) |
| `--csv FILE` | Also export every packet to CSV |

---

## 5. What it detects

### Suspicious ports

Traffic to any of these is flagged, with the reason and a recommendation:

| Port | Service | Why it matters |
|---|---|---|
| 21 | FTP | Credentials sent in cleartext |
| 23 | Telnet | Credentials sent in cleartext |
| 69 | TFTP | No authentication; used to pull malware |
| 135 | MSRPC | Lateral-movement and worm target |
| 139 | NetBIOS | Legacy sharing, information disclosure |
| 445 | SMB | Ransomware / EternalBlue target |
| 1433 | MSSQL | Exposed database, brute force target |
| 3306 | MySQL | Exposed database, brute force target |
| 3389 | RDP | Top brute force / ransomware entry point |
| 4444 | Metasploit | Default Meterpreter reverse-shell port |
| 5555 | ADB / backdoor | Debug bridge or known backdoor |
| 5900 | VNC | Remote desktop, often unauthenticated |
| 6667 | IRC | Classic botnet command-and-control |
| 8080 | HTTP-alt | Proxy or unmanaged web service |
| 31337 | BackOrifice | Historic backdoor port |

### Traffic anomalies

| Detection | Rule | Severity |
|---|---|---|
| Port scan | One source makes connection attempts to 15+ distinct ports | HIGH |
| SYN flood | 20+ SYNs with a SYN:SYN-ACK ratio of 3:1 or worse | HIGH |
| Host sweep | One source contacts 15+ distinct hosts | MEDIUM |
| ICMP flood | 50+ echo requests from one source | MEDIUM |
| Cleartext protocols | Any traffic on FTP / Telnet / HTTP / POP3 / IMAP | MEDIUM |
| Oversized packets | Any packet over 1400 bytes | LOW |

**Avoiding false positives:** a port only counts as scan evidence when the
packet is a *new connection attempt* (TCP SYN without ACK) or a UDP packet to
a non-ephemeral port. Without this rule a normal web server replying from
port 443 to many client ports would be mistaken for a port scanner.

Thresholds are constants at the top of `analyzer.py` and can be tuned.

---

## 6. Results from the sample capture

380 packets analysed; **17 findings — 7 High, 9 Medium, 1 Low**.

| Severity | Finding |
|---|---|
| HIGH | Traffic to port 445 (SMB) — leaving the local network to an external host |
| HIGH | Traffic to port 23 (Telnet) — cleartext login observed |
| HIGH | Traffic to port 4444 (Metasploit) — reverse-shell indicator |
| HIGH | Traffic to ports 21 (FTP) and 3389 (RDP) |
| HIGH | Port scan from 192.168.1.99 — 18 distinct ports on one target |
| HIGH | SYN flood from 203.0.113.55 — 40 SYNs, 0 SYN-ACKs |
| MEDIUM | Host sweep + ICMP flood from 192.168.1.99 — 60 hosts pinged |
| MEDIUM | Cleartext protocols in use (FTP, Telnet, HTTP) |
| LOW | One 1460-byte packet to an external host |

The single host **192.168.1.99** accounts for three separate findings
(port scan, host sweep, ICMP flood), which together describe a host performing
network reconnaissance — the clearest action item in the capture.

Full detail is in [report.md](report.md).

---

## 7. How to verify the results in Wireshark

Open `sample.pcap` in Wireshark and apply these display filters to confirm
each finding by hand:

```
tcp.port == 4444
```

```
ip.src == 192.168.1.99 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

```
tcp.port == 23 || tcp.port == 21
```

---

## 8. Limitations

- Reads `.pcap`; save as `.pcap` rather than `.pcapng` in Wireshark.
- Detection is threshold-based, not signature-based — it flags behaviour for
  an analyst to review, it is not an IDS.
- Encrypted payloads are counted and classified but not inspected.
- Live capture requires Administrator rights and Npcap.
