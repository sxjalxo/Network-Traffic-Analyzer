# Network Traffic Analysis Report

- **Generated:** 2026-11-19 09:39:47
- **Source:** sample.pcap
- **Packets analysed:** 380
- **Total bytes:** 46,352
- **Capture duration:** 14.20 seconds

## 1. Summary

Findings: **7 High**, **9 Medium**, **1 Low**.

## 2. Protocol Breakdown

| Protocol | Packets | Share |
|---|---:|---:|
| TCP/HTTPS | 122 | 32.1% |
| TCP | 61 | 16.1% |
| ICMP | 60 | 15.8% |
| TCP/HTTP | 53 | 13.9% |
| UDP/DNS | 25 | 6.6% |
| UDP | 25 | 6.6% |
| TCP/SMB | 9 | 2.4% |
| TCP/Telnet | 7 | 1.8% |
| TCP/Metasploit | 5 | 1.3% |
| TCP/FTP | 1 | 0.3% |
| TCP/SSH | 1 | 0.3% |
| TCP/SMTP | 1 | 0.3% |
| TCP/DNS | 1 | 0.3% |
| TCP/POP3 | 1 | 0.3% |
| TCP/MSRPC | 1 | 0.3% |
| TCP/NetBIOS | 1 | 0.3% |
| TCP/IMAP | 1 | 0.3% |
| TCP/MSSQL | 1 | 0.3% |
| TCP/MySQL | 1 | 0.3% |
| TCP/RDP | 1 | 0.3% |
| TCP/VNC | 1 | 0.3% |
| TCP/HTTP-alt | 1 | 0.3% |

## 3. Top Talkers

| Source IP | Packets sent |
|---|---:|
| 192.168.1.99 | 78 |
| 192.168.1.13 | 41 |
| 203.0.113.55 | 40 |
| 192.168.1.14 | 38 |
| 192.168.1.12 | 36 |
| 192.168.1.11 | 35 |
| 192.168.1.10 | 27 |
| 192.168.1.1 | 25 |
| 93.184.216.34 | 18 |
| 142.250.183.14 | 15 |

| Destination IP | Packets received |
|---|---:|
| 192.168.1.1 | 66 |
| 93.184.216.34 | 36 |
| 192.168.1.50 | 31 |
| 142.250.183.14 | 30 |
| 104.18.32.47 | 28 |
| 151.101.1.69 | 26 |
| 192.168.1.11 | 20 |
| 192.168.1.13 | 20 |
| 192.168.1.14 | 18 |
| 192.168.1.12 | 16 |

## 4. Top Destination Ports

| Port | Service | Packets | Flagged |
|---|---|---:|---|
| 443 | HTTPS | 122 |  |
| 80 | HTTP | 53 |  |
| 53 | DNS | 26 |  |
| 49152 | unknown | 25 |  |
| 445 | SMB | 9 | YES |
| 23 | Telnet | 7 | YES |
| 4444 | Metasploit | 5 | YES |
| 62089 | unknown | 1 |  |
| 52236 | unknown | 1 |  |
| 56187 | unknown | 1 |  |
| 62854 | unknown | 1 |  |
| 63062 | unknown | 1 |  |
| 56467 | unknown | 1 |  |
| 62150 | unknown | 1 |  |
| 53515 | unknown | 1 |  |

## 5. Top Conversations

| Source | Destination | Protocol | Packets |
|---|---|---|---:|
| 203.0.113.55 | 192.168.1.1 | TCP/HTTP | 40 |
| 192.168.1.14 | 93.184.216.34 | TCP/HTTPS | 14 |
| 192.168.1.12 | 142.250.183.14 | TCP/HTTPS | 8 |
| 192.168.1.11 | 93.184.216.34 | TCP/HTTPS | 8 |
| 192.168.1.11 | 104.18.32.47 | TCP/HTTPS | 8 |
| 192.168.1.13 | 151.101.1.69 | TCP/HTTPS | 8 |
| 192.168.1.13 | 104.18.32.47 | TCP/HTTPS | 8 |
| 192.168.1.11 | 142.250.183.14 | TCP/HTTPS | 8 |
| 192.168.1.13 | 198.51.100.77 | TCP/SMB | 8 |
| 93.184.216.34 | 192.168.1.14 | TCP | 7 |

## 6. Findings

### 1. [HIGH] Traffic to suspicious port 445 (SMB)

- **Observation:** 9 packet(s) sent to port 445. Ransomware / EternalBlue lateral movement target
- **Recommendation:** Confirm whether port 445 is required. Block it at the firewall or move the service to an encrypted equivalent.

### 2. [HIGH] Traffic to suspicious port 23 (Telnet)

- **Observation:** 7 packet(s) sent to port 23. Cleartext remote login - credentials sent unencrypted
- **Recommendation:** Confirm whether port 23 is required. Block it at the firewall or move the service to an encrypted equivalent.

### 3. [HIGH] Traffic to suspicious port 4444 (Metasploit)

- **Observation:** 5 packet(s) sent to port 4444. Default Meterpreter reverse-shell port
- **Recommendation:** Confirm whether port 4444 is required. Block it at the firewall or move the service to an encrypted equivalent.

### 4. [HIGH] Traffic to suspicious port 21 (FTP)

- **Observation:** 1 packet(s) sent to port 21. Cleartext file transfer - credentials sent unencrypted
- **Recommendation:** Confirm whether port 21 is required. Block it at the firewall or move the service to an encrypted equivalent.

### 5. [HIGH] Traffic to suspicious port 3389 (RDP)

- **Observation:** 1 packet(s) sent to port 3389. Remote desktop - top brute force / ransomware entry point
- **Recommendation:** Confirm whether port 3389 is required. Block it at the firewall or move the service to an encrypted equivalent.

### 6. [HIGH] Possible port scan from 192.168.1.99

- **Observation:** 192.168.1.99 contacted 18 distinct destination ports (threshold 15). This is typical of reconnaissance before an attack.
- **Recommendation:** Verify the host is an authorised scanner. If not, isolate it and review it for compromise.

### 7. [HIGH] SYN flood / half-open connections from 203.0.113.55

- **Observation:** 40 SYN packets but only 0 SYN-ACK replies, so the TCP handshakes are not completing.
- **Recommendation:** Enable SYN cookies and rate limiting, and investigate the source.

### 8. [MEDIUM] Traffic to suspicious port 135 (MSRPC)

- **Observation:** 1 packet(s) sent to port 135. Common lateral-movement and worm target
- **Recommendation:** Confirm whether port 135 is required. Block it at the firewall or move the service to an encrypted equivalent.

### 9. [MEDIUM] Traffic to suspicious port 139 (NetBIOS)

- **Observation:** 1 packet(s) sent to port 139. Legacy Windows file sharing - information disclosure
- **Recommendation:** Confirm whether port 139 is required. Block it at the firewall or move the service to an encrypted equivalent.

### 10. [MEDIUM] Traffic to suspicious port 1433 (MSSQL)

- **Observation:** 1 packet(s) sent to port 1433. Database exposed - brute force target
- **Recommendation:** Confirm whether port 1433 is required. Block it at the firewall or move the service to an encrypted equivalent.

### 11. [MEDIUM] Traffic to suspicious port 3306 (MySQL)

- **Observation:** 1 packet(s) sent to port 3306. Database exposed - brute force target
- **Recommendation:** Confirm whether port 3306 is required. Block it at the firewall or move the service to an encrypted equivalent.

### 12. [MEDIUM] Traffic to suspicious port 5900 (VNC)

- **Observation:** 1 packet(s) sent to port 5900. Remote desktop, often unauthenticated
- **Recommendation:** Confirm whether port 5900 is required. Block it at the firewall or move the service to an encrypted equivalent.

### 13. [MEDIUM] Traffic to suspicious port 8080 (HTTP-alt)

- **Observation:** 1 packet(s) sent to port 8080. Proxy or unmanaged web service
- **Recommendation:** Confirm whether port 8080 is required. Block it at the firewall or move the service to an encrypted equivalent.

### 14. [MEDIUM] Possible host sweep from 192.168.1.99

- **Observation:** 192.168.1.99 contacted 60 distinct hosts (threshold 15).
- **Recommendation:** Check whether this is a monitoring tool. Otherwise treat it as network reconnaissance.

### 15. [MEDIUM] ICMP echo flood from 192.168.1.99

- **Observation:** 60 ICMP echo requests from a single source (threshold 50).
- **Recommendation:** Rate-limit ICMP at the gateway and confirm it is not a ping sweep.

### 16. [MEDIUM] Cleartext protocols in use

- **Observation:** Traffic observed on: FTP(21), Telnet(23), HTTP(80), POP3(110), IMAP(143). Data and credentials on these protocols travel unencrypted and can be read by anyone on the path.
- **Recommendation:** Migrate to the SSH / HTTPS / IMAPS equivalents.

### 17. [LOW] 1 unusually large packet(s)

- **Observation:** Largest was 1514 bytes from 192.168.1.11 to 198.51.100.200 (threshold 1400 bytes). Can indicate bulk transfer or data exfiltration.
- **Recommendation:** Confirm the transfer is an expected backup or upload.

## 7. Detection Thresholds Used

- Port scan: 15+ distinct destination ports from one source
- Host sweep: 15+ distinct destination hosts from one source
- SYN flood: 20+ SYNs with a SYN:SYN-ACK ratio of 3.0 or higher
- ICMP flood: 50+ echo requests from one source
- Large packet: over 1400 bytes
