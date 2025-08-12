# PRODIGY_CS_05 — Simple Packet Sniffer (Educational Use Only)

## Task Overview
Capture live network packets and display key details including IP addresses, protocol, and payload size.

## Features
- Uses Scapy for live packet capture
- Displays source and destination IP addresses
- Identifies TCP, UDP, ICMP, and other protocols
- Shows payload size in bytes

## How to Run
```bash
pip install scapy
sudo python Prodigy_CS_05.py

[*] Starting packet capture...
[+] 192.168.1.5 -> 8.8.8.8 | Protocol: UDP | Payload: 32 bytes
[+] 192.168.1.5 -> 142.250.72.14 | Protocol: TCP | Payload: 512 bytes
