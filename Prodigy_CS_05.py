# Prodigy_CS_05.py
# Simple Packet Sniffer - Educational Use Only!

from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "Other")
        payload_size = len(packet[IP].payload)

        print(f"[+] {ip_src} -> {ip_dst} | Protocol: {proto_name} | Payload: {payload_size} bytes")

# Start sniffing (you might need sudo/root permissions)
print("[*] Starting packet capture...")
sniff(prn=packet_callback, store=False)

