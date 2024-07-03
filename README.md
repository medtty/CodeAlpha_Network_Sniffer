# Basic Network Sniffer

This repository contains a Python-based network sniffer that captures and analyzes network traffic. It extracts and displays anonymized information about each packet, including the protocol, source IP, destination IP, source port, and destination port.

## Installation
To use the network sniffer, install the required library using pip:

```bash
pip install scapy
```

```Python

from scapy.all import sniff, IP, TCP, UDP

packet_count = 0

def packet_callback(packet):
    global packet_count
    packet_count += 1

    packet_data = {}

    if IP in packet:
        ip_layer = packet[IP]
        packet_data["Source IP"] = ip_layer.src
        packet_data["Destination IP"] = ip_layer.dst

        if TCP in packet:
            tcp_layer = packet[TCP]
            packet_data["Protocol"] = "TCP"
            packet_data["Source Port"] = tcp_layer.sport
            packet_data["Destination Port"] = tcp_layer.dport

        elif UDP in packet:
            udp_layer = packet[UDP]
            packet_data["Protocol"] = "UDP"
            packet_data["Source Port"] = udp_layer.sport
            packet_data["Destination Port"] = udp_layer.dport

    if packet_data:
        print(f"\n{packet_count}. New Packet:")
        print(f"    {'-'*20}")
        for key, value in packet_data.items():
            print(f"    {key}: {value}")
        print(f"    {'-'*20}")

# Start sniffing (use appropriate network interface, e.g., 'en0' for Wi-Fi on Mac)
print("Starting network sniffer...")
sniff(prn=packet_callback, count=5)  # Remove count to keep it running indefinitely

```
