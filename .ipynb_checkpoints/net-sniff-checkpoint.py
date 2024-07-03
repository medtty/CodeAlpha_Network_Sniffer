from scapy.all import sniff, IP, TCP, UDP, wrpcap
import hashlib

def anonymize_ip(ip):
    return hashlib.sha256(ip.encode()).hexdigest()[:8]  # Use a hash for anonymization

packet_count = 0  # Initialize a packet counter

def packet_callback(packet):
    global packet_count
    packet_count += 1

    # Initialize an empty dictionary to store important packet data
    packet_data = {}

    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        packet_data["Source IP"] = anonymize_ip(ip_layer.src)
        packet_data["Destination IP"] = anonymize_ip(ip_layer.dst)

        # Check if the packet has a TCP layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            packet_data["Protocol"] = "TCP"
            packet_data["Source Port"] = tcp_layer.sport  # Optional: anonymize port
            packet_data["Destination Port"] = tcp_layer.dport  # Optional: anonymize port

        # Check if the packet has a UDP layer
        elif UDP in packet:
            udp_layer = packet[UDP]
            packet_data["Protocol"] = "UDP"
            packet_data["Source Port"] = udp_layer.sport  # Optional: anonymize port
            packet_data["Destination Port"] = udp_layer.dport  # Optional: anonymize port

    # Print the important packet data
    if packet_data:
        print(f"\n{packet_count}. New Packet:")
        print(f"    {'-'*20}")
        for key, value in packet_data.items():
            print(f"    {key}: {value}")
        print(f"    {'-'*20}")

# Start sniffing (use appropriate network interface, e.g., 'en0' for Wi-Fi on Mac)
print("Starting network sniffer...")
sniff(prn=packet_callback, count=5)  # Remove count to keep it running indefinitely
