# Basic Network Sniffer

This repository contains a Python-based network sniffer that captures and analyzes network traffic. It extracts and displays anonymized information about each packet, including the protocol, source IP, destination IP, source port, and destination port.

## Installation
To use the network sniffer, install the required library using pip:

```bash
pip install scapy
```

## Usage
1. Clone the Repository:
Clone this repository to your local machine:

```bash
git clone https://github.com/medtty/CodeAlpha_Network_Sniffer.git
```
2. Run the Sniffer:
Navigate to the repository directory and run the network sniffer script with root permissions:

```bash
sudo python network_sniffer.py
```

3. Analysis Details:
The network sniffer script captures and analyzes network packets in real-time. It extracts the following information for each packet:

- Source IP: The source IP address of the packet sender.
- Destination IP: The destination IP address of the packet receiver.
- Protocol: The protocol used (TCP or UDP).
- Source Port: The source port number used by the sender.
- Destination Port: The destination port number used by the receiver.

The script utilizes the Scapy library to handle packet sniffing and parsing.



```Python
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
```

## Output

```bash
Starting network sniffer...

1. New Packet:
    --------------------
    Source IP: c3f32a4b
    Destination IP: d728cb51
    Protocol: TCP
    Source Port: 12345
    Destination Port: 80
    --------------------

2. New Packet:
    --------------------
    Source IP: abfd13c7
    Destination IP: e8e3c9a0
    Protocol: UDP
    Source Port: 54321
    Destination Port: 53
    --------------------
```

### Here i used hash for anonymization
```python
import hashlib

def anonymize_ip(ip):
    return hashlib.sha256(ip.encode()).hexdigest()[:8]  # Use a hash for anonymization


# it can be used like this
if IP in packet:
    ip_layer = packet[IP]
    packet_data["Source IP"] = anonymize_ip(ip_layer.src)
    packet_data["Destination IP"] = anonymize_ip(ip_layer.dst)
```

## Contributing
Contributions are welcome! If you have any suggestions or improvements, please create a pull request or open an issue.

## License
This project is licensed under the MIT License.

## Contact
For any questions or feedback, feel free to reach out to me at [Medtty](doussm101@gmail.com).
