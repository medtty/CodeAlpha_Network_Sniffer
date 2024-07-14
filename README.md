# Basic Network Sniffer

This repository contains a Python-based network sniffer that captures and analyzes network traffic. It extracts and displays anonymized information about each packet, including the protocol, source IP, destination IP, source port, and destination port.

## Features
- Captures TCP and UDP packets.
- Logs source and destination IP addresses.
- Option to hash IP addresses for privacy.

## Requirements
- Python 3.x
- Scapy
- Root privileges (use sudo to run)

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
sudo python nsnif.py
```

## Using Hashed IP Addresses
To enable IP address hashing, run the script with the --hash option:

```bash
sudo python3 nsnif.py --hash
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

## Example Output
When the script is running, you will see logs similar to the following:

### Normal Mode Output

```bash
Starting network sniffer...

2024-07-14 12:26:16,178 - INFO - Scapy - Protocol: TCP Source: 192.168.1.10 Destination: 192.168.1.20
.
.
.
```

### Hashed Mode Output

```bash
Starting network sniffer...

2024-07-14 12:26:16,178 - INFO - Scapy - Protocol: TCP Source: a1b2c3d4 Destination: e5f6g7h8
.
.
.
```

## Stopping the Sniffer
You can stop the sniffer at any time by pressing Ctrl + C. The script will gracefully terminate and log that it has stopped.


## Contributing
Contributions are welcome! If you have any suggestions or improvements, please create a pull request or open an issue.

## License
This project is licensed under the MIT License.

## Contact
For any questions or feedback, feel free to reach out to me at [Medtty](doussm101@gmail.com).
