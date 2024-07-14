# import signal
# import threading
# import logging
# import sys
# import time
# import hashlib
# from scapy.all import sniff, IP, TCP, UDP, conf

# # Set up logging
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# logger = logging.getLogger(__name__)

# # Disable Scapy warnings
# conf.verb = 0

# def hash_ip(ip):
#     """Hash the IP address using MD5 and return a shortened version."""
#     return hashlib.md5(ip.encode()).hexdigest()[:8]  # Shorten to 8 characters

# def scapy_packet_callback(packet):
#     if IP in packet:
#         ip_layer = packet[IP]
#         src_hash = hash_ip(ip_layer.src)
#         dst_hash = hash_ip(ip_layer.dst)
#         protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else None
#         if protocol:
#             logger.info(f"Scapy - Protocol: {protocol} Source (hashed): {src_hash} Destination (hashed): {dst_hash}")

# def run_scapy_sniffer(stop_event: threading.Event):
#     logger.info("Starting network sniffer using Scapy...")
#     try:
#         sniff(prn=scapy_packet_callback, stop_filter=lambda x: stop_event.is_set(), store=0, iface='en0')  # Adjust iface as needed
#     except Exception as e:
#         logger.error(f"Error in Scapy sniffer: {e}")
#     finally:
#         logger.info("Scapy sniffer stopped.")

# def signal_handler(signal, frame):
#     logger.info("Received signal to stop. Setting stop event...")
#     stop_event.set()

# def main():
#     global stop_event
#     stop_event = threading.Event()
#     threads = []

#     scapy_thread = threading.Thread(target=run_scapy_sniffer, args=(stop_event,))
#     scapy_thread.daemon = True
#     threads.append(scapy_thread)

#     for thread in threads:
#         thread.start()

#     signal.signal(signal.SIGINT, signal_handler)

#     try:
#         while not stop_event.is_set():
#             for thread in threads:
#                 if not thread.is_alive():
#                     logger.error("A sniffer thread has unexpectedly stopped. Shutting down...")
#                     stop_event.set()
#                     break
#             time.sleep(0.1)
#     except KeyboardInterrupt:
#         logger.info("Received KeyboardInterrupt. Stopping threads...")
#         stop_event.set()
#     finally:
#         for thread in threads:
#             thread.join(timeout=5)  # Wait up to 5 seconds for each thread
#         logger.info("All threads stopped. Exiting program.")
#         sys.exit(0)

# if __name__ == "__main__":
#     main()

import signal
import threading
import logging
import sys
import time
import hashlib
import argparse
from scapy.all import sniff, IP, TCP, UDP, conf

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Disable Scapy warnings
conf.verb = 0

def hash_ip(ip):
    """Hash the IP address using MD5 and return a shortened version."""
    return hashlib.md5(ip.encode()).hexdigest()[:8]  # Shorten to 8 characters

def scapy_packet_callback(packet, use_hash):
    if IP in packet:
        ip_layer = packet[IP]
        src = hash_ip(ip_layer.src) if use_hash else ip_layer.src
        dst = hash_ip(ip_layer.dst) if use_hash else ip_layer.dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else None
        if protocol:
            logger.info(f"Scapy - Protocol: {protocol} Source: {src} Destination: {dst}")

def run_scapy_sniffer(stop_event: threading.Event, use_hash: bool):
    logger.info("Starting network sniffer using Scapy...")
    try:
        sniff(prn=lambda x: scapy_packet_callback(x, use_hash), stop_filter=lambda x: stop_event.is_set(), store=0, iface='en0')  # Adjust iface as needed
    except Exception as e:
        logger.error(f"Error in Scapy sniffer: {e}")
    finally:
        logger.info("Scapy sniffer stopped.")

def signal_handler(signal, frame):
    logger.info("Received signal to stop. Setting stop event...")
    stop_event.set()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument("--hash", action="store_true", help="Use hashed IP addresses in output")
    return parser.parse_args()

def main():
    global stop_event
    stop_event = threading.Event()
    args = parse_arguments()

    scapy_thread = threading.Thread(target=run_scapy_sniffer, args=(stop_event, args.hash))
    scapy_thread.daemon = True
    scapy_thread.start()

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while not stop_event.is_set():
            time.sleep(0.1)
    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt. Stopping threads...")
        stop_event.set()
    finally:
        scapy_thread.join(timeout=5)  # Wait up to 5 seconds for the thread to finish
        logger.info("All threads stopped. Exiting program.")
        sys.exit(0)

if __name__ == "__main__":
    main()
