import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from collections import defaultdict
import matplotlib.pyplot as plt
from datetime import datetime

# Global variables to track packet statistics
packet_count = defaultdict(int)
packet_protocol_stats = defaultdict(int)

# Function to handle and analyze each packet
def process_packet(packet):
    global packet_count, packet_protocol_stats

    # Count the packet
    packet_count['total'] += 1

    # Analyze packet protocol
    if packet.haslayer(scapy.IP):
        ip_layer = packet.getlayer(scapy.IP)
        protocol = ip_layer.proto
        if protocol == 6:  # TCP
            packet_protocol_stats['TCP'] += 1
            log_packet(packet, "TCP")
        elif protocol == 17:  # UDP
            packet_protocol_stats['UDP'] += 1
            log_packet(packet, "UDP")
        elif packet.haslayer(HTTPRequest):  # HTTP
            packet_protocol_stats['HTTP'] += 1
            log_packet(packet, "HTTP")
        else:
            packet_protocol_stats['Other'] += 1

    # Visualize stats every 50 packets
    if packet_count['total'] % 50 == 0:
        visualize_stats()

    # Trigger alert for high TCP or HTTP traffic
    check_alert_conditions()

# Log packet information into a text file
def log_packet(packet, protocol):
    with open("packet_data.txt", "a") as f:
        f.write(f"Time: {datetime.now()}\n")
        f.write(f"Protocol: {protocol}\n")
        if protocol == "TCP" or protocol == "UDP":
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            f.write(f"Source IP: {ip_src}\n")
            f.write(f"Destination IP: {ip_dst}\n")
        if protocol == "HTTP":
            f.write(f"HTTP Request: {packet[HTTPRequest].Host.decode()} {packet[HTTPRequest].Path.decode()}\n")
        f.write("="*40 + "\n")

# Function to visualize packet statistics
def visualize_stats():
    protocols = list(packet_protocol_stats.keys())
    counts = list(packet_protocol_stats.values())
    plt.bar(protocols, counts, color='blue')
    plt.xlabel("Protocol")
    plt.ylabel("Packet Count")
    plt.title("Packet Statistics")
    plt.show()

# Function to check alert conditions
def check_alert_conditions():
    # Example: Trigger alert if TCP traffic exceeds 100 packets
    if packet_protocol_stats['TCP'] > 100:
        print("[ALERT] High TCP Traffic Detected!")
    # Example: Trigger alert if HTTP traffic exceeds 50 packets
    if packet_protocol_stats['HTTP'] > 50:
        print("[ALERT] High HTTP Traffic Detected!")

# Start packet sniffing
def start_sniffing(interface):
    print(f"Starting packet sniffing on interface: {interface}")
    try:
        scapy.sniff(iface=interface, prn=process_packet, store=False)
    except Exception as e:
        print(f"Error during sniffing: {e}")

if __name__ == "__main__":
    interface = "wlan0"  # Use your network interface here
    start_sniffing(interface)
