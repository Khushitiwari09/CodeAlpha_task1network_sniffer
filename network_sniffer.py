from scapy.all import sniff, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
import datetime

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ip_layer.proto
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_size = len(packet)  # Feature 1: Packet size

        # Determine the protocol
        protocol_name = ""
        if protocol == 1:
            protocol_name = "ICMP"
        elif protocol == 6:
            protocol_name = "TCP"
            src_port = packet[TCP].sport  # Feature 2: Port numbers for TCP/UDP
            dst_port = packet[TCP].dport
        elif protocol == 17:
            protocol_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            protocol_name = "Unknown Protocol"

        # Get current timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Print packet details
        print(f"\n[+] Packet captured at {timestamp}")
        print(f"Protocol: {protocol_name}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        
        # Display ports if TCP or UDP
        if protocol_name in ["TCP", "UDP"]:
            print(f"Source Port: {src_port}")
            print(f"Destination Port: {dst_port}")
            
        print(f"Packet Size: {packet_size} bytes")  # Display packet size
        print("-" * 50)

def main():
    print("Starting packet sniffer...")
    print("Press Ctrl+C to stop\n")
    # Capture packets on the default network interface
    sniff(prn=packet_callback, filter="ip", store=0)

if __name__ == "__main__":
    main()