import argparse
from scapy.all import sniff, IP, ICMP, TCP, UDP, ARP, DHCP, DNS

# Callback function to process packets
def process_packet(packet):
    if DHCP in packet:
        print("DHCP Request:", packet.summary())
    elif DNS in packet:
        print("DNS Request:", packet.summary())
    elif ARP in packet:
        print("ARP Request:", packet.summary())
    elif ICMP in packet:
        print("ICMP Packet:", packet.summary())
    elif TCP in packet:
        print("TCP Packet:", packet.summary())
    elif UDP in packet:
        print("UDP Packet:", packet.summary())

# Function to sniff packets based on interface, filter, and count
def sniff_packets(interface=None, packet_filter=None, count=None):
    # Set a default value for count if None
    count = count if count is not None else -1  # -1 represents infinite count
    sniff(prn=process_packet, iface=interface, filter=packet_filter, count=count)

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Network Sniffer")
    parser.add_argument("interface", type=str, help="Interface name (e.g., wlan0, eth0, lo)")
    parser.add_argument("-P", "--protocol", type=str, help="Protocol to filter (e.g., icmp, tcp, udp)")
    parser.add_argument("-c", "--count", type=int, default=None, help="Number of packets to capture (default: None for infinity)")
    args = parser.parse_args()

    # Specify the packet filter for analysis based on the protocol
    if args.protocol:
        packet_filter = args.protocol
    else:
        packet_filter = "icmp or tcp or udp or arp or (port 67 or port 68) or (udp and port 53)"

    # Sniff packets based on command-line arguments
    sniff_packets(interface=args.interface, packet_filter=packet_filter, count=args.count)
