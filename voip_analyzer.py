from scapy.all import sniff, RTP, IP

def packet_callback(packet):
    if packet.haslayer(RTP):
        rtp_layer = packet.getlayer(RTP)
        print(f"RTP Packet: Seq={rtp_layer.seq}, Timestamp={rtp_layer.timestamp}, PayloadType={rtp_layer.payload_type}")

def main():
    print("Starting VoIP Traffic Analyzer...")
    print("Sniffing RTP packets on network. Press Ctrl+C to stop.")
    sniff(filter="udp", prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
