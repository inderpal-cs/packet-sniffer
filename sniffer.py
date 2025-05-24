import socket


def sniff_packets():
    # Create a raw socket
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind(("0.0.0.0", 0))  # Listen on all interfaces

        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("❌ Run as administrator/root to access raw socket.")
        return

    print("🚀 Sniffing started... (Press Ctrl+C to stop)")

    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            print(f"\n[+] Packet received from {addr}")
            print(raw_data[:40])  # Just print a slice for now
    except KeyboardInterrupt:
        print("\n🛑 Sniffing stopped.")
        sniffer.close()
