import socket
from packet_parser import parse_ip_header, parse_tcp_header, parse_udp_header
from logger import log_packet_summary

def sniff_packets():
    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("❌ You need root privileges. Run with sudo.")
        return

    print("🚀 Sniffing packets... Press Ctrl+C to stop.\n")

    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            print(f"Received packet of size {len(raw_data)}")

            eth_proto = socket.ntohs(int.from_bytes(raw_data[12:14], "big"))
            print(f"Ethernet Protocol: {hex(eth_proto)}")
            if eth_proto == 0x0800:  # IPv4
                ip = parse_ip_header(raw_data[14:])
                print(f"🌐 IPv4 Packet: {ip['src']} → {ip['target']} | Protocol: {ip['protocol']}")

            ip = parse_ip_header(raw_data[14:])
            protocol = ip["protocol"]
            ip_header_len = ip["header_size"]
            transport_data = raw_data[14 + ip_header_len:]

            if protocol == 6:
                tcp = parse_tcp_header(transport_data)
                log_packet_summary(ip, tcp, "TCP")
            elif protocol == 17:
                udp = parse_udp_header(transport_data)
                log_packet_summary(ip, udp, "UDP")

    except KeyboardInterrupt:
        print("\n🛑 Sniffing stopped.")
        sniffer.close()
