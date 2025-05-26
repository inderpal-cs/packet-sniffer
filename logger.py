def log_packet_summary(ip, transport, protocol):
    print(f"📦 {protocol} Packet:")
    print(f" - From: {ip['src']}:{transport['src_port']}")
    print(f" - To  : {ip['target']}:{transport['dest_port']}")
    print(f" - TTL : {ip['ttl']}")
    print(f" - Flags/Size: {transport.get('flags', transport.get('size', 'N/A'))}")
    print("-" * 40)
