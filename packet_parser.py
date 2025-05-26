import struct


def parse_ip_header(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack("!8xBB2x4s4s", data[:20])
    return {
        "version": version,
        "header_size": header_len,
        "ttl": ttl,
        "protocol": proto,
        "src": format_ip(src),
        "target": format_ip(target)
    }


def parse_tcp_header(data):
    src_port, dest_port, seq, ack, offset_reserved_flags = struct.unpack("!HHLLH", data[:14])
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "sequence": seq,
        "acknowledgment": ack,
        "flags": offset_reserved_flags
    }


def parse_udp_header(data):
    src_port, dest_port, size = struct.unpack("!HHH", data[:6])
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "size": size
    }


def format_ip(raw_bytes):
    return ".".join(map(str, raw_bytes))
