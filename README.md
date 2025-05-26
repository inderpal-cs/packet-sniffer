# 🕵️‍♂️ Python Packet Sniffer

A low-level, real-time packet sniffer built with Python. This tool captures live network traffic at the Ethernet level, parses protocol headers, and prints structured information about IP and UDP packets. Built from scratch using raw sockets — no external libraries required.

---

## 📦 Features

- 🧠 Raw **Ethernet frame capture**
- 🌐 IPv4 header parsing (source, destination, protocol)
- 📦 UDP packet parsing (ports, length)
- ✅ Works on Linux (tested with WSL + Ubuntu)
- 🗃️ Modular structure for future expansion (DNS, TCP, HTTP parsing, logging)

---

## 🚀 Usage

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/python-packet-sniffer.git
cd python-packet-sniffer
```

### 2. Run sniffer (requeres sudo access)
sudo python3 main.py

### 3. Generate some traffic
ping 8.8.8.8
curl http://example.com


You should see:
Received packet of size 74
Ethernet Protocol: 0x800
🌐 IPv4 Packet: 172.20.80.1 → 8.8.8.8 | Protocol: 17
📦 UDP Packet: Port 55321 → 53 (DNS)

## What I Learned

-Understanding of how raw network traffic flows through Ethernet and IP layers

-Manual bitwise parsing of protocol headers (no libraries used)

-Practical experience working with sockets, WSL/Linux, and low-level networking

-Foundation for future work in packet inspection, IDS development, or malware traffic analysis

