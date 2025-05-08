# 🕵️ Network Analysis Toolkit (Python + Scapy)

This is a Python-based command-line network analysis tool built using [Scapy](https://scapy.net/). It provides functionality to scan subnets, analyze live packets, send custom packets, and measure basic network performance metrics such as latency, throughput, and jitter.

⚠️ **Note:** This tool is designed to run on **Linux (Ubuntu preferred)** with **root privileges** due to raw packet operations.

## 📦 Features

1. **🔍 Subnet Scanning**  
   Discover active devices on a subnet using ARP requests. Displays IP and MAC addresses.

2. **📊 Packet Analysis**  
   Capture and display live TCP/UDP/ICMP traffic for a specific IP. Filter by protocol and limit by packet count. Save captured traffic to a `.pcap` file for later inspection (e.g., with Wireshark).

3. **📤 Send Custom Packets**  
   Craft and send a single packet of a chosen protocol (ICMP, TCP, UDP) to a target IP.

4. **📈 Network Performance Measurement**  
   Estimate latency, throughput, and jitter by sending ICMP packets to Google DNS (`8.8.8.8`). Results are logged in `performance_log.txt`.

## 🚀 Getting Started

### 🔧 Requirements

- Python 3.6 or higher  
- Linux (Ubuntu recommended)  
- Root privileges  
- Scapy library

### 📥 Installation

Clone the repository and install the required package:

```bash
git clone https://github.com/your-username/network-toolkit.git
cd network-toolkit
pip install scapy
