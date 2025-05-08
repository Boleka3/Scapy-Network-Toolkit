import tkinter as tk
from tkinter import messagebox, scrolledtext
from scapy.all import send, IP, ICMP, TCP, UDP, sniff, wrpcap, ARP, Ether, srp, rdpcap
import datetime
import time

# List to store captured packets
captured_packets = []

# Function to analyze and display packet details
def packet_analysis(target_ips, protocol_filter=None, max_packets=5, pcap_file="traffic_capture.pcap"):
    # Nonlocal variable to modify in the inner function
    remaining_packets = max_packets
    packet_details = ""

    def analyze_packet(packet):
        nonlocal remaining_packets  # Allow modification of 'remaining_packets'
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Check if either the source or destination IP matches the target hosts
            if src_ip in target_ips or dst_ip in target_ips:
                protocol = None
                packet_size = len(packet)

                # Check the protocol and extract relevant details
                if packet.haslayer(TCP) and (protocol_filter is None or protocol_filter == TCP):
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif packet.haslayer(UDP) and (protocol_filter is None or protocol_filter == UDP):
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif packet.haslayer(ICMP) and (protocol_filter is None or protocol_filter == ICMP):
                    protocol = "ICMP"
                    src_port = dst_port = None  # ICMP doesn't use ports

                # If the packet matches the filter protocol, build details for display
                if protocol:
                    packet_details += f"Timestamp: {datetime.datetime.now()}\n"
                    packet_details += f"Packet {max_packets - remaining_packets + 1}:\n"
                    packet_details += f"Source: {src_ip}\n"
                    packet_details += f"Destination: {dst_ip}\n"
                    packet_details += f"Protocol: {protocol}\n"
                    if protocol == "TCP" or protocol == "UDP":
                        packet_details += f"Source Port: {src_port}\n"
                        packet_details += f"Destination Port: {dst_port}\n"
                    packet_details += f"Packet Size: {packet_size} bytes\n"
                    packet_details += "-" * 50 + "\n"
                    
                    # Add the packet to the captured list
                    captured_packets.append(packet)

                    remaining_packets -= 1
                    if remaining_packets <= 0:
                        return True  # Stop sniffing after reaching the maximum number of packets

    # Determine the filter based on the protocol
    if protocol_filter == TCP:
        protocol_str = "tcp"
    elif protocol_filter == UDP:
        protocol_str = "udp"
    elif protocol_filter == ICMP:
        protocol_str = "icmp"
    else:
        protocol_str = "ip"  # Capture all IP packets if no specific protocol is provided

    # Sniff the packets based on the filter for the given protocol and target hosts
    sniff(filter=f"ip and {protocol_str}", prn=analyze_packet, store=False, count=max_packets)
    
    return packet_details

# Function to scan the subnet
def scan(subnet):
    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, _ = srp(arp_request_broadcast, timeout=2, verbose=False)

    devices = {}
    for sent, responded in answered:
        devices[responded.psrc] = responded.hwsrc  # Use IP as key to avoid duplicates

    return devices

# Function to send custom packets
def create_and_send_packet(dst_ip, protocol="ICMP"):
    if protocol == "ICMP":
        packet = IP(dst=dst_ip) / ICMP()
    elif protocol == "TCP":
        packet = IP(dst=dst_ip) / TCP(dport=80, flags="S")
    elif protocol == "UDP":
        packet = IP(dst=dst_ip) / UDP(dport=53)
    else:
        return "Invalid protocol selected!"
    
    send(packet)
    return f"{protocol} packet sent to {dst_ip}"

# Function to measure network performance and log it to a file
def measure_network_performance():
    log_file = "performance_log.txt"  # Log file to store the output
    try:
        # Start measuring latency
        start_time = time.time()
        send(IP(dst="8.8.8.8") / ICMP())
        latency = (time.time() - start_time) * 1000  # Convert to ms

        # Calculate throughput and jitter
        throughput = len(captured_packets) / (latency / 1000) if latency > 0 else 0
        jitter = abs(latency - (len(captured_packets) / 2 if len(captured_packets) > 1 else 0))

        # Create the performance summary
        performance_summary = (
            f"Latency: {latency:.2f} ms\n"
            f"Throughput: {throughput:.2f} packets/s\n"
            f"Jitter: {jitter:.2f} ms\n"
            f"Timestamp: {datetime.datetime.now()}\n"
            f"{'-' * 50}\n"
        )

        # Write performance summary to the log file
        with open(log_file, "a") as file:  # Open in append mode
            file.write(performance_summary)

        return performance_summary.strip()  # Return for display

    except Exception as e:
        error_message = f"Error measuring performance: {e}\n"
        with open(log_file, "a") as file:
            file.write(error_message)
        return error_message

# Main GUI interface (Tkinter)
class NetworkToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Tools")

        # Set up UI elements
        self.protocol_var = tk.StringVar()
        self.protocol_var.set("ICMP")

        self.target_ip_entry = tk.Entry(self.root)
        self.subnet_entry = tk.Entry(self.root)
        self.packet_details_text = scrolledtext.ScrolledText(self.root, width=80, height=20)

        self.protocol_menu = tk.OptionMenu(self.root, self.protocol_var, "ICMP", "TCP", "UDP")

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Target IP:").grid(row=0, column=0)
        self.target_ip_entry.grid(row=0, column=1)

        tk.Label(self.root, text="Subnet (e.g., 192.168.1.0/24):").grid(row=1, column=0)
        self.subnet_entry.grid(row=1, column=1)

        tk.Label(self.root, text="Protocol:").grid(row=2, column=0)
        self.protocol_menu.grid(row=2, column=1)

        self.packet_details_text.grid(row=3, column=0, columnspan=2)

        tk.Button(self.root, text="Scan Subnet", command=self.scan_subnet).grid(row=4, column=0)
        tk.Button(self.root, text="Start Packet Analysis", command=self.packet_analysis).grid(row=4, column=1)
        tk.Button(self.root, text="Send Custom Packet", command=self.send_custom_packet).grid(row=5, column=0)
        tk.Button(self.root, text="Measure Network Performance", command=self.measure_network_performance).grid(row=5, column=1)

    def scan_subnet(self):
        subnet = self.subnet_entry.get()
        if subnet:
            devices = scan(subnet)
            result = "\n".join([f"{ip} - {mac}" for ip, mac in devices.items()])
            messagebox.showinfo("Devices Found", result)
        else:
            messagebox.showerror("Error", "Please enter a subnet.")

    def packet_analysis(self):
        target_ip = self.target_ip_entry.get()
        protocol = self.protocol_var.get()

        if target_ip:
            packet_details = packet_analysis([target_ip], protocol_filter=eval(protocol.upper()))
            self.packet_details_text.delete(1.0, tk.END)
            self.packet_details_text.insert(tk.END, packet_details)
            messagebox.showinfo("Packet Analysis", "Packet analysis complete.")
        else:
            messagebox.showerror("Error", "Please enter a target IP.")

    def send_custom_packet(self):
        dst_ip = self.target_ip_entry.get()
        protocol = self.protocol_var.get()

        if dst_ip:
            result = create_and_send_packet(dst_ip, protocol)
            messagebox.showinfo("Packet Sent", result)
        else:
            messagebox.showerror("Error", "Please enter a destination IP.")

    def measure_network_performance(self):
        performance = measure_network_performance()
        self.packet_details_text.delete(1.0, tk.END)
        self.packet_details_text.insert(tk.END, performance)


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkToolGUI(root)
    root.mainloop()
