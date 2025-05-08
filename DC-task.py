from scapy.all import send, IP, ICMP
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP, rdpcap
import datetime
import time

# List to store captured packets
captured_packets = []

# Function to analyze and display packet details
def packet_analysis(target_ips, protocol_filter=None, max_packets=5, pcap_file="traffic_capture.pcap"):
    # Nonlocal variable to modify in the inner function
    remaining_packets = max_packets
    
    def analyze_packet(packet):
        nonlocal remaining_packets  # Allow modification of 'remaining_packets'
        print("Analyzing packet...")  # Debugging line to check if packets are being captured
        # Only process IP packets and filter by target IP and protocol
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

                # If the packet matches the filter protocol, print details in the desired format
                if protocol:
                    print(f"Timestamp: {datetime.datetime.now()}")  # Print timestamp
                    print(f"Packet {max_packets - remaining_packets + 1}:")
                    print(f"Source: {src_ip}")
                    print(f"Destination: {dst_ip}")
                    print(f"Protocol: {protocol}")
                    if protocol == "TCP" or protocol == "UDP":
                        print(f"Source Port: {src_port}")
                        print(f"Destination Port: {dst_port}")
                    print(f"Packet Size: {packet_size} bytes")
                    print("-" * 50)  # Separator for each packet
                    
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

    print(f"Starting packet sniffing for {protocol_str.upper()} packets for target hosts: {', '.join(target_ips)}...\n")
    
    # Sniff the packets based on the filter for the given protocol and target hosts
    sniff(filter=f"ip and {protocol_str}", prn=analyze_packet, store=False, count=max_packets)

    # Write captured packets to a PCAP file (append if exists)
    if captured_packets:
        try:
            # Append the captured packets to the existing PCAP file
            current_packets = captured_packets
            # Try to load existing pcap file to append packets
            try:
                existing_packets = rdpcap(pcap_file)
                current_packets = existing_packets + captured_packets
            except:
                # If the file does not exist, create a new list of packets
                pass
            wrpcap(pcap_file, current_packets)  # Save the combined packets to the pcap file
            print(f"Captured packets saved to {pcap_file}.")
        except Exception as e:
            print(f"Error writing to PCAP file: {e}")

# Function to scan the subnet
def scan(subnet):
    from scapy.all import ARP, Ether, srp

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

# Main interface (command line)
def main():
    while True:
        print("\nSelect a task:")
        print("1. Scan Subnet")
        print("2. Packet Analysis")
        print("3. Send Custom Packet")
        print("4. Measure Network Performance")
        print("5. Exit")

        choice = input("Enter your choice (1-5): ")

        if choice == "1":
            subnet = input("Enter the subnet to scan (e.g., 192.168.1.0/24): ")
            try:
                devices = scan(subnet)
                print("\nActive devices in the subnet:")
                print("IP Address\t\tMAC Address")
                print("-" * 40)
                for ip, mac in devices.items():
                    print(f"{ip}\t\t{mac}")
            except Exception as e:
                print(f"Error scanning subnet: {e}")

        elif choice == "2":
            target_ip = input("Enter target IP for packet analysis: ")
            protocol = input("Enter protocol (ICMP/TCP/UDP): ")
            try:
                packet_analysis([target_ip], protocol_filter=eval(protocol.upper()))
                print(f"Packets captured for {target_ip} and saved to 'traffic_capture.pcap'.")
            except Exception as e:
                print(f"Error during packet analysis: {e}")

        elif choice == "3":
            dst_ip = input("Enter destination IP for custom packet: ")
            protocol = input("Enter protocol (ICMP/TCP/UDP): ")
            try:
                result = create_and_send_packet(dst_ip, protocol)
                print(result)
            except Exception as e:
                print(f"Error sending packet: {e}")

        elif choice == "4":
            try:
                performance = measure_network_performance()
                print(performance)
            except Exception as e:
                print(f"Error measuring performance: {e}")

        elif choice == "5":
            print("Exiting...")
            break

        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()