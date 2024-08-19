from scapy.all import *
import textwrap
import chardet  # Library for better character encoding detection

# Define the log file
LOG_FILE = 'packet_log.txt'

# Function to process each packet
def packet_callback(packet):
    log_data = []

    # Extract Ethernet information
    if packet.haslayer(Ether):
        eth = packet[Ether]
        log_data.append(f"\nEthernet Frame: ")
        log_data.append(f"Destination MAC: {eth.dst}, Source MAC: {eth.src}, Type: {eth.type}")

    # Extract IPv4 information
    if packet.haslayer(IP):
        ip = packet[IP]
        log_data.append(f"IPv4 Packet: ")
        log_data.append(f"Version: {ip.version}, Header Length: {ip.ihl * 4} bytes, TTL: {ip.ttl}")
        log_data.append(f"Protocol: {ip.proto}, Source: {ip.src}, Target: {ip.dst}")

        # Extract TCP information (e.g., HTTP and HTTPS traffic)
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            log_data.append(f"TCP Segment: ")
            log_data.append(f"Source Port: {tcp.sport}, Destination Port: {tcp.dport}")
            log_data.append(f"Sequence Number: {tcp.seq}, Acknowledgment: {tcp.ack}")
            log_data.append(f"Flags: {tcp.flags}")

            # Detect HTTP traffic (port 80) and HTTPS traffic (port 443)
            if tcp.dport in [80, 443] or tcp.sport in [80, 443]:
                if packet.haslayer(Raw):
                    raw_payload = packet[Raw].load
                    log_data.append(f"HTTP/HTTPS Data: ")
                    log_data.append(format_multi_line('\t', safe_decode(raw_payload)))

                    # Detect sensitive information in HTTP/HTTPS payload
                    if b"POST" in raw_payload or b"GET" in raw_payload:
                        http_text = safe_decode(raw_payload)
                        if "username" in http_text or "password" in http_text:
                            log_data.append("\n*** POSSIBLE CREDENTIALS FOUND ***")
                            log_data.append(http_text)

        # Extract UDP information
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            log_data.append(f"UDP Segment: ")
            log_data.append(f"Source Port: {udp.sport}, Destination Port: {udp.dport}, Length: {udp.len}")

            if packet.haslayer(Raw):
                raw_payload = packet[Raw].load
                log_data.append(f"UDP Data: ")
                log_data.append(format_multi_line('\t', safe_decode(raw_payload)))

        # Extract ICMP information
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            log_data.append(f"ICMP Packet: ")
            log_data.append(f"Type: {icmp.type}, Code: {icmp.code}, Checksum: {icmp.chksum}")

            if packet.haslayer(Raw):
                raw_payload = packet[Raw].load
                log_data.append(f"ICMP Data: ")
                log_data.append(format_multi_line('\t', safe_decode(raw_payload)))

    # Extract Raw Data and decode it
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        decoded_data = safe_decode(raw_data)
        log_data.append(f"\n[Raw Data Decoded]:\n{format_multi_line('\t', decoded_data)}")

    # Write log data to file with UTF-8 encoding
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        for line in log_data:
            f.write(line + '\n')

    # Print log data to console for immediate feedback
    for line in log_data:
        print(line)

# Safe decode function to handle non-printable characters
def safe_decode(data):
    try:
        # Detect encoding
        result = chardet.detect(data)
        encoding = result['encoding']
        decoded = data.decode(encoding, errors='ignore')  # Decode raw data with detected encoding
    except Exception as e:
        decoded = f"[Undecodable Data] {data}"
    # Filter out non-printable characters
    decoded = ''.join(ch for ch in decoded if ch.isprintable() or ch in '\n\r\t')
    return decoded

# Format multi-line output for better readability
def format_multi_line(prefix, string, size=80):
    """Format multi-line output for better readability."""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def main():
    print("Starting continuous packet sniffer... Press CTRL + C to stop.")
    try:
        # Start sniffing on the default interface indefinitely
        sniff(prn=packet_callback, filter="tcp or udp or icmp")
    except KeyboardInterrupt:
        print("\nPacket Sniffer Stopped.")

if __name__ == "__main__":
    main()
