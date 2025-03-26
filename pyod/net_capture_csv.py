#!/usr/bin/env python
# Network Capture to CSV for Anomaly Detection
# Simplified version that focuses on generating CSV data

import argparse
import time
from datetime import datetime
import os
import sys
from scapy.all import sniff, get_if_list, get_windows_if_list, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
import pandas as pd

def show_windows_interfaces():
    """Display all Windows network interfaces"""
    interfaces = get_windows_if_list()
    print("Available network interfaces:")
    print("-----------------------------")
    
    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface['name']}")
        print(f"    Description: {iface['description']}")
        print(f"    MAC: {iface.get('mac', 'N/A')}")
        print(f"    IPv4: {', '.join(iface.get('ips', ['N/A']))}")
        print("")
    
    return interfaces

def extract_features(packet, timestamp):
    """Extract network features from packet for anomaly detection"""
    # Initialize features dictionary with default values
    features = {
        'timestamp': timestamp,
        'protocol': 'OTHER',
        'src_ip': None,
        'dst_ip': None,
        'src_port': None, 
        'dst_port': None,
        'packet_size': len(packet) if packet else 0,
        'flags': None,
        'window_size': None,
        'ttl': None,
        'payload_size': 0
    }
    
    try:
        # Extract Layer 3 (IP) information if present
        if IP in packet:
            features['src_ip'] = packet[IP].src
            features['dst_ip'] = packet[IP].dst
            features['ttl'] = packet[IP].ttl
            
            # Determine protocol
            if packet[IP].proto == 1:  # ICMP
                features['protocol'] = 'ICMP'
                if ICMP in packet:
                    features['icmp_type'] = packet[ICMP].type
                    features['icmp_code'] = packet[ICMP].code
            elif packet[IP].proto == 6:  # TCP
                features['protocol'] = 'TCP'
                if TCP in packet:
                    features['src_port'] = packet[TCP].sport
                    features['dst_port'] = packet[TCP].dport
                    features['flags'] = str(packet[TCP].flags)
                    features['window_size'] = packet[TCP].window
            elif packet[IP].proto == 17:  # UDP
                features['protocol'] = 'UDP'
                if UDP in packet:
                    features['src_port'] = packet[UDP].sport
                    features['dst_port'] = packet[UDP].dport
        
        # Calculate payload size
        if hasattr(packet, 'payload') and packet.payload:
            features['payload_size'] = len(packet.payload)
            
        # Add more context-specific features
        features['is_private_src'] = is_private_ip(features['src_ip']) if features['src_ip'] else None
        features['is_private_dst'] = is_private_ip(features['dst_ip']) if features['dst_ip'] else None
        features['is_common_port'] = is_common_port(features['dst_port']) if features['dst_port'] else None
        
    except Exception as e:
        # Silently handle errors but continue
        pass
        
    return features

def is_private_ip(ip):
    """Check if IP address is in private range"""
    if not ip:
        return None
    
    # Check common private IP ranges
    if ip.startswith('10.') or ip.startswith('192.168.') or \
       (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31) or \
       ip.startswith('127.'):
        return 1
    return 0

def is_common_port(port):
    """Check if port is a commonly used one"""
    if not port:
        return None
    
    common_ports = {
        20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
        993, 995, 3306, 3389, 5900, 8080, 8443
    }
    
    return 1 if port in common_ports else 0

def capture_network_data(interface, duration=30, output_file=None, packet_limit=None, verbose=True):
    """Capture network data and save to CSV"""
    
    # Create default output filename with timestamp
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"network_data_{timestamp}.csv"
    
    # Storage for packets and features
    packet_features = []
    start_time = time.time()
    
    if verbose:
        print(f"Starting network capture on {interface} for {duration} seconds...")
        print(f"Data will be saved to {output_file}")
    
    # Packet callback function
    def process_packet(packet):
        try:
            # Generate timestamp for this packet
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            
            # Extract features
            features = extract_features(packet, timestamp)
            packet_features.append(features)
            
            # Print progress
            if verbose and len(packet_features) % 100 == 0:
                elapsed = time.time() - start_time
                print(f"Captured {len(packet_features)} packets ({elapsed:.1f}s elapsed)")
                
            # Check if we've hit time or packet limit
            if packet_limit and len(packet_features) >= packet_limit:
                return True
                
            if duration and (time.time() - start_time) >= duration:
                return True
                
        except Exception as e:
            if verbose:
                print(f"Error processing packet: {e}")
    
    try:
        # Start packet capture
        sniff(
            iface=interface,
            prn=process_packet,
            store=False
        )
    except KeyboardInterrupt:
        if verbose:
            print("\nCapture stopped by user.")
    except Exception as e:
        if verbose:
            print(f"Error during capture: {e}")
    
    # Process captured data
    if packet_features:
        if verbose:
            print(f"\nCapture complete. Processing {len(packet_features)} packets...")
        
        try:
            # Convert to DataFrame and save to CSV
            df = pd.DataFrame(packet_features)
            df.to_csv(output_file, index=False)
            
            if verbose:
                print(f"Network data saved to {output_file}")
                
                # Print basic statistics
                print("\nCapture Statistics:")
                print(f"Total packets: {len(df)}")
                
                if 'protocol' in df.columns:
                    proto_counts = df['protocol'].value_counts()
                    print("\nProtocol distribution:")
                    for proto, count in proto_counts.items():
                        print(f"  {proto}: {count} ({count/len(df)*100:.1f}%)")
                
                if 'src_ip' in df.columns:
                    unique_ips = df['src_ip'].nunique()
                    print(f"\nUnique source IPs: {unique_ips}")
                    
                    top_src = df['src_ip'].value_counts().head(5)
                    print("\nTop source IPs:")
                    for ip, count in top_src.items():
                        if ip:
                            print(f"  {ip}: {count}")
                
                if 'dst_port' in df.columns and df['dst_port'].notna().any():
                    top_ports = df['dst_port'].value_counts().head(5)
                    print("\nTop destination ports:")
                    for port, count in top_ports.items():
                        if port:
                            print(f"  {port}: {count}")
        
        except Exception as e:
            if verbose:
                print(f"Error saving data: {e}")
            return None
            
        return df
    else:
        if verbose:
            print("No packets captured.")
        return None

def main():
    parser = argparse.ArgumentParser(description="Capture network traffic to CSV for anomaly detection")
    parser.add_argument("--interface", "-i", help="Network interface to capture on")
    parser.add_argument("--duration", "-d", type=int, default=30, help="Duration in seconds to capture")
    parser.add_argument("--output", "-o", help="Output CSV file")
    parser.add_argument("--packets", "-p", type=int, help="Maximum number of packets to capture")
    parser.add_argument("--list", "-l", action="store_true", help="List available interfaces and exit")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress output")
    
    args = parser.parse_args()
    
    # List interfaces if requested
    if args.list:
        interfaces = show_windows_interfaces()
        sys.exit(0)
    
    # Set interface
    interface = args.interface
    if not interface:
        interfaces = show_windows_interfaces()
        
        try:
            idx = int(input("\nSelect interface by number: "))
            if 0 <= idx < len(interfaces):
                interface = interfaces[idx]['name']
            else:
                print("Invalid interface selection")
                sys.exit(1)
        except ValueError:
            print("Invalid input")
            sys.exit(1)
    
    # Capture data
    capture_network_data(
        interface=interface,
        duration=args.duration,
        output_file=args.output,
        packet_limit=args.packets,
        verbose=not args.quiet
    )

if __name__ == "__main__":
    main() 