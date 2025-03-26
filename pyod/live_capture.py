#!/usr/bin/env python
# Live Network Capture Script using Scapy
# Compatible with Npcap on Windows

import argparse
import time
from datetime import datetime
import os
import sys
from scapy.all import sniff, wrpcap, conf, get_if_list, show_interfaces
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
import pandas as pd
import csv

def get_interface(interface_arg):
    """
    Get the actual interface to use for packet capture
    
    Parameters:
    -----------
    interface_arg : str
        Interface name, index, or device string
    """
    # If it's an integer, treat as index
    try:
        idx = int(interface_arg)
        ifaces = get_if_list()
        if 0 <= idx < len(ifaces):
            return ifaces[idx]
        else:
            print(f"Interface index {idx} is out of range")
            show_interfaces()
            return None
    except ValueError:
        # Not an integer, use as is
        return interface_arg

def extract_packet_features(packet, timestamp):
    """
    Extract detailed features from a packet for anomaly detection
    
    Parameters:
    -----------
    packet : Scapy packet
        The packet to extract features from
    timestamp : str
        Capture timestamp
    
    Returns:
    --------
    dict : Dictionary of features
    """
    # Initialize with basic fields
    features = {
        'timestamp': timestamp,
        'packet_time': packet.time if hasattr(packet, 'time') else 0,
        'protocol': 'UNKNOWN',
        'src_mac': None,
        'dst_mac': None,
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None,
        'packet_size': len(packet) if packet else 0,
        'ip_version': None,
        'ip_ttl': None,
        'ip_flags': None,
        'tcp_flags': None,
        'tcp_window': None,
        'icmp_type': None,
        'icmp_code': None,
        'payload_size': 0,
        'has_payload': 0
    }
    
    try:
        # Extract Ethernet layer info if present
        if Ether in packet:
            features['src_mac'] = packet[Ether].src
            features['dst_mac'] = packet[Ether].dst
        
        # Extract IP layer info if present
        if IP in packet:
            features['protocol'] = packet[IP].proto
            features['src_ip'] = packet[IP].src
            features['dst_ip'] = packet[IP].dst
            features['ip_version'] = packet[IP].version
            features['ip_ttl'] = packet[IP].ttl
            features['ip_flags'] = packet[IP].flags
            
            # Get protocol name based on IP protocol number
            if packet[IP].proto == 1:
                features['protocol'] = 'ICMP'
            elif packet[IP].proto == 6:
                features['protocol'] = 'TCP'
            elif packet[IP].proto == 17:
                features['protocol'] = 'UDP'
        
        # Extract TCP layer info if present
        if TCP in packet:
            features['src_port'] = packet[TCP].sport
            features['dst_port'] = packet[TCP].dport
            features['tcp_flags'] = packet[TCP].flags
            features['tcp_window'] = packet[TCP].window
        
        # Extract UDP layer info if present
        elif UDP in packet:
            features['src_port'] = packet[UDP].sport
            features['dst_port'] = packet[UDP].dport
        
        # Extract ICMP info if present
        elif ICMP in packet:
            features['icmp_type'] = packet[ICMP].type
            features['icmp_code'] = packet[ICMP].code
        
        # Check for payload
        if hasattr(packet, 'payload') and len(packet.payload) > 0:
            features['payload_size'] = len(packet.payload)
            features['has_payload'] = 1
            
    except Exception as e:
        # If any error occurs during feature extraction, log it but continue
        print(f"Warning: Error extracting features from packet: {e}")
    
    return features

def capture_packets(interface, duration, output_file=None, csv_output=None, packet_count=None, verbose=True):
    """
    Capture network packets and save to pcap and csv files
    
    Parameters:
    -----------
    interface : str
        Network interface to capture on (name, index, or device string)
    duration : int
        Duration in seconds to capture packets
    output_file : str, optional
        File to save captured packets (.pcap format)
    csv_output : str, optional
        File to save packet features (.csv format)
    packet_count : int, optional
        Maximum number of packets to capture
    verbose : bool, default=True
        Whether to print status messages
    """
    # Create timestamp for default filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Set default output files if not specified
    if not output_file:
        output_file = f"capture_{timestamp}.pcap"
    
    if not csv_output:
        csv_output = f"network_data_{timestamp}.csv"
    
    # Get actual interface
    actual_iface = get_interface(interface)
    if not actual_iface:
        return [], []
    
    packets = []
    packet_features = []
    start_time = time.time()
    end_time = start_time + duration
    
    def packet_callback(packet):
        try:
            capture_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            packets.append(packet)
            
            # Extract features for this packet
            features = extract_packet_features(packet, capture_time)
            packet_features.append(features)
            
            if verbose and len(packets) % 100 == 0:
                print(f"Captured {len(packets)} packets...")
            
            # Stop capturing if duration exceeded
            if time.time() > end_time:
                return True
        except Exception as e:
            print(f"Warning: Error processing packet: {e}")
    
    try:
        if verbose:
            print(f"Starting capture on interface '{actual_iface}' for {duration} seconds...")
            print(f"PCAP output will be saved to: {output_file}")
            print(f"CSV data will be saved to: {csv_output}")
            print("Note: Running with admin privileges may improve capture results")
        
        # Start packet capture with error handling
        try:
            sniff(
                iface=actual_iface,
                prn=packet_callback,
                count=packet_count,
                timeout=duration,
                store=False
            )
        except Exception as e:
            print(f"Warning: Capture error: {e}")
            print("Continuing with packet processing...")
        
        # Save captured packets to pcap
        if packets:
            if verbose:
                print(f"Saving {len(packets)} packets to {output_file}")
            try:
                wrpcap(output_file, packets)
                print(f"PCAP capture saved to {output_file}")
            except Exception as e:
                print(f"Error saving PCAP file: {e}")
            
            # Save features to CSV
            if packet_features:
                try:
                    # Create DataFrame from features
                    df = pd.DataFrame(packet_features)
                    
                    # Save to CSV
                    df.to_csv(csv_output, index=False)
                    print(f"Network data saved to {csv_output}")
                    
                    # Print sample statistics
                    print(f"\nCapture summary:")
                    if 'protocol' in df.columns:
                        protocol_counts = df['protocol'].value_counts()
                        print(f"Top protocols: {protocol_counts.head(3).to_dict()}")
                    
                    if 'packet_size' in df.columns:
                        avg_size = df['packet_size'].mean()
                        print(f"Average packet size: {avg_size:.2f} bytes")
                except Exception as e:
                    print(f"Error saving CSV file: {e}")
                
        else:
            print("No packets captured.")
            
        return packets, packet_features
        
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
        if packets:
            try:
                wrpcap(output_file, packets)
                
                # Save features to CSV
                if packet_features:
                    df = pd.DataFrame(packet_features)
                    df.to_csv(csv_output, index=False)
                    print(f"Saved {len(packets)} packets to {output_file}")
                    print(f"Network data saved to {csv_output}")
            except Exception as e:
                print(f"Error saving files after interruption: {e}")
    except Exception as e:
        print(f"Error during capture: {e}")
        if verbose:
            print("Available interfaces:")
            show_interfaces()
    
    return packets, packet_features

def analyze_capture(packets, features_df=None):
    """
    Analyze captured packets and feature data
    
    Parameters:
    -----------
    packets : list
        List of captured packets
    features_df : pandas.DataFrame, optional
        DataFrame with extracted features
    """
    if not packets:
        print("No packets to analyze")
        return
    
    # Analyze packets
    protocols = {}
    ip_sources = {}
    ip_destinations = {}
    ports = {}
    
    for pkt in packets:
        # Get protocol name from highest layer
        protocol = pkt.name if hasattr(pkt, 'name') else "Unknown"
        protocols[protocol] = protocols.get(protocol, 0) + 1
        
        # Try to extract IP addresses if present
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ip_sources[src_ip] = ip_sources.get(src_ip, 0) + 1
            ip_destinations[dst_ip] = ip_destinations.get(dst_ip, 0) + 1
            
            # Extract ports
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                ports[f"{src_ip}:{src_port}"] = ports.get(f"{src_ip}:{src_port}", 0) + 1
                ports[f"{dst_ip}:{dst_port}"] = ports.get(f"{dst_ip}:{dst_port}", 0) + 1
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                ports[f"{src_ip}:{src_port}"] = ports.get(f"{src_ip}:{src_port}", 0) + 1
                ports[f"{dst_ip}:{dst_port}"] = ports.get(f"{dst_ip}:{dst_port}", 0) + 1
    
    # Print basic packet summary
    print("\nPacket Capture Summary:")
    print(f"Total packets: {len(packets)}")
    
    print("\nTop Protocols:")
    for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {proto}: {count} packets")
    
    print("\nTop Source IPs:")
    for ip, count in sorted(ip_sources.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {ip}: {count} packets")
    
    print("\nTop Destination IPs:")
    for ip, count in sorted(ip_destinations.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {ip}: {count} packets")
    
    print("\nTop Endpoint Ports:")
    for endpoint, count in sorted(ports.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {endpoint}: {count} packets")
    
    # Analyze features if available
    if features_df is not None and not features_df.empty:
        print("\nFeature Statistics:")
        
        # Calculate basic statistics
        if 'packet_size' in features_df.columns:
            print(f"  Packet size (min/avg/max): {features_df['packet_size'].min():.0f}/{features_df['packet_size'].mean():.0f}/{features_df['packet_size'].max():.0f} bytes")
        
        if 'protocol' in features_df.columns:
            print("  Protocol distribution:")
            proto_counts = features_df['protocol'].value_counts()
            for proto, count in proto_counts.items():
                print(f"    {proto}: {count} ({count/len(features_df)*100:.1f}%)")
        
        if 'src_port' in features_df.columns:
            unique_src_ports = features_df['src_port'].nunique()
            print(f"  Unique source ports: {unique_src_ports}")
            top_src_ports = features_df['src_port'].value_counts().head(3)
            print("  Top source ports:")
            for port, count in top_src_ports.items():
                if port is not None:
                    print(f"    {port}: {count}")
        
        if 'dst_port' in features_df.columns:
            unique_dst_ports = features_df['dst_port'].nunique()
            print(f"  Unique destination ports: {unique_dst_ports}")
            top_dst_ports = features_df['dst_port'].value_counts().head(3)
            print("  Top destination ports:")
            for port, count in top_dst_ports.items():
                if port is not None:
                    print(f"    {port}: {count}")

def list_interfaces():
    """Show available interfaces and exit"""
    print("Available network interfaces:")
    print("-----------------------------")
    show_interfaces()
    print("\nTo capture on an interface, use its index number or name.")
    print("Example: --interface 0")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="Capture live network traffic for anomaly detection")
    parser.add_argument("--interface", "-i", help="Network interface to capture on (index number or name)")
    parser.add_argument("--duration", "-d", type=int, default=30, help="Duration in seconds to capture")
    parser.add_argument("--output", "-o", help="Output pcap file")
    parser.add_argument("--csv", "-c", help="Output CSV file for detailed network data")
    parser.add_argument("--count", "-n", type=int, help="Maximum number of packets to capture")
    parser.add_argument("--analyze", "-a", action="store_true", help="Analyze captured packets")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress status messages")
    parser.add_argument("--list", "-l", action="store_true", help="List available interfaces and exit")
    
    args = parser.parse_args()
    
    # List interfaces if requested
    if args.list:
        list_interfaces()
    
    # Check for required interface
    if not args.interface:
        print("Error: Interface is required")
        list_interfaces()
    
    # Capture packets
    packets, features = capture_packets(
        interface=args.interface,
        duration=args.duration,
        output_file=args.output,
        csv_output=args.csv,
        packet_count=args.count,
        verbose=not args.quiet
    )
    
    # Analyze if requested
    if args.analyze and packets:
        features_df = pd.DataFrame(features) if features else None
        analyze_capture(packets, features_df)

if __name__ == "__main__":
    main() 