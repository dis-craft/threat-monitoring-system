#!/usr/bin/env python
# Simple Network Traffic Monitor for Anomaly Detection
# Uses standard Python libraries instead of scapy

import socket
import time
import csv
import os
import argparse
import threading
import datetime
import json
from collections import defaultdict
import sys

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False
    print("Warning: psutil not found. Installing with pip:")
    try:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
        import psutil
        HAVE_PSUTIL = True
    except Exception as e:
        print(f"Error installing psutil: {e}")

# Global variables
connections = []
stats = {
    'bytes_sent': 0,
    'bytes_recv': 0,
    'packets_sent': 0,
    'packets_recv': 0,
    'conn_established': 0,
    'conn_closed': 0
}

# For storing active/recent connections
active_connections = {}
connection_history = []

# For thread synchronization
lock = threading.Lock()

def monitor_connections(interval=1.0, duration=None):
    """Monitor network connections at regular intervals"""
    global connections, stats, active_connections, connection_history
    
    start_time = time.time()
    last_check = {}  # Store previous connection stats
    
    try:
        print(f"Starting network monitoring for {duration if duration else 'unlimited'} seconds...")
        print("Press Ctrl+C to stop monitoring")
        
        while True:
            current_time = time.time()
            
            # Check if duration has elapsed
            if duration and (current_time - start_time) >= duration:
                print(f"\nReached specified duration of {duration} seconds")
                break
            
            # Get all network connections
            if HAVE_PSUTIL:
                try:
                    new_connections = psutil.net_connections(kind='all')
                    
                    # Process each connection
                    with lock:
                        # First, mark all current connections as inactive
                        for conn_id in active_connections:
                            active_connections[conn_id]['active'] = False
                        
                        # Process new/updated connections
                        for conn in new_connections:
                            # Skip connections with no remote address (e.g., listening sockets)
                            if not conn.raddr:
                                continue
                                
                            # Create a connection ID from the 5-tuple
                            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "None"
                            remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "None"
                            conn_id = f"{conn.proto}|{local_addr}|{remote_addr}"
                            
                            # Update or add to active connections
                            if conn_id in active_connections:
                                # Update existing connection
                                active_connections[conn_id]['active'] = True
                                active_connections[conn_id]['status'] = conn.status
                                active_connections[conn_id]['last_seen'] = current_time
                            else:
                                # New connection
                                active_connections[conn_id] = {
                                    'proto': conn.proto,
                                    'local_addr': local_addr,
                                    'remote_addr': remote_addr,
                                    'status': conn.status,
                                    'pid': conn.pid,
                                    'first_seen': current_time,
                                    'last_seen': current_time,
                                    'active': True
                                }
                                
                                # Record new connection in history
                                conn_record = {
                                    'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                                    'proto': conn.proto,
                                    'local_addr': local_addr,
                                    'remote_addr': remote_addr,
                                    'status': conn.status,
                                    'pid': conn.pid,
                                    'type': 'new_connection'
                                }
                                connection_history.append(conn_record)
                        
                        # Check for closed connections
                        for conn_id, conn_data in active_connections.items():
                            if not conn_data['active'] and conn_data.get('status') != 'CLOSE':
                                # Connection was active but now closed
                                conn_data['status'] = 'CLOSE'
                                
                                # Record closed connection
                                conn_record = {
                                    'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                                    'proto': conn_data['proto'],
                                    'local_addr': conn_data['local_addr'],
                                    'remote_addr': conn_data['remote_addr'],
                                    'duration': current_time - conn_data['first_seen'],
                                    'type': 'closed_connection'
                                }
                                connection_history.append(conn_record)
                                
                    # Get network I/O stats
                    net_io = psutil.net_io_counters()
                    
                    # Calculate deltas since last check
                    if last_check:
                        with lock:
                            stats['bytes_sent'] += net_io.bytes_sent - last_check.get('bytes_sent', 0)
                            stats['bytes_recv'] += net_io.bytes_recv - last_check.get('bytes_recv', 0)
                            stats['packets_sent'] += net_io.packets_sent - last_check.get('packets_sent', 0)
                            stats['packets_recv'] += net_io.packets_recv - last_check.get('packets_recv', 0)
                    
                    # Update last check values
                    last_check = {
                        'bytes_sent': net_io.bytes_sent,
                        'bytes_recv': net_io.bytes_recv,
                        'packets_sent': net_io.packets_sent,
                        'packets_recv': net_io.packets_recv
                    }
                    
                except Exception as e:
                    print(f"Error monitoring connections: {e}")
            
            # Sleep until next interval
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")
    
    return connection_history, stats

def save_to_csv(connection_data, output_file=None):
    """Save captured network data to CSV"""
    if not output_file:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"network_data_{timestamp}.csv"
    
    # Convert connection data to flat format for CSV
    flat_data = []
    
    for conn in connection_data:
        flat_conn = {
            'timestamp': conn['timestamp'],
            'protocol': conn['proto'],
            'local_address': conn['local_addr'],
            'remote_address': conn['remote_addr'],
            'status': conn.get('status', ''),
            'type': conn.get('type', ''),
            'duration': conn.get('duration', ''),
            'pid': conn.get('pid', '')
        }
        flat_data.append(flat_conn)
    
    # Write to CSV
    try:
        with open(output_file, 'w', newline='') as csvfile:
            if flat_data:
                fieldnames = flat_data[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(flat_data)
                print(f"Network data saved to {output_file}")
            else:
                print("No data to save")
    except Exception as e:
        print(f"Error saving CSV file: {e}")
    
    return output_file

def analyze_connections(connection_data, network_stats):
    """Analyze connection data and print summary"""
    if not connection_data:
        print("No connection data to analyze")
        return
    
    # Count by protocol
    proto_counts = defaultdict(int)
    
    # Count by remote IP
    remote_ips = defaultdict(int)
    
    # Count by connection type (new/closed)
    type_counts = defaultdict(int)
    
    # Process each connection
    for conn in connection_data:
        # Count protocols
        proto_counts[conn['proto']] += 1
        
        # Extract remote IP from remote_addr (ip:port format)
        if ':' in conn['remote_addr']:
            remote_ip = conn['remote_addr'].split(':')[0]
            remote_ips[remote_ip] += 1
        
        # Count by type
        type_counts[conn.get('type', 'unknown')] += 1
    
    # Print summary
    print("\nNetwork Activity Summary:")
    print("-----------------------")
    print(f"Total connections recorded: {len(connection_data)}")
    print(f"New connections: {type_counts['new_connection']}")
    print(f"Closed connections: {type_counts['closed_connection']}")
    
    print("\nProtocol distribution:")
    for proto, count in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True):
        proto_name = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }.get(proto, str(proto))
        print(f"  {proto_name}: {count}")
    
    print("\nTop remote addresses:")
    for ip, count in sorted(remote_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {ip}: {count} connections")
    
    print("\nNetwork I/O stats:")
    print(f"  Bytes sent: {network_stats['bytes_sent']:,}")
    print(f"  Bytes received: {network_stats['bytes_recv']:,}")
    print(f"  Packets sent: {network_stats['packets_sent']:,}")
    print(f"  Packets received: {network_stats['packets_recv']:,}")

def main():
    parser = argparse.ArgumentParser(description="Simple Network Traffic Monitor for Anomaly Detection")
    parser.add_argument("--duration", "-d", type=int, default=30, help="Duration in seconds to monitor")
    parser.add_argument("--interval", "-i", type=float, default=1.0, help="Sampling interval in seconds")
    parser.add_argument("--output", "-o", help="Output CSV file for detailed network data")
    parser.add_argument("--analyze", "-a", action="store_true", help="Analyze capture data")
    
    args = parser.parse_args()
    
    if not HAVE_PSUTIL:
        print("Error: psutil module is required but could not be installed.")
        print("Try installing it manually: pip install psutil")
        sys.exit(1)
    
    # Start monitoring
    connection_data, network_stats = monitor_connections(
        interval=args.interval,
        duration=args.duration
    )
    
    # Save to CSV
    output_file = save_to_csv(connection_data, args.output)
    
    # Analyze data
    if args.analyze:
        analyze_connections(connection_data, network_stats)

if __name__ == "__main__":
    main() 