#!/usr/bin/env python
# Network Monitor for Anomaly Detection
# Captures both traffic statistics and connection data
# No dependencies on scapy - works with standard libraries

import os
import sys
import time
import csv
import argparse
import threading
import socket
import datetime
import json
from collections import defaultdict

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

# Global variables for connections
active_connections = {}
connection_history = []
conn_lock = threading.Lock()

# Global variables for traffic stats
traffic_stats = []
stats_lock = threading.Lock()

# Global flag for stopping threads
should_stop = False

def monitor_traffic_stats(interval=1.0, verbose=True):
    """Monitor network traffic statistics at regular intervals"""
    global traffic_stats, should_stop
    
    prev_counters = psutil.net_io_counters()
    prev_time = time.time()
    
    if verbose:
        print("\nTimestamp            | KB/s Sent | KB/s Recv | Pkt/s Sent | Pkt/s Recv")
        print("-" * 70)
    
    try:
        while not should_stop:
            # Sleep for interval
            time.sleep(interval)
            
            # Get current counters
            curr_time = time.time()
            curr_counters = psutil.net_io_counters()
            
            # Calculate time difference
            time_diff = curr_time - prev_time
            
            # Calculate deltas
            bytes_sent = curr_counters.bytes_sent - prev_counters.bytes_sent
            bytes_recv = curr_counters.bytes_recv - prev_counters.bytes_recv
            packets_sent = curr_counters.packets_sent - prev_counters.packets_sent
            packets_recv = curr_counters.packets_recv - prev_counters.packets_recv
            
            # Calculate rates per second
            bytes_sent_rate = bytes_sent / time_diff
            bytes_recv_rate = bytes_recv / time_diff
            packets_sent_rate = packets_sent / time_diff
            packets_recv_rate = packets_recv / time_diff
            
            # Create data point
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            data_point = {
                'timestamp': timestamp,
                'bytes_sent': bytes_sent,
                'bytes_recv': bytes_recv,
                'packets_sent': packets_sent,
                'packets_recv': packets_recv,
                'bytes_sent_rate': bytes_sent_rate,
                'bytes_recv_rate': bytes_recv_rate,
                'packets_sent_rate': packets_sent_rate,
                'packets_recv_rate': packets_recv_rate,
                'errin': curr_counters.errin - prev_counters.errin,
                'errout': curr_counters.errout - prev_counters.errout,
                'dropin': curr_counters.dropin - prev_counters.dropin,
                'dropout': curr_counters.dropout - prev_counters.dropout
            }
            
            # Add to traffic stats (thread-safe)
            with stats_lock:
                traffic_stats.append(data_point)
            
            # Display current rates if verbose
            if verbose:
                print(f"{timestamp} | {bytes_sent_rate/1024:8.2f} | {bytes_recv_rate/1024:8.2f} | {packets_sent_rate:10.1f} | {packets_recv_rate:10.1f}")
            
            # Update previous counters for next iteration
            prev_counters = curr_counters
            prev_time = curr_time
    
    except Exception as e:
        print(f"\nError monitoring traffic stats: {e}")
        
    return traffic_stats

def monitor_connections(interval=1.0, verbose=False):
    """Monitor network connections"""
    global active_connections, connection_history, should_stop
    
    last_connections = set()
    
    try:
        while not should_stop:
            try:
                # Get current connections
                connections = psutil.net_connections(kind='all')
                current_connections = set()
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                
                # Process connections
                for conn in connections:
                    # Skip connections with no remote address
                    if not conn.raddr:
                        continue
                    
                    # Create a connection ID
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "None"
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "None"
                    conn_id = f"{conn.proto}|{local_addr}|{remote_addr}"
                    current_connections.add(conn_id)
                    
                    # Process connection
                    with conn_lock:
                        if conn_id in active_connections:
                            # Update existing connection
                            active_connections[conn_id]['status'] = conn.status
                            active_connections[conn_id]['last_seen'] = time.time()
                        else:
                            # New connection
                            try:
                                process_name = "Unknown"
                                if conn.pid:
                                    try:
                                        process = psutil.Process(conn.pid)
                                        process_name = process.name()
                                    except:
                                        pass
                                
                                # Add to active connections
                                active_connections[conn_id] = {
                                    'proto': conn.proto,
                                    'local_addr': local_addr,
                                    'remote_addr': remote_addr,
                                    'status': conn.status,
                                    'pid': conn.pid,
                                    'process': process_name,
                                    'first_seen': time.time(),
                                    'last_seen': time.time()
                                }
                                
                                # Add to history
                                connection_record = {
                                    'timestamp': timestamp,
                                    'type': 'new',
                                    'proto': conn.proto,
                                    'local_addr': local_addr,
                                    'remote_addr': remote_addr,
                                    'status': conn.status,
                                    'pid': conn.pid,
                                    'process': process_name
                                }
                                connection_history.append(connection_record)
                                
                                if verbose:
                                    proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(conn.proto, str(conn.proto))
                                    print(f"New connection: {proto_name} from {local_addr} to {remote_addr} ({process_name})")
                            except Exception as e:
                                if verbose:
                                    print(f"Error processing new connection: {e}")
                
                # Find closed connections
                closed_connections = last_connections - current_connections
                for conn_id in closed_connections:
                    with conn_lock:
                        if conn_id in active_connections:
                            conn_data = active_connections[conn_id]
                            
                            # Add to history
                            connection_record = {
                                'timestamp': timestamp,
                                'type': 'closed',
                                'proto': conn_data['proto'],
                                'local_addr': conn_data['local_addr'],
                                'remote_addr': conn_data['remote_addr'],
                                'duration': time.time() - conn_data['first_seen'],
                                'process': conn_data.get('process', 'Unknown')
                            }
                            connection_history.append(connection_record)
                            
                            if verbose:
                                proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(conn_data['proto'], str(conn_data['proto']))
                                print(f"Closed connection: {proto_name} from {conn_data['local_addr']} to {conn_data['remote_addr']}")
                            
                            # Remove from active connections
                            del active_connections[conn_id]
                
                # Update last connections
                last_connections = current_connections
                
            except Exception as e:
                print(f"Error monitoring connections: {e}")
            
            # Wait for next interval
            time.sleep(interval)
                
    except Exception as e:
        print(f"\nError in connection monitor: {e}")
    
    return connection_history

def save_data_to_csv(traffic_data, connection_data, traffic_file=None, connection_file=None):
    """Save collected data to CSV files"""
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Set default filenames
    if not traffic_file:
        traffic_file = f"network_traffic_{timestamp}.csv"
    if not connection_file:
        connection_file = f"network_connections_{timestamp}.csv"
    
    # Save traffic data
    if traffic_data:
        try:
            with open(traffic_file, 'w', newline='') as csvfile:
                fieldnames = traffic_data[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(traffic_data)
                print(f"Traffic statistics saved to {traffic_file}")
        except Exception as e:
            print(f"Error saving traffic data: {e}")
    
    # Save connection data
    if connection_data:
        try:
            with open(connection_file, 'w', newline='') as csvfile:
                # Get all possible fields from all records
                all_fields = set()
                for record in connection_data:
                    all_fields.update(record.keys())
                
                writer = csv.DictWriter(csvfile, fieldnames=list(all_fields))
                writer.writeheader()
                writer.writerows(connection_data)
                print(f"Connection data saved to {connection_file}")
        except Exception as e:
            print(f"Error saving connection data: {e}")
    
    return traffic_file, connection_file

def analyze_data(traffic_data, connection_data):
    """Analyze the collected network data"""
    
    print("\n===== Network Traffic Analysis =====")
    if traffic_data:
        # Calculate statistics
        total_bytes_sent = sum(dp['bytes_sent'] for dp in traffic_data)
        total_bytes_recv = sum(dp['bytes_recv'] for dp in traffic_data)
        total_packets_sent = sum(dp['packets_sent'] for dp in traffic_data)
        total_packets_recv = sum(dp['packets_recv'] for dp in traffic_data)
        
        avg_bytes_sent = total_bytes_sent / len(traffic_data)
        avg_bytes_recv = total_bytes_recv / len(traffic_data)
        
        max_bytes_sent = max(dp['bytes_sent'] for dp in traffic_data)
        max_bytes_recv = max(dp['bytes_recv'] for dp in traffic_data)
        
        # Calculate packet sizes
        avg_packet_size_sent = total_bytes_sent / total_packets_sent if total_packets_sent > 0 else 0
        avg_packet_size_recv = total_bytes_recv / total_packets_recv if total_packets_recv > 0 else 0
        
        # Print summary
        print(f"Sampling period: {len(traffic_data)} intervals")
        print(f"Total data transferred: {(total_bytes_sent + total_bytes_recv) / (1024*1024):.2f} MB")
        print(f"  Sent: {total_bytes_sent / (1024*1024):.2f} MB ({total_packets_sent} packets)")
        print(f"  Received: {total_bytes_recv / (1024*1024):.2f} MB ({total_packets_recv} packets)")
        
        print("\nAverage transfer rates:")
        print(f"  Upload: {avg_bytes_sent / 1024:.2f} KB/s")
        print(f"  Download: {avg_bytes_recv / 1024:.2f} KB/s")
        
        print("\nPeak transfer rates:")
        print(f"  Max Upload: {max_bytes_sent / 1024:.2f} KB/s")
        print(f"  Max Download: {max_bytes_recv / 1024:.2f} KB/s")
        
        print("\nAverage packet sizes:")
        print(f"  Sent packets: {avg_packet_size_sent:.2f} bytes")
        print(f"  Received packets: {avg_packet_size_recv:.2f} bytes")
    else:
        print("No traffic data available for analysis")
    
    print("\n===== Connection Analysis =====")
    if connection_data:
        # Count connections by type
        connections_by_type = defaultdict(int)
        for conn in connection_data:
            connections_by_type[conn.get('type', 'unknown')] += 1
        
        # Count by protocol
        connections_by_proto = defaultdict(int)
        for conn in connection_data:
            if 'proto' in conn:
                proto = conn['proto']
                proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))
                connections_by_proto[proto_name] += 1
        
        # Count by remote IP
        remote_ips = defaultdict(int)
        for conn in connection_data:
            if 'remote_addr' in conn and ':' in conn['remote_addr']:
                ip = conn['remote_addr'].split(':')[0]
                remote_ips[ip] += 1
        
        # Count by process
        processes = defaultdict(int)
        for conn in connection_data:
            if 'process' in conn:
                processes[conn['process']] += 1
        
        # Print summary
        print(f"Total connections recorded: {len(connection_data)}")
        print(f"  New connections: {connections_by_type.get('new', 0)}")
        print(f"  Closed connections: {connections_by_type.get('closed', 0)}")
        
        print("\nConnections by protocol:")
        for proto, count in sorted(connections_by_proto.items(), key=lambda x: x[1], reverse=True):
            print(f"  {proto}: {count}")
        
        print("\nTop remote addresses:")
        for ip, count in sorted(remote_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count}")
        
        print("\nTop processes:")
        for process, count in sorted(processes.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {process}: {count}")
    else:
        print("No connection data available for analysis")

def run_network_monitor(duration=60, traffic_interval=1.0, conn_interval=2.0, 
                     traffic_file=None, connection_file=None, 
                     analyze=True, verbose_traffic=True, verbose_connections=False):
    """Run the complete network monitoring solution"""
    global should_stop, traffic_stats, connection_history
    
    # Reset global variables
    should_stop = False
    traffic_stats = []
    connection_history = []
    
    print(f"Starting network monitoring for {duration} seconds...")
    print(f"Traffic sampling interval: {traffic_interval}s")
    print(f"Connection sampling interval: {conn_interval}s")
    print("Press Ctrl+C to stop monitoring")
    
    try:
        # Start traffic monitoring thread
        traffic_thread = threading.Thread(
            target=monitor_traffic_stats,
            args=(traffic_interval, verbose_traffic)
        )
        traffic_thread.daemon = True
        traffic_thread.start()
        
        # Start connection monitoring thread
        connection_thread = threading.Thread(
            target=monitor_connections,
            args=(conn_interval, verbose_connections)
        )
        connection_thread.daemon = True
        connection_thread.start()
        
        # Wait for specified duration or until user interrupts
        try:
            for _ in range(int(duration)):
                time.sleep(1)
                if should_stop:
                    break
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
        
        # Set stop flag for threads
        should_stop = True
        
        # Wait for threads to finish
        traffic_thread.join(timeout=2.0)
        connection_thread.join(timeout=2.0)
        
        # Save collected data
        print("\nSaving collected data...")
        traffic_path, connection_path = save_data_to_csv(
            traffic_stats, connection_history,
            traffic_file, connection_file
        )
        
        # Analyze data if requested
        if analyze:
            analyze_data(traffic_stats, connection_history)
        
        return traffic_stats, connection_history
            
    except Exception as e:
        print(f"Error in network monitor: {e}")
        should_stop = True
        return traffic_stats, connection_history

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Comprehensive Network Monitor for Anomaly Detection")
    parser.add_argument("--duration", "-d", type=int, default=60, 
                        help="Duration in seconds to run the monitor")
    parser.add_argument("--traffic-interval", "-ti", type=float, default=1.0,
                        help="Sampling interval for traffic statistics")
    parser.add_argument("--connection-interval", "-ci", type=float, default=2.0,
                        help="Sampling interval for connection monitoring")
    parser.add_argument("--traffic-file", "-tf", 
                        help="Output file for traffic statistics")
    parser.add_argument("--connection-file", "-cf", 
                        help="Output file for connection data")
    parser.add_argument("--analyze", "-a", action="store_true", default=True,
                        help="Analyze the collected data")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress real-time statistics output")
    parser.add_argument("--verbose-connections", "-vc", action="store_true",
                        help="Show detailed connection information in real-time")
    
    args = parser.parse_args()
    
    # Check if psutil is available
    if not HAVE_PSUTIL:
        print("Error: psutil is required but could not be installed.")
        print("Please install it manually: pip install psutil")
        sys.exit(1)
    
    # Run the monitor
    run_network_monitor(
        duration=args.duration,
        traffic_interval=args.traffic_interval,
        conn_interval=args.connection_interval,
        traffic_file=args.traffic_file,
        connection_file=args.connection_file,
        analyze=args.analyze,
        verbose_traffic=not args.quiet,
        verbose_connections=args.verbose_connections
    )

if __name__ == "__main__":
    main() 