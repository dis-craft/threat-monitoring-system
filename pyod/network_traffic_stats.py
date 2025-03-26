#!/usr/bin/env python
# Simple Network Traffic Statistics Monitor
# Captures network statistics for anomaly detection

import psutil
import time
import csv
import datetime
import argparse
import sys
import os

def monitor_network_traffic(duration=30, interval=1.0, output_file=None):
    """
    Monitor network traffic statistics
    
    Parameters:
    -----------
    duration : int
        Duration in seconds to monitor
    interval : float
        Sampling interval in seconds
    output_file : str
        Output CSV file for statistics
    """
    # Create default output filename with timestamp
    if not output_file:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"network_stats_{timestamp}.csv"
    
    print(f"Starting network traffic monitoring for {duration} seconds...")
    print(f"Sampling every {interval} seconds")
    print(f"Data will be saved to: {output_file}")
    print("Press Ctrl+C to stop")
    
    # Store previous network counters to calculate rates
    prev_counters = psutil.net_io_counters()
    prev_time = time.time()
    
    # Store all data points
    data_points = []
    
    # Header for display
    header_shown = False
    
    try:
        # Run for specified duration
        end_time = time.time() + duration
        
        while time.time() < end_time:
            # Sleep for interval
            time.sleep(interval)
            
            # Get current counters
            curr_time = time.time()
            curr_counters = psutil.net_io_counters()
            
            # Calculate time difference
            time_diff = curr_time - prev_time
            
            # Calculate rates
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
            
            # Add to data points list
            data_points.append(data_point)
            
            # Display current rates
            if not header_shown:
                print("\nTimestamp            | KB/s Sent | KB/s Recv | Pkt/s Sent | Pkt/s Recv")
                print("-" * 70)
                header_shown = True
            
            print(f"{timestamp} | {bytes_sent_rate/1024:8.2f} | {bytes_recv_rate/1024:8.2f} | {packets_sent_rate:10.1f} | {packets_recv_rate:10.1f}")
            
            # Update previous counters for next iteration
            prev_counters = curr_counters
            prev_time = curr_time
    
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")
    
    # Save data to CSV
    if data_points:
        try:
            with open(output_file, 'w', newline='') as csvfile:
                fieldnames = data_points[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data_points)
                print(f"\nNetwork statistics saved to {output_file}")
        except Exception as e:
            print(f"Error saving CSV file: {e}")
    else:
        print("No data collected")
    
    return data_points

def analyze_traffic_data(data_points):
    """
    Analyze collected network traffic statistics
    
    Parameters:
    -----------
    data_points : list
        List of network statistics data points
    """
    if not data_points:
        print("No data to analyze")
        return
    
    print("\nNetwork Traffic Analysis:")
    print("------------------------")
    
    # Calculate average rates
    avg_bytes_sent = sum(dp['bytes_sent'] for dp in data_points) / len(data_points)
    avg_bytes_recv = sum(dp['bytes_recv'] for dp in data_points) / len(data_points)
    avg_packets_sent = sum(dp['packets_sent'] for dp in data_points) / len(data_points)
    avg_packets_recv = sum(dp['packets_recv'] for dp in data_points) / len(data_points)
    
    # Calculate max rates
    max_bytes_sent = max(dp['bytes_sent'] for dp in data_points)
    max_bytes_recv = max(dp['bytes_recv'] for dp in data_points)
    max_packets_sent = max(dp['packets_sent'] for dp in data_points)
    max_packets_recv = max(dp['packets_recv'] for dp in data_points)
    
    # Calculate total traffic
    total_bytes_sent = sum(dp['bytes_sent'] for dp in data_points)
    total_bytes_recv = sum(dp['bytes_recv'] for dp in data_points)
    total_packets_sent = sum(dp['packets_sent'] for dp in data_points)
    total_packets_recv = sum(dp['packets_recv'] for dp in data_points)
    
    # Calculate packet sizes
    avg_sent_packet_size = total_bytes_sent / total_packets_sent if total_packets_sent > 0 else 0
    avg_recv_packet_size = total_bytes_recv / total_packets_recv if total_packets_recv > 0 else 0
    
    # Print results
    print(f"Sampling period: {len(data_points)} intervals")
    
    print("\nTraffic totals:")
    print(f"  Total sent: {total_bytes_sent/1024/1024:.2f} MB ({total_packets_sent} packets)")
    print(f"  Total received: {total_bytes_recv/1024/1024:.2f} MB ({total_packets_recv} packets)")
    
    print("\nTraffic rates (per interval):")
    print(f"  Avg sent: {avg_bytes_sent/1024:.2f} KB ({avg_packets_sent:.1f} packets)")
    print(f"  Avg received: {avg_bytes_recv/1024:.2f} KB ({avg_packets_recv:.1f} packets)")
    print(f"  Max sent: {max_bytes_sent/1024:.2f} KB")
    print(f"  Max received: {max_bytes_recv/1024:.2f} KB")
    
    print("\nAverage packet sizes:")
    print(f"  Sent packets: {avg_sent_packet_size:.2f} bytes")
    print(f"  Received packets: {avg_recv_packet_size:.2f} bytes")
    
    # Check for errors or drops
    total_errors = sum(dp['errin'] for dp in data_points) + sum(dp['errout'] for dp in data_points)
    total_drops = sum(dp['dropin'] for dp in data_points) + sum(dp['dropout'] for dp in data_points)
    
    if total_errors > 0 or total_drops > 0:
        print("\nErrors and drops:")
        print(f"  Errors: {total_errors} (in: {sum(dp['errin'] for dp in data_points)}, out: {sum(dp['errout'] for dp in data_points)})")
        print(f"  Drops: {total_drops} (in: {sum(dp['dropin'] for dp in data_points)}, out: {sum(dp['dropout'] for dp in data_points)})")

def main():
    parser = argparse.ArgumentParser(description="Simple Network Traffic Statistics Monitor")
    parser.add_argument("--duration", "-d", type=int, default=30, help="Duration in seconds to monitor")
    parser.add_argument("--interval", "-i", type=float, default=1.0, help="Sampling interval in seconds")
    parser.add_argument("--output", "-o", help="Output CSV file")
    parser.add_argument("--analyze", "-a", action="store_true", help="Analyze captured data")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress output during monitoring")
    
    args = parser.parse_args()
    
    # Check for psutil
    try:
        import psutil
    except ImportError:
        print("Error: psutil module is required but not installed.")
        print("Please install it using: pip install psutil")
        sys.exit(1)
    
    # Monitor network traffic
    data_points = monitor_network_traffic(
        duration=args.duration,
        interval=args.interval,
        output_file=args.output
    )
    
    # Analyze data if requested
    if args.analyze:
        analyze_traffic_data(data_points)

if __name__ == "__main__":
    main() 