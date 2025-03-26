import pandas as pd
import numpy as np
import time
from datetime import datetime
from config import DATA_PATH, BATCH_SIZE, SLEEP_INTERVAL

class RuleBasedDetector:
    def __init__(self):
        self.rules = {
            'zero_day_ports': [31337, 666, 31335],
            'unusual_tcp_flags': ['SYN+FIN', 'SYN+RST', 'FIN+RST'],
            'http_status_codes': list(range(100, 600)),
            'traffic_thresholds': {
                'bytes_sent': 1_000_000,
                'bytes_received': 100,
                'packets': 1000,
                'duration': 300
            }
        }
        
        # Track IPs for rate limiting
        self.ip_request_count = {}
        self.rate_limit_threshold = 50  # Alerts if more than 50 requests
        
    def check_rules(self, row):
        alerts = []
        
        # Port-based detection
        if row['dst_port'] in self.rules['zero_day_ports']:
            alerts.append(('zero_day_port', 1.0))
        
        # TCP flag detection
        if str(row['tcp_flags']) in self.rules['unusual_tcp_flags']:
            alerts.append(('suspicious_flags', 0.9))
        
        # Traffic volume detection
        if row['bytes_sent'] > self.rules['traffic_thresholds']['bytes_sent']:
            alerts.append(('high_bytes_sent', 0.8))
        
        # Unusual duration
        if row['duration'] > self.rules['traffic_thresholds']['duration']:
            alerts.append(('long_duration', 0.7))
            
        # Unusual packet count
        if row['packets'] > self.rules['traffic_thresholds']['packets']:
            alerts.append(('high_packet_count', 0.75))
            
        # Invalid HTTP status
        if row['http_status'] not in self.rules['http_status_codes']:
            alerts.append(('invalid_http_status', 0.7))
            
        # Rate limiting check
        src_ip = row['src_ip']
        self.ip_request_count[src_ip] = self.ip_request_count.get(src_ip, 0) + 1
        if self.ip_request_count[src_ip] > self.rate_limit_threshold:
            alerts.append(('rate_limit_exceeded', 0.6))
            
        return alerts

def simulate_real_time():
    print("Starting rule-based network anomaly detection...")
    detector = RuleBasedDetector()
    df = pd.read_csv(DATA_PATH)
    
    print(f"Processing {len(df)} records in batches of {BATCH_SIZE}...")
    
    # Process in batches
    for i in range(0, len(df), BATCH_SIZE):
        batch = df.iloc[i:i+BATCH_SIZE]
        batch_alerts = False
        
        for _, row in batch.iterrows():
            alerts = detector.check_rules(row)
            if alerts:
                if not batch_alerts:
                    print(f"\nFound anomalies in batch {i//BATCH_SIZE + 1}:")
                    batch_alerts = True
                
                for (alert_type, confidence) in alerts:
                    # Determine severity color
                    if confidence >= 0.9:
                        color = '\033[91m'  # Red - high severity
                    elif confidence >= 0.7:
                        color = '\033[93m'  # Yellow - medium severity
                    else:
                        color = '\033[96m'  # Cyan - low severity
                        
                    print(f"{color}ALERT: {row['timestamp']} {row['src_ip']}:{row['src_port']} -> "
                          f"{row['dst_ip']}:{row['dst_port']} [{row['protocol']}] | "
                          f"{alert_type.upper()} (Confidence: {confidence:.2f})\033[0m")
        
        if not batch_alerts:
            print(f"No anomalies detected in batch {i//BATCH_SIZE + 1}")
        
        time.sleep(SLEEP_INTERVAL)
    
    print("\nAnomaly detection completed!")

if __name__ == '__main__':
    simulate_real_time() 