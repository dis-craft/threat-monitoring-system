import pandas as pd
import numpy as np
from faker import Faker
from datetime import datetime, timedelta
from config import DATA_PATH, NUM_RECORDS, ANOMALY_RATIO
import os

fake = Faker()

def generate_network_logs():
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
    
    # Base normal traffic
    data = []
    start_time = datetime.now() - timedelta(days=1)
    
    for _ in range(NUM_RECORDS):
        record = {
            'timestamp': (start_time + timedelta(seconds=np.random.randint(0, 86400))).isoformat(),
            'src_ip': fake.ipv4(),
            'dst_ip': fake.ipv4(),
            'src_port': np.random.randint(1024, 65535),
            'dst_port': np.random.choice([80, 443, 22, 53, 3389]),
            'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], p=[0.7, 0.25, 0.05]),
            'bytes_sent': np.random.randint(100, 100000),
            'bytes_received': np.random.randint(100, 50000),
            'duration': np.random.exponential(60),
            'packets': np.random.randint(1, 100),
            'tcp_flags': np.random.choice(['SYN', 'ACK', 'PSH', 'RST', 'FIN'], size=1)[0],
            'http_status': np.random.choice([200, 301, 404, 500], p=[0.9, 0.05, 0.03, 0.02])
        }
        data.append(record)

    # Inject anomalies
    num_anomalies = int(NUM_RECORDS * ANOMALY_RATIO)
    for _ in range(num_anomalies):
        anomaly = {
            'timestamp': (start_time + timedelta(seconds=np.random.randint(0, 86400))).isoformat(),
            'src_ip': fake.ipv4(),
            'dst_ip': fake.ipv4(),
            'src_port': np.random.randint(1024, 65535),
            'dst_port': 31337,  # Common anomaly port
            'protocol': 'TCP',
            'bytes_sent': np.random.randint(1000000, 5000000),
            'bytes_received': np.random.randint(0, 100),
            'duration': np.random.exponential(600),
            'packets': np.random.randint(1000, 5000),
            'tcp_flags': 'SYN+FIN',  # Uncommon combination
            'http_status': 999  # Invalid status
        }
        data.append(anomaly)
    
    df = pd.DataFrame(data)
    df.to_csv(DATA_PATH, index=False)
    print(f"Generated {len(df)} records at {DATA_PATH}")

if __name__ == '__main__':
    generate_network_logs() 