import numpy as np
import pandas as pd
import time
import random
import json
from datetime import datetime
import threading

class NetworkTrafficSimulator:
    """Simulates live network traffic with occasional anomalies"""
    
    # Network protocol types
    PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP', 'SMTP', 'POP3']
    
    # Service types 
    SERVICES = ['http', 'ftp', 'smtp', 'ssh', 'dns', 'sql', 'telnet', 'irc', 'pop3', 'other']
    
    # Attack types
    ATTACK_TYPES = [
        'DoS', 'Probe', 'R2L', 'U2R', 'Backdoor', 'Analysis', 
        'Fuzzers', 'Worms', 'Shellcode', 'Generic'
    ]
    
    # Common source ports
    SOURCE_PORTS = [1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033]
    
    # Common destination ports 
    DEST_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]
    
    # Internal and external IP patterns
    INTERNAL_IPS = ['192.168.1.', '10.0.0.', '172.16.0.']
    EXTERNAL_IPS = ['203.0.113.', '198.51.100.', '8.8.8.', '104.16.', '151.101.']
    
    def __init__(self, anomaly_probability=0.1):
        """
        Initialize the simulator
        
        Parameters:
        -----------
        anomaly_probability : float, default=0.1
            Probability of generating an anomalous connection
        """
        self.anomaly_probability = anomaly_probability
        self.features = None
        self.current_data = None
        self.stop_flag = False
        
    def generate_normal_traffic(self, n_samples=1):
        """Generate normal network traffic features"""
        
        data = {
            'duration': np.random.exponential(30, n_samples),  # Connection duration in seconds
            'protocol_type': np.random.choice(self.PROTOCOLS, n_samples),
            'service': np.random.choice(self.SERVICES, n_samples),
            'src_bytes': np.random.exponential(500, n_samples),  # Source to dest bytes
            'dst_bytes': np.random.exponential(300, n_samples),  # Dest to source bytes
            'count': np.random.poisson(3, n_samples),  # Connection count to same host
            'srv_count': np.random.poisson(3, n_samples),  # Connection count to same service
            'dst_host_same_src_port_rate': np.random.beta(2, 5, n_samples),
            'dst_host_srv_diff_host_rate': np.random.beta(2, 5, n_samples), 
            'src_port': np.random.choice(self.SOURCE_PORTS, n_samples),
            'dst_port': np.random.choice(self.DEST_PORTS, n_samples),
            'flag': np.random.choice(['S0', 'S1', 'SF', 'REJ', 'RSTO'], n_samples),
            'src_ip': [random.choice(self.INTERNAL_IPS) + str(random.randint(1, 254)) for _ in range(n_samples)],
            'dst_ip': [random.choice(self.EXTERNAL_IPS) + str(random.randint(1, 254)) for _ in range(n_samples)],
            'timestamp': [datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] for _ in range(n_samples)],
            'packets': np.random.poisson(10, n_samples),
            'bytes': np.random.exponential(1000, n_samples),
            'urgent': np.zeros(n_samples),  # Urgent packets (rarely used in normal traffic)
            'land': np.zeros(n_samples),    # Land attack (source/dest are same)
            'wrong_fragment': np.zeros(n_samples),  # Wrong fragments
            'num_failed_logins': np.zeros(n_samples)  # Failed login attempts
        }
        
        # Add a few more network-specific features
        data['ack_rate'] = np.random.beta(5, 2, n_samples)  # Rate of ACK packets
        data['psh_rate'] = np.random.beta(2, 5, n_samples)  # Rate of PSH packets 
        data['rst_rate'] = np.random.beta(1, 10, n_samples)  # Rate of RST packets
        data['syn_rate'] = np.random.beta(1, 5, n_samples)   # Rate of SYN packets
        data['fin_rate'] = np.random.beta(1, 5, n_samples)   # Rate of FIN packets
        
        # Label as normal
        data['label'] = ['normal'] * n_samples
        data['is_anomaly'] = [0] * n_samples
        
        return pd.DataFrame(data)
    
    def generate_anomalous_traffic(self, n_samples=1):
        """Generate anomalous network traffic features"""
        
        # Start with normal traffic base
        data = self.generate_normal_traffic(n_samples).to_dict('records')
        
        for i in range(n_samples):
            # Select a random attack type
            attack_type = random.choice(self.ATTACK_TYPES)
            data[i]['label'] = attack_type
            data[i]['is_anomaly'] = 1
            
            # Modify features based on attack type
            if attack_type == 'DoS':
                # DoS attacks often have many connections to the same host/service
                data[i]['count'] = np.random.poisson(20)
                data[i]['srv_count'] = np.random.poisson(20)
                data[i]['dst_host_same_src_port_rate'] = np.random.beta(5, 2)
                data[i]['syn_rate'] = np.random.beta(5, 1)  # Many SYN packets
                data[i]['ack_rate'] = np.random.beta(1, 5)  # Few ACK packets
                
            elif attack_type == 'Probe':
                # Probe attacks often have connections to many ports
                data[i]['dst_port'] = random.randint(1, 65535)
                data[i]['srv_count'] = np.random.poisson(1)
                data[i]['dst_host_srv_diff_host_rate'] = np.random.beta(5, 2)
                
            elif attack_type == 'R2L' or attack_type == 'U2R':
                # Remote to Local or User to Root often involves login attempts
                data[i]['dst_port'] = random.choice([22, 23, 3389])  # SSH, Telnet, RDP
                data[i]['duration'] = np.random.exponential(300)  # Longer duration
                data[i]['num_failed_logins'] = random.randint(1, 5)
                
            elif attack_type in ['Backdoor', 'Shellcode']:
                # Backdoor/Shellcode often has unusual data patterns
                data[i]['src_bytes'] = np.random.exponential(5000)
                data[i]['dst_bytes'] = np.random.exponential(5000)
                data[i]['dst_port'] = random.choice([4444, 5555, 6666, 7777, 8888])  # Common backdoor ports
                
            elif attack_type == 'Worms':
                # Worms try to spread
                data[i]['count'] = np.random.poisson(15)
                data[i]['srv_count'] = np.random.poisson(15)
                data[i]['dst_host_same_src_port_rate'] = np.random.beta(5, 1)
                
            # Add some randomness to make detection more challenging
            if random.random() < 0.3:
                # Sometimes anomalies try to blend in
                data[i]['duration'] = np.random.exponential(30)
                data[i]['count'] = np.random.poisson(3)
                
            # Generate suspicious source IPs for some attacks
            if random.random() < 0.7:
                data[i]['src_ip'] = random.choice(self.EXTERNAL_IPS) + str(random.randint(1, 254))
        
        return pd.DataFrame(data)
    
    def generate_mixed_traffic(self, n_samples=10):
        """Generate a mix of normal and anomalous traffic"""
        
        # Determine number of anomalies
        n_anomalies = np.random.binomial(n_samples, self.anomaly_probability)
        n_normal = n_samples - n_anomalies
        
        # Generate both types
        normal_traffic = self.generate_normal_traffic(n_normal)
        
        if n_anomalies > 0:
            anomalous_traffic = self.generate_anomalous_traffic(n_anomalies)
            mixed_traffic = pd.concat([normal_traffic, anomalous_traffic]).sample(frac=1).reset_index(drop=True)
        else:
            mixed_traffic = normal_traffic
            
        return mixed_traffic
    
    def get_numeric_features(self, df):
        """Extract numeric features from the dataframe for modeling"""
        
        # Create encoded versions of categorical features
        categorical_cols = ['protocol_type', 'service', 'flag']
        numeric_df = df.copy()
        
        for col in categorical_cols:
            if col in df.columns:
                # Simple one-hot encoding
                dummies = pd.get_dummies(df[col], prefix=col)
                numeric_df = pd.concat([numeric_df, dummies], axis=1)
                numeric_df.drop(col, axis=1, inplace=True)
        
        # Remove non-numeric columns 
        for col in ['src_ip', 'dst_ip', 'timestamp', 'label']:
            if col in numeric_df.columns:
                numeric_df.drop(col, axis=1, inplace=True)
        
        return numeric_df
    
    def start_simulation(self, callback=None, interval=1.0):
        """
        Start a continuous simulation sending data at regular intervals
        
        Parameters:
        -----------
        callback : function, optional
            Function to call with each batch of data
        interval : float, default=1.0
            Time in seconds between data generation
        """
        self.stop_flag = False
        
        def simulation_loop():
            while not self.stop_flag:
                # Generate new batch of 1-5 connections
                batch_size = random.randint(1, 5)
                self.current_data = self.generate_mixed_traffic(batch_size)
                
                # Extract features for modeling
                self.features = self.get_numeric_features(self.current_data)
                
                if callback is not None:
                    callback(self.current_data, self.features)
                
                time.sleep(interval)
        
        # Start the simulation in a background thread
        thread = threading.Thread(target=simulation_loop)
        thread.daemon = True
        thread.start()
        return thread
    
    def stop_simulation(self):
        """Stop the simulation"""
        self.stop_flag = True

if __name__ == "__main__":
    # Simple test
    simulator = NetworkTrafficSimulator(anomaly_probability=0.2)
    
    def print_traffic(data, features):
        print(f"Generated {len(data)} connections, {data['is_anomaly'].sum()} anomalies")
        print(data[['src_ip', 'dst_ip', 'protocol_type', 'dst_port', 'label']].head())
        print("\n")
    
    # Start simulation for 10 seconds
    simulator.start_simulation(callback=print_traffic, interval=2.0)
    time.sleep(10)
    simulator.stop_simulation() 