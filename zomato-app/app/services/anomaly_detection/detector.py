"""
Network Anomaly Detection Module
--------------------------------
This module provides rule-based network traffic anomaly detection
using the KDD Cup dataset format, integrated with the Zomato application.
"""

import pandas as pd
import numpy as np
import time
from datetime import datetime
import queue
import os
import threading

# Import threat intelligence service
try:
    from app.services.anomaly_detection.threat_intel import threat_intel
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    print("Threat intelligence module not available, continuing without it")
    THREAT_INTEL_AVAILABLE = False

# Global queue for real-time anomaly updates
anomaly_queue = queue.Queue()

# Global list for storing detected anomalies
detected_anomalies = []

class RuleBasedDetector:
    """
    Rule-based anomaly detector for network traffic data.
    Analyzes network connections based on predefined rules and thresholds.
    """
    
    def __init__(self):
        """Initialize detector with predefined rules."""
        # Define rules for different attack types
        self.rules = {
            # Known attack services
            'suspicious_services': ['finger', 'ftp_data', 'imap4', 'mtp', 'netbios_dgm', 
                                    'netbios_ns', 'pop_3', 'rje', 'shell', 'sql_net', 'supdup'],
            
            # Suspicious protocol-flag combinations
            'protocol_flag_combos': [
                ('tcp', 'REJ'), ('tcp', 'RSTO'), ('tcp', 'RSTOSO'), ('tcp', 'S0'),
                ('tcp', 'S1'), ('tcp', 'S2'), ('tcp', 'S3'), ('tcp', 'SF')
            ],
            
            # Thresholds for numeric features
            'thresholds': {
                'duration': 300,  # Long connection duration in seconds
                'src_bytes': 100000,  # Large data transfer from source
                'dst_bytes': 100000,  # Large data transfer to destination
                'count': 100,  # High connection count to same host
                'srv_count': 100,  # High connection count to same service
                'serror_rate': 0.7,  # High SYN error rate
                'srv_serror_rate': 0.7,  # High service SYN error rate
                'rerror_rate': 0.7,  # High REJ error rate
                'srv_rerror_rate': 0.7,  # High service REJ error rate
                'same_srv_rate': 0.9,  # High same service rate
            }
        }
        
        # Known attack labels from KDD dataset
        self.attack_labels = [
            'back', 'buffer_overflow', 'ftp_write', 'guess_passwd', 'imap', 
            'ipsweep', 'land', 'loadmodule', 'multihop', 'neptune', 'nmap', 'perl', 
            'phf', 'pod', 'portsweep', 'rootkit', 'satan', 'smurf', 'spy', 
            'teardrop', 'warezclient', 'warezmaster'
        ]
        
        # Track IP addresses for rate limiting
        self.connection_tracker = {}
        
        # If threat intelligence is available, fetch known threats
        self.known_threat_services = set()
        if THREAT_INTEL_AVAILABLE:
            try:
                self.update_threat_intelligence()
            except Exception as e:
                print(f"Error initializing threat intelligence: {str(e)}")
    
    def update_threat_intelligence(self):
        """Update the detector with the latest threat intelligence data."""
        if not THREAT_INTEL_AVAILABLE:
            return
            
        try:
            threats = threat_intel.get_known_threats()
            if threats:
                # Extract services from known threats
                self.known_threat_services = set([
                    threat.get('service') for threat in threats 
                    if threat.get('service')
                ])
                
                # Add known threat services to our suspicious services list
                self.rules['suspicious_services'].extend(
                    [s for s in self.known_threat_services 
                     if s not in self.rules['suspicious_services']]
                )
                
                print(f"Updated with {len(threats)} known threats")
        except Exception as e:
            print(f"Error updating threat intelligence: {str(e)}")
        
    def check_rules(self, row):
        """
        Apply detection rules to a network connection record.
        
        Args:
            row: Pandas Series or dict containing connection data
            
        Returns:
            List of tuples with (alert_type, confidence_score)
        """
        alerts = []
        
        # Check for attacks by service type
        if row['service'] in self.rules['suspicious_services']:
            alerts.append(('suspicious_service', 0.7))
        
        # Check for suspicious protocol-flag combinations
        if (row['protocol_type'], row['flag']) in self.rules['protocol_flag_combos']:
            if row['flag'] in ['S0', 'S1', 'S2', 'S3']:
                alerts.append(('potential_scan', 0.8))
            elif row['flag'] in ['REJ', 'RSTO', 'RSTOSO']:
                alerts.append(('connection_rejected', 0.6))
        
        # Check thresholds for numeric features
        if row['duration'] > self.rules['thresholds']['duration']:
            alerts.append(('long_duration', 0.7))
            
        if row['src_bytes'] > self.rules['thresholds']['src_bytes']:
            alerts.append(('high_data_transfer', 0.8))
            
        if row['dst_bytes'] > self.rules['thresholds']['dst_bytes']:
            alerts.append(('high_data_received', 0.8))
            
        if row['count'] > self.rules['thresholds']['count']:
            alerts.append(('high_connection_count', 0.9))
            
        # Check error rates
        if row['serror_rate'] > self.rules['thresholds']['serror_rate']:
            alerts.append(('high_syn_error_rate', 0.95))
            
        if row['rerror_rate'] > self.rules['thresholds']['rerror_rate']:
            alerts.append(('high_reject_rate', 0.85))
        
        # If the dataset already has labels, use them
        if 'labels' in row and row['labels'] in self.attack_labels:
            alerts.append((f'known_attack_{row["labels"]}', 1.0))
            
        return alerts
        
    def process_batch(self, batch):
        """
        Process a batch of network connection records.
        
        Args:
            batch: Pandas DataFrame with network connection data
            
        Returns:
            DataFrame containing only the detected anomalies
        """
        all_anomalies = []
        
        for _, row in batch.iterrows():
            alerts = self.check_rules(row)
            if alerts:
                # Add alerts to the row
                row_data = row.to_dict()
                row_data['alerts'] = alerts
                row_data['highest_confidence'] = max([conf for _, conf in alerts])
                row_data['alert_types'] = ', '.join([alert for alert, _ in alerts])
                
                # Add timestamp if not present
                if 'timestamp' not in row_data:
                    row_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                all_anomalies.append(row_data)
                
                # Add to real-time queue for dashboard updates
                anomaly_queue.put(row_data)
                
                # Add to global list of detected anomalies
                global detected_anomalies
                detected_anomalies.append(row_data)
                
                # If threat intel is available and it's a high confidence alert, report it
                if THREAT_INTEL_AVAILABLE and row_data['highest_confidence'] > 0.8:
                    try:
                        threat_intel.report_anomaly(row_data)
                    except Exception as e:
                        print(f"Error reporting to threat intelligence: {str(e)}")
        
        if all_anomalies:
            return pd.DataFrame(all_anomalies)
        else:
            return pd.DataFrame()

# Function to get the latest anomalies from the queue
def get_latest_anomalies(max_items=10):
    """
    Get the latest anomalies from the queue without blocking.
    
    Args:
        max_items: Maximum number of items to retrieve
        
    Returns:
        List of anomaly dictionaries
    """
    anomalies = []
    for _ in range(max_items):
        try:
            # Non-blocking get
            anomaly = anomaly_queue.get_nowait()
            anomalies.append(anomaly)
            anomaly_queue.task_done()
        except queue.Empty:
            break
    return anomalies

# Function to process a dataset file in batches for real-time simulation
def process_kdd_dataset(file_path, batch_size=100, sleep_interval=1):
    """
    Process a KDD dataset file in batches, simulating real-time detection.
    
    Args:
        file_path: Path to the KDD dataset CSV file
        batch_size: Number of records to process in each batch
        sleep_interval: Seconds to wait between batches
        
    Returns:
        None (results are added to anomaly_queue)
    """
    detector = RuleBasedDetector()
    
    # Load dataset with correct column names
    print(f"Loading KDD dataset from {file_path}...")
    
    try:
        # Attempt to load the dataset - ensure the first row is used as headers
        df = pd.read_csv(file_path)
        print(f"Loaded dataset with {len(df)} records and {len(df.columns)} columns")
        print(f"Column names: {df.columns.tolist()}")
        
        # Check if required columns exist
        required_columns = ['protocol_type', 'service', 'flag', 'duration', 'src_bytes', 'dst_bytes', 
                           'count', 'serror_rate', 'rerror_rate', 'srv_count']
                           
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            print(f"Error: Missing required columns: {missing_columns}")
            return None
        
        # Process in batches
        print(f"Processing in batches of {batch_size} records...")
        batch_count = 0
        
        for i in range(0, len(df), batch_size):
            batch_count += 1
            batch = df.iloc[i:i+batch_size]
            
            print(f"Processing batch {batch_count} with {len(batch)} records")
            anomalies = detector.process_batch(batch)
            
            if len(anomalies) > 0:
                print(f"Batch {batch_count}: Found {len(anomalies)} anomalies")
                # Print first anomaly for debugging
                first_anomaly = anomalies.iloc[0].to_dict() if not anomalies.empty else {}
                print(f"Sample anomaly: {first_anomaly}")
            else:
                print(f"Batch {batch_count}: No anomalies detected")
                
            # Simulate real-time processing
            time.sleep(sleep_interval)
            
    except Exception as e:
        print(f"Error processing dataset: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

# Global flag to track if detection is running
detection_running = False

# Main function to start the detection process
def start_anomaly_detection(dataset_path=None):
    """
    Start the anomaly detection process using the specified dataset.
    
    Args:
        dataset_path: Path to the KDD dataset file
        
    Returns:
        True if started successfully, False otherwise
    """
    global detection_running
    global detected_anomalies
    
    # Don't start if already running
    if detection_running:
        print("Detection already running, not starting again")
        return False
    
    try:
        # Clear the anomaly queue before starting
        while not anomaly_queue.empty():
            try:
                anomaly_queue.get_nowait()
                anomaly_queue.task_done()
            except:
                break
        
        # Clear detected anomalies list
        detected_anomalies = []
        
        print(f"Attempting to start anomaly detection with dataset: {dataset_path}")
        
        # Handle relative vs absolute paths
        if dataset_path:
            abs_path = os.path.abspath(dataset_path)
            print(f"Absolute path: {abs_path}")
            
            if os.path.exists(abs_path):
                print(f"Dataset file exists at: {abs_path}")
                # Start in a separate thread to not block the web application
                detection_thread = threading.Thread(
                    target=process_kdd_dataset,
                    args=(abs_path, 100, 5),
                    daemon=True
                )
                detection_running = True
                detection_thread.start()
                print("Detection thread started successfully")
                return True
            else:
                print(f"Dataset file does not exist at: {abs_path}")
                
                # Try in the current working directory
                cwd = os.getcwd()
                alt_path = os.path.join(cwd, dataset_path)
                print(f"Trying alternate path: {alt_path}")
                
                if os.path.exists(alt_path):
                    print(f"Dataset found at alternate path: {alt_path}")
                    detection_thread = threading.Thread(
                        target=process_kdd_dataset,
                        args=(alt_path, 100, 5),
                        daemon=True
                    )
                    detection_running = True
                    detection_thread.start()
                    print("Detection thread started successfully with alternate path")
                    return True
                else:
                    print(f"Dataset not found at alternate path: {alt_path}")
                    return False
        else:
            print("No dataset path provided")
            return False
    except Exception as e:
        print(f"Error starting anomaly detection: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

# Function to stop detection
def stop_anomaly_detection():
    """
    Stop the anomaly detection process.
    
    Returns:
        True if stopped successfully, False otherwise
    """
    global detection_running
    detection_running = False
    
    # If threat intel is available, report all high-confidence anomalies
    if THREAT_INTEL_AVAILABLE and detected_anomalies:
        try:
            # Filter high-confidence anomalies
            high_confidence_anomalies = [
                a for a in detected_anomalies 
                if a.get('highest_confidence', 0) > 0.8
            ]
            
            if high_confidence_anomalies:
                print(f"Reporting {len(high_confidence_anomalies)} high-confidence anomalies to threat intelligence")
                threat_intel.bulk_report_anomalies(high_confidence_anomalies)
        except Exception as e:
            print(f"Error reporting to threat intelligence: {str(e)}")
    
    return True

# Function to fetch external threats
def fetch_external_threats():
    """
    Fetch threats from external threat intelligence.
    
    Returns:
        List of threat dictionaries or None if unavailable
    """
    if not THREAT_INTEL_AVAILABLE:
        return None
        
    try:
        return threat_intel.get_known_threats()
    except Exception as e:
        print(f"Error fetching external threats: {str(e)}")
        return None

# For testing
if __name__ == "__main__":
    test_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                            'data_kdd', 'kdd_test.csv')
    process_kdd_dataset(test_path) 