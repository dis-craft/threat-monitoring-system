import pandas as pd
import numpy as np
import time
import joblib
from config import DATA_PATH, MODEL_PATH, BATCH_SIZE, SLEEP_INTERVAL

class AnomalyDetector:
    def __init__(self):
        self.model = joblib.load(MODEL_PATH)
        self.feature_columns = ['bytes_sent', 'bytes_received', 'duration', 'packets', 
                               'protocol', 'tcp_flags', 'http_status']
        
    def detect(self, batch):
        # Predict returns -1 for anomalies and 1 for normal data
        predictions = self.model.predict(batch[self.feature_columns])
        # Calculate anomaly scores (larger negative values = more anomalous)
        scores = self.model.decision_function(batch[self.feature_columns])
        # Find anomalies (where prediction is -1)
        anomalies = batch[predictions == -1].copy()
        # Add the anomaly score
        anomaly_indices = np.where(predictions == -1)[0]
        if len(anomaly_indices) > 0:
            anomalies['anomaly_score'] = -scores[anomaly_indices]  # Convert to positive for clarity
        return anomalies

def simulate_real_time():
    print("Loading model and data...")
    detector = AnomalyDetector()
    df = pd.read_csv(DATA_PATH)
    
    print(f"Starting anomaly detection on {len(df)} records...")
    print(f"Processing in batches of {BATCH_SIZE} records with {SLEEP_INTERVAL}s intervals...\n")
    
    # Process in batches
    for i in range(0, len(df), BATCH_SIZE):
        batch = df.iloc[i:i+BATCH_SIZE]
        anomalies = detector.detect(batch)
        
        if len(anomalies) > 0:
            print(f"\nFound {len(anomalies)} anomalies in batch {i//BATCH_SIZE + 1}:")
            
            for _, row in anomalies.iterrows():
                # Determine alert color
                if row['dst_port'] == 31337 or 'SYN+FIN' in str(row['tcp_flags']):
                    color = '\033[91m'  # Red - high severity
                else:
                    color = '\033[93m'  # Yellow - medium severity
                    
                print(f"{color}ALERT: {row['timestamp']} {row['src_ip']}:{row['src_port']} -> "
                      f"{row['dst_ip']}:{row['dst_port']} [{row['protocol']}] "
                      f"Score: {row['anomaly_score']:.2f}\033[0m")
        else:
            print(f"No anomalies detected in batch {i//BATCH_SIZE + 1}")
        
        time.sleep(SLEEP_INTERVAL)
    
    print("\nAnomaly detection completed!")

if __name__ == '__main__':
    simulate_real_time() 