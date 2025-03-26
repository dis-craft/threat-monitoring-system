import json
import time
from datetime import datetime
from live_network_simulator import NetworkTrafficSimulator
from pyod_detector import PyODDetector
import pandas as pd
import numpy as np

class LiveDetector:
    def __init__(self, dataset_name='kdd', anomaly_probability=0.1, batch_size=30):
        """
        Initialize the live detector
        
        Parameters:
        -----------
        dataset_name : str, default='kdd'
            Name of the dataset to use for detection
        anomaly_probability : float, default=0.1
            Probability of generating anomalous traffic
        batch_size : int, default=30
            Number of samples to collect before processing
        """
        self.dataset_name = dataset_name
        self.simulator = NetworkTrafficSimulator(anomaly_probability=anomaly_probability)
        self.detector = PyODDetector()  # Initialize without parameters
        self.detection_history = []
        self.data_buffer = []
        self.features_buffer = []
        self.batch_size = batch_size
        self.latest_history_file = None
        
    def process_batch(self, data, features):
        """
        Process a batch of network traffic data
        
        Parameters:
        -----------
        data : pd.DataFrame
            Raw network traffic data
        features : pd.DataFrame
            Preprocessed features for detection
        """
        # Add data to buffer
        self.data_buffer.append(data)
        self.features_buffer.append(features)
        
        # If we have enough data, run detection
        if sum(len(df) for df in self.data_buffer) >= self.batch_size:
            # Combine all data
            all_data = pd.concat(self.data_buffer).reset_index(drop=True)
            all_features = pd.concat(self.features_buffer).reset_index(drop=True)
            
            # Clear buffer
            self.data_buffer = []
            self.features_buffer = []
            
            # Run detection
            print(f"\nProcessing batch of {len(all_data)} connections...")
            results = self.detector.detect_threats(all_features, dataset_name=self.dataset_name)
            
            # Combine results with original data
            for i, row in all_data.iterrows():
                # Get attributes
                confidence = 0.0
                anomaly_type = "normal"
                
                if i < len(results['anomalies']):
                    is_anomaly = bool(results['anomalies'][i])
                    if is_anomaly:
                        confidence = float(results['confidence_scores'][i])
                        anomaly_type = results['anomaly_types'][i]
                else:
                    is_anomaly = False
                
                detection = {
                    'timestamp': row['timestamp'],
                    'src_ip': row['src_ip'],
                    'dst_ip': row['dst_ip'],
                    'protocol': row['protocol_type'],
                    'service': row['service'],
                    'src_port': int(row['src_port']),
                    'dst_port': int(row['dst_port']),
                    'bytes': float(row['bytes']),
                    'packets': int(row['packets']),
                    'is_anomaly': is_anomaly,
                    'confidence': confidence,
                    'true_label': row['label'],
                    'detected_label': anomaly_type
                }
                
                # Add feature importance if available
                if 'feature_importance' in results and i < len(results['feature_importance']):
                    top_features = {}
                    for feat, score in results['feature_importance'][i].items():
                        top_features[feat] = float(score)
                    detection['top_features'] = top_features
                
                self.detection_history.append(detection)
                
                # Print detection results
                if detection['is_anomaly']:
                    print(f"\nALERT: Anomaly Detected!")
                    print(f"Time: {detection['timestamp']}")
                    print(f"Source: {detection['src_ip']}:{detection['src_port']}")
                    print(f"Destination: {detection['dst_ip']}:{detection['dst_port']}")
                    print(f"Protocol: {detection['protocol']}")
                    print(f"Service: {detection['service']}")
                    print(f"Confidence: {detection['confidence']:.2f}")
                    print(f"Detected Type: {detection['detected_label']}")
                    print(f"True Type: {detection['true_label']}")
                    print("-" * 50)
            
            # Print summary
            anomalies = sum(1 for d in results['anomalies'] if d)
            print(f"Batch processing complete: {anomalies} anomalies detected out of {len(all_data)} connections")
    
    def start_detection(self, interval=1.0, duration=None):
        """
        Start live detection
        
        Parameters:
        -----------
        interval : float, default=1.0
            Time between processing batches
        duration : float, optional
            Duration in seconds to run detection (None for indefinite)
        """
        print(f"Starting live detection for {self.dataset_name} dataset...")
        print(f"Collecting data in batches of {self.batch_size} connections")
        print("Press Ctrl+C to stop")
        
        start_time = time.time()
        
        try:
            # Start simulation
            sim_thread = self.simulator.start_simulation(
                callback=self.process_batch,
                interval=interval
            )
            
            # Keep main thread alive
            while True:
                time.sleep(1)
                if duration and time.time() - start_time > duration:
                    print(f"\nReached specified duration of {duration} seconds")
                    break
                
        except KeyboardInterrupt:
            print("\nDetection stopped by user")
        finally:
            print("\nStopping simulation...")
            self.simulator.stop_simulation()
            
            # Save detection history
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"detection_history_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(self.detection_history, f, indent=2)
            
            # Store the latest history file path
            self.latest_history_file = filename
            
            print(f"Detection history saved to {filename}")
            
            # Print summary
            total_detections = len(self.detection_history)
            anomalies = sum(1 for d in self.detection_history if d['is_anomaly'])
            true_positives = sum(1 for d in self.detection_history 
                               if d['is_anomaly'] and d['detected_label'] == d['true_label'])
            
            print("\nDetection Summary:")
            print(f"Total connections analyzed: {total_detections}")
            print(f"Anomalies detected: {anomalies}")
            print(f"True positives: {true_positives}")
            if anomalies > 0:
                accuracy = true_positives/anomalies
                print(f"Accuracy: {accuracy:.2%}")
            else:
                accuracy = 0
            
            # Return to web server
            return {
                'total': total_detections,
                'anomalies': anomalies,
                'true_positives': true_positives,
                'accuracy': accuracy,
                'history_file': self.latest_history_file
            }

if __name__ == "__main__":
    # Initialize detector with 20% anomaly probability
    detector = LiveDetector(dataset_name='kdd', anomaly_probability=0.2, batch_size=50)
    
    # Start detection with 1-second intervals, run for 60 seconds
    detector.start_detection(interval=0.5, duration=60) 