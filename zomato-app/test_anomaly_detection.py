#!/usr/bin/env python
"""
Anomaly Detection Test Script
----------------------------
This script tests the anomaly detection system to diagnose why it's not working.
"""

import os
import sys
import pandas as pd
from datetime import datetime

# Add the current directory to the path so we can import from app
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

try:
    from app.services.anomaly_detection.detector import process_kdd_dataset, start_anomaly_detection, get_latest_anomalies
    print("Successfully imported detection module")
except ImportError as e:
    print(f"Error importing detection module: {str(e)}")
    print("Traceback:")
    import traceback
    traceback.print_exc()
    sys.exit(1)

def test_dataset_path():
    """Test if the dataset path is correct and file exists."""
    print("\n--- Testing Dataset Path ---")
    
    # Get the current working directory
    cwd = os.getcwd()
    print(f"Current working directory: {cwd}")
    
    # Try different relative paths
    dataset_paths = [
        "data_kdd/kdd_test.csv",
        os.path.join("data_kdd", "kdd_test.csv"),
        os.path.join(".", "data_kdd", "kdd_test.csv"),
        os.path.join("..", "data_kdd", "kdd_test.csv")
    ]
    
    for path in dataset_paths:
        abs_path = os.path.abspath(path)
        exists = os.path.exists(abs_path)
        print(f"Path: {path}")
        print(f"  Absolute path: {abs_path}")
        print(f"  Exists: {exists}")
        
        if exists:
            print(f"  File size: {os.path.getsize(abs_path)} bytes")
            # Try to read the file
            try:
                df = pd.read_csv(abs_path)
                print(f"  Successfully read CSV with {len(df)} rows and {len(df.columns)} columns")
                print(f"  Columns: {df.columns.tolist()}")
                return abs_path
            except Exception as e:
                print(f"  Error reading CSV: {str(e)}")
    
    print("Could not find a valid dataset file")
    return None

def test_detection_functionality(dataset_path):
    """Test if the detection module works with the given dataset."""
    print("\n--- Testing Detection Functionality ---")
    
    if not dataset_path:
        print("No valid dataset path provided")
        return False
    
    print(f"Starting detection with dataset: {dataset_path}")
    
    # Test direct function call
    try:
        print("Testing direct process_kdd_dataset function call:")
        process_kdd_dataset(dataset_path, batch_size=5, sleep_interval=1)
        print("Processing completed")
        
        # Check if any anomalies were detected
        anomalies = get_latest_anomalies(max_items=10)
        print(f"Got {len(anomalies)} anomalies from queue")
        
        if anomalies:
            print("Sample anomaly:")
            print(anomalies[0])
            return True
        else:
            print("No anomalies detected")
    except Exception as e:
        print(f"Error in process_kdd_dataset: {str(e)}")
        print("Traceback:")
        import traceback
        traceback.print_exc()
    
    # Test start_anomaly_detection function
    try:
        print("\nTesting start_anomaly_detection function call:")
        result = start_anomaly_detection(dataset_path)
        print(f"start_anomaly_detection result: {result}")
        
        # Wait a bit for processing to happen
        import time
        print("Waiting for detection to run...")
        time.sleep(10)
        
        # Check if any anomalies were detected
        anomalies = get_latest_anomalies(max_items=10)
        print(f"Got {len(anomalies)} anomalies from queue")
        
        if anomalies:
            print("Sample anomaly:")
            print(anomalies[0])
            return True
        else:
            print("No anomalies detected")
    except Exception as e:
        print(f"Error in start_anomaly_detection: {str(e)}")
        print("Traceback:")
        import traceback
        traceback.print_exc()
    
    return False

if __name__ == "__main__":
    print("Anomaly Detection Test Script")
    print("-----------------------------")
    print(f"Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Test the dataset path
    dataset_path = test_dataset_path()
    
    # Test the detection functionality
    if dataset_path:
        success = test_detection_functionality(dataset_path)
        if success:
            print("\nTest completed successfully - anomaly detection is working!")
        else:
            print("\nTest failed - anomaly detection is not working properly.")
    else:
        print("\nTest failed - could not find a valid dataset file.") 