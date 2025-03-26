#!/usr/bin/env python
import sys
import os
import time
import json
from pyod_detector import PyODDetector

def test_dataset(dataset_id, samples=10):
    """
    Test anomaly detection on a specific dataset
    
    Args:
        dataset_id: Dataset ID (0=TRAIN, 1=KDD, 2=UNSW)
        samples: Number of samples to analyze
    """
    dataset_paths = {
        0: "data/preprocessed_test_data.csv",
        1: "data/KDD_Test_preprocessed.csv",
        2: "data/UNSW_NB15_test_preprocessed.csv"
    }
    
    dataset_names = {
        0: "train",
        1: "kdd",
        2: "unsw"
    }
    
    if dataset_id not in dataset_paths:
        print(f"Invalid dataset ID: {dataset_id}")
        print(f"Available datasets: {list(dataset_paths.keys())}")
        return
    
    data_path = dataset_paths[dataset_id]
    dataset_name = dataset_names[dataset_id]
    
    print(f"Testing on {dataset_name.upper()} dataset with {samples} samples")
    print(f"Data path: {data_path}")
    
    # Create detector
    detector = PyODDetector(model_dir='unified_model')
    
    # Start timer
    start_time = time.time()
    
    # Run detection
    results = detector.detect_threats(data_path, dataset_name, samples)
    
    # End timer
    elapsed_time = time.time() - start_time
    
    # Print results
    if "error" in results:
        print(f"Error: {results['error']}")
        return
    
    print("\n" + "="*50)
    print(f"DETECTION RESULTS - {dataset_name.upper()}")
    print("="*50)
    
    print(f"\nAnalyzed {results['total_records']} records in {elapsed_time:.2f} seconds")
    print(f"Risk Assessment: {results['risk_assessment']}")
    
    # Print threat distribution
    print("\nThreat Distribution:")
    for threat_type, count in results['threat_distribution']['counts'].items():
        percentage = results['threat_distribution']['percentages'][threat_type]
        print(f"  {threat_type}: {count} ({percentage:.2f}%)")
    
    # Print detailed threats if any
    if results['detailed_threats']:
        print("\nDetailed Threats:")
        for threat in results['detailed_threats']:
            print(f"\n  ID: {threat['id']}")
            print(f"  Type: {threat['type']}")
            print(f"  Confidence: {threat['confidence']}%")
            print(f"  Severity: {threat['severity']}")
            
            # Print top contributing features
            if threat['features']:
                print("  Top Contributing Features:")
                i = 0
                for feature, importance in threat['features'].items():
                    if i < 5:  # Only show top 5 features
                        print(f"    {feature}: {importance:.4f}")
                        i += 1
                    else:
                        break
    else:
        print("\nNo threats detected!")
    
    # Save results to file
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_file = f"pyod_results_{dataset_name}_{timestamp}.json"
    
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {output_file}")

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python test_pyod.py <dataset_id> [samples]")
        print("  dataset_id: 0=TRAIN, 1=KDD, 2=UNSW")
        print("  samples: Number of samples to analyze (default: 10)")
        return
    
    try:
        dataset_id = int(sys.argv[1])
    except ValueError:
        print("Error: dataset_id must be an integer")
        return
    
    samples = 10
    if len(sys.argv) >= 3:
        try:
            samples = int(sys.argv[2])
        except ValueError:
            print("Error: samples must be an integer")
            return
    
    test_dataset(dataset_id, samples)

if __name__ == "__main__":
    main() 