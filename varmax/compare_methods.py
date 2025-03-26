#!/usr/bin/env python
import sys
import os
import time
import json
import argparse
from detect_anomalies_advanced import detect_anomalies
from pyod_detector import PyODDetector

def print_header(title):
    """Print a formatted header"""
    print("\n" + "="*80)
    print(f" {title} ".center(80, "="))
    print("="*80 + "\n")

def compare_detectors(dataset_path, dataset_name=None, max_samples=10):
    """
    Compare original detector with PyOD-based detector
    
    Args:
        dataset_path: Path to dataset
        dataset_name: Name of dataset for PyOD (kdd, train, unsw)
        max_samples: Maximum number of samples to analyze
    """
    # Create detectors
    pyod_detector = PyODDetector(model_dir='unified_model')
    
    # Run both detectors and measure time
    print_header("ORIGINAL DETECTOR")
    original_results = None
    original_time = 0
    try:
        original_start = time.time()
        original_results = detect_anomalies(dataset_path, max_samples)
        original_time = time.time() - original_start
        print(f"Analysis completed in {original_time:.2f} seconds\n")
    except Exception as e:
        print(f"Error with original detector: {str(e)}")
        original_results = {"error": str(e), "threats": []}
    
    print_header("PYOD DETECTOR")
    pyod_results = None
    pyod_time = 0
    try:
        pyod_start = time.time()
        pyod_results = pyod_detector.detect_threats(dataset_path, dataset_name, max_samples)
        pyod_time = time.time() - pyod_start
        print(f"Analysis completed in {pyod_time:.2f} seconds\n")
    except Exception as e:
        print(f"Error with PyOD detector: {str(e)}")
        pyod_results = {"error": str(e), "threat_distribution": {"counts": {}}}
    
    # Print comparison
    print_header("COMPARISON")
    
    # Original results summary
    original_threats = []
    original_types = {"Normal": 0, "Anomaly": 0, "Zero-Day Attack": 0}
    if original_results and "threats" in original_results:
        original_threats = original_results.get('threats', [])
        for threat in original_threats:
            threat_type = threat.get('type')
            if threat_type:
                original_types[threat_type] = original_types.get(threat_type, 0) + 1
    
    # PyOD results summary
    pyod_types = {"Normal": 0, "Anomaly": 0, "Zero-Day": 0}
    if pyod_results and "threat_distribution" in pyod_results and "counts" in pyod_results["threat_distribution"]:
        pyod_types = pyod_results['threat_distribution']['counts']
    
    # Print comparison table
    print(f"{'Detector':<20} {'Normal':<15} {'Anomaly':<15} {'Zero-Day':<15} {'Time (s)':<10}")
    print("-" * 75)
    print(f"{'Original':<20} {original_types.get('Normal', 0):<15} {original_types.get('Anomaly', 0):<15} {original_types.get('Zero-Day Attack', 0):<15} {original_time:<10.2f}")
    print(f"{'PyOD':<20} {pyod_types.get('Normal', 0):<15} {pyod_types.get('Anomaly', 0):<15} {pyod_types.get('Zero-Day', 0):<15} {pyod_time:<10.2f}")
    print("\n")
    
    # Risk assessment comparison
    original_risk = "N/A"
    if original_types.get('Zero-Day Attack', 0) > 0:
        original_risk = "CRITICAL RISK"
    elif original_types.get('Anomaly', 0) > 5:
        original_risk = "HIGH RISK"
    elif original_types.get('Anomaly', 0) > 0:
        original_risk = "MEDIUM RISK"
    else:
        original_risk = "LOW RISK"
        
    pyod_risk = pyod_results.get('risk_assessment', 'N/A') if pyod_results else 'N/A'
    
    print(f"Risk Assessment:")
    print(f"  Original: {original_risk}")
    print(f"  PyOD:     {pyod_risk}")
    
    # Save results to file
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    
    # Save comparison results
    comparison = {
        'dataset': dataset_path,
        'dataset_name': dataset_name,
        'max_samples': max_samples,
        'timestamp': timestamp,
        'original': {
            'time': original_time,
            'threat_types': original_types,
            'risk': original_risk,
            'error': original_results.get('error', None) if original_results else 'Failed to run'
        },
        'pyod': {
            'time': pyod_time,
            'threat_types': pyod_types,
            'risk': pyod_risk,
            'error': pyod_results.get('error', None) if pyod_results else 'Failed to run'
        }
    }
    
    with open(f"comparison_{timestamp}.json", "w") as f:
        json.dump(comparison, f, indent=2)
    
    print(f"Comparison saved to comparison_{timestamp}.json")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Compare anomaly detection methods')
    parser.add_argument('--data', type=str, required=True, help='Path to dataset')
    parser.add_argument('--dataset', type=str, help='Dataset name (kdd, train, unsw)')
    parser.add_argument('--samples', type=int, default=10, help='Maximum samples to analyze')
    
    args = parser.parse_args()
    compare_detectors(args.data, args.dataset, args.samples)

if __name__ == '__main__':
    main() 