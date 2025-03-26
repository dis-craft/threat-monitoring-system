import requests
import json
import sys

def test_detection(dataset_id=1, max_samples=50):
    """
    Test the anomaly detection API
    
    Args:
        dataset_id: ID of the dataset to test (0=general, 1=KDD, 2=UNSW)
        max_samples: Maximum number of samples to analyze
    """
    # Get available datasets
    print("Getting available datasets...")
    response = requests.get("http://localhost:5000/api/datasets")
    datasets = response.json()
    
    # Find the selected dataset
    selected_dataset = None
    for dataset in datasets:
        if dataset["id"] == dataset_id:
            selected_dataset = dataset
            break
            
    if not selected_dataset:
        print(f"Dataset with ID {dataset_id} not found")
        return
        
    print(f"Testing with dataset: {selected_dataset['name']}")
    print(f"Path: {selected_dataset['path']}")
    
    # Run detection
    payload = {
        "test_data_path": selected_dataset["path"],
        "max_samples": max_samples,
        "dataset_name": selected_dataset.get("name").lower().replace(" ", "_").replace("-", "_")
    }
    
    print(f"Running detection with payload: {payload}")
    response = requests.post("http://localhost:5000/api/test", json=payload)
    
    # Check for errors
    result = response.json()
    if "error" in result:
        print(f"Error: {result['error']}")
        return
        
    # Print results
    print("\nDetection Results:")
    print("-----------------")
    
    if "threat_distribution" in result:
        print("\nThreat Distribution:")
        for threat_type, percentage in result["threat_distribution"]["percentages"].items():
            count = result["threat_distribution"]["counts"][threat_type]
            print(f"  {threat_type}: {count} records ({percentage}%)")
            
    if "risk_assessment" in result:
        print(f"\nRisk Assessment: {result['risk_assessment']}")
        
    if "detailed_threats" in result:
        print(f"\nDetailed Threats: {len(result['detailed_threats'])}")
        
        for i, threat in enumerate(result["detailed_threats"][:5]):  # Show first 5
            print(f"\nThreat {i+1}:")
            print(f"  Type: {threat['type']}")
            print(f"  Confidence: {threat['confidence']}%")
            print(f"  Severity: {threat['severity']}")
            
            if threat["features"]:
                print("  Top contributing features:")
                for feature, importance in list(threat["features"].items())[:3]:
                    print(f"    {feature}: {importance:.4f}")
    
    print("\nFull detection completed successfully!")
    print(f"Total records analyzed: {result.get('total_records', 0)}")
    print(f"Analysis time: {result.get('analysis_time', 0)} seconds")

if __name__ == "__main__":
    dataset_id = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    max_samples = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    
    test_detection(dataset_id, max_samples) 