import requests
import json
import pandas as pd
import sys
import os
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init()

def format_color(text, color):
    return f"{color}{text}{Style.RESET_ALL}"

def test_api(test_data_path, max_samples=100, save_report=True):
    print(f"Testing API with data: {test_data_path}")
    print(f"Max samples: {max_samples}")
    
    # Call the API
    url = "http://localhost:5000/api/test"
    data = {
        "test_data_path": test_data_path,
        "max_samples": max_samples
    }
    
    try:
        response = requests.post(url, json=data)
        response.raise_for_status()
        result = response.json()
        
        if not result.get('success', False):
            print(f"API Error: {result.get('error', 'Unknown error')}")
            return
        
        # Display statistics
        stats = result.get('stats', {})
        print("\n" + format_color("=== STATISTICS ===", Fore.CYAN))
        print(f"Total samples: {stats.get('total_samples', 0)}")
        print(f"Detected threats: {stats.get('detected_threats', 0)}")
        print(f"Models used: {', '.join(stats.get('models_used', []))}")
        
        # Display threats by type
        threats = result.get('threats', [])
        
        # Count by type
        threat_counts = {}
        for threat in threats:
            attack_type = threat.get('attack_type')
            threat_counts[attack_type] = threat_counts.get(attack_type, 0) + 1
        
        print("\n" + format_color("=== THREAT DISTRIBUTION ===", Fore.CYAN))
        for attack_type, count in threat_counts.items():
            color = Fore.GREEN if attack_type == 'Normal' else Fore.RED if attack_type == 'Zero-Day' else Fore.YELLOW
            print(f"{format_color(attack_type, color)}: {count}")
        
        # Display top threats
        print("\n" + format_color("=== TOP 10 THREATS ===", Fore.CYAN))
        threats_by_severity = sorted(threats, key=lambda x: x.get('severity', 0), reverse=True)
        
        for i, threat in enumerate(threats_by_severity[:10]):
            attack_type = threat.get('attack_type')
            severity = threat.get('severity', 0)
            model = threat.get('model', 'unknown')
            
            color = Fore.GREEN if attack_type == 'Normal' else Fore.RED if attack_type == 'Zero-Day' else Fore.YELLOW
            print(f"{i+1}. {format_color(attack_type, color)} (Severity: {severity:.2f}, Model: {model})")
        
        # Save results to CSV if requested
        if save_report:
            # Create a dataframe for the threats
            threat_data = []
            for threat in threats:
                # Add basic threat info
                threat_info = {
                    'id': threat.get('id'),
                    'model': threat.get('model'),
                    'attack_type': threat.get('attack_type'),
                    'severity': threat.get('severity'),
                    'confidence': threat.get('confidence')
                }
                
                # Add prediction probabilities
                probs = threat.get('details', {}).get('prediction_probabilities', {})
                threat_info.update({
                    'prob_normal': probs.get('normal', 0),
                    'prob_anomaly': probs.get('anomaly', 0), 
                    'prob_zero_day': probs.get('zero_day', 0)
                })
                
                threat_data.append(threat_info)
            
            # Create dataframe and save to CSV
            df = pd.DataFrame(threat_data)
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threat_report_{timestamp}.csv"
            
            df.to_csv(filename, index=False)
            print(f"\n{format_color('Report saved to:', Fore.CYAN)} {filename}")
            
            # Create a summary file
            summary_data = {
                'Test Data': test_data_path,
                'Max Samples': max_samples,
                'Total Samples': stats.get('total_samples', 0),
                'Detected Threats': stats.get('detected_threats', 0),
                'Models Used': ', '.join(stats.get('models_used', [])),
                'Normal Count': threat_counts.get('Normal', 0),
                'Anomaly Count': threat_counts.get('Anomaly', 0),
                'Zero-Day Count': threat_counts.get('Zero-Day', 0)
            }
            
            pd.DataFrame([summary_data]).to_csv(f"summary_{timestamp}.csv", index=False)
            print(f"{format_color('Summary saved to:', Fore.CYAN)} summary_{timestamp}.csv")
    
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to API: {e}")
    except json.JSONDecodeError:
        print("Error decoding JSON response")

if __name__ == "__main__":
    # Default values
    test_data_path = "C:\\Users\\sachi\\OneDrive\\Desktop\\VARMAX 1\\KDD_Test_preprocessed.csv"
    max_samples = 100
    
    # Get command line arguments
    if len(sys.argv) > 1:
        test_data_path = sys.argv[1]
    if len(sys.argv) > 2:
        max_samples = int(sys.argv[2])
    
    test_api(test_data_path, max_samples) 