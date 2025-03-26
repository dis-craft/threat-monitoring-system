"""
Zero Day Sentinel Integration Script
-----------------------------------
This script connects to the Zero Day Sentinel threat intelligence service
to fetch known threats and report detected anomalies.

Usage:
    python fetch_threats.py

Example:
    python fetch_threats.py --fetch-only  # Only fetch threats without reporting
    python fetch_threats.py --report-all  # Report all stored anomalies
"""

import requests
import json
import argparse
import time
import os
import sys
import uuid
from datetime import datetime

# Add the parent directory to the path so we can import from the package
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

# Now we can import from the app package
try:
    from app.services.anomaly_detection.detector import detected_anomalies, fetch_external_threats
    from app.services.anomaly_detection.threat_intel import threat_intel
except ImportError:
    print("Failed to import from app package. Make sure you're running this script from the project root.")
    sys.exit(1)

def fetch_threats_from_zero_day_sentinel():
    """
    Fetch threats directly from the Zero Day Sentinel service.
    
    Returns:
        List of threats or None if failed
    """
    url = "https://zero-day-sentinel.onrender.com/threat"
    
    try:
        print(f"Fetching threats from {url}...")
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            threats = response.json()
            print(f"Successfully retrieved {len(threats)} threats")
            
            # Print a sample of threats
            if threats:
                print("\nSample threats:")
                for i, threat in enumerate(threats[:3]):
                    print(f"  {i+1}. {json.dumps(threat, indent=2)}")
                print()
            
            return threats
        else:
            print(f"Failed to retrieve threats: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return None
            
    except Exception as e:
        print(f"Error fetching threats: {str(e)}")
        return None

def verify_threat_in_chain(threat_id):
    """
    Verify if a reported threat exists in the blockchain.
    
    Args:
        threat_id: The ID of the threat to verify
        
    Returns:
        True if found, False otherwise
    """
    url = "https://zero-day-sentinel.onrender.com/chain"
    
    try:
        print(f"Checking blockchain for threat ID: {threat_id}...")
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            chain_data = response.json()
            
            # Search for the threat ID in the blockchain
            for block in chain_data:
                if 'transactions' in block:
                    for transaction in block['transactions']:
                        if transaction.get('id') == threat_id:
                            print(f"Found threat {threat_id} in block {block.get('index', 'unknown')}")
                            return True
            
            print(f"Threat {threat_id} not found in the blockchain")
            return False
        else:
            print(f"Failed to retrieve blockchain: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"Error checking blockchain: {str(e)}")
        return False

def report_anomaly_to_zero_day_sentinel(anomaly):
    """
    Report an anomaly directly to the Zero Day Sentinel service.
    
    Args:
        anomaly: Dictionary with anomaly data
        
    Returns:
        Threat ID if successful, None otherwise
    """
    url = "https://zero-day-sentinel.onrender.com/threat"
    
    try:
        # Generate a UUID for the threat
        threat_id = str(uuid.uuid4())
        
        # Map anomaly types to attack types
        attack_type_mapping = {
            'potential_scan': 'Port Scan',
            'connection_rejected': 'Connection Attempt',
            'long_duration': 'Persistent Connection',
            'high_data_transfer': 'Data Exfiltration',
            'high_data_received': 'Data Download',
            'high_connection_count': 'Connection Flood',
            'high_syn_error_rate': 'SYN Flood',
            'high_reject_rate': 'Connection Flood',
            'suspicious_service': 'Suspicious Service'
        }
        
        # Determine the attack type based on alert types
        alert_types = anomaly.get('alert_types', '').split(', ')
        primary_attack_type = 'Unknown'
        for alert in alert_types:
            if alert in attack_type_mapping:
                primary_attack_type = attack_type_mapping[alert]
                break
        
        # Determine severity based on confidence
        confidence = anomaly.get('highest_confidence', 0.5)
        if confidence >= 0.9:
            severity = "High"
        elif confidence >= 0.7:
            severity = "Medium"
        else:
            severity = "Low"
        
        # Format the anomaly data according to the required format
        threat_report = {
            "id": threat_id,
            "timestamp": anomaly.get('timestamp', datetime.now().isoformat()),
            "ip": anomaly.get('src_ip', '192.168.1.' + str(int(anomaly.get('duration', 0) % 255))),
            "attack_type": primary_attack_type,
            "severity": severity,
            "status": "Detected",
            "details": {
                "user_agent": "Zomato Anomaly Detector/1.0",
                "method": "GET",
                "url_path": "/" + anomaly.get('service', 'unknown'),
                "source_port": int(anomaly.get('src_bytes', 0) % 65535) or 32768,
                "destination_port": 80 if anomaly.get('service', '') == 'http' else 443 if anomaly.get('service', '') == 'https' else 21 if anomaly.get('service', '') == 'ftp' else 22 if anomaly.get('service', '') == 'ssh' else 3306,
                "protocol": anomaly.get('protocol_type', 'tcp'),
                "flag": anomaly.get('flag', ''),
                "duration": int(anomaly.get('duration', 0)),
                "bytes_sent": int(anomaly.get('src_bytes', 0)),
                "bytes_received": int(anomaly.get('dst_bytes', 0))
            }
        }
        
        print(f"Reporting anomaly to {url}")
        print(f"Threat data: {json.dumps(threat_report, indent=2)}")
        
        response = requests.post(
            url,
            json=threat_report,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        if response.status_code in [200, 201]:
            print(f"Successfully reported threat: {response.status_code}")
            print(f"Response: {response.text}")
            return threat_id
        else:
            print(f"Failed to report threat: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return None
            
    except Exception as e:
        print(f"Error reporting threat: {str(e)}")
        return None

def generate_sample_threat():
    """
    Generate a sample threat for testing purposes.
    
    Returns:
        Dictionary with sample threat data
    """
    threat_id = str(uuid.uuid4())
    return {
        "id": threat_id,
        "timestamp": datetime.now().isoformat(),
        "ip": "73.75.24.207",
        "attack_type": "Brute Force",
        "severity": "Medium",
        "status": "Detected",
        "details": {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
            "method": "POST",
            "url_path": "/login",
            "source_port": 25344,
            "destination_port": 3000,
            "failed_attempts": 43,
            "target_account": "admin"
        }
    }

def convert_anomaly_to_threat(anomaly):
    """
    Convert an anomaly to a threat format expected by Zero Day Sentinel
    
    Args:
        anomaly: The anomaly dictionary
        
    Returns:
        A threat dictionary
    """
    # Generate a UUID for the threat
    threat_id = str(uuid.uuid4())
    
    # Map anomaly types to attack types
    attack_type_mapping = {
        'potential_scan': 'Port Scan',
        'connection_rejected': 'Connection Attempt',
        'long_duration': 'Persistent Connection',
        'high_data_transfer': 'Data Exfiltration',
        'high_data_received': 'Data Download',
        'high_connection_count': 'Connection Flood',
        'high_syn_error_rate': 'SYN Flood',
        'high_reject_rate': 'Connection Flood',
        'suspicious_service': 'Suspicious Service'
    }
    
    # Determine the attack type based on alert types
    alert_types = anomaly.get('alert_types', '').split(', ')
    primary_attack_type = 'Unknown'
    for alert in alert_types:
        if alert in attack_type_mapping:
            primary_attack_type = attack_type_mapping[alert]
            break
    
    # Determine severity based on confidence
    confidence = anomaly.get('highest_confidence', 0.5)
    if confidence >= 0.9:
        severity = "High"
    elif confidence >= 0.7:
        severity = "Medium"
    else:
        severity = "Low"
    
    # Format the anomaly data according to the required format
    return {
        "id": threat_id,
        "timestamp": anomaly.get('timestamp', datetime.now().isoformat()),
        "ip": anomaly.get('src_ip', '192.168.1.' + str(int(anomaly.get('duration', 0) % 255))),
        "attack_type": primary_attack_type,
        "severity": severity,
        "status": "Detected",
        "details": {
            "user_agent": "Zomato Anomaly Detector/1.0",
            "method": "GET",
            "url_path": "/" + anomaly.get('service', 'unknown'),
            "source_port": int(anomaly.get('src_bytes', 0) % 65535) or 32768,
            "destination_port": 80 if anomaly.get('service', '') == 'http' else 443 if anomaly.get('service', '') == 'https' else 21 if anomaly.get('service', '') == 'ftp' else 22 if anomaly.get('service', '') == 'ssh' else 3306,
            "protocol": anomaly.get('protocol_type', 'tcp'),
            "flag": anomaly.get('flag', ''),
            "duration": int(anomaly.get('duration', 0)),
            "bytes_sent": int(anomaly.get('src_bytes', 0)),
            "bytes_received": int(anomaly.get('dst_bytes', 0))
        }
    }

def main():
    parser = argparse.ArgumentParser(description="Zero Day Sentinel Integration Tool")
    parser.add_argument('--fetch-only', action='store_true', help='Only fetch threats without reporting')
    parser.add_argument('--report-all', action='store_true', help='Report all stored anomalies')
    parser.add_argument('--report-sample', action='store_true', help='Report a sample threat')
    parser.add_argument('--verify', type=str, help='Verify a threat ID in the blockchain')
    args = parser.parse_args()
    
    if args.verify:
        # Verify a threat in the blockchain
        verify_threat_in_chain(args.verify)
        return
    
    if args.fetch_only or not (args.report_all or args.report_sample):
        # Fetch threats
        threats = fetch_threats_from_zero_day_sentinel()
        if threats:
            print(f"Retrieved {len(threats)} threats from Zero Day Sentinel")
        else:
            print("Failed to retrieve threats from Zero Day Sentinel")
    
    if args.report_all:
        # Report all stored anomalies
        if detected_anomalies:
            print(f"Reporting {len(detected_anomalies)} stored anomalies...")
            success_count = 0
            threat_ids = []
            for anomaly in detected_anomalies:
                threat_id = report_anomaly_to_zero_day_sentinel(anomaly)
                if threat_id:
                    success_count += 1
                    threat_ids.append(threat_id)
                time.sleep(1)  # Be nice to the API
            print(f"Reported {success_count}/{len(detected_anomalies)} anomalies successfully")
            
            # Verify threats in blockchain
            if threat_ids:
                print("\nVerifying reported threats in blockchain...")
                time.sleep(5)  # Give time for threats to be added to the blockchain
                for threat_id in threat_ids:
                    verify_threat_in_chain(threat_id)
        else:
            print("No stored anomalies to report")
    
    if args.report_sample:
        # Report a sample threat
        print("Reporting sample threat...")
        sample = generate_sample_threat()
        print(f"Sample threat: {json.dumps(sample, indent=2)}")
        
        response = requests.post(
            "https://zero-day-sentinel.onrender.com/threat",
            json=sample,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        if response.status_code in [200, 201]:
            print(f"Successfully reported sample threat: {response.status_code}")
            print(f"Response: {response.text}")
            
            # Verify in blockchain
            print("\nVerifying sample threat in blockchain...")
            time.sleep(5)  # Give time for threat to be added to the blockchain
            verify_threat_in_chain(sample["id"])
        else:
            print(f"Failed to report sample threat: HTTP {response.status_code}")
            print(f"Response: {response.text}")

if __name__ == "__main__":
    main() 