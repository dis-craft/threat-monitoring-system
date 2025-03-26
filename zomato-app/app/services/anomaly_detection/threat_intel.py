"""
Threat Intelligence Integration Module
-------------------------------------
This module provides integration with external threat intelligence services
to enhance the network anomaly detection capabilities.
"""

import requests
import json
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('threat_intel')

class ThreatIntelligence:
    """
    Integration with external threat intelligence services.
    Retrieves known threats and reports detected anomalies.
    """
    
    def __init__(self, base_url="https://zero-day-sentinel.onrender.com"):
        """Initialize with the base URL of the threat intelligence service."""
        self.base_url = base_url
        self.threat_endpoint = f"{base_url}/threat"
        
    def get_known_threats(self):
        """
        Retrieve known threats from the threat intelligence service.
        
        Returns:
            List of threat dictionaries or None if request fails
        """
        try:
            logger.info(f"Fetching known threats from {self.threat_endpoint}")
            response = requests.get(self.threat_endpoint, timeout=10)
            
            if response.status_code == 200:
                threats = response.json()
                logger.info(f"Successfully retrieved {len(threats)} threats")
                return threats
            else:
                logger.error(f"Failed to retrieve threats: HTTP {response.status_code}")
                logger.error(f"Response: {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error retrieving threats: {str(e)}")
            return None
    
    def report_anomaly(self, anomaly_data):
        """
        Report a detected anomaly to the threat intelligence service.
        
        Args:
            anomaly_data: Dictionary containing anomaly information
            
        Returns:
            True if report was successful, False otherwise
        """
        try:
            # Format the anomaly data for the threat intelligence service
            threat_report = {
                "timestamp": anomaly_data.get('timestamp', datetime.now().isoformat()),
                "source_ip": anomaly_data.get('src_ip', '0.0.0.0'),
                "destination_ip": anomaly_data.get('dst_ip', '0.0.0.0'),
                "protocol": anomaly_data.get('protocol_type', 'unknown'),
                "service": anomaly_data.get('service', 'unknown'),
                "threat_type": anomaly_data.get('alert_types', 'suspicious_activity'),
                "confidence": anomaly_data.get('highest_confidence', 0.5),
                "details": {
                    "flag": anomaly_data.get('flag', ''),
                    "duration": anomaly_data.get('duration', 0),
                    "src_bytes": anomaly_data.get('src_bytes', 0),
                    "dst_bytes": anomaly_data.get('dst_bytes', 0)
                }
            }
            
            logger.info(f"Reporting anomaly to {self.threat_endpoint}")
            logger.debug(f"Anomaly data: {json.dumps(threat_report)}")
            
            response = requests.post(
                self.threat_endpoint,
                json=threat_report,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"Successfully reported anomaly: {response.status_code}")
                return True
            else:
                logger.error(f"Failed to report anomaly: HTTP {response.status_code}")
                logger.error(f"Response: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error reporting anomaly: {str(e)}")
            return False
    
    def bulk_report_anomalies(self, anomalies):
        """
        Report multiple anomalies to the threat intelligence service.
        
        Args:
            anomalies: List of anomaly dictionaries
            
        Returns:
            Number of successfully reported anomalies
        """
        success_count = 0
        
        for anomaly in anomalies:
            if self.report_anomaly(anomaly):
                success_count += 1
        
        logger.info(f"Reported {success_count}/{len(anomalies)} anomalies successfully")
        return success_count

# Singleton instance
threat_intel = ThreatIntelligence()

# For testing
if __name__ == "__main__":
    # Test retrieval of known threats
    threats = threat_intel.get_known_threats()
    if threats:
        print(f"Retrieved {len(threats)} threats")
        
    # Test reporting an anomaly
    test_anomaly = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": "192.168.1.100",
        "dst_ip": "203.0.113.1",
        "protocol_type": "tcp",
        "service": "http",
        "flag": "S0",
        "duration": 120,
        "src_bytes": 15000,
        "dst_bytes": 4000,
        "alert_types": "potential_scan",
        "highest_confidence": 0.85
    }
    
    success = threat_intel.report_anomaly(test_anomaly)
    print(f"Anomaly report {'succeeded' if success else 'failed'}") 