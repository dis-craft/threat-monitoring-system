#!/usr/bin/env python
"""
OWASP ZAP Scanner for Zomato-like application
This script automates vulnerability scanning using OWASP ZAP
"""
import time
import json
import os
import sys
import logging
from datetime import datetime
from zapv2 import ZAPv2

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("zap_scan.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('zap_scanner')

class ZapScanner:
    def __init__(self, target='http://localhost:5000', api_key='', zap_path=None):
        """Initialize the ZAP scanner with configuration parameters"""
        self.target = target
        self.api_key = api_key
        self.zap_path = zap_path
        self.zap = None
        self.results_dir = 'static/scan_results'
        
        # Ensure results directory exists
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
    
    def connect_to_zap(self):
        """Connect to ZAP API"""
        try:
            self.zap = ZAPv2(apikey=self.api_key, 
                           proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
            logger.info("Successfully connected to ZAP API")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to ZAP: {e}")
            return False
    
    def start_zap(self):
        """Start ZAP daemon if path is provided"""
        if not self.zap_path:
            logger.info("No ZAP path provided, assuming ZAP is already running")
            return
        
        # Implementation for starting ZAP would go here
        # This depends on the OS and ZAP installation
        logger.info(f"Starting ZAP from: {self.zap_path}")
        # Example: subprocess.Popen([self.zap_path, '-daemon', '-config', f'api.key={self.api_key}'])
    
    def is_zap_running(self):
        """Check if ZAP is running"""
        try:
            return self.zap.core.is_running if self.zap else False
        except:
            return False
    
    def access_target(self):
        """Access the target URL via ZAP proxy"""
        try:
            logger.info(f"Accessing target: {self.target}")
            self.zap.urlopen(self.target)
            return True
        except Exception as e:
            logger.error(f"Failed to access target via ZAP: {e}")
            return False
    
    def run_spider(self):
        """Run the ZAP spider on the target"""
        try:
            logger.info("Starting spider scan...")
            scan_id = self.zap.spider.scan(self.target)
            
            # Wait for spider to complete
            while int(self.zap.spider.status(scan_id)) < 100:
                logger.info(f"Spider progress: {self.zap.spider.status(scan_id)}%")
                time.sleep(5)
            
            logger.info("Spider scan completed")
            return True
        except Exception as e:
            logger.error(f"Spider scan failed: {e}")
            return False
    
    def run_ajax_spider(self):
        """Run the ZAP AJAX spider on the target"""
        try:
            logger.info("Starting AJAX spider scan...")
            self.zap.ajaxSpider.scan(self.target)
            
            # Wait for AJAX spider to complete
            while self.zap.ajaxSpider.status == 'running':
                logger.info("AJAX Spider running, please wait...")
                time.sleep(5)
            
            logger.info("AJAX Spider scan completed")
            return True
        except Exception as e:
            logger.error(f"AJAX Spider scan failed: {e}")
            return False
    
    def run_active_scan(self):
        """Run active scan on the target"""
        try:
            logger.info("Starting active scan...")
            scan_id = self.zap.ascan.scan(self.target)
            
            # Wait for active scan to complete
            while int(self.zap.ascan.status(scan_id)) < 100:
                logger.info(f"Active scan progress: {self.zap.ascan.status(scan_id)}%")
                time.sleep(5)
            
            logger.info("Active scan completed")
            return True
        except Exception as e:
            logger.error(f"Active scan failed: {e}")
            return False
    
    def get_alerts(self):
        """Get all alerts from the ZAP scan"""
        try:
            logger.info("Retrieving alerts...")
            alerts = self.zap.core.alerts(baseurl=self.target)
            logger.info(f"Found {len(alerts)} alerts")
            return alerts
        except Exception as e:
            logger.error(f"Failed to retrieve alerts: {e}")
            return []
    
    def save_results(self):
        """Save scan results to JSON file"""
        try:
            alerts = self.get_alerts()
            if not alerts:
                logger.warning("No alerts to save")
                return False
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.results_dir}/zap_scan_results_{timestamp}.json"
            
            # Create a more structured results object
            results = {
                'scan_date': datetime.now().isoformat(),
                'target': self.target,
                'summary': {
                    'high_risk': len([a for a in alerts if a.get('risk') == 'High']),
                    'medium_risk': len([a for a in alerts if a.get('risk') == 'Medium']),
                    'low_risk': len([a for a in alerts if a.get('risk') == 'Low']),
                    'informational': len([a for a in alerts if a.get('risk') == 'Informational']),
                    'total': len(alerts)
                },
                'alerts': alerts
            }
            
            with open(filename, 'w') as file:
                json.dump(results, file, indent=4)
            
            # Also save a latest.json for easy access
            with open(f"{self.results_dir}/latest.json", 'w') as file:
                json.dump(results, file, indent=4)
            
            logger.info(f"Results saved to {filename}")
            return filename
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            return False
    
    def run_full_scan(self):
        """Run a complete ZAP scan process"""
        if not self.connect_to_zap():
            return False
        
        if not self.is_zap_running():
            logger.error("ZAP is not running. Please start ZAP daemon first.")
            return False
        
        if not self.access_target():
            return False
        
        # Run the scans
        self.run_spider()
        self.run_ajax_spider()
        self.run_active_scan()
        
        # Save and return results
        return self.save_results()

def main():
    """Main function to run the ZAP scanner"""
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = 'http://localhost:5000'
    
    api_key = os.environ.get('ZAP_API_KEY', '')
    zap_path = os.environ.get('ZAP_PATH', '')
    
    scanner = ZapScanner(target=target, api_key=api_key, zap_path=zap_path)
    result = scanner.run_full_scan()
    
    if result:
        logger.info(f"Scan completed successfully. Results saved to {result}")
        sys.exit(0)
    else:
        logger.error("Scan failed.")
        sys.exit(1)

if __name__ == "__main__":
    main() 