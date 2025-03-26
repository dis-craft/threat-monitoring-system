#!/usr/bin/env python
"""
Test script to verify ZAP connection
Run this after starting ZAP in daemon mode to make sure the connection works
"""
import os
import sys
from zapv2 import ZAPv2

def test_zap_connection():
    # Get API key from environment variable or use default
    api_key = os.environ.get('ZAP_API_KEY', 'zap123')
    
    print(f"Trying to connect to ZAP with API key: {api_key}")
    
    try:
        # Initialize ZAP API client
        zap = ZAPv2(apikey=api_key, 
                  proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        
        # Get ZAP version to verify connection
        version = zap.core.version
        print(f"Successfully connected to ZAP!")
        print(f"ZAP version: {version}")
        
        # Check if ZAP is running
        if zap.core.is_running:
            print("ZAP daemon is running correctly")
        else:
            print("ZAP doesn't seem to be running properly")
        
        return True
    except Exception as e:
        print(f"Failed to connect to ZAP: {e}")
        print("\nPossible issues:")
        print("1. ZAP is not running - make sure to run start_zap.bat or start_zap.sh")
        print("2. API key is incorrect - check that you're using the same API key in ZAP and in the environment")
        print("3. ZAP is running on a different port - default should be 8080")
        return False

if __name__ == "__main__":
    success = test_zap_connection()
    sys.exit(0 if success else 1)