#!/usr/bin/env python
# List Windows network interfaces for packet capture

import subprocess
import re

def main():
    try:
        # Run netsh to get adapter information
        output = subprocess.check_output("netsh interface show interface", shell=True).decode('utf-8')
        
        print("Windows Network Interfaces:")
        print("--------------------------")
        print(output)
        
        # Also show adapter information
        print("\nAdapter Information:")
        print("--------------------------")
        ipconfig_output = subprocess.check_output("ipconfig /all", shell=True).decode('utf-8')
        print(ipconfig_output)
        
    except Exception as e:
        print(f"Error listing interfaces: {e}")

if __name__ == "__main__":
    main() 