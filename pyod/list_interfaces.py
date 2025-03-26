#!/usr/bin/env python
# List all available network interfaces for packet capture

from scapy.all import conf, show_interfaces

def main():
    print("Available network interfaces:")
    print("-----------------------------")
    
    # Show all interfaces
    show_interfaces()
    
    # Show default interface
    print(f"\nDefault interface: {conf.iface}")

if __name__ == "__main__":
    main() 