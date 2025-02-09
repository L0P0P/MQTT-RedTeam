"""
Univerità degli studi di Bologna
Project for the Cybersecurity course
Academic year 2024/2025

Script for monitoring and analyzing MQTT traffic between two specific hosts.
Uses Scapy to capture packets and logs MQTT message details, including PUBLISH topics and payloads.

Usage: python deauth.py -i <interface> --host1 <host1_ip> --host2 <host2_ip>
- interface: Network interface to monitor
- host1_ip: IP address of the first host
- host2_ip: IP address of the second host

Authors:
- Emanuele Grasso   (0001141478)
- Simone Rinaldi    (0001140193)
"""

#!/usr/bin/env python3

import argparse
from scapy.all import *

def get_args():
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed command-line arguments containing network interface and host IPs.
    """
    parser = argparse.ArgumentParser(description='Monitor MQTT Traffic Between Two Hosts')
    parser.add_argument('-i', '--interface', required=True, help='Network interface to monitor')
    parser.add_argument('--host1', required=True, help='First host IP address')
    parser.add_argument('--host2', required=True, help='Second host IP address')
    return parser.parse_args()

def validate_ip(ip):
    """
    Validate IP address format.
    
    Args:
        ip (str): IP address to validate.

    Returns:
        bool: True if the IP address is valid, False otherwise.
    """
    try:
        parts = ip.split('.')
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except:
        return False

def analyze_mqtt_packet(payload):
    """
    Analyze MQTT packet and return packet type and details.
    
    Args:
        payload (bytes): Raw packet payload containing MQTT message.

    Returns:
        str: MQTT packet type.
        dict: MQTT message details.
    """
    MQTT_TYPES = {
        1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK",
        5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE",
        9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK",
        12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT"
    }
    try:
        if len(payload) > 0:
            msg_type = (payload[0] & 0xF0) >> 4
            return MQTT_TYPES.get(msg_type, "Unknown MQTT"), {}
    except:
        pass
    return "Unknown", {}

def analyze_packet(packet, host1, host2):
    """
    Analyze MQTT packets between specified hosts.
    
    Args:
        packet (scapy.Packet): Captured packet.
        host1 (str): IP address of the first host.
        host2 (str): IP address of the second host.
    """
    try:
        if IP in packet and TCP in packet:
            src_ip, dst_ip = packet[IP].src, packet[IP].dst
            if (src_ip, dst_ip) in [(host1, host2), (host2, host1)] and (packet[TCP].sport == 1883 or packet[TCP].dport == 1883):
                if packet.haslayer(Raw):
                    mqtt_type, _ = analyze_mqtt_packet(bytes(packet[Raw]))
                    print(f"MQTT {mqtt_type} From {src_ip} -> {dst_ip}")
    except Exception as e:
        print(f"Error analyzing packet: {str(e)}")

def monitor_mqtt_traffic(interface, host1, host2):
    """
    Monitor MQTT traffic between two specific hosts.
    
    Args:
        interface (str): Network interface to monitor.
        host1 (str): IP address of the first host.
        host2 (str): IP address of the second host.
    """
    filter_expr = f"(host {host1} and host {host2}) and (port 1883)"
    print(f"Starting MQTT traffic analysis on {interface}")
    try:
        sniff(
            iface=interface,
            filter=filter_expr,
            prn=lambda x: analyze_packet(x, host1, host2),
            store=0
        )
    except KeyboardInterrupt:
        print("Monitoring stopped by user")
    except Exception as e:
        print(f"Error during monitoring: {str(e)}")

if __name__ == "__main__":
    args = get_args()
    if not validate_ip(args.host1) or not validate_ip(args.host2):
        print("Error: Invalid IP addresses")
        sys.exit(1)
    print("MQTT Traffic Monitor\nPress Ctrl+C to stop monitoring")
    monitor_mqtt_traffic(args.interface, args.host1, args.host2)
