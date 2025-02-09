# MQTT Security Testing Tools

This repository contains a collection of security testing tools developed for a Cybersecurity course project at the University of Bologna. These tools demonstrate security vulnerabilities in MQTT-based IoT systems and should only be used in controlled, authorized testing environments.

## ⚠️ Warning

These tools are intended for **educational and research purposes only**. Unauthorized use against systems is illegal and unethical. The authors and the University of Bologna bear no responsibility for misuse.

## Tools Overview

The repository includes various tools for MQTT security testing:

### MQTT Man-in-the-Middle (mitm.py)

This tool performs ARP spoofing to intercept MQTT traffic, capturing and analyzing packets while monitoring PUBLISH messages and their contents. To use it, execute:
```bash
python mitm.py -g <gateway_ip> -t <target_ip> -i <interface>
```

### MQTT Message Replay (replay.py)

Designed to capture and replay MQTT PUBLISH messages, this tool connects to a broker using Paho-MQTT and can target specific source IP addresses. Run it with:
```bash
python replay.py -i <interface> --source <source_ip> --broker <broker_ip> [--port <broker_port>]
```

### MQTT Traffic Sniffing (sniff.py)

This script monitors MQTT traffic between two hosts, analyzing packet types and contents with detailed breakdowns. Execute it as follows:
```bash
python sniff.py -i <interface> --host1 <host1_ip> --host2 <host2_ip>
```

### Wi-Fi Deauthentication (deauth.py)

By sending deauthentication frames, this tool disconnects devices from Wi-Fi networks. It requires a network interface in monitor mode. Usage:
```bash
python deauth.py -t <target_mac> -a <ap_mac> -i <interface>
```

### MQTT DoS Testing (dos.py)

This script tests a broker's load handling capacity by sending a high volume of messages to specified topics. The message size and frequency are configurable. Run it with:
```bash
python dos.py --broker <broker_ip> --port <broker_port> --topic <topic>
```

### ESP32 MQTT Clients

The repository includes two ESP32 MQTT client implementations: a **Basic MQTT Client** and a **Secure MQTT Client**. The basic version provides fundamental WiFi and MQTT connectivity, automatic reconnection handling, and message publishing/subscription but lacks encryption. The secure version incorporates TLS encryption, JSON message formatting with nonce values, advanced WiFi configuration, and security features such as certificate-based authentication and a structured message format. Both implementations demonstrate proper connection handling and message delivery for IoT devices.

## Prerequisites

### Required Tools for Network Reconnaissance

Before running any scripts, network reconnaissance is necessary to gather information.

**Wireshark** is used to capture and analyze MQTT traffic, identify brokers and clients, monitor message patterns and topics, and determine protocol configurations.

**Nmap** helps discover active hosts, identify open MQTT ports (1883, 8883), detect brokers and their IP addresses, and find MAC addresses of target devices.

### Other Requirements

Ensure the following dependencies are installed:
- Python 3.x
- Scapy (`pip install scapy`)
- Paho-MQTT (`pip install paho-mqtt`)
- A network interface card supporting monitor mode (for deauth.py)
- Root/Administrator privileges
- An ESP32 development board (for MQTT clients)
- Arduino IDE with ESP32 support and necessary libraries (WiFi, PubSubClient, WiFiClientSecure, ArduinoJson)

## Installation

To set up the tools, first install Wireshark and Nmap:
```bash
# Debian/Ubuntu
sudo apt-get install wireshark nmap

# Red Hat/Fedora
sudo dnf install wireshark nmap

# macOS
brew install wireshark nmap
```

Clone the repository and install required Python dependencies:
```bash
git clone <repository-url>
cd mqtt-security-tools
pip install -r requirements.txt
```

For ESP32 development, install the Arduino IDE, add ESP32 board support, and install required libraries through the Arduino Library Manager.

## Network Reconnaissance Steps

Before running attack scripts, gather necessary information. Scan the network for MQTT brokers:
```bash
nmap -p 1883,8883 X.X.X.X/24
```

Capture MQTT traffic using Wireshark by starting it on your network interface and applying the filter:
```
mqtt || tcp.port == 1883 || tcp.port == 8883
```
Analyze the captured traffic to identify brokers, clients, and topics.

Take note of broker and client IP addresses, MAC addresses of targets, and active MQTT topics before proceeding.

## Common Usage Scenarios

### Testing MQTT Broker Security

Monitor MQTT traffic and test broker load handling:
```bash
python monitor.py -i wlan0 --host1 X.X.X.X --host2 X.X.X.X
python dos.py --broker X.X.X.X --port 1883 --topic <topic>
```

### Testing Device Security

Perform a Man-in-the-Middle attack or capture and replay MQTT messages:
```bash
python mitm.py -g X.X.X.X -t X.X.X.X -i wlan0
python replay.py -i wlan0 --source X.X.X.X --broker X.X.X.X
```

## Security Recommendations

To mitigate vulnerabilities, implement the following best practices:
- Enable TLS encryption (MQTT over TLS)
- Use strong authentication mechanisms
- Implement access control lists (ACLs)
- Secure Wi-Fi networks with WPA2/WPA3
- Apply rate limiting and traffic monitoring
- Regularly update firmware and software
- Use secure MQTT clients with TLS
- Implement message signing or nonce values
- Enable enterprise WiFi security features

## Research Context

These tools were developed as part of a research project analyzing MQTT security in IoT environments. The accompanying research paper provides a detailed discussion of vulnerabilities and mitigation strategies.

## Authors

- **Emanuele Grasso (0001141478)**
- **Simone Rinaldi (0001140193)**

University of Bologna
Department of Computer Science and Engineering
Cybersecurity Course Project
Academic Year 2024/2025

## License

This project is intended for educational purposes only. See the LICENSE file for details.

