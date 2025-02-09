/**
 * Univerità degli studi di Bologna
 * Project for the Cybersecurity course
 * Academic year 2024/2025
 *
 * ESP32 MQTT Client with WiFi Connectivity  
 * This script connects an ESP32 to a WiFi network and communicates with an MQTT broker  
 * to send and receive messages. It ensures automatic reconnection to both WiFi and  
 * the MQTT broker in case of disconnection.  
 * 
 * Authors:
 * - Emanuele Grasso   (0001141478)
 * - Simone Rinaldi    (0001140193)
 */

#include <WiFi.h>
#include <PubSubClient.h>

// Include configuration file for credentials and settings
#include "config.h"

// Global variables
WiFiClient espClient;                 // Standard WiFi client for non-TLS MQTT
PubSubClient mqttClient(espClient);   // MQTT client using the standard WiFi client
unsigned long lastMessageTime = 0;    // Tracks the last time a message was sent
const long publishInterval = 5000;    // Interval between messages (milliseconds)
const long retryInterval = 5000;      // Interval before retrying connection

/**
 * Callback function to handle incoming MQTT messages.
 * Prints the received message to the serial monitor.
 *
 * @param topic The topic on which the message was received.
 * @param payload The message payload.
 * @param length The length of the payload.
 */
void callback(char* topic, byte* payload, unsigned int length) {
  Serial.print("Message received on topic '");
  Serial.print(topic);
  Serial.print("': ");
  String receivedMessage = "";
  for (unsigned int i = 0; i < length; i++) {
    receivedMessage += (char)payload[i];
  }
  Serial.println(receivedMessage);
}

/**
 * Connects to the WiFi network using the credentials in config.h.
 * Blocks execution until the connection is established.
 */
void connectToWiFi() {
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("WiFi already connected.");
    return;
  }

  Serial.print("Connecting to WiFi: ");
  Serial.println(WIFI_SSID);

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  // Wait until the connection is established
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nWiFi connected!");
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());
}

/**
 * Establishes a connection to the MQTT broker.
 * Blocks execution until the connection is established.
 * Subscribes to the configured MQTT topic to receive messages.
 */
void connectToMQTT() {
  while (!mqttClient.connected()) {
    Serial.print("Connecting to MQTT broker...");

    // Generate a unique client ID
    String clientId = "ESP32Client-" + String(random(0xffff), HEX);

    // Attempt to connect with credentials
    if (mqttClient.connect(clientId.c_str())) {
      Serial.println("connected!");
      mqttClient.subscribe(MQTT_SUB_TOPIC);
      Serial.println("Subscribed to topic: " + String(MQTT_SUB_TOPIC));
    } else {
      Serial.print("failed, error code: ");
      Serial.print(mqttClient.state());
      Serial.println(" Retrying in " + String(retryInterval) + " milliseconds...");
      delay(retryInterval);
    }
  }
}

/**
 * Publishes a new message to the MQTT topic at regular intervals.
 *
 * @param message The message to be published.
 */
void publishMessage(String message) {
  delay(publishInterval);

  if (mqttClient.publish(MQTT_PUB_TOPIC, message.c_str())) {
    Serial.print("Published: ");
    Serial.println(message);
  } else {
    Serial.println("Message publish failed!");
  }
}

/**
 * Arduino setup function. Runs once at startup.
 */
void setup() {
  Serial.begin(115200); // Initialize serial communication
  delay(100);

  // Connect to WiFi
  connectToWiFi();

  // Configure MQTT client
  mqttClient.setServer(MQTT_SERVER, MQTT_PORT);
  mqttClient.setCallback(callback);

  // Connect to MQTT broker
  connectToMQTT();
}

/**
 * Arduino loop function. Runs continuously after setup.
 * Maintains WiFi and MQTT connections.
 */
void loop() {
  // Ensure WiFi connection remains active
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Disconnected from WiFi! Reconnecting...");
    connectToWiFi();
  }

  // Ensure MQTT connection remains active
  if (!mqttClient.connected()) {
    Serial.println("Disconnected from MQTT broker! Reconnecting...");
    connectToMQTT();
  }

  mqttClient.loop(); // Process incoming messages
}
