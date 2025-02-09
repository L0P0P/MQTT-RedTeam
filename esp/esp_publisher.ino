/**
 * Univerità degli studi di Bologna
 * Project for the Cybersecurity course
 * Academic year 2024/2025
 * 
 * Secure ESP32 MQTT Client with WiFi Connectivity
 * This script connects an ESP32 device to a WiFi network and securely communicates
 * with an MQTT broker using TLS encryption. It ensures reliable message delivery
 * with automatic reconnection and supports JSON-formatted messages for enhanced security.
 * 
 * Authors:
 * - Emanuele Grasso   (0001141478)
 * - Simone Rinaldi    (0001140193)
 **/

#include <WiFi.h>
#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include "esp_wifi.h"
#include "esp_eap_client.h"
#include "config.h"
#include "ArduinoJson.h"

// Global variables
WiFiClientSecure espClient;           // Secure WiFi client for TLS MQTT
PubSubClient mqttClient(espClient);   // MQTT client using the secure WiFi client
unsigned long lastMessageTime = 0;    // Tracks the last time a message was sent
const long publishInterval = 5000;    // Interval between messages (milliseconds)
const long retryInterval = 5000;      // Interval before retrying connection

/**
 * Callback function for handling received MQTT messages.
 *
 * @param topic The topic the message was received on.
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
 * Connect to the specified WiFi network.
 */
void connectToWiFi() {
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("WiFi already connected.");
    return;
  }

  Serial.print("Connecting to WiFi: ");
  Serial.println(WIFI_SSID);

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  WiFi.setSleep(false);
  esp_wifi_set_ps(WIFI_PS_NONE); // Disable power-saving mode

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nWiFi connected!");
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());
}

/**
 * Establish a connection to the MQTT broker.
 */
void connectToMQTT() {
  espClient.setCACert(MQTT_CERT_CA);

  while (!mqttClient.connected()) {
    Serial.print("Connecting to MQTT broker...");
    String clientId = "ESP32Client-" + String(random(0xffff), HEX);

    if (mqttClient.connect(clientId.c_str(), MQTT_USERNAME, MQTT_PASSWORD)) {
      Serial.println("connected!");
      mqttClient.subscribe(MQTT_SUB_TOPIC);
      Serial.println("Subscribed to topic: " + String(MQTT_SUB_TOPIC));
    } else {
      Serial.print("failed, error code: ");
      Serial.print(mqttClient.state());
      Serial.println(" Retrying in " + String(retryInterval) + " ms...");
      delay(retryInterval);
    }
  }
}

/**
 * Generate a secure JSON message with a nonce value.
 *
 * @param message The message to be sent.
 * @return A JSON string containing the message and a unique nonce.
 */
String generateSecureMessage(String message) {
  DynamicJsonDocument doc(256);
  doc["nonce"] = millis(); // Use timestamp to ensure uniqueness
  doc["message"] = message;
  String jsonMessage;
  serializeJson(doc, jsonMessage);
  return jsonMessage;
}

/**
 * Publish a secure message to the MQTT broker.
 *
 * @param message The message to be sent.
 */
void publishMessage(String message) {
  delay(publishInterval);
  String secureMessage = generateSecureMessage(message);

  if (mqttClient.publish(MQTT_PUB_TOPIC, secureMessage.c_str())) {
    Serial.print("Published: ");
    Serial.println(secureMessage);
  } else {
    Serial.println("Message publish failed!");
  }
}

/**
 * Setup function executed at startup.
 */
void setup() {
  Serial.begin(115200);
  delay(100);
  connectToWiFi();
  WiFi.enableSTA(true);
  WiFi.setTxPower(WIFI_POWER_19_5dBm);

  esp_wifi_sta_enterprise_enable(); // Enforce WPA2 encryption
  esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
  esp_wifi_config_11b_rate(WIFI_IF_STA, WIFI_PHY_RATE_MAX);

  mqttClient.setServer(MQTT_SERVER, MQTT_PORT);
  mqttClient.setCallback(callback);
  connectToMQTT();
}

/**
 * Main loop function, continuously checks WiFi and MQTT connections.
 */
void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Disconnected from WiFi!");
    connectToWiFi();
  }

  if (!mqttClient.connected()) {
    Serial.println("Disconnected from MQTT broker!");
    connectToMQTT();
  }

  mqttClient.loop();
}
