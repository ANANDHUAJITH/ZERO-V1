/**
 * BeaconSpam.cpp - Beacon spam implementation
 */

#include "BeaconSpam.h"

BeaconSpamModule::BeaconSpamModule() 
    : active(false), delayTime(BEACON_DEFAULT_DELAY), lastBeacon(0) {
    ssidChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
}

void BeaconSpamModule::begin() {
    // Initialize packet template
    uint8_t packetTemplate[128] = {
        0x80, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0xc0, 0x6c,
        0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00,
        0x64, 0x00,
        0x01, 0x04,
        0x00, 0x06, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72,
        0x01, 0x08, 0x82, 0x84,
        0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, 0x03, 0x01,
        0x04
    };
    memcpy(packet, packetTemplate, sizeof(packetTemplate));
}

void BeaconSpamModule::enter() {
    Serial.println(F("Beacon Spam Mode"));
    wifi_set_opmode(STATION_MODE);
    wifi_promiscuous_enable(1);
}

void BeaconSpamModule::exit() {
    active = false;
    wifi_promiscuous_enable(0);
}

void BeaconSpamModule::update() {
    if (!active) return;
    
    if (millis() - lastBeacon >= delayTime) {
        sendBeacon();
        lastBeacon = millis();
    }
}

void BeaconSpamModule::toggle() {
    active = !active;
    Serial.print(F("Beacon spam: "));
    Serial.println(active ? F("ON") : F("OFF"));
}

void BeaconSpamModule::increaseRate() {
    delayTime = max(BEACON_MIN_DELAY, delayTime - 5);
    Serial.print(F("Beacon delay: "));
    Serial.print(delayTime);
    Serial.println(F("ms"));
}

void BeaconSpamModule::decreaseRate() {
    delayTime = min(BEACON_MAX_DELAY, delayTime + 5);
    Serial.print(F("Beacon delay: "));
    Serial.print(delayTime);
    Serial.println(F("ms"));
}

void BeaconSpamModule::sendBeacon() {
    // Random channel
    uint8_t channel = random(1, 12);
    wifi_set_channel(channel);
    
    // Random MAC
    packet[10] = packet[16] = random(256);
    packet[11] = packet[17] = random(256);
    packet[12] = packet[18] = random(256);
    packet[13] = packet[19] = random(256);
    packet[14] = packet[20] = random(256);
    packet[15] = packet[21] = random(256);
    
    // Generate SSID
    String ssid = "ZERO-";
    for (int i = 0; i < 3; i++) {
        ssid += ssidChars[random(ssidChars.length())];
    }
    
    // Update SSID in packet
    packet[37] = ssid.length();
    for (size_t i = 0; i < ssid.length() && i < MAX_SSID_LENGTH; i++) {
        packet[38 + i] = ssid[i];
    }
    
    // Update channel
    packet[56] = channel;
    
    // Send beacon
    wifi_send_pkt_freedom(packet, 57, 0);
    wifi_send_pkt_freedom(packet, 57, 0);
    wifi_send_pkt_freedom(packet, 57, 0);
}
