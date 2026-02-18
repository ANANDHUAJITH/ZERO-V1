/**
 * Deauth.h - Deauth attack module
 */

#ifndef DEAUTH_H
#define DEAUTH_H

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include "Config.h"
#include "Display.h"

extern "C" {
    #include "user_interface.h"
}

struct AccessPoint {
    String ssid;
    uint8_t bssid[6];
    int channel;
    int8_t rssi;
    uint8_t deauthPacket[26];
    bool found;
    int packetCount;
};

class DeauthModule {
private:
    DisplayManager* display;
    bool active;
    bool scanning;
    AccessPoint networks[MAX_ACCESS_POINTS];
    int networkCount;
    int selectedNetwork;
    unsigned long lastScan;
    unsigned long lastDeauth;
    
public:
    DeauthModule();
    void begin(DisplayManager* disp);
    void enter();
    void exit();
    void update();
    void toggleAttack();
    void selectNextNetwork();
    void selectPreviousNetwork();
    void rescan();
    
private:
    void scan();
    void sendDeauth(int index);
    void displayNetworks();
    static void ICACHE_FLASH_ATTR promiscCallback(uint8_t *buf, uint16_t len);
};

#endif // DEAUTH_H
