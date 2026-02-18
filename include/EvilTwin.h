/**
 * EvilTwin.h - Evil Twin attack module
 */

#ifndef EVILTWIN_H
#define EVILTWIN_H

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include "Config.h"
#include "Display.h"

struct NetworkTarget {
    String ssid;
    uint8_t bssid[6];
    uint8_t channel;
};

class EvilTwinModule {
private:
    DisplayManager* display;
    DNSServer* dnsServer;
    ESP8266WebServer* webServer;
    bool active;
    bool deauthActive;
    NetworkTarget networks[16];
    NetworkTarget selectedNetwork;
    int networkCount;
    int selectedIndex;
    String capturedPassword;
    unsigned long lastScan;
    unsigned long lastDeauth;
    
public:
    EvilTwinModule();
    ~EvilTwinModule();
    void begin(DisplayManager* disp);
    void enter();
    void exit();
    void update();
    void toggleAttack();
    void selectNextNetwork();
    void selectPreviousNetwork();
    void rescan();
    
private:
    void scanNetworks();
    void startAP();
    void stopAP();
    void sendDeauth();
    void handleRoot();
    void handleResult();
    void displayStatus();
};

#endif // EVILTWIN_H
