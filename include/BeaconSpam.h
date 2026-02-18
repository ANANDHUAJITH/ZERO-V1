/**
 * BeaconSpam.h - Beacon frame spam module
 */

#ifndef BEACON_SPAM_H
#define BEACON_SPAM_H

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include "Config.h"

extern "C" {
    #include "user_interface.h"
}

class BeaconSpamModule {
private:
    bool active;
    int delayTime;
    unsigned long lastBeacon;
    uint8_t packet[128];
    String ssidChars;
    
public:
    BeaconSpamModule();
    void begin();
    void enter();
    void exit();
    void update();
    void toggle();
    void increaseRate();
    void decreaseRate();
    
private:
    void sendBeacon();
};

#endif // BEACON_SPAM_H
