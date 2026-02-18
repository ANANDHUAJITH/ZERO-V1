/**
 * WebAdmin.h - Web-based admin interface
 */

#ifndef WEBADMIN_H
#define WEBADMIN_H

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESPAsyncWebServer.h>
#include <ESPAsyncTCP.h>
#include "Config.h"
#include "Display.h"

class WebAdminModule {
private:
    DisplayManager* display;
    AsyncWebServer* server;
    bool active;
    IPAddress localIP;
    
public:
    WebAdminModule();
    ~WebAdminModule();
    void begin(DisplayManager* disp);
    void enter();
    void exit();
    void update();
    void toggleServer();
    
private:
    void startServer();
    void stopServer();
    void setupRoutes();
    String getStatusJSON();
    String getConfigHTML();
    void displayStatus();
};

#endif // WEBADMIN_H
