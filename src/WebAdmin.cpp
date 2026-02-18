/**
 * WebAdmin.cpp - Web admin interface implementation
 */

#include "WebAdmin.h"

WebAdminModule::WebAdminModule()
    : display(nullptr), server(nullptr), active(false),
      localIP(192, 168, 4, 1) {
}

WebAdminModule::~WebAdminModule() {
    if (server) delete server;
}

void WebAdminModule::begin(DisplayManager* disp) {
    display = disp;
}

void WebAdminModule::enter() {
    Serial.println(F("Web Admin Mode"));
}

void WebAdminModule::exit() {
    if (active) {
        stopServer();
    }
}

void WebAdminModule::update() {
    displayStatus();
}

void WebAdminModule::toggleServer() {
    if (active) {
        stopServer();
    } else {
        startServer();
    }
}

void WebAdminModule::startServer() {
    WiFi.mode(WIFI_AP);
    WiFi.softAPConfig(localIP, localIP, IPAddress(255, 255, 255, 0));
    WiFi.softAP(WEBADMIN_SSID, WEBADMIN_PASSWORD);
    
    server = new AsyncWebServer(80);
    setupRoutes();
    server->begin();
    
    active = true;
    
    Serial.println(F("Web server started"));
    Serial.print(F("SSID: "));
    Serial.println(WEBADMIN_SSID);
    Serial.print(F("Password: "));
    Serial.println(WEBADMIN_PASSWORD);
    Serial.print(F("IP: "));
    Serial.println(localIP);
}

void WebAdminModule::stopServer() {
    if (server) {
        server->end();
        delete server;
        server = nullptr;
    }
    
    WiFi.softAPdisconnect(true);
    active = false;
    
    Serial.println(F("Web server stopped"));
}

void WebAdminModule::setupRoutes() {
    // Home page
    server->on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
        String html = F("<!DOCTYPE html><html><head>");
        html += F("<meta name='viewport' content='width=device-width, initial-scale=1.0'>");
        html += F("<title>ZERO V2 Admin</title>");
        html += F("<style>");
        html += F("body{font-family:Arial;max-width:800px;margin:20px auto;padding:20px;background:#1a1a1a;color:#fff;}");
        html += F("h1{color:#00ff00;border-bottom:2px solid #00ff00;padding-bottom:10px;}");
        html += F(".card{background:#2a2a2a;padding:20px;margin:20px 0;border-radius:8px;}");
        html += F(".btn{background:#00ff00;color:#000;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin:5px;}");
        html += F(".btn:hover{background:#00cc00;}");
        html += F("</style></head><body>");
        html += F("<h1>ZERO V2 - Admin Panel</h1>");
        html += F("<div class='card'>");
        html += F("<h2>System Status</h2>");
        html += F("<p>Version: 2.0</p>");
        html += F("<p>Free Heap: ");
        html += String(ESP.getFreeHeap());
        html += F(" bytes</p>");
        html += F("</div>");
        html += F("<div class='card'>");
        html += F("<h2>Configuration</h2>");
        html += F("<button class='btn' onclick='location.href=\"/config\"'>Settings</button>");
        html += F("<button class='btn' onclick='location.href=\"/status\"'>Status JSON</button>");
        html += F("<button class='btn' onclick='location.href=\"/restart\"'>Restart</button>");
        html += F("</div>");
        html += F("<div class='card'>");
        html += F("<h2>Documentation</h2>");
        html += F("<p><a href='https://github.com/ANANDHUAJITH/ZERO-V2' style='color:#00ff00;'>GitHub Repository</a></p>");
        html += F("</div>");
        html += F("</body></html>");
        
        request->send(200, "text/html", html);
    });
    
    // Status JSON
    server->on("/status", HTTP_GET, [this](AsyncWebServerRequest *request) {
        request->send(200, "application/json", getStatusJSON());
    });
    
    // Config page
    server->on("/config", HTTP_GET, [this](AsyncWebServerRequest *request) {
        request->send(200, "text/html", getConfigHTML());
    });
    
    // Restart
    server->on("/restart", HTTP_GET, [](AsyncWebServerRequest *request) {
        request->send(200, "text/plain", "Restarting...");
        delay(1000);
        ESP.restart();
    });
    
    // 404
    server->onNotFound([](AsyncWebServerRequest *request) {
        request->send(404, "text/plain", "Not found");
    });
}

String WebAdminModule::getStatusJSON() {
    String json = "{";
    json += "\"version\":\"2.0\",";
    json += "\"uptime\":" + String(millis()) + ",";
    json += "\"freeHeap\":" + String(ESP.getFreeHeap()) + ",";
    json += "\"chipId\":\"" + String(ESP.getChipId(), HEX) + "\",";
    json += "\"flashSize\":" + String(ESP.getFlashChipSize()) + ",";
    json += "\"cpuFreq\":" + String(ESP.getCpuFreqMHz());
    json += "}";
    return json;
}

String WebAdminModule::getConfigHTML() {
    String html = F("<!DOCTYPE html><html><head>");
    html += F("<meta name='viewport' content='width=device-width, initial-scale=1.0'>");
    html += F("<title>Configuration - ZERO V2</title>");
    html += F("<style>");
    html += F("body{font-family:Arial;max-width:600px;margin:20px auto;padding:20px;background:#1a1a1a;color:#fff;}");
    html += F("h1{color:#00ff00;}");
    html += F(".form-group{margin:20px 0;}");
    html += F("label{display:block;margin-bottom:5px;}");
    html += F("input,select{width:100%;padding:8px;margin-bottom:10px;background:#2a2a2a;color:#fff;border:1px solid #444;border-radius:4px;}");
    html += F(".btn{background:#00ff00;color:#000;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;}");
    html += F("</style></head><body>");
    html += F("<h1>Configuration</h1>");
    html += F("<form method='POST' action='/save-config'>");
    html += F("<div class='form-group'>");
    html += F("<label>Device Name:</label>");
    html += F("<input type='text' name='deviceName' value='ZERO-V2'>");
    html += F("</div>");
    html += F("<div class='form-group'>");
    html += F("<label>Auto Sleep (minutes):</label>");
    html += F("<input type='number' name='sleepTimeout' value='5'>");
    html += F("</div>");
    html += F("<button type='submit' class='btn'>Save Configuration</button>");
    html += F("</form>");
    html += F("<br><button class='btn' onclick='location.href=\"/\"'>Back</button>");
    html += F("</body></html>");
    
    return html;
}

void WebAdminModule::displayStatus() {
    if (!display) return;
    
    display->clear();
    display->drawFrame("WEB ADMIN");
    
    Adafruit_SSD1306* d = display->getDisplay();
    d->setTextSize(1);
    
    if (active) {
        d->setCursor(4, 20);
        d->print("Status: ACTIVE");
        
        d->setCursor(4, 32);
        d->print("SSID: ");
        d->print(WEBADMIN_SSID);
        
        d->setCursor(4, 44);
        d->print("IP: ");
        d->print(localIP);
    } else {
        d->setCursor(4, 35);
        d->print("Press SELECT");
        d->setCursor(4, 47);
        d->print("to start server");
    }
    
    display->update();
}
