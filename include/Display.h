/**
 * Display.h - Display management and rendering
 */

#ifndef DISPLAY_H
#define DISPLAY_H

#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Wire.h>
#include "Config.h"

class DisplayManager {
private:
    Adafruit_SSD1306* display;
    bool initialized;
    unsigned long lastUpdate;
    bool sleeping;

public:
    DisplayManager();
    ~DisplayManager();
    
    bool begin();
    void clear();
    void update();
    void sleep();
    void wake();
    bool isSleeping() const { return sleeping; }
    
    // Drawing functions
    void drawText(int16_t x, int16_t y, const char* text, uint8_t size = 1);
    void drawTextCentered(int16_t y, const char* text, uint8_t size = 1);
    void drawProgressBar(int16_t x, int16_t y, int16_t w, int16_t h, uint8_t progress);
    void drawFrame(const char* title);
    void drawScrollText(int16_t y, const char* text, int16_t& scrollPos);
    
    // Special screens
    void showSplash(const char* title, const char* subtitle = nullptr);
    void showMessage(const char* title, const char* message);
    void showError(const char* error);
    void showLoading(const char* text = "Loading...");
    
    // Menu rendering
    void drawMenuItem(int16_t y, const char* text, bool selected);
    void drawMenuHeader(const char* title, int current, int total);
    
    // Get display object for custom drawing
    Adafruit_SSD1306* getDisplay() { return display; }
};

#endif // DISPLAY_H
