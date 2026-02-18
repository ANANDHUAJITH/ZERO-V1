/**
 * Display.cpp - Display management implementation
 */

#include "Display.h"

DisplayManager::DisplayManager() 
    : display(nullptr), initialized(false), lastUpdate(0), sleeping(false) {
}

DisplayManager::~DisplayManager() {
    if (display) {
        delete display;
    }
}

bool DisplayManager::begin() {
    Wire.begin(OLED_SDA, OLED_SCL);
    
    display = new Adafruit_SSD1306(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
    
    if (!display->begin(SSD1306_SWITCHCAPVCC, OLED_ADDRESS)) {
        Serial.println(F("SSD1306 allocation failed"));
        return false;
    }
    
    display->clearDisplay();
    display->setTextColor(SSD1306_WHITE);
    display->display();
    
    initialized = true;
    sleeping = false;
    
    return true;
}

void DisplayManager::clear() {
    if (!initialized || !display) return;
    display->clearDisplay();
}

void DisplayManager::update() {
    if (!initialized || !display) return;
    display->display();
    lastUpdate = millis();
}

void DisplayManager::sleep() {
    if (!initialized || !display) return;
    clear();
    update();
    sleeping = true;
}

void DisplayManager::wake() {
    sleeping = false;
}

void DisplayManager::drawText(int16_t x, int16_t y, const char* text, uint8_t size) {
    if (!initialized || !display) return;
    display->setTextSize(size);
    display->setCursor(x, y);
    display->print(text);
}

void DisplayManager::drawTextCentered(int16_t y, const char* text, uint8_t size) {
    if (!initialized || !display) return;
    
    int16_t x1, y1;
    uint16_t w, h;
    display->setTextSize(size);
    display->getTextBounds(text, 0, 0, &x1, &y1, &w, &h);
    
    int16_t x = (SCREEN_WIDTH - w) / 2;
    display->setCursor(x, y);
    display->print(text);
}

void DisplayManager::drawProgressBar(int16_t x, int16_t y, int16_t w, int16_t h, uint8_t progress) {
    if (!initialized || !display) return;
    
    // Draw outline
    display->drawRect(x, y, w, h, SSD1306_WHITE);
    
    // Draw fill
    int16_t fillWidth = ((w - 4) * progress) / 100;
    if (fillWidth > 0) {
        display->fillRect(x + 2, y + 2, fillWidth, h - 4, SSD1306_WHITE);
    }
}

void DisplayManager::drawFrame(const char* title) {
    if (!initialized || !display) return;
    
    // Draw title bar
    display->fillRect(0, 0, SCREEN_WIDTH, 12, SSD1306_WHITE);
    display->setTextColor(SSD1306_BLACK);
    display->setTextSize(1);
    display->setCursor(4, 2);
    display->print(title);
    display->setTextColor(SSD1306_WHITE);
    
    // Draw border
    display->drawRect(0, 12, SCREEN_WIDTH, SCREEN_HEIGHT - 12, SSD1306_WHITE);
}

void DisplayManager::drawScrollText(int16_t y, const char* text, int16_t& scrollPos) {
    if (!initialized || !display) return;
    
    int16_t x1, y1;
    uint16_t w, h;
    display->setTextSize(1);
    display->getTextBounds(text, 0, 0, &x1, &y1, &w, &h);
    
    if (w > SCREEN_WIDTH) {
        display->setCursor(scrollPos, y);
        display->print(text);
        
        scrollPos -= 2;
        if (scrollPos < -(int16_t)w) {
            scrollPos = SCREEN_WIDTH;
        }
    } else {
        drawTextCentered(y, text, 1);
    }
}

void DisplayManager::showSplash(const char* title, const char* subtitle) {
    if (!initialized || !display) return;
    
    clear();
    
    // Draw title
    display->setTextSize(3);
    int16_t x1, y1;
    uint16_t w, h;
    display->getTextBounds(title, 0, 0, &x1, &y1, &w, &h);
    display->setCursor((SCREEN_WIDTH - w) / 2, 15);
    display->print(title);
    
    // Draw subtitle if provided
    if (subtitle) {
        display->setTextSize(1);
        display->getTextBounds(subtitle, 0, 0, &x1, &y1, &w, &h);
        display->setCursor((SCREEN_WIDTH - w) / 2, 45);
        display->print(subtitle);
    }
    
    update();
}

void DisplayManager::showMessage(const char* title, const char* message) {
    if (!initialized || !display) return;
    
    clear();
    drawFrame(title);
    
    display->setTextSize(1);
    display->setCursor(4, 20);
    
    // Word wrap
    char* msg = strdup(message);
    char* line = strtok(msg, "\n");
    int16_t y = 20;
    
    while (line != NULL && y < SCREEN_HEIGHT - 10) {
        display->setCursor(4, y);
        display->print(line);
        y += 10;
        line = strtok(NULL, "\n");
    }
    
    free(msg);
    update();
}

void DisplayManager::showError(const char* error) {
    if (!initialized || !display) return;
    
    clear();
    
    display->setTextSize(2);
    drawTextCentered(10, "ERROR", 2);
    
    display->setTextSize(1);
    display->setCursor(4, 35);
    display->print(error);
    
    update();
}

void DisplayManager::showLoading(const char* text) {
    if (!initialized || !display) return;
    
    clear();
    drawTextCentered(28, text, 1);
    
    // Draw spinning animation
    static uint8_t frame = 0;
    const char spinner[] = {'|', '/', '-', '\\'};
    display->setTextSize(2);
    display->setCursor(SCREEN_WIDTH / 2 - 6, 40);
    display->print(spinner[frame % 4]);
    frame++;
    
    update();
}

void DisplayManager::drawMenuItem(int16_t y, const char* text, bool selected) {
    if (!initialized || !display) return;
    
    if (selected) {
        display->fillRect(0, y, SCREEN_WIDTH, 12, SSD1306_WHITE);
        display->setTextColor(SSD1306_BLACK);
        display->setCursor(4, y + 2);
        display->print("> ");
        display->print(text);
        display->setTextColor(SSD1306_WHITE);
    } else {
        display->setCursor(8, y + 2);
        display->print(text);
    }
}

void DisplayManager::drawMenuHeader(const char* title, int current, int total) {
    if (!initialized || !display) return;
    
    display->fillRect(0, 0, SCREEN_WIDTH, 10, SSD1306_WHITE);
    display->setTextColor(SSD1306_BLACK);
    display->setTextSize(1);
    display->setCursor(2, 1);
    display->print(title);
    
    // Draw counter
    char counter[16];
    snprintf(counter, sizeof(counter), "%d/%d", current + 1, total);
    int16_t x1, y1;
    uint16_t w, h;
    display->getTextBounds(counter, 0, 0, &x1, &y1, &w, &h);
    display->setCursor(SCREEN_WIDTH - w - 2, 1);
    display->print(counter);
    
    display->setTextColor(SSD1306_WHITE);
}
