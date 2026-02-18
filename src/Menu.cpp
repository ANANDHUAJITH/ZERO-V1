/**
 * Menu.cpp - Main menu implementation
 */

#include "Menu.h"

MenuManager::MenuManager() 
    : display(nullptr), selectedIndex(0), scrollOffset(0), 
      lastUpdate(0), animFrame(0) {
}

void MenuManager::begin(DisplayManager* disp) {
    display = disp;
    selectedIndex = 0;
    scrollOffset = 0;
}

void MenuManager::show() {
    render();
}

void MenuManager::next() {
    selectedIndex++;
    if (selectedIndex >= MENU_ITEMS) {
        selectedIndex = 0;
        scrollOffset = 0;
    } else if (selectedIndex >= scrollOffset + visibleItems) {
        scrollOffset++;
    }
    render();
}

void MenuManager::previous() {
    selectedIndex--;
    if (selectedIndex < 0) {
        selectedIndex = MENU_ITEMS - 1;
        scrollOffset = max(0, MENU_ITEMS - visibleItems);
    } else if (selectedIndex < scrollOffset) {
        scrollOffset--;
    }
    render();
}

OperatingMode MenuManager::getSelectedMode() {
    return static_cast<OperatingMode>(selectedIndex + 1);
}

void MenuManager::update() {
    // Animate selection
    if (millis() - lastUpdate > 200) {
        animFrame = (animFrame + 1) % 4;
        render();
        lastUpdate = millis();
    }
}

void MenuManager::render() {
    if (!display) return;
    
    display->clear();
    
    // Draw header
    display->drawMenuHeader("MAIN MENU", selectedIndex, MENU_ITEMS);
    
    // Draw menu items
    int16_t y = 14;
    for (int i = scrollOffset; i < min(scrollOffset + visibleItems, MENU_ITEMS); i++) {
        bool selected = (i == selectedIndex);
        
        if (selected) {
            // Draw selection indicator with animation
            int offset = (animFrame < 2) ? 0 : 1;
            display->getDisplay()->fillRect(0, y + offset, 3, 10, SSD1306_WHITE);
        }
        
        // Draw icon
        drawIcon(6, y + 1, i + 1);
        
        // Draw menu text
        display->getDisplay()->setTextSize(1);
        display->getDisplay()->setCursor(18, y + 1);
        
        if (selected) {
            display->getDisplay()->setTextColor(SSD1306_WHITE, SSD1306_BLACK);
            display->getDisplay()->fillRect(16, y, SCREEN_WIDTH - 16, 12, SSD1306_WHITE);
            display->getDisplay()->setTextColor(SSD1306_BLACK);
        }
        
        char menuText[32];
        strcpy_P(menuText, MENU_ITEMS_TEXT[i]);
        display->getDisplay()->print(menuText);
        
        if (selected) {
            display->getDisplay()->setTextColor(SSD1306_WHITE);
        }
        
        y += 13;
    }
    
    // Draw scroll indicators
    if (scrollOffset > 0) {
        display->getDisplay()->fillTriangle(
            SCREEN_WIDTH - 8, 14,
            SCREEN_WIDTH - 4, 14,
            SCREEN_WIDTH - 6, 18,
            SSD1306_WHITE
        );
    }
    if (scrollOffset + visibleItems < MENU_ITEMS) {
        display->getDisplay()->fillTriangle(
            SCREEN_WIDTH - 8, SCREEN_HEIGHT - 4,
            SCREEN_WIDTH - 4, SCREEN_HEIGHT - 4,
            SCREEN_WIDTH - 6, SCREEN_HEIGHT - 8,
            SSD1306_WHITE
        );
    }
    
    display->update();
}

void MenuManager::drawIcon(int x, int y, int mode) {
    Adafruit_SSD1306* d = display->getDisplay();
    
    switch (mode) {
        case MODE_CLOCK:
            // Clock icon
            d->drawCircle(x + 4, y + 4, 4, SSD1306_WHITE);
            d->drawLine(x + 4, y + 4, x + 4, y + 2, SSD1306_WHITE);
            d->drawLine(x + 4, y + 4, x + 6, y + 4, SSD1306_WHITE);
            break;
            
        case MODE_EYES:
            // Eyes icon
            d->fillCircle(x + 2, y + 4, 2, SSD1306_WHITE);
            d->fillCircle(x + 6, y + 4, 2, SSD1306_WHITE);
            break;
            
        case MODE_BEACON:
            // WiFi icon
            d->drawCircle(x + 4, y + 6, 1, SSD1306_WHITE);
            d->drawCircle(x + 4, y + 6, 3, SSD1306_WHITE);
            d->drawCircle(x + 4, y + 6, 5, SSD1306_WHITE);
            break;
            
        case MODE_EVILTWIN:
            // Evil twin icon (two antennas)
            d->drawLine(x + 2, y + 2, x + 2, y + 6, SSD1306_WHITE);
            d->drawLine(x + 6, y + 2, x + 6, y + 6, SSD1306_WHITE);
            d->drawCircle(x + 2, y + 2, 1, SSD1306_WHITE);
            d->drawCircle(x + 6, y + 2, 1, SSD1306_WHITE);
            break;
            
        case MODE_DEAUTH:
            // Deauth icon (X over WiFi)
            d->drawLine(x + 1, y + 1, x + 7, y + 7, SSD1306_WHITE);
            d->drawLine(x + 7, y + 1, x + 1, y + 7, SSD1306_WHITE);
            break;
            
        case MODE_WEBADMIN:
            // Web icon (globe)
            d->drawCircle(x + 4, y + 4, 4, SSD1306_WHITE);
            d->drawLine(x + 4, y, x + 4, y + 8, SSD1306_WHITE);
            d->drawLine(x, y + 4, x + 8, y + 4, SSD1306_WHITE);
            break;
    }
}
