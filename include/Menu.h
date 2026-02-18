/**
 * Menu.h - Main menu system
 */

#ifndef MENU_H
#define MENU_H

#include <Arduino.h>
#include "Config.h"
#include "Display.h"

class MenuManager {
private:
    DisplayManager* display;
    int selectedIndex;
    int scrollOffset;
    const int visibleItems = 4;
    unsigned long lastUpdate;
    int animFrame;
    
public:
    MenuManager();
    
    void begin(DisplayManager* disp);
    void show();
    void next();
    void previous();
    OperatingMode getSelectedMode();
    void update();
    
private:
    void render();
    void drawIcon(int x, int y, int mode);
};

#endif // MENU_H
