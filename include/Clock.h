/**
 * Clock.h - Real-time clock display module
 */

#ifndef CLOCK_H
#define CLOCK_H

#include <Arduino.h>
#include <RTClib.h>
#include "Config.h"
#include "Display.h"

class ClockModule {
private:
    DS1307 rtc;
    DisplayManager* display;
    bool initialized;
    bool inSetMode;
    int setField; // 0=hour, 1=minute, 2=day, 3=month, 4=year
    DateTime setTime;
    unsigned long lastUpdate;
    unsigned long lastBlink;
    bool blinkState;
    
    const char* daysOfWeek[7] = {"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"};
    const char* months[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", 
                              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    
public:
    ClockModule();
    
    bool begin();
    void enter();
    void exit();
    void update();
    void enterSetMode();
    void handleInput(ButtonEvent event);
    
private:
    void displayTime();
    void displaySetMode();
};

#endif // CLOCK_H
