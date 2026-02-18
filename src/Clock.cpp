/**
 * Clock.cpp - Real-time clock implementation
 */

#include "Clock.h"

ClockModule::ClockModule() 
    : display(nullptr), initialized(false), inSetMode(false), 
      setField(0), lastUpdate(0), lastBlink(0), blinkState(false) {
}

bool ClockModule::begin() {
    if (!rtc.begin()) {
        Serial.println(F("RTC not found!"));
        return false;
    }
    
    if (!rtc.isrunning()) {
        Serial.println(F("RTC not running, setting default time"));
        // Set to compile time as default
        rtc.adjust(DateTime(F(__DATE__), F(__TIME__)));
    }
    
    initialized = true;
    Serial.println(F("Clock module initialized"));
    return true;
}

void ClockModule::enter() {
    display = nullptr;
    inSetMode = false;
    lastUpdate = 0;
}

void ClockModule::exit() {
    inSetMode = false;
}

void ClockModule::update() {
    if (!initialized) return;
    
    if (millis() - lastUpdate > CLOCK_UPDATE_INTERVAL) {
        if (inSetMode) {
            displaySetMode();
        } else {
            displayTime();
        }
        lastUpdate = millis();
    }
    
    // Update blink state for set mode
    if (millis() - lastBlink > 500) {
        blinkState = !blinkState;
        lastBlink = millis();
        if (inSetMode) {
            displaySetMode();
        }
    }
}

void ClockModule::enterSetMode() {
    if (!initialized) return;
    
    inSetMode = !inSetMode;
    
    if (inSetMode) {
        setTime = rtc.now();
        setField = 0;
        Serial.println(F("Entering time set mode"));
    } else {
        rtc.adjust(setTime);
        Serial.println(F("Time saved"));
    }
}

void ClockModule::handleInput(ButtonEvent event) {
    if (!inSetMode) return;
    
    if (event == BTN_SELECT_PRESS) {
        // Move to next field
        setField = (setField + 1) % 5;
    } else if (event == BTN_UP_PRESS) {
        // Increment current field
        switch (setField) {
            case 0: // Hour
                setTime = DateTime(setTime.year(), setTime.month(), setTime.day(),
                                  (setTime.hour() + 1) % 24, setTime.minute(), setTime.second());
                break;
            case 1: // Minute
                setTime = DateTime(setTime.year(), setTime.month(), setTime.day(),
                                  setTime.hour(), (setTime.minute() + 1) % 60, setTime.second());
                break;
            case 2: // Day
                {
                    int maxDay = 31; // Simplified
                    int newDay = (setTime.day() % maxDay) + 1;
                    setTime = DateTime(setTime.year(), setTime.month(), newDay,
                                      setTime.hour(), setTime.minute(), setTime.second());
                }
                break;
            case 3: // Month
                setTime = DateTime(setTime.year(), (setTime.month() % 12) + 1, setTime.day(),
                                  setTime.hour(), setTime.minute(), setTime.second());
                break;
            case 4: // Year
                setTime = DateTime(setTime.year() + 1, setTime.month(), setTime.day(),
                                  setTime.hour(), setTime.minute(), setTime.second());
                break;
        }
    } else if (event == BTN_DOWN_PRESS) {
        // Decrement current field
        switch (setField) {
            case 0: // Hour
                setTime = DateTime(setTime.year(), setTime.month(), setTime.day(),
                                  (setTime.hour() + 23) % 24, setTime.minute(), setTime.second());
                break;
            case 1: // Minute
                setTime = DateTime(setTime.year(), setTime.month(), setTime.day(),
                                  setTime.hour(), (setTime.minute() + 59) % 60, setTime.second());
                break;
            case 2: // Day
                {
                    int maxDay = 31;
                    int newDay = setTime.day() - 1;
                    if (newDay < 1) newDay = maxDay;
                    setTime = DateTime(setTime.year(), setTime.month(), newDay,
                                      setTime.hour(), setTime.minute(), setTime.second());
                }
                break;
            case 3: // Month
                {
                    int newMonth = setTime.month() - 1;
                    if (newMonth < 1) newMonth = 12;
                    setTime = DateTime(setTime.year(), newMonth, setTime.day(),
                                      setTime.hour(), setTime.minute(), setTime.second());
                }
                break;
            case 4: // Year
                setTime = DateTime(setTime.year() - 1, setTime.month(), setTime.day(),
                                  setTime.hour(), setTime.minute(), setTime.second());
                break;
        }
    }
    
    displaySetMode();
}

void ClockModule::displayTime() {
    if (!initialized || !display) return;
    
    DateTime now = rtc.now();
    
    display->clear();
    Adafruit_SSD1306* d = display->getDisplay();
    
    // Draw day of week
    d->setTextSize(2);
    d->setCursor(5, 10);
    d->print(daysOfWeek[now.dayOfTheek()]);
    
    // Draw date
    d->setTextSize(3);
    d->setCursor(58, 6);
    if (now.day() < 10) d->print("0");
    d->print(now.day());
    
    // Draw month and year
    d->setTextSize(1);
    d->setCursor(97, 8);
    d->print(months[now.month() - 1]);
    d->setCursor(97, 20);
    d->print(now.year());
    
    // Draw time (12-hour format)
    int hour = now.hour();
    const char* meridiem = (hour >= 12) ? "PM" : "AM";
    if (hour > 12) hour -= 12;
    if (hour == 0) hour = 12;
    
    d->setTextSize(3);
    d->setCursor(5, 39);
    if (hour < 10) d->print("0");
    d->print(hour);
    d->print(":");
    if (now.minute() < 10) d->print("0");
    d->print(now.minute());
    
    // Draw seconds and meridiem
    d->setTextSize(2);
    d->setCursor(100, 37);
    if (now.second() < 10) d->print("0");
    d->print(now.second());
    d->setTextSize(1);
    d->setCursor(100, 55);
    d->print(meridiem);
    
    display->update();
}

void ClockModule::displaySetMode() {
    if (!initialized || !display) return;
    
    display->clear();
    Adafruit_SSD1306* d = display->getDisplay();
    
    d->setTextSize(1);
    d->setCursor(0, 0);
    d->print("SET TIME (SEL=OK)");
    
    // Show current setting with blinking
    char buffer[32];
    d->setTextSize(2);
    
    // Time
    int hour = setTime.hour();
    if (hour > 12) hour -= 12;
    if (hour == 0) hour = 12;
    
    bool showHour = (setField != 0 || blinkState);
    bool showMin = (setField != 1 || blinkState);
    
    snprintf(buffer, sizeof(buffer), "%s%02d:%s%02d", 
             showHour ? "" : "  ", hour,
             showMin ? "" : "  ", setTime.minute());
    d->setCursor(10, 20);
    d->print(buffer);
    
    // Date
    d->setTextSize(1);
    bool showDay = (setField != 2 || blinkState);
    bool showMonth = (setField != 3 || blinkState);
    bool showYear = (setField != 4 || blinkState);
    
    snprintf(buffer, sizeof(buffer), "%s%02d/%s%02d/%s%04d",
             showDay ? "" : "  ", setTime.day(),
             showMonth ? "" : "  ", setTime.month(),
             showYear ? "    " : "", setTime.year());
    d->setCursor(10, 45);
    d->print(buffer);
    
    display->update();
}
