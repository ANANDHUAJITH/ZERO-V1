/**
 * ButtonHandler.cpp - Button input implementation
 */

#include "ButtonHandler.h"

// ========================
// Button Class
// ========================

Button::Button(uint8_t pin) 
    : pin(pin), lastState(HIGH), currentState(HIGH), 
      lastDebounceTime(0), pressStartTime(0), longPressTriggered(false) {
}

void Button::begin() {
    pinMode(pin, INPUT_PULLUP);
}

ButtonEvent Button::update() {
    bool reading = digitalRead(pin);
    ButtonEvent event = BTN_NONE;
    
    // Check for state change
    if (reading != lastState) {
        lastDebounceTime = millis();
    }
    
    // Debounce
    if ((millis() - lastDebounceTime) > BTN_DEBOUNCE_MS) {
        if (reading != currentState) {
            currentState = reading;
            
            if (currentState == LOW) {
                // Button pressed
                pressStartTime = millis();
                longPressTriggered = false;
            } else {
                // Button released
                if (!longPressTriggered) {
                    event = BTN_SELECT_PRESS; // Generic press event
                }
                longPressTriggered = false;
            }
        }
    }
    
    // Check for long press
    if (currentState == LOW && !longPressTriggered) {
        if ((millis() - pressStartTime) > BTN_LONG_PRESS_MS) {
            longPressTriggered = true;
            event = BTN_SELECT_LONG_PRESS; // Generic long press event
        }
    }
    
    lastState = reading;
    return event;
}

// ========================
// ButtonHandler Class
// ========================

ButtonHandler::ButtonHandler() 
    : btnUp(BTN_UP_PIN), btnDown(BTN_DOWN_PIN), 
      btnSelect(BTN_SELECT_PIN), btnMode(BTN_MODE_PIN) {
}

void ButtonHandler::begin() {
    btnUp.begin();
    btnDown.begin();
    btnSelect.begin();
    btnMode.begin();
    
    Serial.println(F("Button handler initialized"));
}

ButtonEvent ButtonHandler::update() {
    ButtonEvent event;
    
    // Check UP button
    event = btnUp.update();
    if (event == BTN_SELECT_PRESS) return BTN_UP_PRESS;
    if (event == BTN_SELECT_LONG_PRESS) return BTN_UP_LONG_PRESS;
    
    // Check DOWN button
    event = btnDown.update();
    if (event == BTN_SELECT_PRESS) return BTN_DOWN_PRESS;
    if (event == BTN_SELECT_LONG_PRESS) return BTN_DOWN_LONG_PRESS;
    
    // Check SELECT button
    event = btnSelect.update();
    if (event == BTN_SELECT_PRESS) return BTN_SELECT_PRESS;
    if (event == BTN_SELECT_LONG_PRESS) return BTN_SELECT_LONG_PRESS;
    
    // Check MODE button
    event = btnMode.update();
    if (event == BTN_SELECT_PRESS) return BTN_MODE_PRESS;
    if (event == BTN_SELECT_LONG_PRESS) return BTN_MODE_LONG_PRESS;
    
    return BTN_NONE;
}

bool ButtonHandler::isUpPressed() {
    return digitalRead(BTN_UP_PIN) == LOW;
}

bool ButtonHandler::isDownPressed() {
    return digitalRead(BTN_DOWN_PIN) == LOW;
}

bool ButtonHandler::isSelectPressed() {
    return digitalRead(BTN_SELECT_PIN) == LOW;
}

bool ButtonHandler::isModePressed() {
    return digitalRead(BTN_MODE_PIN) == LOW;
}
