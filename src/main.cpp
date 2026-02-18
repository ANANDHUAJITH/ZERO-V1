/**
 * ZERO V2 - WiFi Security Testing Tool
 * 
 * WARNING: This tool is for educational and authorized testing purposes only.
 * Unauthorized use on networks you don't own or have permission to test is illegal.
 * 
 * GitHub: https://github.com/ANANDHUAJITH/ZERO-V2
 * License: MIT
 * 
 * Features:
 * - Clock Display Mode
 * - Animated Eyes Mode
 * - Beacon Spam Mode
 * - Evil Twin Attack Mode
 * - Deauth Attack Mode
 * - Web Admin Configuration Mode
 */

#include <Arduino.h>
#include "Config.h"
#include "Display.h"
#include "Menu.h"
#include "Clock.h"
#include "Eyes.h"
#include "BeaconSpam.h"
#include "EvilTwin.h"
#include "Deauth.h"
#include "WebAdmin.h"
#include "ButtonHandler.h"

// Global objects
DisplayManager displayManager;
MenuManager menuManager;
ClockModule clockModule;
EyesModule eyesModule;
BeaconSpamModule beaconModule;
EvilTwinModule evilTwinModule;
DeauthModule deauthModule;
WebAdminModule webAdminModule;
ButtonHandler buttonHandler;

// Current mode
OperatingMode currentMode = MODE_MENU;
OperatingMode previousMode = MODE_MENU;

void setup() {
    Serial.begin(115200);
    Serial.println(F("\n\n================================="));
    Serial.println(F("ZERO V2 - WiFi Security Tool"));
    Serial.println(F("=================================\n"));
    
    // Initialize display
    if (!displayManager.begin()) {
        Serial.println(F("FATAL: Display initialization failed!"));
        while (1) delay(1000);
    }
    
    // Show splash screen
    displayManager.showSplash("ZERO V2", "Initializing...");
    delay(1500);
    
    // Initialize button handler
    buttonHandler.begin();
    
    // Initialize clock module
    if (!clockModule.begin()) {
        Serial.println(F("WARNING: RTC not found, clock disabled"));
    }
    
    // Initialize other modules
    eyesModule.begin(&displayManager);
    beaconModule.begin();
    evilTwinModule.begin(&displayManager);
    deauthModule.begin(&displayManager);
    webAdminModule.begin(&displayManager);
    
    // Initialize menu
    menuManager.begin(&displayManager);
    
    Serial.println(F("Initialization complete!\n"));
    
    // Show menu
    currentMode = MODE_MENU;
    menuManager.show();
}

void loop() {
    // Update button states
    ButtonEvent event = buttonHandler.update();
    
    // Handle mode switching
    if (event == BTN_MODE_LONG_PRESS) {
        // Long press on mode button returns to menu
        if (currentMode != MODE_MENU) {
            // Exit current mode
            exitCurrentMode();
            currentMode = MODE_MENU;
            menuManager.show();
        }
    }
    
    // Handle based on current mode
    switch (currentMode) {
        case MODE_MENU:
            handleMenuMode(event);
            break;
            
        case MODE_CLOCK:
            handleClockMode(event);
            break;
            
        case MODE_EYES:
            handleEyesMode(event);
            break;
            
        case MODE_BEACON:
            handleBeaconMode(event);
            break;
            
        case MODE_EVILTWIN:
            handleEvilTwinMode(event);
            break;
            
        case MODE_DEAUTH:
            handleDeauthMode(event);
            break;
            
        case MODE_WEBADMIN:
            handleWebAdminMode(event);
            break;
    }
    
    delay(10); // Small delay for stability
}

void handleMenuMode(ButtonEvent event) {
    if (event == BTN_UP_PRESS) {
        menuManager.previous();
    } else if (event == BTN_DOWN_PRESS) {
        menuManager.next();
    } else if (event == BTN_SELECT_PRESS) {
        // Enter selected mode
        currentMode = menuManager.getSelectedMode();
        enterCurrentMode();
    }
}

void handleClockMode(ButtonEvent event) {
    clockModule.update();
    
    if (event == BTN_SELECT_LONG_PRESS) {
        // Enter time setting mode
        clockModule.enterSetMode();
    } else if (event == BTN_UP_PRESS || event == BTN_DOWN_PRESS) {
        // Handle time setting if in set mode
        clockModule.handleInput(event);
    }
}

void handleEyesMode(ButtonEvent event) {
    eyesModule.update();
    
    if (event == BTN_UP_PRESS) {
        eyesModule.nextAnimation();
    } else if (event == BTN_DOWN_PRESS) {
        eyesModule.previousAnimation();
    }
}

void handleBeaconMode(ButtonEvent event) {
    beaconModule.update();
    
    if (event == BTN_SELECT_PRESS) {
        beaconModule.toggle();
    } else if (event == BTN_UP_PRESS) {
        beaconModule.increaseRate();
    } else if (event == BTN_DOWN_PRESS) {
        beaconModule.decreaseRate();
    }
}

void handleEvilTwinMode(ButtonEvent event) {
    evilTwinModule.update();
    
    if (event == BTN_SELECT_PRESS) {
        evilTwinModule.toggleAttack();
    } else if (event == BTN_UP_PRESS) {
        evilTwinModule.selectPreviousNetwork();
    } else if (event == BTN_DOWN_PRESS) {
        evilTwinModule.selectNextNetwork();
    } else if (event == BTN_MODE_PRESS) {
        evilTwinModule.rescan();
    }
}

void handleDeauthMode(ButtonEvent event) {
    deauthModule.update();
    
    if (event == BTN_SELECT_PRESS) {
        deauthModule.toggleAttack();
    } else if (event == BTN_UP_PRESS) {
        deauthModule.selectPreviousNetwork();
    } else if (event == BTN_DOWN_PRESS) {
        deauthModule.selectNextNetwork();
    } else if (event == BTN_MODE_PRESS) {
        deauthModule.rescan();
    }
}

void handleWebAdminMode(ButtonEvent event) {
    webAdminModule.update();
    
    if (event == BTN_SELECT_PRESS) {
        webAdminModule.toggleServer();
    }
}

void enterCurrentMode() {
    Serial.print(F("Entering mode: "));
    Serial.println(currentMode);
    
    switch (currentMode) {
        case MODE_CLOCK:
            clockModule.enter();
            break;
        case MODE_EYES:
            eyesModule.enter();
            break;
        case MODE_BEACON:
            beaconModule.enter();
            break;
        case MODE_EVILTWIN:
            evilTwinModule.enter();
            break;
        case MODE_DEAUTH:
            deauthModule.enter();
            break;
        case MODE_WEBADMIN:
            webAdminModule.enter();
            break;
        default:
            break;
    }
}

void exitCurrentMode() {
    Serial.print(F("Exiting mode: "));
    Serial.println(currentMode);
    
    switch (currentMode) {
        case MODE_CLOCK:
            clockModule.exit();
            break;
        case MODE_EYES:
            eyesModule.exit();
            break;
        case MODE_BEACON:
            beaconModule.exit();
            break;
        case MODE_EVILTWIN:
            evilTwinModule.exit();
            break;
        case MODE_DEAUTH:
            deauthModule.exit();
            break;
        case MODE_WEBADMIN:
            webAdminModule.exit();
            break;
        default:
            break;
    }
}
