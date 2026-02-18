/**
 * Config.h - Configuration and constants
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <Arduino.h>

// ========================
// Hardware Configuration
// ========================

// Display pins (I2C)
#define OLED_SDA 4  // GPIO4
#define OLED_SCL 5  // GPIO5
#define OLED_RESET -1
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_ADDRESS 0x3C

// Button pins
#define BTN_UP_PIN 12
#define BTN_DOWN_PIN 14
#define BTN_SELECT_PIN 13
#define BTN_MODE_PIN 16

// Button settings
#define BTN_DEBOUNCE_MS 50
#define BTN_LONG_PRESS_MS 1000

// ========================
// Operating Modes
// ========================

enum OperatingMode {
    MODE_MENU = 0,
    MODE_CLOCK = 1,
    MODE_EYES = 2,
    MODE_BEACON = 3,
    MODE_EVILTWIN = 4,
    MODE_DEAUTH = 5,
    MODE_WEBADMIN = 6
};

// ========================
// Display Settings
// ========================

#define SPLASH_DURATION 2000
#define MENU_ITEMS 6
#define SLEEP_TIMEOUT 300000  // 5 minutes

// ========================
// Clock Settings
// ========================

#define CLOCK_UPDATE_INTERVAL 1000

// ========================
// Eyes Settings
// ========================

#define EYE_HEIGHT 40
#define EYE_WIDTH 40
#define EYE_SPACING 10
#define EYE_CORNER_RADIUS 10
#define EYES_UPDATE_INTERVAL 50

// ========================
// WiFi Attack Settings
// ========================

// Beacon Spam
#define BEACON_MIN_DELAY 1
#define BEACON_MAX_DELAY 100
#define BEACON_DEFAULT_DELAY 10
#define MAX_SSID_LENGTH 32

// Deauth Settings
#define DEAUTH_REASON_CODE 0x01
#define MAX_ACCESS_POINTS 50
#define CHANNEL_SCAN_TIME 1000
#define PACKET_LIMIT 500
#define DEAUTH_CYCLE_TIME 60000

// Evil Twin Settings
#define DNS_PORT 53
#define WEB_SERVER_PORT 80
#define SCAN_INTERVAL 15000
#define DEAUTH_INTERVAL 1000

// ========================
// Web Admin Settings
// ========================

#define WEBADMIN_SSID "ZERO-Admin"
#define WEBADMIN_PASSWORD "zero1234"
#define WEBADMIN_IP IPAddress(192, 168, 4, 1)

// ========================
// Button Events
// ========================

enum ButtonEvent {
    BTN_NONE = 0,
    BTN_UP_PRESS,
    BTN_UP_LONG_PRESS,
    BTN_DOWN_PRESS,
    BTN_DOWN_LONG_PRESS,
    BTN_SELECT_PRESS,
    BTN_SELECT_LONG_PRESS,
    BTN_MODE_PRESS,
    BTN_MODE_LONG_PRESS
};

// ========================
// Menu Items
// ========================

const char* const MENU_ITEMS_TEXT[MENU_ITEMS] PROGMEM = {
    "Clock",
    "Eyes Anim",
    "Beacon Spam",
    "Evil Twin",
    "Deauth",
    "Web Admin"
};

const char* const MENU_ITEMS_DESC[MENU_ITEMS] PROGMEM = {
    "Show time & date",
    "Animated eyes",
    "Fake AP broadcast",
    "WiFi phishing",
    "Disconnect clients",
    "Web interface"
};

// ========================
// Utility Macros
// ========================

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#ifdef DEBUG
    #define DEBUG_PRINT(x) Serial.print(x)
    #define DEBUG_PRINTLN(x) Serial.println(x)
    #define DEBUG_PRINTF(...) Serial.printf(__VA_ARGS__)
#else
    #define DEBUG_PRINT(x)
    #define DEBUG_PRINTLN(x)
    #define DEBUG_PRINTF(...)
#endif

#endif // CONFIG_H
