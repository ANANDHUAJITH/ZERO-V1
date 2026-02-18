# ZERO V2 - Architecture Documentation

## System Overview

ZERO V2 follows a modular, object-oriented architecture that separates concerns and makes the codebase maintainable and extensible.

```
┌─────────────────────────────────────────────────────────────┐
│                         main.cpp                             │
│                    (Main Controller)                         │
└────────┬─────────────────────────────────────────┬──────────┘
         │                                          │
         ├──────────┬──────────┬──────────┬────────┤
         │          │          │          │        │
    ┌────▼───┐ ┌───▼────┐ ┌───▼────┐ ┌──▼───┐ ┌──▼───┐
    │Display │ │ Button │ │  Menu  │ │Clock │ │ Eyes │
    │Manager │ │Handler │ │Manager │ │Module│ │Module│
    └────────┘ └────────┘ └────────┘ └──────┘ └──────┘
                                         │        │
                                    ┌────▼───┬────▼──────┬─────────┐
                                    │ Beacon │ EvilTwin  │ Deauth  │
                                    │ Spam   │  Module   │ Module  │
                                    └────────┴───────────┴─────────┘
                                         │          │          │
                                    ┌────▼──────────▼──────────▼────┐
                                    │        WiFi Hardware           │
                                    │       (ESP8266 SDK)            │
                                    └────────────────────────────────┘
```

## Module Breakdown

### Core Modules

#### 1. DisplayManager
**Responsibility:** All OLED display operations

```cpp
class DisplayManager {
    - Initialization and power management
    - Drawing primitives (text, shapes, progress bars)
    - Special screens (splash, error, loading)
    - Menu rendering helpers
    - Display update synchronization
}
```

**Key Features:**
- Centralized display control
- Buffered rendering
- Power saving (sleep mode)
- Consistent UI elements

#### 2. ButtonHandler
**Responsibility:** Physical button input processing

```cpp
class ButtonHandler {
    - Debouncing logic
    - Long press detection
    - Multi-button coordination
    - Event generation
}
```

**State Machine:**
```
IDLE → PRESSED → [DEBOUNCE] → CONFIRMED → LONG_PRESS
  ↑                                |
  └────────────────────────────────┘
           RELEASED
```

#### 3. MenuManager
**Responsibility:** Main menu system

```cpp
class MenuManager {
    - Menu navigation (up/down/select)
    - Scroll handling
    - Icon rendering
    - Selection animation
    - Mode launching
}
```

**Menu Structure:**
```
Main Menu
├── Clock Mode
├── Eyes Animation
├── Beacon Spam
├── Evil Twin
├── Deauth Attack
└── Web Admin
```

### Operating Mode Modules

#### 4. ClockModule
**Purpose:** RTC-based clock display

```cpp
class ClockModule {
    - Real-time clock reading (DS1307)
    - 12/24 hour format conversion
    - Time/date rendering
    - Interactive time setting
}
```

**Features:**
- Persistent time keeping
- User-friendly time adjustment
- Multiple display formats

#### 5. EyesModule
**Purpose:** Animated robot eyes

```cpp
class EyesModule {
    - Eye position management
    - Animation sequences
    - Emotional expressions
    - Movement calculations
}
```

**Animation Types:**
- Blink (various speeds)
- Saccade (quick movements)
- Happy expression
- Big eye effect
- Random movements

#### 6. BeaconSpamModule
**Purpose:** Fake access point broadcasting

```cpp
class BeaconSpamModule {
    - Beacon frame generation
    - Random SSID creation
    - Channel hopping
    - Transmission rate control
}
```

**Packet Structure:**
```
[MAC Header | Frame Control | Beacon Interval | 
 Capability | SSID | Supported Rates | Channel]
```

#### 7. EvilTwinModule
**Purpose:** WiFi phishing attack

```cpp
class EvilTwinModule {
    - Network scanning
    - Rogue AP creation
    - DNS spoofing
    - Captive portal
    - Password capture
    - Coordinated deauth
}
```

**Attack Flow:**
```
1. Scan for target network
2. Create identical SSID
3. Start DNS server
4. Launch web server
5. Deauth legitimate clients
6. Capture credentials
7. Validate password
```

#### 8. DeauthModule
**Purpose:** Client disconnection attack

```cpp
class DeauthModule {
    - Network discovery
    - Channel monitoring
    - Deauth frame injection
    - Multi-target support
}
```

**Deauth Packet:**
```
Type: Management (0xC0)
Subtype: Deauthentication (0x0C)
Reason Code: Unspecified (0x01)
```

#### 9. WebAdminModule
**Purpose:** HTTP-based administration

```cpp
class WebAdminModule {
    - Async web server
    - REST API endpoints
    - Configuration interface
    - Status monitoring
    - OTA updates (future)
}
```

**API Endpoints:**
```
GET  /           → Dashboard
GET  /status     → System status JSON
GET  /config     → Configuration page
POST /save-config → Save settings
GET  /restart    → Reboot device
```

## Data Flow

### Button Event Flow

```
[Physical Button Press]
         ↓
   [ButtonHandler]
    ├─ Debounce
    ├─ Detect long press
    └─ Generate event
         ↓
     [main.cpp]
    ├─ Route to current mode
    └─ Call handler function
         ↓
   [Mode Module]
    ├─ Process event
    ├─ Update state
    └─ Request display update
         ↓
  [DisplayManager]
    └─ Render to OLED
```

### Display Update Flow

```
[Module needs to update display]
         ↓
   [DisplayManager.clear()]
         ↓
   [Draw operations]
    ├─ drawText()
    ├─ drawFrame()
    └─ custom drawing
         ↓
   [DisplayManager.update()]
         ↓
   [Hardware display refresh]
```

### WiFi Attack Flow

```
[User activates attack]
         ↓
   [Attack Module]
    ├─ Initialize WiFi hardware
    ├─ Set channel
    ├─ Enable promiscuous mode
    └─ Start packet injection
         ↓
   [ESP8266 SDK]
    └─ wifi_send_pkt_freedom()
         ↓
   [Hardware transmission]
```

## Memory Management

### Static Allocation

All major data structures use static allocation to avoid heap fragmentation:

```cpp
// Fixed-size arrays
AccessPoint networks[MAX_ACCESS_POINTS];
NetworkTarget targets[16];

// Pre-allocated buffers
uint8_t packet[128];
char textBuffer[64];
```

### Dynamic Allocation (Minimal)

Only used where necessary:

```cpp
// Web server instances (single allocation at startup)
AsyncWebServer* server;
DNSServer* dnsServer;

// Display instance (single allocation at startup)
Adafruit_SSD1306* display;
```

### Memory Layout

```
┌─────────────────────────────────────┐ 0x3FFFFFFF
│         Stack (grows down)          │
├─────────────────────────────────────┤
│              Heap                   │
├─────────────────────────────────────┤
│         Global/Static Data          │
│   - Module instances               │
│   - Network arrays                  │
│   - Packet buffers                  │
├─────────────────────────────────────┤
│         Program Code (.text)        │
└─────────────────────────────────────┘ 0x40100000
```

## Timing and Scheduling

### Main Loop Architecture

```cpp
void loop() {
    // 1. Handle input (fast, <1ms)
    ButtonEvent event = buttonHandler.update();
    
    // 2. Route to mode handler (fast, <1ms)
    switch(currentMode) {
        case MODE_CLOCK: handleClockMode(event); break;
        // ... other modes
    }
    
    // 3. Mode update (varies by mode)
    // Clock: 1000ms interval
    // Eyes: 50ms interval
    // Attacks: 1-1000ms interval
    
    // 4. Small delay for stability
    delay(10);
}
```

### Timing Constraints

| Operation | Target | Max | Notes |
|-----------|--------|-----|-------|
| Button polling | <1ms | 5ms | Must be responsive |
| Display update | 16ms | 50ms | 20+ FPS for smooth animation |
| WiFi packet | <10ms | 100ms | Attack effectiveness |
| Menu response | <50ms | 100ms | User experience |

## Configuration System

### Compile-Time Configuration

All in `Config.h`:

```cpp
// Hardware pins
#define BTN_UP_PIN 12
#define OLED_ADDRESS 0x3C

// Feature limits
#define MAX_ACCESS_POINTS 50

// Timing
#define BEACON_DEFAULT_DELAY 10
```

### Runtime Configuration

Stored in module state:

```cpp
class BeaconSpamModule {
    int delayTime;        // Adjustable at runtime
    bool active;          // Toggle state
};
```

### Future: EEPROM Configuration

```cpp
struct Config {
    char deviceName[32];
    uint8_t defaultMode;
    uint32_t sleepTimeout;
    // ... more settings
};

void saveConfig() {
    EEPROM.put(0, config);
    EEPROM.commit();
}
```

## Error Handling

### Strategy

1. **Initialization Errors** - Fail gracefully with error screen
2. **Runtime Errors** - Log and continue
3. **Critical Errors** - Reset device

### Example:

```cpp
bool ClockModule::begin() {
    if (!rtc.begin()) {
        Serial.println(F("RTC not found!"));
        display->showError("RTC Error");
        return false;  // Non-fatal, continue without clock
    }
    return true;
}
```

## Extension Points

### Adding New Mode

1. Create header in `include/`
2. Create implementation in `src/`
3. Add to `Config.h` enum:
   ```cpp
   enum OperatingMode {
       MODE_MENU = 0,
       // ... existing modes
       MODE_YOUR_NEW_MODE = 7
   };
   ```
4. Update menu in `main.cpp`
5. Add handler functions

### Adding New Attack

1. Extend appropriate module (Deauth, EvilTwin, etc.)
2. Add packet template
3. Implement transmission logic
4. Add UI controls
5. Test thoroughly!

## Performance Optimization

### Critical Paths

Optimized for minimal latency:

```cpp
// Fast button reading
inline bool isButtonPressed(uint8_t pin) {
    return digitalRead(pin) == LOW;
}

// Efficient display updates
display->clear();
// ... draw operations ...
display->update();  // Single SPI transaction
```

### Memory Optimization

```cpp
// Use PROGMEM for constants
const char MENU_TEXT[] PROGMEM = "Menu Item";

// Reuse buffers
char sharedBuffer[64];  // Single buffer for temporary strings
```

## Security Considerations

### What ZERO V2 Does NOT Do

- ❌ Encrypt captured passwords
- ❌ Implement WPA2 cracking
- ❌ Store credentials permanently
- ❌ Provide remote access

### Safety Features

- ⚠️ Clear warnings in UI
- 📝 Educational messages
- 🔒 No credential storage
- 🚫 Requires physical access

## Testing Strategy

### Unit Testing

Each module should be testable independently:

```cpp
void testButtonHandler() {
    ButtonHandler handler;
    handler.begin();
    
    // Simulate button press
    // Verify event generation
}
```

### Integration Testing

Test mode transitions:

```cpp
void testModeSwitch() {
    enterMode(MODE_CLOCK);
    delay(1000);
    exitMode();
    // Verify clean state
}
```

### Hardware Testing

Checklist:
- [ ] All buttons responsive
- [ ] Display clear and stable
- [ ] RTC keeps time
- [ ] WiFi attacks function
- [ ] Web server accessible

## Future Enhancements

### Planned Features

1. **SD Card Logging**
   - Attack logs
   - Captured credentials
   - System events

2. **Bluetooth Support**
   - BLE scanning
   - Classic Bluetooth attacks

3. **GPS Module**
   - Wardriving
   - Location-based attacks

4. **Battery Management**
   - Charge monitoring
   - Power saving modes

5. **OTA Updates**
   - Web-based firmware updates
   - Version checking

### Architecture Changes

```
Current:
[Module] → [WiFi] → [Hardware]

Proposed:
[Module] → [Attack Manager] → [WiFi/BLE/GPS] → [Hardware]
                ↓
          [Logger] → [SD Card]
```

## Conclusion

ZERO V2's architecture provides:
- ✅ Clean separation of concerns
- ✅ Easy testing and debugging
- ✅ Simple extension mechanism
- ✅ Efficient resource usage
- ✅ Maintainable codebase

The modular design ensures that adding new features or fixing bugs in one module doesn't affect others, making the project sustainable for long-term development.
