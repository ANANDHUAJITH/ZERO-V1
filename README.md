# ZERO V2 - WiFi Security Testing Tool

<p align="center">
  <img src="https://img.shields.io/badge/Platform-ESP8266-blue.svg" />
  <img src="https://img.shields.io/badge/Framework-Arduino-00979D.svg" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg" />
  <img src="https://img.shields.io/badge/Version-2.0-orange.svg" />
</p>

A professional-grade ESP8266-based WiFi security testing tool with modular architecture, intuitive menu system, and comprehensive attack capabilities.

## ⚠️ Legal Disclaimer

**THIS TOOL IS FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY**

Using this tool to attack networks you don't own or don't have explicit permission to test is **ILLEGAL** and **UNETHICAL**. The developers assume no liability and are not responsible for any misuse or damage caused by this software.

Always:
- ✅ Test only on your own networks
- ✅ Obtain written permission before testing
- ✅ Understand local laws and regulations
- ❌ Never use on public or unauthorized networks

## 🌟 Features

### Operating Modes

1. **Clock Mode** - Real-time clock with date display
   - 12/24 hour format support
   - DS1307 RTC integration
   - Time setting functionality

2. **Eyes Animation** - Animated robot eyes
   - Multiple animation patterns
   - Blink, saccade, and emotional expressions
   - Smooth OLED rendering

3. **Beacon Spam** - Fake access point broadcasting
   - Adjustable transmission rate
   - Random SSID generation
   - Multi-channel broadcasting

4. **Evil Twin** - WiFi phishing attack
   - Captive portal with authentic interface
   - Password capture capability
   - Automatic deauth coordination

5. **Deauth Attack** - Client disconnection
   - Multi-network targeting
   - Automatic channel hopping
   - Real-time packet counter

6. **Web Admin** - Async web interface
   - Configuration management
   - System status monitoring
   - OTA updates ready

## 🛠️ Hardware Requirements

### Required Components

| Component | Specification | Notes |
|-----------|--------------|-------|
| ESP8266 Board | NodeMCU v2/v3 | 160MHz, 4MB Flash |
| OLED Display | 128x64 SSD1306 | I2C interface |
| RTC Module | DS1307 | With CR2032 battery |
| Buttons | 4x Tactile switches | Pull-up configuration |
| Power | 5V USB or Battery | 500mA minimum |

### Wiring Diagram

```
ESP8266 NodeMCU         Component
─────────────────────────────────────
GPIO4 (D2)      →       OLED SDA
GPIO5 (D1)      →       OLED SCL
GPIO12 (D6)     →       Button UP
GPIO14 (D5)     →       Button DOWN
GPIO13 (D7)     →       Button SELECT
GPIO16 (D0)     →       Button MODE
3.3V            →       OLED VCC, RTC VCC
GND             →       OLED GND, RTC GND, Buttons GND
```

### Button Configuration

All buttons should be wired with internal pull-up resistors (no external resistors needed).

- **UP Button (GPIO12)**: Navigate up in menus
- **DOWN Button (GPIO14)**: Navigate down in menus
- **SELECT Button (GPIO13)**: Confirm selection / Toggle feature
- **MODE Button (GPIO16)**: Return to menu (long press)

## 📥 Installation

### Prerequisites

- [Visual Studio Code](https://code.visualstudio.com/)
- [PlatformIO IDE](https://platformio.org/install/ide?install=vscode)
- Git (optional)

### Setup Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/ANANDHUAJITH/ZERO-V2.git
   cd ZERO-V2
   ```

2. **Open in VS Code**
   ```bash
   code .
   ```

3. **Install dependencies**
   PlatformIO will automatically install all required libraries listed in `platformio.ini`

4. **Configure upload port** (if needed)
   Edit `platformio.ini` and change:
   ```ini
   upload_port = /dev/ttyUSB0  ; Linux/Mac
   ; upload_port = COM3         ; Windows
   ```

5. **Build and upload**
   - Click the PlatformIO icon in VS Code
   - Select "Upload" or press `Ctrl+Alt+U`

6. **Monitor serial output**
   - Select "Serial Monitor" or press `Ctrl+Alt+S`

## 🎮 Usage Guide

### First Boot

1. Device shows "ZERO V2" splash screen
2. Main menu appears with 6 modes
3. Use UP/DOWN buttons to navigate
4. Press SELECT to enter a mode
5. Long press MODE to return to menu

### Menu Navigation

```
┌─────────────────────┐
│ MAIN MENU      1/6  │
├─────────────────────┤
│ > Clock             │
│   Eyes Anim         │
│   Beacon Spam       │
│   Evil Twin         │
└─────────────────────┘
```

### Mode Controls

#### Clock Mode
- **SELECT (long press)**: Enter time setting
- **UP/DOWN**: Adjust selected field
- **SELECT**: Move to next field

#### Eyes Animation
- **UP/DOWN**: Change animation pattern
- Auto-cycles through animations

#### Beacon Spam
- **SELECT**: Start/Stop broadcasting
- **UP**: Increase transmission rate
- **DOWN**: Decrease transmission rate

#### Evil Twin
- **UP/DOWN**: Select target network
- **SELECT**: Start/Stop attack
- **MODE**: Rescan networks

#### Deauth Attack
- **UP/DOWN**: Select target network
- **SELECT**: Start/Stop attack
- **MODE**: Rescan networks

#### Web Admin
- **SELECT**: Start/Stop web server
- Access at: `http://192.168.4.1`
- Default SSID: `ZERO-Admin`
- Default Password: `zero1234`

## 📁 Project Structure

```
ZERO-V2/
├── src/
│   ├── main.cpp              # Main program entry
│   ├── Display.cpp           # Display management
│   ├── Menu.cpp              # Menu system
│   ├── ButtonHandler.cpp     # Input handling
│   ├── Clock.cpp             # Clock module
│   ├── Eyes.cpp              # Eyes animation
│   ├── BeaconSpam.cpp        # Beacon spam module
│   ├── EvilTwin.cpp          # Evil twin module
│   ├── Deauth.cpp            # Deauth module
│   └── WebAdmin.cpp          # Web admin module
├── include/
│   ├── Config.h              # Global configuration
│   ├── Display.h             # Display interface
│   ├── Menu.h                # Menu interface
│   ├── ButtonHandler.h       # Button interface
│   ├── Clock.h               # Clock interface
│   ├── Eyes.h                # Eyes interface
│   ├── BeaconSpam.h          # Beacon interface
│   ├── EvilTwin.h            # Evil twin interface
│   ├── Deauth.h              # Deauth interface
│   └── WebAdmin.h            # Web admin interface
├── platformio.ini            # Build configuration
├── README.md                 # This file
├── LICENSE                   # MIT License
└── .gitignore                # Git ignore rules
```

## 🔧 Configuration

### Compile-Time Options

Edit `include/Config.h` to customize:

```cpp
// Hardware pins
#define BTN_UP_PIN 12
#define BTN_DOWN_PIN 14
#define BTN_SELECT_PIN 13
#define BTN_MODE_PIN 16

// Display settings
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_ADDRESS 0x3C

// Attack parameters
#define MAX_ACCESS_POINTS 50
#define BEACON_DEFAULT_DELAY 10
#define DEAUTH_CYCLE_TIME 60000

// Web admin credentials
#define WEBADMIN_SSID "ZERO-Admin"
#define WEBADMIN_PASSWORD "zero1234"
```

### Debug Mode

Enable debug output by adding to `platformio.ini`:
```ini
build_flags = -D DEBUG
```

View debug messages via serial monitor at 115200 baud.

## 🚀 Advanced Features

### Web Admin API

Access the JSON API for system integration:

```bash
# Get system status
curl http://192.168.4.1/status

# Response
{
  "version": "2.0",
  "uptime": 123456,
  "freeHeap": 45678,
  "chipId": "12345abc",
  "flashSize": 4194304,
  "cpuFreq": 160
}
```

### Customization

#### Adding Custom SSIDs for Beacon Spam

Edit `src/BeaconSpam.cpp`:
```cpp
String customSSIDs[] = {
    "Free WiFi",
    "Hotel Guest",
    "Airport WiFi"
};
```

#### Changing Evil Twin Template

Edit `src/EvilTwin.cpp` in the `handleRoot()` function to customize the captive portal appearance.

## 🐛 Troubleshooting

### Display Not Working

1. Check I2C address with scanner
2. Verify SDA/SCL connections
3. Try different OLED address in Config.h

### Buttons Not Responding

1. Verify GPIO pins are correct
2. Check for shorts in wiring
3. Test buttons with multimeter

### Upload Fails

1. Select correct upload port
2. Press FLASH button during upload
3. Try lower upload speed (115200)

### RTC Loses Time

1. Check CR2032 battery voltage (>2.5V)
2. Verify RTC module connections
3. Reinitialize time after battery replacement

## 📊 Performance

- **Boot Time**: <2 seconds
- **Menu Response**: <50ms
- **Attack Latency**: <10ms
- **Memory Usage**: ~35KB RAM
- **Power Consumption**: ~170mA @ 3.3V

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### Code Style

- Use meaningful variable names
- Comment complex logic
- Follow existing formatting
- Keep functions under 50 lines

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Original ZERO-V1 by ANANDHUAJITH
- ESP8266 Community
- Adafruit for excellent libraries
- WiFi security researchers

## 📞 Support

- **GitHub Issues**: [Report bugs](https://github.com/ANANDHUAJITH/ZERO-V2/issues)
- **Discussions**: [Ask questions](https://github.com/ANANDHUAJITH/ZERO-V2/discussions)
- **Documentation**: [Wiki](https://github.com/ANANDHUAJITH/ZERO-V2/wiki)

## 🔗 Related Projects

- [ESP8266Deauther](https://github.com/SpacehuhnTech/esp8266_deauther)
- [WiFi Pineapple](https://shop.hak5.org/products/wifi-pineapple)
- [Flipper Zero](https://flipperzero.one/)

## 📈 Changelog

### Version 2.0 (Current)
- ✨ Complete rewrite with modular architecture
- 🎨 Modern menu system with icons
- 🌐 Async web server for admin
- 🔧 Improved button handling
- 📱 Better OLED display management
- 🐛 Numerous bug fixes

### Version 1.0
- Initial release
- Basic WiFi attack features
- Monolithic code structure

---

**Made with ❤️ for security education and awareness**

Remember: With great power comes great responsibility. Use ethically!
