# ZERO V2 - Quick Start Guide

## 🚀 Get Started in 5 Minutes

### What You'll Need

- NodeMCU ESP8266 board
- 128x64 OLED display (I2C)
- DS1307 RTC module
- 4 tactile buttons
- USB cable
- Computer with VS Code

### Installation Steps

1. **Download Project**
   - Extract ZERO-V2.tar.gz or use the ZERO-V2 folder

2. **Install Software**
   ```bash
   # Download VS Code
   https://code.visualstudio.com/
   
   # Install PlatformIO extension
   VS Code → Extensions → Search "PlatformIO" → Install
   ```

3. **Wire Hardware**
   ```
   OLED Display:
   VCC → 3.3V
   GND → GND
   SDA → D2 (GPIO4)
   SCL → D1 (GPIO5)
   
   RTC Module:
   VCC → 3.3V
   GND → GND
   SDA → D2 (GPIO4)
   SCL → D1 (GPIO5)
   
   Buttons:
   UP     → D6 (GPIO12) → GND
   DOWN   → D5 (GPIO14) → GND
   SELECT → D7 (GPIO13) → GND
   MODE   → D0 (GPIO16) → GND
   ```

4. **Upload Code**
   ```bash
   # Open project in VS Code
   cd ZERO-V2
   code .
   
   # Wait for PlatformIO to load
   # Click Upload button (→)
   # Or press Ctrl+Alt+U
   ```

5. **Test It!**
   - Display should show "ZERO V2"
   - Main menu appears
   - Press buttons to navigate

## 📋 File Structure

```
ZERO-V2/
├── README.md              # Main documentation
├── SETUP.md               # Detailed setup guide
├── ARCHITECTURE.md        # Technical docs
├── PROJECT_SUMMARY.md     # This summary
├── platformio.ini         # Build configuration
├── include/               # Header files
│   ├── Config.h          # Pin definitions
│   ├── Display.h         # Display manager
│   ├── Menu.h            # Menu system
│   ├── ButtonHandler.h   # Button input
│   ├── Clock.h           # Clock module
│   ├── Eyes.h            # Animation module
│   ├── BeaconSpam.h      # Beacon attack
│   ├── EvilTwin.h        # Evil twin attack
│   ├── Deauth.h          # Deauth attack
│   └── WebAdmin.h        # Web interface
└── src/                   # Implementation files
    ├── main.cpp          # Main program
    ├── Display.cpp       # Display code
    ├── Menu.cpp          # Menu code
    ├── ButtonHandler.cpp # Button code
    ├── Clock.cpp         # Clock code
    ├── Eyes.cpp          # Animation code
    ├── BeaconSpam.cpp    # Beacon code
    ├── EvilTwin.cpp      # Evil twin code
    ├── Deauth.cpp        # Deauth code
    └── WebAdmin.cpp      # Web code
```

## 🎮 Basic Usage

### Menu Navigation
- **UP** - Scroll up in menu
- **DOWN** - Scroll down in menu
- **SELECT** - Enter selected mode
- **MODE** (long press) - Return to menu

### Modes Available

1. **Clock** - Display time and date
   - Long press SELECT to set time
   
2. **Eyes Anim** - Show animated eyes
   - UP/DOWN changes animations
   
3. **Beacon Spam** - Broadcast fake WiFi networks
   - SELECT to start/stop
   - UP/DOWN adjusts speed
   
4. **Evil Twin** - WiFi phishing attack
   - UP/DOWN select network
   - SELECT to start attack
   
5. **Deauth** - Disconnect WiFi clients
   - UP/DOWN select network
   - SELECT to start attack
   
6. **Web Admin** - Web-based control
   - SELECT to start server
   - Connect to "ZERO-Admin" (password: zero1234)
   - Open http://192.168.4.1

## ⚠️ Important Safety Notes

### Legal Warning

**STOP! READ THIS FIRST:**

This tool is for EDUCATIONAL and AUTHORIZED TESTING ONLY!

✅ **Legal Use:**
- Testing YOUR OWN networks
- Authorized penetration testing
- Security research with permission
- Educational demonstrations

❌ **Illegal Use:**
- Attacking public WiFi
- Unauthorized network access
- Interfering with others' networks
- Any use without permission

**Using this tool illegally can result in:**
- Criminal charges
- Heavy fines
- Imprisonment
- Civil lawsuits

### Responsible Usage

Before using ANY attack feature:

1. ✅ Verify you own the network OR
2. ✅ Have written permission from owner AND
3. ✅ Understand local laws AND
4. ✅ Have legitimate security testing purpose

When in doubt, DON'T!

## 🔧 Configuration

### Changing Pin Assignments

Edit `include/Config.h`:

```cpp
// Change button pins
#define BTN_UP_PIN 12      // Currently D6
#define BTN_DOWN_PIN 14    // Currently D5
#define BTN_SELECT_PIN 13  // Currently D7
#define BTN_MODE_PIN 16    // Currently D0
```

### Adjusting Attack Parameters

Edit `include/Config.h`:

```cpp
// Max networks to track
#define MAX_ACCESS_POINTS 50

// Beacon spam speed
#define BEACON_DEFAULT_DELAY 10  // milliseconds

// Deauth timing
#define DEAUTH_CYCLE_TIME 60000  // 1 minute
```

### Web Admin Credentials

Edit `include/Config.h`:

```cpp
#define WEBADMIN_SSID "ZERO-Admin"
#define WEBADMIN_PASSWORD "zero1234"
```

## 🐛 Troubleshooting

### Display Not Working
1. Check I2C address (usually 0x3C)
2. Verify wiring: SDA → D2, SCL → D1
3. Test with I2C scanner

### Buttons Not Responding
1. Check GPIO connections
2. Verify buttons connect to GND
3. Test with multimeter

### Upload Fails
1. Select correct COM port
2. Try pressing FLASH button
3. Lower upload speed to 115200

### RTC Loses Time
1. Check CR2032 battery (>2.5V)
2. Verify connections
3. Set time again after battery change

## 📚 Documentation

### For Users
- **README.md** - Overview and features
- **SETUP.md** - Detailed setup instructions
- **This file** - Quick reference

### For Developers
- **ARCHITECTURE.md** - System design
- **CONTRIBUTING.md** - How to contribute
- **Code comments** - Inline documentation

## 🤝 Getting Help

### Support Channels
1. **GitHub Issues** - Bug reports
2. **GitHub Discussions** - Questions
3. **Serial Monitor** - Debug output

### Before Asking
1. Read documentation
2. Check existing issues
3. Test with hardware
4. Include serial output

## 📈 Next Steps

### After Basic Setup

1. **Test Each Mode** - Verify all features work
2. **Set the Clock** - Configure time and date
3. **Read Documentation** - Understand capabilities
4. **Customize Settings** - Adjust to your needs
5. **Practice Safely** - Test on your own network

### Learning Path

**Beginner:**
1. Clock display
2. Eyes animation
3. Basic navigation

**Intermediate:**
4. Beacon spam (passive)
5. Network scanning
6. Web admin interface

**Advanced:**
7. Deauth attacks
8. Evil twin setup
9. Custom modifications

## 🌟 Features Highlights

### What Makes V2 Better

✨ **Modern UI** - Professional menu system
🎨 **Icons** - Visual menu indicators  
⚡ **Fast** - <50ms response time
🔧 **Modular** - Easy to customize
📱 **Web UI** - Remote access via WiFi
🛡️ **Safe** - Error handling throughout
📚 **Documented** - Comprehensive guides
🔓 **Open Source** - MIT license

### Module Breakdown

- **DisplayManager** (300 lines) - OLED control
- **ButtonHandler** (150 lines) - Input processing
- **MenuManager** (200 lines) - Navigation
- **ClockModule** (250 lines) - RTC display
- **EyesModule** (300 lines) - Animations
- **BeaconSpam** (150 lines) - Fake APs
- **EvilTwin** (400 lines) - Phishing
- **Deauth** (300 lines) - Disconnection
- **WebAdmin** (250 lines) - Web interface

Total: ~2500 lines of organized, documented code!

## 📞 Contact

- **Project**: ZERO V2
- **Author**: ANANDHUAJITH
- **GitHub**: https://github.com/ANANDHUAJITH/ZERO-V2
- **License**: MIT

## 🎯 Project Goals

1. ✅ Production-ready code
2. ✅ Modular architecture
3. ✅ Comprehensive docs
4. ✅ Ethical usage emphasis
5. ✅ Easy customization
6. ✅ Professional UI
7. ✅ Community friendly

---

**Remember: Great power, great responsibility!**

Use this tool to learn, teach, and improve security. Never to harm, harass, or break laws.

Happy ethical hacking! 🔐
