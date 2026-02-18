# ZERO V2 - Detailed Setup Guide

## Table of Contents
1. [Hardware Assembly](#hardware-assembly)
2. [Software Installation](#software-installation)
3. [First Boot Configuration](#first-boot-configuration)
4. [Testing Each Mode](#testing-each-mode)
5. [Troubleshooting](#troubleshooting)

## Hardware Assembly

### Required Tools
- Soldering iron and solder
- Wire strippers
- Multimeter (optional but recommended)
- Breadboard (for prototyping)
- Jumper wires

### Step-by-Step Assembly

#### 1. Prepare the ESP8266 NodeMCU

```
NodeMCU v2 Pinout:
         ┌─────────┐
    RST  │1      30│ D0 (GPIO16) → Mode Button
    ADC  │2      29│ D1 (GPIO5)  → OLED SCL
    EN   │3      28│ D2 (GPIO4)  → OLED SDA
    D10  │4      27│ D3
     9V  │5      26│ D4
    GND  │6      25│ 3V3 → OLED VCC, RTC VCC
    VIN  │7      24│ GND → OLED GND, RTC GND
    D9   │8      23│ D5 (GPIO14) → Down Button
    D11  │9      22│ D6 (GPIO12) → Up Button
    CMD  │10     21│ D7 (GPIO13) → Select Button
    SD2  │11     20│ D8
    SD3  │12     19│ RX
    SD1  │13     18│ TX
    SC   │14     17│ GND
    S0   │15     16│ 3V3
         └─────────┘
```

#### 2. Connect the OLED Display (I2C)

```
SSD1306 OLED → ESP8266
──────────────────────
VCC  → 3.3V
GND  → GND
SDA  → D2 (GPIO4)
SCL  → D1 (GPIO5)
```

**Important Notes:**
- Use 3.3V, NOT 5V (will damage display)
- Keep I2C wires short (<15cm) to reduce noise
- Add 4.7kΩ pull-up resistors on SDA/SCL for long wires

#### 3. Connect the RTC Module

```
DS1307 RTC → ESP8266
────────────────────
VCC → 3.3V
GND → GND
SDA → D2 (GPIO4) [shared with OLED]
SCL → D1 (GPIO5) [shared with OLED]
```

**Note:** Both OLED and RTC share the same I2C bus.

#### 4. Connect the Buttons

```
Button Schematic (using internal pull-ups):

Button → GPIO → GND

Each button:
─┐
 │  Button
─┘
 │
 ├───────→ GPIO Pin
 │
GND
```

All buttons connect GPIO to GND when pressed. Internal pull-up resistors are enabled in software.

#### 5. Power Options

**Option A: USB Power (Recommended for Development)**
```
USB Cable → NodeMCU USB Port
```

**Option B: Battery Power**
```
Battery Pack (3.7V LiPo or 5V USB) → VIN Pin
```

**Power Specifications:**
- Minimum: 500mA @ 5V
- Recommended: 1A @ 5V for reliable operation
- Peak current during WiFi TX: ~300mA

### Assembly Tips

1. **Test First:** Use a breadboard before soldering
2. **Check Continuity:** Verify all connections with multimeter
3. **Label Wires:** Use color-coded wires for easier debugging
4. **Secure Components:** Use hot glue or mounting brackets
5. **Add Case:** 3D print or use project box for protection

### PCB Design (Optional)

For a permanent installation, consider designing a custom PCB:

```
Recommended PCB Features:
- ESP-12E/F module socket
- SSD1306 OLED breakout header
- DS1307 RTC IC with crystal
- 4x tactile switches with debounce capacitors
- USB-to-Serial chip (CH340 or CP2102)
- 3.3V regulator (AMS1117-3.3)
- Protection diodes and filtering capacitors
```

## Software Installation

### Method 1: PlatformIO (Recommended)

1. **Install Visual Studio Code**
   - Download from https://code.visualstudio.com/
   - Install for your operating system

2. **Install PlatformIO Extension**
   ```
   VS Code → Extensions (Ctrl+Shift+X) → Search "PlatformIO" → Install
   ```

3. **Clone Repository**
   ```bash
   git clone https://github.com/ANANDHUAJITH/ZERO-V2.git
   cd ZERO-V2
   code .
   ```

4. **Open Project**
   - PlatformIO will detect the project automatically
   - Wait for dependency installation (~5 minutes first time)

5. **Configure Upload Port**
   - Edit `platformio.ini`
   - Windows: `upload_port = COM3` (check Device Manager)
   - Linux: `upload_port = /dev/ttyUSB0` (or ttyACM0)
   - Mac: `upload_port = /dev/cu.usbserial-*`

6. **Build Project**
   - Click PlatformIO icon
   - Select "Build" or press `Ctrl+Alt+B`
   - Wait for compilation (~2 minutes first time)

7. **Upload Firmware**
   - Select "Upload" or press `Ctrl+Alt+U`
   - NodeMCU will auto-reset and upload
   - If upload fails, press FLASH button during upload

8. **Monitor Serial Output**
   - Select "Serial Monitor" or press `Ctrl+Alt+S`
   - Baud rate: 115200
   - You should see boot messages

### Method 2: Arduino IDE

1. **Install Arduino IDE**
   - Download from https://www.arduino.cc/en/software

2. **Add ESP8266 Board Support**
   ```
   File → Preferences → Additional Board Manager URLs
   Add: http://arduino.esp8266.com/stable/package_esp8266com_index.json
   ```

3. **Install Board**
   ```
   Tools → Board → Boards Manager → Search "ESP8266" → Install
   ```

4. **Install Libraries**
   ```
   Tools → Manage Libraries → Search and install:
   - Adafruit GFX Library
   - Adafruit SSD1306
   - RTClib by Adafruit
   - ArduinoJson
   - ESPAsyncWebServer
   - ESPAsyncTCP
   ```

5. **Configure Board**
   ```
   Tools → Board → ESP8266 Boards → NodeMCU 1.0 (ESP-12E Module)
   Tools → Upload Speed → 115200
   Tools → CPU Frequency → 160 MHz
   Tools → Flash Size → 4MB (FS:2MB OTA:~1019KB)
   Tools → Port → [Your COM Port]
   ```

6. **Combine Source Files**
   - Create single .ino file by combining all .cpp files
   - Or use "Sketch → Add File" for each module

7. **Upload**
   - Click Upload button
   - Monitor serial output

## First Boot Configuration

### Initial Boot Sequence

1. **Power On**
   - Connect USB cable
   - Blue LED on NodeMCU should flash

2. **Splash Screen**
   ```
   ╔═══════════════════╗
   ║                   ║
   ║      ZERO V2      ║
   ║   Initializing... ║
   ║                   ║
   ╚═══════════════════╝
   ```

3. **Main Menu Appears**
   ```
   ╔═══════════════════╗
   ║ MAIN MENU    1/6  ║
   ╠═══════════════════╣
   ║ > Clock           ║
   ║   Eyes Anim       ║
   ║   Beacon Spam     ║
   ║   Evil Twin       ║
   ╚═══════════════════╝
   ```

### Set the Clock (First Time)

1. Enter Clock Mode (SELECT on first menu item)
2. Long-press SELECT to enter time setting
3. Use UP/DOWN to adjust current field
4. Press SELECT to move to next field:
   - Hour → Minute → Day → Month → Year
5. Long-press SELECT again to save

### Serial Monitor Initial Output

```
=================================
ZERO V2 - WiFi Security Tool
=================================

Button handler initialized
RTC not running, setting default time
Clock module initialized
Eyes module initialized
Beacon module initialized
Evil Twin module initialized
Deauth module initialized
Web Admin module initialized
Initialization complete!
```

If you see errors, refer to [Troubleshooting](#troubleshooting).

## Testing Each Mode

### 1. Clock Mode Test

**Enter Mode:**
```
Main Menu → UP/DOWN to "Clock" → SELECT
```

**Expected Display:**
```
╔═══════════════════════╗
║ MON        15         ║
║              Jan      ║
║              2024     ║
║                       ║
║ 03:45:30              ║
║          PM           ║
╚═══════════════════════╝
```

**Test Time Setting:**
1. Long-press SELECT
2. Display should show blinking fields
3. Use UP/DOWN to change hour
4. Press SELECT to move to minutes
5. Continue through all fields
6. Long-press SELECT to save

**Serial Output:**
```
Entering time set mode
Time saved
```

### 2. Eyes Animation Test

**Enter Mode:**
```
Main Menu → "Eyes Anim" → SELECT
```

**Expected Behavior:**
- Eyes should appear on screen
- Should blink automatically
- Eyes should move and show expressions
- Press UP/DOWN to change animations

**Animations Cycle:**
1. Center position
2. Slow blink
3. Fast blink
4. Happy eyes
5. Random saccade
6. Big eye movement

### 3. Beacon Spam Test

**Enter Mode:**
```
Main Menu → "Beacon Spam" → SELECT
```

**Test Sequence:**
1. Press SELECT to start
2. Check nearby WiFi devices for "ZERO-XXX" networks
3. Press UP to increase speed (faster SSIDs)
4. Press DOWN to decrease speed
5. Press SELECT to stop

**Serial Output:**
```
Beacon Spam Mode
Beacon spam: ON
Beacon delay: 10ms
```

**Verify:**
- Open phone WiFi settings
- Should see multiple "ZERO-XXX" networks appearing
- Networks should change rapidly

⚠️ **Legal Note:** Only test in authorized environment!

### 4. Evil Twin Test

**⚠️ CRITICAL: Only test on YOUR OWN network with permission!**

**Enter Mode:**
```
Main Menu → "Evil Twin" → SELECT
```

**Test Sequence:**
1. Device scans for networks (wait 5 seconds)
2. Use UP/DOWN to select YOUR network
3. Press SELECT to start Evil Twin
4. Connect phone to cloned network
5. Phone should be redirected to login page
6. Enter test password
7. Check serial monitor for captured password

**Serial Output:**
```
Evil Twin Mode
Found 5 networks
Evil Twin started: YourNetwork

=== PASSWORD CAPTURED ===
SSID: YourNetwork
Password: testpassword123
========================
```

**Important:**
- Use dedicated test network
- Never test on production networks
- Always get written permission

### 5. Deauth Test

**⚠️ CRITICAL: Only test on YOUR OWN network!**

**Enter Mode:**
```
Main Menu → "Deauth" → SELECT
```

**Test Sequence:**
1. Device scans for networks
2. Use UP/DOWN to select YOUR network
3. Press SELECT to start deauth
4. Devices should disconnect from network
5. Press SELECT to stop

**Serial Output:**
```
Deauth Mode
Scanning networks...
Found 8 networks
Deauth: ON
```

**Verify:**
- Connected device should lose connection
- Should reconnect after stopping attack
- Check packet counter increases

### 6. Web Admin Test

**Enter Mode:**
```
Main Menu → "Web Admin" → SELECT
```

**Test Sequence:**
1. Press SELECT to start server
2. Display shows IP address (192.168.4.1)
3. Connect phone to "ZERO-Admin" WiFi (password: zero1234)
4. Open browser to http://192.168.4.1
5. Should see admin panel
6. Test all web interface features

**Expected Display:**
```
╔═══════════════════════╗
║      WEB ADMIN        ║
╠═══════════════════════╣
║ Status: ACTIVE        ║
║ SSID: ZERO-Admin      ║
║ IP: 192.168.4.1       ║
╚═══════════════════════╝
```

**Web Interface Test:**
```bash
# Test API endpoint
curl http://192.168.4.1/status

# Expected response:
{
  "version": "2.0",
  "uptime": 123456,
  "freeHeap": 45678,
  ...
}
```

## Troubleshooting

### Display Issues

**Problem: Blank OLED Screen**

Solution:
```
1. Check power: Multimeter on VCC (should be 3.3V)
2. Test I2C address:
   - Upload I2C scanner sketch
   - Check serial output for address (usually 0x3C)
   - Update Config.h if different
3. Verify connections:
   - SDA to D2 (GPIO4)
   - SCL to D1 (GPIO5)
4. Try different OLED module
```

**Problem: Garbled Display**

Solution:
```
1. Reduce I2C speed in Config.h:
   Wire.begin(OLED_SDA, OLED_SCL);
   Wire.setClock(100000); // Add this line
2. Check for loose connections
3. Add 4.7kΩ pull-up resistors on SDA/SCL
```

### Button Issues

**Problem: Buttons Don't Respond**

Solution:
```
1. Test with multimeter:
   - Measure GPIO voltage: should be 3.3V (pulled high)
   - Press button: should read 0V (pulled to ground)
2. Check button connections:
   - One side to GPIO
   - Other side to GND
3. Test in serial monitor:
   Serial.println(digitalRead(BTN_UP_PIN));
4. Verify pin definitions in Config.h
```

**Problem: False Triggers**

Solution:
```
1. Increase debounce time in Config.h:
   #define BTN_DEBOUNCE_MS 100  // Increase from 50
2. Add hardware debounce:
   - 100nF capacitor across button terminals
3. Check for electrical noise:
   - Keep wires away from power lines
   - Use shielded cable if necessary
```

### RTC Issues

**Problem: Clock Loses Time**

Solution:
```
1. Check battery:
   - CR2032 should measure >2.5V
   - Replace if below 2.5V
2. Verify connections:
   - VCC to 3.3V (NOT 5V!)
   - SDA/SCL properly connected
3. Test RTC:
   rtc.begin();
   if (!rtc.isrunning()) {
     Serial.println("RTC not running!");
   }
```

### WiFi Issues

**Problem: No Networks Found**

Solution:
```
1. Check antenna:
   - ESP8266 has built-in antenna
   - Ensure no metal objects nearby
2. Test WiFi:
   WiFi.mode(WIFI_STA);
   int n = WiFi.scanNetworks();
   Serial.println(n);  // Should be > 0
3. Try different channel
4. Reduce distance to AP
```

**Problem: Attacks Not Working**

Solution:
```
1. Verify promiscuous mode:
   wifi_promiscuous_enable(1);
   // Check return value
2. Check channel:
   - Must match target AP
   - Use WiFi.channel() to verify
3. Monitor serial output:
   - Should see packet sends
   - Check for error messages
4. Increase transmission power:
   WiFi.setOutputPower(20.5);  // Max power
```

### Upload Issues

**Problem: Upload Fails**

Solution:
```
1. Check COM port:
   - Windows: Device Manager
   - Linux: ls /dev/ttyUSB*
   - Mac: ls /dev/cu.*
2. Manual flash mode:
   - Hold FLASH button
   - Press RESET button
   - Release RESET
   - Release FLASH after 2 seconds
   - Try upload
3. Reduce upload speed:
   upload_speed = 115200  // In platformio.ini
4. Check USB cable:
   - Use data cable (not charge-only)
   - Try different USB port
   - Use USB 2.0 port (not 3.0)
```

### Memory Issues

**Problem: Out of Memory Errors**

Solution:
```
1. Check free heap:
   Serial.println(ESP.getFreeHeap());
   // Should be >30000 bytes
2. Reduce buffer sizes in Config.h:
   #define MAX_ACCESS_POINTS 30  // Reduce from 50
3. Disable debug mode:
   // Remove -D DEBUG from build_flags
4. Flash larger firmware partition:
   // In platformio.ini:
   board_build.flash_mode = dio
   board_build.ldscript = eagle.flash.4m2m.ld
```

### Common Error Messages

```
Error: SSD1306 allocation failed
→ Display not connected or wrong I2C address

Error: RTC not found
→ Check RTC connections, battery, I2C address

Error: WiFi scan failed
→ Antenna issue or ESP8266 hardware fault

Error: DNS server start failed
→ Already running or network conflict

Error: Web server cannot bind port
→ Port 80 already in use or memory issue
```

## Getting Help

If you're still experiencing issues:

1. **Check Serial Monitor**
   - Enable debug mode
   - Look for error messages

2. **Verify Hardware**
   - Test each component individually
   - Check all connections with multimeter

3. **Update Firmware**
   - Ensure you have latest code
   - git pull origin main

4. **Ask Community**
   - GitHub Issues: Describe problem in detail
   - Include serial output
   - Provide hardware setup photos

## Next Steps

Once everything is working:
- Customize display messages
- Add your own attack modules
- Design a custom case
- Integrate additional sensors
- Contribute improvements back to project

Happy testing! Remember to always use ethically and legally. 🔒
