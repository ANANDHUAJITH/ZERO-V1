#ZERO V1: The Programmable Hacker's Watch
 

Table of Contents
Introduction
Features
Hardware Components
Getting Started
Installation
Usage
Contributing
License
Introduction
ZERO V1 is a versatile, programmable hacker's watch based on the ESP8266 chip. It combines functionality with compactness, fitting into a wristwatch case like that of a G-Shock. With five distinct modes, ZERO V1 offers both practical and experimental uses, ranging from a real-time clock to advanced WiFi attacks.

Features
RTC OLED Clock: A real-time clock with an awesome UI.
Deauthentication Attack: Disrupts the WiFi connectivity of nearby devices.
WiFi Beacon Attack: Creates multiple fake WiFi networks.
Evil Twin Attack: Sets up a fake WiFi access point with a web portal to capture credentials.
Animated Display: Shows a pair of eyes blinking and changing expressions.
Hardware Components
ESP8266 Chip
0.91" I2C OLED Display
RTC Module
1117 3.3V Voltage Regulator
Battery
Push Buttons
Wristwatch Case (e.g., G-Shock)
Getting Started
Prerequisites
Arduino IDE installed on your computer.
ESP8266 board package installed in Arduino IDE.
Basic soldering skills for assembling the hardware.
Hardware Assembly
Solder the ESP8266 chip to a PCB or use a breakout board.
Connect the 0.91" I2C OLED display to the ESP8266.
Integrate the RTC module for timekeeping functionality.
Add the 1117 3.3V voltage regulator to ensure stable power supply.
Connect the push buttons for mode switching.
Fit the assembled circuit inside the wristwatch case.
Power the circuit with a suitable battery.
Installation
Clone this repository:
sh
Copy code
git clone https://github.com/ANANDHUAJITH/ZERO-V1.git
Open the project in Arduino IDE.
Select the correct board and port from the Tools menu.
Upload the code to the ESP8266.
Usage
Power on the ZERO V1.
Use the push buttons to switch between the different modes:
Mode 1: RTC OLED Clock
Mode 2: Deauthentication Attack
Mode 3: WiFi Beacon Attack
Mode 4: Evil Twin Attack with Web Portal
Mode 5: Animated Display of Blinking Eyes
Explore each mode and its functionalities.
Contributing
Contributions are welcome! Please follow these steps:

Fork this repository.
Create a new branch (git checkout -b feature-xyz).
Commit your changes (git commit -m 'Add feature').
Push to the branch (git push origin feature-xyz).
Open a pull request.
License
This project is licensed under the MIT License. See the LICENSE file for details.
