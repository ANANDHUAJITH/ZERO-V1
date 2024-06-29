# ZERO V1: The Programmable Hacker's Watch

![ZERO V1](path_to_image) *(Replace with an actual image of your project)*

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Hardware Components](#hardware-components)
- [Getting Started](#getting-started)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Introduction
ZERO V1 is a versatile, programmable hacker's watch based on the ESP8266 chip. It combines functionality with compactness, fitting into a wristwatch case like that of a G-Shock. With five distinct modes, ZERO V1 offers both practical and experimental uses, ranging from a real-time clock to advanced WiFi attacks.

## Features
1. **RTC OLED Clock**: A real-time clock with an awesome UI.
2. **Deauthentication Attack**: Disrupts the WiFi connectivity of nearby devices.
3. **WiFi Beacon Attack**: Creates multiple fake WiFi networks.
4. **Evil Twin Attack**: Sets up a fake WiFi access point with a web portal to capture credentials.
5. **Animated Display**: Shows a pair of eyes blinking and changing expressions.

## Hardware Components
- **ESP8266 Chip**
- **0.91" I2C OLED Display**
- **RTC Module**
- **1117 3.3V Voltage Regulator**
- **Battery**
- **Push Buttons**
- **Wristwatch Case (e.g., G-Shock)**

## Getting Started
### Prerequisites
- Arduino IDE installed on your computer.
- ESP8266 board package installed in Arduino IDE.
- Basic soldering skills for assembling the hardware.

### Hardware Assembly
1. Solder the ESP8266 chip to a PCB or use a breakout board.
2. Connect the 0.91" I2C OLED display to the ESP8266.
3. Integrate the RTC module for timekeeping functionality.
4. Add the 1117 3.3V voltage regulator to ensure a stable power supply.
5. Connect the push buttons for mode switching.
6. Fit the assembled circuit inside the wristwatch case.
7. Power the circuit with a suitable battery.

## Installation
1. Clone this repository:
    ```sh
   https://github.com/ANANDHUAJITH/ZERO-V1.git
    ```
2. Open the project in Arduino IDE.
3. Select the correct board and port from the Tools menu.
4. Upload the code to the ESP8266.

## Usage
1. Power on the ZERO V1.
2. Use the push buttons to switch between the different modes:
   - **Mode 1**: RTC OLED Clock
   - **Mode 2**: Deauthentication Attack
   - **Mode 3**: WiFi Beacon Attack
   - **Mode 4**: Evil Twin Attack with Web Portal
   - **Mode 5**: Animated Display of Blinking Eyes
3. Explore each mode and its functionalities.

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork this repository.
2. Create a new branch (`git checkout -b feature-xyz`).
3. Commit your changes (`git commit -m 'Add feature'`).
4. Push to the branch (`git push origin feature-xyz`).
5. Open a pull request.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
