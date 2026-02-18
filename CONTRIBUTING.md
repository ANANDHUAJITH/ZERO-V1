# Contributing to ZERO V2

Thank you for your interest in contributing to ZERO V2! This document provides guidelines and instructions for contributing.

## Code of Conduct

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Positive behavior includes:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Unacceptable behavior includes:**
- Illegal activities or encouraging illegal use
- Trolling, insulting/derogatory comments, and personal attacks
- Public or private harassment
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce**
- **Expected vs actual behavior**
- **Hardware setup** (board, display, etc.)
- **Software version** (commit hash or release)
- **Serial output** (if applicable)
- **Photos/screenshots** (if helpful)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. Include:

- **Clear use case**
- **Expected behavior**
- **Why this would be useful**
- **Possible implementation** (optional)

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Test thoroughly**
5. **Commit with clear messages**
   ```bash
   git commit -m "Add amazing feature"
   ```
6. **Push to your fork**
   ```bash
   git push origin feature/amazing-feature
   ```
7. **Open a Pull Request**

## Development Setup

### Prerequisites

- PlatformIO IDE
- ESP8266 hardware
- Git knowledge

### Local Development

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/ZERO-V2.git
cd ZERO-V2

# Create branch
git checkout -b feature/your-feature

# Build and test
pio run
pio run --target upload
pio device monitor
```

## Coding Standards

### C++ Style Guide

```cpp
// Use clear, descriptive names
bool isNetworkConnected();  // Good
bool chk();                 // Bad

// Use const correctness
void displayMessage(const char* message);

// Prefer references over pointers when not null
void updateDisplay(DisplayManager& display);

// Use explicit types
uint8_t channel = 1;        // Good
auto channel = 1;           // Avoid in embedded

// Comment complex logic
// Calculate eye position based on saccade vector
int newX = leftEyeX + (moveDistance * directionX);
```

### File Organization

```
include/
  ModuleName.h          # Header with class declaration
src/
  ModuleName.cpp        # Implementation
```

### Header File Template

```cpp
/**
 * ModuleName.h - Brief description
 */

#ifndef MODULE_NAME_H
#define MODULE_NAME_H

#include <Arduino.h>
#include "Config.h"

class ModuleName {
private:
    // Private members
    int privateVariable;
    
public:
    ModuleName();
    
    // Public methods
    void begin();
    void update();
    
private:
    // Private methods
    void helperFunction();
};

#endif // MODULE_NAME_H
```

### Implementation File Template

```cpp
/**
 * ModuleName.cpp - Implementation
 */

#include "ModuleName.h"

ModuleName::ModuleName() 
    : privateVariable(0) {
    // Constructor
}

void ModuleName::begin() {
    Serial.println(F("Module initialized"));
}

void ModuleName::update() {
    // Main logic
}

void ModuleName::helperFunction() {
    // Helper logic
}
```

### Naming Conventions

- **Classes**: PascalCase (`DisplayManager`)
- **Functions**: camelCase (`updateDisplay`)
- **Variables**: camelCase (`networkCount`)
- **Constants**: UPPER_SNAKE_CASE (`MAX_NETWORKS`)
- **Private members**: prefix with underscore (optional)

### Comments

```cpp
// Single-line for brief explanations
int count = 0;  // Track network count

/* Multi-line for longer explanations
 * This function implements the deauth
 * attack by sending spoofed frames
 */
void sendDeauth() {
    // Implementation
}

/**
 * Doxygen-style for public APIs
 * @param channel WiFi channel (1-14)
 * @return true if successful
 */
bool setChannel(uint8_t channel);
```

## Testing Requirements

### Before Submitting PR

- [ ] Code compiles without warnings
- [ ] All modes tested on hardware
- [ ] No memory leaks (check free heap)
- [ ] Serial output clean (no spam)
- [ ] Display renders correctly
- [ ] Buttons respond as expected
- [ ] Legal warnings present

### Test Checklist

```cpp
// Functional tests
✓ Module initializes correctly
✓ Enters/exits cleanly
✓ Updates without crashes
✓ Handles errors gracefully

// Integration tests
✓ Modes switch properly
✓ Memory usage stable
✓ No interference between modules

// Hardware tests
✓ Display updates smoothly
✓ Buttons debounced correctly
✓ WiFi operations functional
```

## Git Commit Messages

### Format

```
type(scope): subject

body (optional)

footer (optional)
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code formatting (no logic change)
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Build process, dependencies

### Examples

```
feat(beacon): add adjustable transmission rate

Allow users to change beacon spam speed using UP/DOWN buttons.
Helps optimize for different scenarios.

Closes #42
```

```
fix(display): prevent screen tearing during animation

Added double buffering to display manager.
Reduces flicker during rapid updates.
```

```
docs(readme): update wiring diagram

Clarified button connections and added note about pull-ups.
```

## Documentation

### Required Documentation

When adding features, update:

1. **README.md** - User-facing documentation
2. **SETUP.md** - Hardware/software setup
3. **ARCHITECTURE.md** - System design
4. **Code comments** - Inline explanations

### Documentation Style

- Clear and concise
- Include examples
- Add diagrams where helpful
- Assume beginner-friendly audience

## Legal Requirements

### Ethical Use Statement

All contributions must:

1. Include legal warnings
2. Emphasize educational purpose
3. Not encourage illegal use
4. Provide responsible use guidelines

### License Agreement

By contributing, you agree that your contributions will be licensed under the MIT License.

## Review Process

### What Reviewers Look For

1. **Code Quality**
   - Follows style guide
   - Well-commented
   - No obvious bugs

2. **Testing**
   - Hardware tested
   - Edge cases considered
   - Error handling present

3. **Documentation**
   - README updated
   - Comments clear
   - Setup instructions included

4. **Legal Compliance**
   - Warnings present
   - Ethical use emphasized

### Review Workflow

```
PR Opened
   ↓
Automated Checks (build, lint)
   ↓
Code Review (maintainer)
   ↓
Request Changes OR Approve
   ↓
Contributor Updates
   ↓
Final Approval
   ↓
Merge to Main
```

## Getting Help

- **Questions**: Open a Discussion
- **Bugs**: Open an Issue
- **Chat**: Join our community (if available)

## Recognition

Contributors are recognized in:
- README.md Contributors section
- Release notes
- Git commit history

Thank you for contributing to ZERO V2! 🎉
