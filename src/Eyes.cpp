/**
 * Eyes.cpp - Animated eyes implementation
 */

#include "Eyes.h"

EyesModule::EyesModule() 
    : display(nullptr), currentAnimation(0), lastUpdate(0) {
    leftEyeX = SCREEN_WIDTH / 2 - EYE_WIDTH / 2 - EYE_SPACING / 2;
    leftEyeY = SCREEN_HEIGHT / 2;
    rightEyeX = SCREEN_WIDTH / 2 + EYE_WIDTH / 2 + EYE_SPACING / 2;
    rightEyeY = SCREEN_HEIGHT / 2;
    leftEyeWidth = leftEyeHeight = EYE_WIDTH;
    rightEyeWidth = rightEyeHeight = EYE_HEIGHT;
}

void EyesModule::begin(DisplayManager* disp) {
    display = disp;
}

void EyesModule::enter() {
    centerEyes();
    wakeup();
}

void EyesModule::exit() {
    sleep();
}

void EyesModule::update() {
    if (millis() - lastUpdate < EYES_UPDATE_INTERVAL) return;
    
    switch (currentAnimation % 6) {
        case 0: centerEyes(); break;
        case 1: blink(10); break;
        case 2: blink(20); break;
        case 3: happyEyes(); break;
        case 4: saccade(random(-1, 2), random(-1, 2)); break;
        case 5: moveBigEye(random(0, 2) ? 1 : -1); break;
    }
    
    lastUpdate = millis();
}

void EyesModule::nextAnimation() {
    currentAnimation++;
}

void EyesModule::previousAnimation() {
    currentAnimation = (currentAnimation > 0) ? currentAnimation - 1 : 5;
}

void EyesModule::drawEyes(bool update) {
    if (!display) return;
    
    display->clear();
    Adafruit_SSD1306* d = display->getDisplay();
    
    int x = leftEyeX - leftEyeWidth / 2;
    int y = leftEyeY - leftEyeHeight / 2;
    d->fillRoundRect(x, y, leftEyeWidth, leftEyeHeight, EYE_CORNER_RADIUS, SSD1306_WHITE);
    
    x = rightEyeX - rightEyeWidth / 2;
    y = rightEyeY - rightEyeHeight / 2;
    d->fillRoundRect(x, y, rightEyeWidth, rightEyeHeight, EYE_CORNER_RADIUS, SSD1306_WHITE);
    
    if (update) {
        display->update();
    }
}

void EyesModule::centerEyes() {
    leftEyeHeight = leftEyeWidth = EYE_HEIGHT;
    rightEyeHeight = rightEyeWidth = EYE_WIDTH;
    leftEyeX = SCREEN_WIDTH / 2 - EYE_WIDTH / 2 - EYE_SPACING / 2;
    leftEyeY = SCREEN_HEIGHT / 2;
    rightEyeX = SCREEN_WIDTH / 2 + EYE_WIDTH / 2 + EYE_SPACING / 2;
    rightEyeY = SCREEN_HEIGHT / 2;
    drawEyes(true);
}

void EyesModule::blink(int speed) {
    for (int i = 0; i < 3; i++) {
        leftEyeHeight -= speed;
        rightEyeHeight -= speed;
        drawEyes(true);
        delay(10);
    }
    for (int i = 0; i < 3; i++) {
        leftEyeHeight += speed;
        rightEyeHeight += speed;
        drawEyes(true);
        delay(10);
    }
}

void EyesModule::wakeup() {
    leftEyeHeight = rightEyeHeight = 2;
    drawEyes(true);
    
    for (int h = 2; h <= EYE_HEIGHT; h += 2) {
        leftEyeHeight = rightEyeHeight = h;
        drawEyes(true);
        delay(30);
    }
}

void EyesModule::sleep() {
    for (int h = EYE_HEIGHT; h >= 2; h -= 2) {
        leftEyeHeight = rightEyeHeight = h;
        drawEyes(true);
        delay(30);
    }
}

void EyesModule::happyEyes() {
    centerEyes();
    Adafruit_SSD1306* d = display->getDisplay();
    
    int offset = EYE_HEIGHT / 2;
    for (int i = 0; i < 10; i++) {
        d->fillTriangle(
            leftEyeX - leftEyeWidth / 2 - 1, leftEyeY + offset,
            leftEyeX + leftEyeWidth / 2 + 1, leftEyeY + 5 + offset,
            leftEyeX - leftEyeWidth / 2 - 1, leftEyeY + leftEyeHeight + offset,
            SSD1306_BLACK
        );
        d->fillTriangle(
            rightEyeX + rightEyeWidth / 2 + 1, rightEyeY + offset,
            rightEyeX - rightEyeWidth / 2 - 1, rightEyeY + 5 + offset,
            rightEyeX + rightEyeWidth / 2 + 1, rightEyeY + rightEyeHeight + offset,
            SSD1306_BLACK
        );
        offset -= 2;
        display->update();
        delay(30);
    }
    delay(1000);
}

void EyesModule::saccade(int dirX, int dirY) {
    int moveX = 8;
    int moveY = 6;
    int blink = 8;
    
    for (int i = 0; i < 2; i++) {
        leftEyeX += moveX * dirX;
        rightEyeX += moveX * dirX;
        leftEyeY += moveY * dirY;
        rightEyeY += moveY * dirY;
        leftEyeHeight -= blink;
        rightEyeHeight -= blink;
        drawEyes(true);
        delay(20);
        
        leftEyeHeight += blink;
        rightEyeHeight += blink;
        drawEyes(true);
        delay(20);
    }
    
    delay(300);
    
    for (int i = 0; i < 2; i++) {
        leftEyeX -= moveX * dirX;
        rightEyeX -= moveX * dirX;
        leftEyeY -= moveY * dirY;
        rightEyeY -= moveY * dirY;
        drawEyes(true);
        delay(20);
    }
}

void EyesModule::moveBigEye(int direction) {
    int move = 2;
    int blink = 5;
    int grow = 1;
    
    for (int i = 0; i < 3; i++) {
        leftEyeX += move * direction;
        rightEyeX += move * direction;
        leftEyeHeight -= blink;
        rightEyeHeight -= blink;
        
        if (direction > 0) {
            rightEyeHeight += grow;
            rightEyeWidth += grow;
        } else {
            leftEyeHeight += grow;
            leftEyeWidth += grow;
        }
        
        drawEyes(true);
        delay(30);
    }
    
    delay(500);
    centerEyes();
}
