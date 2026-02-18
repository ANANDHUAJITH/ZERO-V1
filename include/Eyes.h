/**
 * Eyes.h - Animated eyes module
 */

#ifndef EYES_H
#define EYES_H

#include <Arduino.h>
#include "Config.h"
#include "Display.h"

class EyesModule {
private:
    DisplayManager* display;
    int leftEyeX, leftEyeY, leftEyeWidth, leftEyeHeight;
    int rightEyeX, rightEyeY, rightEyeWidth, rightEyeHeight;
    int currentAnimation;
    unsigned long lastUpdate;
    
public:
    EyesModule();
    void begin(DisplayManager* disp);
    void enter();
    void exit();
    void update();
    void nextAnimation();
    void previousAnimation();
    
private:
    void drawEyes(bool update = true);
    void centerEyes();
    void blink(int speed = 12);
    void wakeup();
    void sleep();
    void happyEyes();
    void saccade(int dirX, int dirY);
    void moveBigEye(int direction);
};

#endif // EYES_H
