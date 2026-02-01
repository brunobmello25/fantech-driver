# Fantech Aria XD7 Driver

Linux configuration tool for the Fantech Aria XD7 mouse, reverse-engineered from USB HID captures.

## Setup

```
pip install hid
```

For non-root access, install the udev rule:

```
python3 fantech_aria.py udev-rule
```

## Commands

### DPI

```bash
# Show all 7 DPI slots
python3 fantech_aria.py dpi

# Set slot 0 to 800 DPI
python3 fantech_aria.py dpi 800

# Set a specific slot (0-6)
python3 fantech_aria.py dpi 1600 --slot 2

# Set asymmetric X/Y DPI
python3 fantech_aria.py dpi 800 --dpi-y 400
```

DPI range: 50-26000 in steps of 50.

### Lights

```bash
# Show current LED colors for each DPI slot
python3 fantech_aria.py lights

# Turn off all LEDs
python3 fantech_aria.py lights --off

# Set all slot LEDs to a color (R,G,B 0-255)
python3 fantech_aria.py lights --color 255,0,0

# Set a specific slot's LED
python3 fantech_aria.py lights --color 0,0,255 --slot 2
```

Each DPI slot has its own LED color. Setting a color to `0,0,0` turns that slot's LED off.

### Button Remapping

```bash
# Remap button 3 (back) to a key
python3 fantech_aria.py button 3 --key a

# Remap to a key combo
python3 fantech_aria.py button 3 --key super+tab
python3 fantech_aria.py button 3 --key ctrl+shift+z

# Reset button to default
python3 fantech_aria.py button 3 --reset
```

Button indices: 0=left, 1=right, 2=middle, 3=back, 4=forward. Supports modifier keys: `ctrl`, `shift`, `alt`, `super`.
