# Fantech Aria XD7 - Linux Setup

## Prerequisites

```sh
pip install hid
```

### udev rule (for non-root access)

Create `/etc/udev/rules.d/99-fantech-aria.rules`:

```
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="25a7", ATTRS{idProduct}=="fa7c", MODE="0660", TAG+="uaccess"
```

Then reload:

```sh
sudo udevadm control --reload-rules && sudo udevadm trigger
```

## Configuration

### DPI

```sh
# Set DPI to 800 (slot 0)
python3 fantech_aria.py dpi 800

# Set DPI to 1600 on slot 2
python3 fantech_aria.py dpi 1600 --slot 2
```

### Side buttons

```sh
# Back button → Super+Tab (next workspace)
python3 fantech_aria.py button 3 --key super+tab

# Forward button → Super+Shift+Tab (previous workspace)
python3 fantech_aria.py button 4 --key super+shift+tab
```

### Button index reference

| Index | Default function |
|-------|-----------------|
| 0     | Left click      |
| 1     | Right click     |
| 2     | Middle click    |
| 3     | Back            |
| 4     | Forward         |

### Supported key names

Single keys: `a`-`z`, `0`-`9`, `tab`, `enter`, `esc`, `space`, `backspace`, `delete`, `insert`, `home`, `end`, `pageup`, `pagedown`, `up`, `down`, `left`, `right`, `f1`-`f12`, `printscreen`, `scrolllock`, `pause`, `minus`, `equal`, `lbracket`, `rbracket`, `backslash`, `semicolon`, `quote`, `grave`, `comma`, `period`, `slash`, `capslock`

Modifiers (combine with `+`): `super`, `shift`, `ctrl`, `alt`, `rshift`, `rctrl`, `ralt`, `rsuper`

### Reset a button to default

```sh
python3 fantech_aria.py button 3 --reset
```
