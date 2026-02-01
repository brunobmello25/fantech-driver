#!/usr/bin/env python3
"""
Fantech Aria XD7 Linux Configuration Tool

Reverse-engineered protocol for configuring DPI, polling rate, debounce,
and other settings on the Fantech Aria XD7 mouse via USB HID.

Protocol summary:
  - Communication via HID SET_REPORT (report ID 0x08) on interface 1
  - Responses come as interrupt IN (report ID 0x09) on endpoint 0x82
  - All packets are 17 bytes: [report_id, command, 0x00, bank, offset, size, data..., checksum]
  - Checksum: sum of all 17 bytes ≡ 0x55 (mod 256)
  - Command 0x07 = write config memory
  - Command 0x08 = read config memory
  - Command 0x03 = status query (poll until ready)

Requires: pip install hid
Requires udev rule for non-root access (see --udev-rule)
"""

import argparse
import sys
import time

try:
    import hid
except ImportError:
    print("Error: 'hid' package not installed. Run: pip install hid", file=sys.stderr)
    sys.exit(1)

VENDOR_ID = 0x25A7
PRODUCT_ID = 0xFA7C

CHECKSUM_MAGIC = 0x55

# Config memory layout (bank 0)
OFFSET_POLLING_RATE = 0x00
OFFSET_DPI_BASE = 0x0C  # 7 slots, 4 bytes each
OFFSET_BUTTON_CONFIG = 0x60  # 4 bytes per button, 11 buttons
OFFSET_LOD = 0xA0
OFFSET_ANGLE_SNAP = 0xA9
OFFSET_DEBOUNCE = 0xB5

# Button config (bank 1) — action data at 0x20-byte intervals
BUTTON_ACTION_BANK = 1
BUTTON_ACTION_STRIDE = 0x20
BUTTON_COUNT = 11

# Button types
BUTTON_TYPE_MOUSE = 0x01
BUTTON_TYPE_KEYBOARD = 0x05

DPI_SLOT_COUNT = 7
DPI_SLOT_SIZE = 4
DPI_STEP = 50
DPI_MIN = 50
DPI_MAX = 26000

# HID key names → HID usage codes
KEY_NAMES = {
    "a": 0x04, "b": 0x05, "c": 0x06, "d": 0x07, "e": 0x08, "f": 0x09,
    "g": 0x0A, "h": 0x0B, "i": 0x0C, "j": 0x0D, "k": 0x0E, "l": 0x0F,
    "m": 0x10, "n": 0x11, "o": 0x12, "p": 0x13, "q": 0x14, "r": 0x15,
    "s": 0x16, "t": 0x17, "u": 0x18, "v": 0x19, "w": 0x1A, "x": 0x1B,
    "y": 0x1C, "z": 0x1D,
    "1": 0x1E, "2": 0x1F, "3": 0x20, "4": 0x21, "5": 0x22,
    "6": 0x23, "7": 0x24, "8": 0x25, "9": 0x26, "0": 0x27,
    "enter": 0x28, "esc": 0x29, "backspace": 0x2A, "tab": 0x2B,
    "space": 0x2C, "minus": 0x2D, "equal": 0x2E, "lbracket": 0x2F,
    "rbracket": 0x30, "backslash": 0x31, "semicolon": 0x33, "quote": 0x34,
    "grave": 0x35, "comma": 0x36, "period": 0x37, "slash": 0x38,
    "capslock": 0x39, "printscreen": 0x46, "scrolllock": 0x47, "pause": 0x48,
    "insert": 0x49, "home": 0x4A, "pageup": 0x4B, "delete": 0x4C,
    "end": 0x4D, "pagedown": 0x4E, "right": 0x4F, "left": 0x50,
    "down": 0x51, "up": 0x52,
    "f1": 0x3A, "f2": 0x3B, "f3": 0x3C, "f4": 0x3D, "f5": 0x3E,
    "f6": 0x3F, "f7": 0x40, "f8": 0x41, "f9": 0x42, "f10": 0x43,
    "f11": 0x44, "f12": 0x45,
}

# Modifier key names → HID usage codes (0xE0-0xE7)
MODIFIER_NAMES = {
    "ctrl": 0xE0, "lctrl": 0xE0, "rctrl": 0xE4,
    "shift": 0xE1, "lshift": 0xE1, "rshift": 0xE5,
    "alt": 0xE2, "lalt": 0xE2, "ralt": 0xE6,
    "super": 0xE3, "gui": 0xE3, "lsuper": 0xE3, "lgui": 0xE3,
    "rsuper": 0xE7, "rgui": 0xE7,
}


def parse_key_combo(combo_str: str) -> tuple[list[int], int]:
    """Parse a key combo string like 'super+shift+tab' into (modifiers, keycode).

    Returns (modifier_keycodes, main_keycode) where modifier_keycodes are
    HID usage codes for modifier keys (0xE0-0xE7).
    """
    parts = [p.strip().lower() for p in combo_str.split("+")]
    modifiers = []
    key = None

    for part in parts:
        if part in MODIFIER_NAMES:
            modifiers.append(MODIFIER_NAMES[part])
        elif part in KEY_NAMES:
            if key is not None:
                raise ValueError(
                    f"Multiple non-modifier keys in combo: '{combo_str}'")
            key = KEY_NAMES[part]
        else:
            raise ValueError(
                f"Unknown key '{part}'. Available keys: "
                f"{', '.join(sorted(set(list(KEY_NAMES) + list(MODIFIER_NAMES))))}")

    if key is None:
        raise ValueError(f"No main key in combo '{combo_str}' (only modifiers)")

    return modifiers, key


def checksum(data: bytes) -> int:
    """Calculate checksum byte so that sum of all bytes ≡ 0x55 (mod 256)."""
    return (CHECKSUM_MAGIC - sum(data)) & 0xFF


def encode_dpi(dpi_x: int, dpi_y: int | None = None) -> bytes:
    """Encode DPI value(s) into the 4-byte wire format.

    Format: [x_low, y_low, high_bits, check]
    Where reg = DPI/50 - 1, x_low = reg & 0xFF, high_bits encodes bits 9:8.
    """
    if dpi_y is None:
        dpi_y = dpi_x

    for label, val in [("X", dpi_x), ("Y", dpi_y)]:
        if val < DPI_MIN or val > DPI_MAX or val % DPI_STEP != 0:
            raise ValueError(
                f"DPI {label}={val} invalid. Must be {DPI_MIN}-{DPI_MAX} in steps of {DPI_STEP}."
            )

    reg_x = dpi_x // DPI_STEP - 1
    reg_y = dpi_y // DPI_STEP - 1

    x_low = reg_x & 0xFF
    y_low = reg_y & 0xFF
    high_bits = (((reg_y >> 8) & 0x03) << 6) | (((reg_x >> 8) & 0x03) << 2)
    chk = (CHECKSUM_MAGIC - x_low - y_low - high_bits) & 0xFF

    return bytes([x_low, y_low, high_bits, chk])


def decode_dpi(data: bytes) -> tuple[int, int]:
    """Decode 4-byte DPI data into (dpi_x, dpi_y)."""
    x_low, y_low, high_bits, _ = data[0], data[1], data[2], data[3]
    x_high = (high_bits >> 2) & 0x03
    y_high = (high_bits >> 6) & 0x03
    dpi_x = (((x_high << 8) | x_low) + 1) * DPI_STEP
    dpi_y = (((y_high << 8) | y_low) + 1) * DPI_STEP
    return dpi_x, dpi_y


def encode_polling_rate(hz: int) -> bytes:
    """Encode polling rate into 2-byte wire format."""
    valid = {125: 8, 250: 4, 500: 2, 1000: 1}
    if hz not in valid:
        raise ValueError(
            f"Polling rate {hz} invalid. Must be one of: {list(valid.keys())}")
    val = valid[hz]
    return bytes([val, (CHECKSUM_MAGIC - val) & 0xFF])


def decode_polling_rate(data: bytes) -> int:
    """Decode 2-byte polling rate data into Hz."""
    val = data[0]
    if val == 0:
        return 0
    return 1000 // val


def encode_debounce(ms: int) -> bytes:
    """Encode debounce time into 2-byte wire format."""
    if ms < 0 or ms > 50:
        raise ValueError(f"Debounce {ms}ms invalid. Must be 0-50.")
    return bytes([ms, (CHECKSUM_MAGIC - ms) & 0xFF])


def decode_debounce(data: bytes) -> int:
    """Decode 2-byte debounce data into ms."""
    return data[0]


def find_config_path() -> bytes:
    """Auto-detect the HID path for the config interface (interface 1)."""
    for dev in hid.enumerate(VENDOR_ID, PRODUCT_ID):
        if dev["interface_number"] == 1:
            return dev["path"]
    raise RuntimeError(
        "Fantech Aria XD7 not found. Is the mouse connected via USB?"
    )


class FantechAria:
    """Driver for Fantech Aria XD7 mouse configuration."""

    def __init__(self, path: bytes | None = None):
        self.device = hid.Device(
            VENDOR_ID, PRODUCT_ID, path=path or find_config_path())
        self.device.nonblocking = True

    def close(self):
        self.device.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _build_packet(self, command: int, bank: int, offset: int, size: int,
                      data: bytes = b"") -> bytes:
        """Build a 17-byte command packet."""
        packet = bytearray(17)
        packet[0] = 0x08  # report ID
        packet[1] = command
        packet[2] = 0x00
        packet[3] = bank
        packet[4] = offset
        packet[5] = size
        for i, b in enumerate(data):
            packet[6 + i] = b
        packet[16] = checksum(packet[:16])
        return bytes(packet)

    def _send(self, packet: bytes) -> bytes | None:
        """Send a SET_REPORT and wait for the interrupt response."""
        self.device.send_feature_report(packet)
        # Read response (report ID 0x09)
        # Some HID backends prepend the report ID, others don't.
        for _ in range(50):
            resp = self.device.read(64)
            if not resp:
                time.sleep(0.01)
                continue
            # Find the report ID 0x09 — it may be at index 0
            if len(resp) >= 17 and resp[0] == 0x09:
                return bytes(resp[:17])
            time.sleep(0.01)
        return None

    def _poll_ready(self) -> bool:
        """Send status query (cmd 0x03) and wait until device is ready."""
        packet = self._build_packet(0x03, 0, 0, 0)
        for _ in range(20):
            resp = self._send(packet)
            if resp and resp[5] == 0x01:
                return True
            time.sleep(0.05)
        return False

    def _write_config(self, bank: int, offset: int, data: bytes) -> bytes | None:
        """Write data to config memory."""
        packet = self._build_packet(0x07, bank, offset, len(data), data)
        return self._send(packet)

    def _read_config(self, bank: int, offset: int, size: int) -> bytes | None:
        """Read data from config memory."""
        packet = self._build_packet(0x08, bank, offset, size)
        resp = self._send(packet)
        if resp:
            return bytes(resp[6:6 + size])
        return None

    def _save(self) -> bytes | None:
        """Send SAVE command (0x04) to persist config to flash."""
        packet = self._build_packet(0x04, 0, 0, 0)
        return self._send(packet)

    def _apply(self, bank: int = 0, flag: int = 0x00) -> bytes | None:
        """Send APPLY command (0x02) with a flag byte.

        flag=0x00: activate changes, flag=0x01: signal intent.
        """
        packet = self._build_packet(0x02, bank, 0, 1, bytes([flag]))
        return self._send(packet)

    # ---- Public API ----

    def get_dpi_all(self) -> list[tuple[int, int]]:
        """Read all 7 DPI slots. Returns list of (dpi_x, dpi_y) tuples."""
        self._poll_ready()
        result = []
        for slot in range(DPI_SLOT_COUNT):
            offset = OFFSET_DPI_BASE + slot * DPI_SLOT_SIZE
            data = self._read_config(0, offset, DPI_SLOT_SIZE)
            if data and len(data) >= 4:
                result.append(decode_dpi(data))
            else:
                result.append((0, 0))
        return result

    def set_dpi(self, slot: int, dpi: int, dpi_y: int | None = None):
        """Set DPI for a specific slot (0-6)."""
        if slot < 0 or slot >= DPI_SLOT_COUNT:
            raise ValueError(f"Slot must be 0-{DPI_SLOT_COUNT - 1}")
        self._poll_ready()
        data = encode_dpi(dpi, dpi_y)
        offset = OFFSET_DPI_BASE + slot * DPI_SLOT_SIZE
        resp = self._write_config(0, offset, data)
        if not resp:
            raise IOError("No response from device")
        self._save()

    def get_polling_rate(self) -> int:
        """Read current polling rate in Hz."""
        self._poll_ready()
        data = self._read_config(0, OFFSET_POLLING_RATE, 2)
        if data:
            return decode_polling_rate(data)
        return 0

    def set_polling_rate(self, hz: int):
        """Set polling rate (125, 250, 500, or 1000 Hz)."""
        self._poll_ready()
        data = encode_polling_rate(hz)
        resp = self._write_config(0, OFFSET_POLLING_RATE, data)
        if not resp:
            raise IOError("No response from device")
        self._save()

    def get_debounce(self) -> int:
        """Read current debounce time in ms."""
        self._poll_ready()
        data = self._read_config(0, OFFSET_DEBOUNCE, 2)
        if data:
            return decode_debounce(data)
        return 0

    def set_debounce(self, ms: int):
        """Set debounce time in ms."""
        self._poll_ready()
        data = encode_debounce(ms)
        resp = self._write_config(0, OFFSET_DEBOUNCE, data)
        if not resp:
            raise IOError("No response from device")
        self._save()

    def get_angle_snap(self) -> int:
        """Read current angle snapping value."""
        self._poll_ready()
        data = self._read_config(0, OFFSET_ANGLE_SNAP, 2)
        if data:
            return data[0]
        return 0

    def set_angle_snap(self, value: int):
        """Set angle snapping value (0-255)."""
        if value < 0 or value > 255:
            raise ValueError(
                f"Angle snap value {value} invalid. Must be 0-255.")
        self._poll_ready()
        data = bytes([value, (CHECKSUM_MAGIC - value) & 0xFF])
        resp = self._write_config(0, OFFSET_ANGLE_SNAP, data)
        if not resp:
            raise IOError("No response from device")
        self._save()

    def get_lod(self) -> int:
        """Read current lift-off distance value."""
        self._poll_ready()
        data = self._read_config(0, OFFSET_LOD, 2)
        if data:
            return data[0]
        return 0

    def set_lod(self, value: int):
        """Set lift-off distance (1 = low/1mm, 2 = high/2mm)."""
        if value not in (1, 2):
            raise ValueError(
                f"LOD value {value} invalid. Must be 1 (low) or 2 (high).")
        self._poll_ready()
        data = bytes([value, (CHECKSUM_MAGIC - value) & 0xFF])
        resp = self._write_config(0, OFFSET_LOD, data)
        if not resp:
            raise IOError("No response from device")
        self._save()

    def set_button_combo(self, button: int, modifiers: list[int],
                         keycode: int):
        """Remap a mouse button to a keyboard key combo.

        Uses macro format: press each modifier, press key, release key,
        release modifiers in reverse order.

        Args:
            button: Button index (0-10).
            modifiers: List of HID modifier keycodes (0xE0-0xE7).
            keycode: HID usage code for the main key (e.g. 0x2B = Tab).
        """
        if button < 0 or button >= BUTTON_COUNT:
            raise ValueError(f"Button must be 0-{BUTTON_COUNT - 1}")

        self._poll_ready()

        # Bank 0: mark button as keyboard type
        config_offset = OFFSET_BUTTON_CONFIG + button * 4
        cfg = bytearray([BUTTON_TYPE_KEYBOARD, 0x00, 0x00, 0x00])
        cfg[3] = (CHECKSUM_MAGIC - sum(cfg[:3])) & 0xFF
        resp = self._write_config(0, config_offset, bytes(cfg))
        if not resp:
            raise IOError("No response from device")

        # Bank 1: build macro action
        # Each event is 3 bytes: [0x81=press|0x41=release, keycode, 0x00]
        events = []
        for mod in modifiers:
            events.append((0x81, mod))   # press modifier
        events.append((0x81, keycode))   # press main key
        events.append((0x41, keycode))   # release main key
        for mod in reversed(modifiers):
            events.append((0x41, mod))   # release modifier

        action = bytearray([len(events)])
        for event_type, key in events:
            action.extend([event_type, key, 0x00])
        action.append((CHECKSUM_MAGIC - sum(action)) & 0xFF)

        # Write in 10-byte chunks to bank 1
        action_offset = button * BUTTON_ACTION_STRIDE
        for i in range(0, len(action), 10):
            chunk = bytes(action[i:i + 10])
            resp = self._write_config(
                BUTTON_ACTION_BANK, action_offset + i, chunk)
            if not resp:
                raise IOError("No response from device")

        self._save()

    def reset_button(self, button: int):
        """Reset a button to its default mouse-button function.

        Args:
            button: Button index (0-10). The default param is button+1
                    (button 0 = left click = mouse button 1, etc.)
        """
        if button < 0 or button >= BUTTON_COUNT:
            raise ValueError(f"Button must be 0-{BUTTON_COUNT - 1}")

        self._poll_ready()

        # Default: type=mouse, param=button+1
        param = button + 1
        config_offset = OFFSET_BUTTON_CONFIG + button * 4
        cfg = bytearray([BUTTON_TYPE_MOUSE, param, 0x00, 0x00])
        cfg[3] = (CHECKSUM_MAGIC - sum(cfg[:3])) & 0xFF
        resp = self._write_config(0, config_offset, bytes(cfg))
        if not resp:
            raise IOError("No response from device")

        self._save()

    def dump_config(self, bank: int = 0, start: int = 0, length: int = 0xC0):
        """Dump raw config memory for debugging."""
        self._poll_ready()
        result = bytearray()
        chunk_size = 10
        for offset in range(start, start + length, chunk_size):
            remaining = min(chunk_size, start + length - offset)
            data = self._read_config(bank, offset, remaining)
            if data:
                result.extend(data)
            else:
                result.extend(b"\xff" * remaining)
        return bytes(result)


def print_status(mouse: FantechAria):
    """Print current mouse configuration."""
    print("Fantech Aria XD7 - Current Configuration")
    print("=" * 42)

    print(f"\nPolling Rate:   {mouse.get_polling_rate()} Hz")
    print(f"Debounce:       {mouse.get_debounce()} ms")
    print(f"Angle Snapping: {mouse.get_angle_snap()}")
    lod = mouse.get_lod()
    print(
        f"Lift-off Dist:  {lod} ({'low' if lod == 1 else 'high' if lod == 2 else lod})")

    print(f"\nDPI Slots:")
    dpis = mouse.get_dpi_all()
    for i, (dx, dy) in enumerate(dpis):
        xy = f"{dx}" if dx == dy else f"{dx}x{dy}"
        print(f"  Slot {i}: {xy}")


def cmd_status(args):
    with FantechAria() as mouse:
        print_status(mouse)


def cmd_dpi(args):
    with FantechAria() as mouse:
        if args.value is None:
            # Read mode
            dpis = mouse.get_dpi_all()
            for i, (dx, dy) in enumerate(dpis):
                xy = f"{dx}" if dx == dy else f"{dx}x{dy}"
                print(f"Slot {i}: {xy}")
        else:
            # Write mode
            dpi_y = args.dpi_y
            mouse.set_dpi(args.slot, args.value, dpi_y)
            dx, dy = args.value, dpi_y or args.value
            xy = f"{dx}" if dx == dy else f"{dx}x{dy}"
            print(f"Set slot {args.slot} to {xy} DPI")


def cmd_polling_rate(args):
    with FantechAria() as mouse:
        if args.value is None:
            print(f"Polling rate: {mouse.get_polling_rate()} Hz")
        else:
            mouse.set_polling_rate(args.value)
            print(f"Set polling rate to {args.value} Hz")


def cmd_debounce(args):
    with FantechAria() as mouse:
        if args.value is None:
            print(f"Debounce: {mouse.get_debounce()} ms")
        else:
            mouse.set_debounce(args.value)
            print(f"Set debounce to {args.value} ms")


def cmd_dump(args):
    with FantechAria() as mouse:
        data = mouse.dump_config(args.bank, args.offset, args.length)
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            addr = args.offset + i
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b <
                                127 else "." for b in chunk)
            print(f"  {addr:04x}: {hex_str:<48s}  {ascii_str}")


def cmd_angle_snap(args):
    with FantechAria() as mouse:
        if args.value is None:
            print(f"Angle snapping: {mouse.get_angle_snap()}")
        else:
            mouse.set_angle_snap(args.value)
            print(f"Set angle snapping to {args.value}")


def cmd_lod(args):
    with FantechAria() as mouse:
        if args.value is None:
            lod = mouse.get_lod()
            label = "low/1mm" if lod == 1 else "high/2mm" if lod == 2 else str(
                lod)
            print(f"Lift-off distance: {lod} ({label})")
        else:
            mouse.set_lod(args.value)
            label = "low/1mm" if args.value == 1 else "high/2mm"
            print(f"Set lift-off distance to {args.value} ({label})")


def cmd_button(args):
    with FantechAria() as mouse:
        if args.key:
            modifiers, keycode = parse_key_combo(args.key)
            mouse.set_button_combo(args.button, modifiers, keycode)
            print(f"Button {args.button} remapped to '{args.key}'")
        elif args.reset:
            mouse.reset_button(args.button)
            print(f"Button {args.button} reset to default")
        else:
            print("Specify --key or --reset. See --help.")


def cmd_udev_rule(_args):
    rule = (
        f'SUBSYSTEM=="hidraw", ATTRS{{idVendor}}=="{VENDOR_ID:04x}", '
        f'ATTRS{{idProduct}}=="{PRODUCT_ID:04x}", MODE="0660", TAG+="uaccess"'
    )
    print("Add this udev rule to /etc/udev/rules.d/99-fantech-aria.rules:")
    print()
    print(f"  {rule}")
    print()
    print("Then reload rules:")
    print("  sudo udevadm control --reload-rules && sudo udevadm trigger")


def main():
    parser = argparse.ArgumentParser(
        description="Fantech Aria XD7 configuration tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s status                     Show current configuration
  %(prog)s dpi                        Show all DPI slots
  %(prog)s dpi 800                    Set slot 0 to 800 DPI
  %(prog)s dpi 1600 --slot 2          Set slot 2 to 1600 DPI
  %(prog)s dpi 800 --dpi-y 400        Set slot 0 to 800x400 DPI (asymmetric)
  %(prog)s polling-rate               Show current polling rate
  %(prog)s polling-rate 1000          Set polling rate to 1000 Hz
  %(prog)s debounce                   Show current debounce time
  %(prog)s debounce 2                 Set debounce to 2ms
  %(prog)s angle-snap                 Show angle snapping value
  %(prog)s angle-snap 10              Set angle snapping to 10
  %(prog)s lod                        Show lift-off distance
  %(prog)s lod 1                      Set lift-off distance to 1 (low)
  %(prog)s button 3 --key a             Remap back button to 'a' key
  %(prog)s button 3 --key super+tab    Remap back button to Super+Tab
  %(prog)s button 3 --key ctrl+shift+z Remap back button to Ctrl+Shift+Z
  %(prog)s button 3 --reset            Reset back button to default
  %(prog)s dump                       Dump raw config memory
  %(prog)s udev-rule                  Print udev rule for non-root access
""",
    )

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status", help="Show current configuration")

    dpi_parser = sub.add_parser("dpi", help="Get/set DPI")
    dpi_parser.add_argument("value", type=int, nargs="?",
                            help="DPI value (50-26000, step 50)")
    dpi_parser.add_argument("--slot", type=int, default=0,
                            help="DPI slot (0-6, default: 0)")
    dpi_parser.add_argument("--dpi-y", type=int,
                            default=None, help="Separate Y-axis DPI")

    poll_parser = sub.add_parser("polling-rate", help="Get/set polling rate")
    poll_parser.add_argument("value", type=int, nargs="?",
                             help="125, 250, 500, or 1000")

    deb_parser = sub.add_parser("debounce", help="Get/set debounce time")
    deb_parser.add_argument("value", type=int, nargs="?",
                            help="Debounce in ms (0-50)")

    angle_parser = sub.add_parser("angle-snap", help="Get/set angle snapping")
    angle_parser.add_argument(
        "value", type=int, nargs="?", help="Angle snapping value (0-255)")

    lod_parser = sub.add_parser("lod", help="Get/set lift-off distance")
    lod_parser.add_argument("value", type=int, nargs="?",
                            help="1 (low/1mm) or 2 (high/2mm)")

    button_parser = sub.add_parser("button", help="Remap mouse buttons")
    button_parser.add_argument("button", type=int, help="Button index (0-10)")
    button_group = button_parser.add_mutually_exclusive_group()
    button_group.add_argument(
        "--key", type=str,
        help="Key or combo (e.g. 'a', 'tab', 'super+tab', 'ctrl+shift+z')")
    button_group.add_argument(
        "--reset", action="store_true", help="Reset to default mouse button")

    dump_parser = sub.add_parser("dump", help="Dump raw config memory")
    dump_parser.add_argument(
        "--bank", type=int, default=0, help="Memory bank (default: 0)")
    dump_parser.add_argument("--offset", type=int,
                             default=0, help="Start offset (default: 0)")
    dump_parser.add_argument("--length", type=int,
                             default=0xC0, help="Bytes to read (default: 192)")

    sub.add_parser("udev-rule", help="Print udev rule for non-root access")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "status": cmd_status,
        "dpi": cmd_dpi,
        "polling-rate": cmd_polling_rate,
        "debounce": cmd_debounce,
        "angle-snap": cmd_angle_snap,
        "lod": cmd_lod,
        "button": cmd_button,
        "dump": cmd_dump,
        "udev-rule": cmd_udev_rule,
    }

    try:
        commands[args.command](args)
    except hid.HIDException as e:
        print(f"HID error: {e}", file=sys.stderr)
        print("Make sure the mouse is connected and you have permission.",
              file=sys.stderr)
        print("Run with sudo or install the udev rule (see: %(prog)s udev-rule)", file=sys.stderr)
        sys.exit(1)
    except (ValueError, IOError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
