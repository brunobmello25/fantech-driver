# USB Traffic Capture Guide for Fantech Aria XD7

## Setup on Windows

1. **Install Wireshark** from https://www.wireshark.org/download.html
   - During installation, make sure to check **USBPcap** when prompted

2. **Install Fantech Software** from https://fantechworld.com/pages/download-mice
   - Download the Aria XD7 software
   - Connect the mouse via USB cable (wired mode)

3. **Reboot** after installing USBPcap

## Capture Procedure

Open Wireshark, select the **USBPcap** interface that corresponds to the USB bus
where the mouse is connected, and start capturing.

To verify you're seeing the right device, use this display filter in Wireshark:
```
usb.idVendor == 0x25a7 && usb.idProduct == 0xfa7c
```

### Capture 1: DPI Changes

Perform these actions **one at a time**, waiting 2-3 seconds between each:

1. Set DPI to **400**
2. Set DPI to **800**
3. Set DPI to **1600**
4. Set DPI to **3200**
5. Set DPI to **6400**
6. Set DPI to **12000**
7. Set DPI to **26000**

Stop capture, save as `dpi_changes.pcapng`.

### Capture 2: Polling Rate Changes

Start a new capture, then:

1. Set polling rate to **125 Hz**
2. Set polling rate to **250 Hz**
3. Set polling rate to **500 Hz**
4. Set polling rate to **1000 Hz**

Stop capture, save as `polling_rate.pcapng`.

### Capture 3: Button Remapping

Start a new capture, then:

1. Remap **Button 4** (side button) to **keyboard key "A"**
2. Remap **Button 5** (other side button) to **keyboard key "B"**
3. Reset buttons to **default**

Stop capture, save as `button_remap.pcapng`.

### Capture 4: Full Config Dump

Start a new capture, then:

1. Open the Fantech software (just open it, some mice send a config read on connect)
2. Wait 5 seconds
3. Click through each tab/settings page

Stop capture, save as `full_config.pcapng`.

## Transfer

Copy all `.pcapng` files to this Linux machine at:
```
/home/brubs/dev/personal/fantech-driver/captures/
```

Then run:
```
python3 analyze_captures.py captures/dpi_changes.pcapng
```
