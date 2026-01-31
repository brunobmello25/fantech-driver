#!/usr/bin/env python3
"""
Analyze USB traffic captures from Wireshark/USBPcap for Fantech Aria XD7.
Filters for vendor-specific HID traffic (SET_REPORT / GET_REPORT) and displays
the payloads in a human-readable format.

Usage:
    python3 analyze_captures.py captures/dpi_changes.pcapng
    python3 analyze_captures.py captures/*.pcapng
"""

import struct
import sys
from pathlib import Path

# Fantech Aria XD7 identifiers
VENDOR_ID = 0x25A7
PRODUCT_ID = 0xFA7C

# USB HID request types
USB_DIR_OUT = 0x00
USB_DIR_IN = 0x80
USB_TYPE_CLASS = 0x20
USB_RECIP_INTERFACE = 0x01

HID_SET_REPORT = 0x09
HID_GET_REPORT = 0x01

# Report types (in wValue high byte)
REPORT_TYPE_INPUT = 0x01
REPORT_TYPE_OUTPUT = 0x02
REPORT_TYPE_FEATURE = 0x03


def parse_pcapng(filepath):
    """Parse a pcapng file and extract USB transfer data."""
    with open(filepath, "rb") as f:
        data = f.read()

    transfers = []
    offset = 0

    while offset < len(data):
        if offset + 8 > len(data):
            break

        block_type = struct.unpack_from("<I", data, offset)[0]
        block_len = struct.unpack_from("<I", data, offset + 4)[0]

        if block_len < 12 or offset + block_len > len(data):
            break

        # Enhanced Packet Block (EPB) = 0x00000006
        if block_type == 0x00000006:
            if block_len >= 32:
                interface_id = struct.unpack_from("<I", data, offset + 8)[0]
                ts_high = struct.unpack_from("<I", data, offset + 12)[0]
                ts_low = struct.unpack_from("<I", data, offset + 16)[0]
                captured_len = struct.unpack_from("<I", data, offset + 20)[0]
                original_len = struct.unpack_from("<I", data, offset + 24)[0]

                packet_data = data[offset + 28 : offset + 28 + captured_len]
                timestamp = (ts_high << 32) | ts_low

                transfers.append(
                    {
                        "timestamp": timestamp,
                        "data": packet_data,
                        "length": captured_len,
                    }
                )

        # Advance to next block (block_len includes padding to 4-byte boundary)
        block_len = (block_len + 3) & ~3
        offset += block_len

    return transfers


def parse_usbpcap_header(packet_data):
    """Parse USBPcap packet header.

    USBPcap header format (27 bytes minimum):
    - headerLen (2 bytes, LE)
    - irpId (8 bytes)
    - status (4 bytes)
    - function (2 bytes): URB function code
    - info (1 byte): direction (bit 0: 0=out, 1=in)
    - bus (2 bytes)
    - device (2 bytes)
    - endpoint (1 byte): endpoint address
    - transfer (1 byte): transfer type (0=iso, 1=interrupt, 2=control, 3=bulk)
    - dataLength (4 bytes)
    """
    if len(packet_data) < 27:
        return None

    header_len = struct.unpack_from("<H", packet_data, 0)[0]
    irp_id = struct.unpack_from("<Q", packet_data, 2)[0]
    status = struct.unpack_from("<I", packet_data, 10)[0]
    function = struct.unpack_from("<H", packet_data, 14)[0]
    info = packet_data[16]
    bus = struct.unpack_from("<H", packet_data, 17)[0]
    device = struct.unpack_from("<H", packet_data, 19)[0]
    endpoint = packet_data[21]
    transfer_type = packet_data[22]
    data_length = struct.unpack_from("<I", packet_data, 23)[0]

    result = {
        "header_len": header_len,
        "irp_id": irp_id,
        "status": status,
        "function": function,
        "info": info,
        "bus": bus,
        "device": device,
        "endpoint": endpoint,
        "transfer_type": transfer_type,
        "data_length": data_length,
        "direction": "IN" if info & 1 else "OUT",
    }

    # For control transfers, parse setup packet if present
    if transfer_type == 2 and header_len >= 27 + 8:
        setup_offset = 27
        if setup_offset + 8 <= len(packet_data):
            bm_request_type = packet_data[setup_offset]
            b_request = packet_data[setup_offset + 1]
            w_value = struct.unpack_from("<H", packet_data, setup_offset + 2)[0]
            w_index = struct.unpack_from("<H", packet_data, setup_offset + 4)[0]
            w_length = struct.unpack_from("<H", packet_data, setup_offset + 6)[0]

            result["setup"] = {
                "bmRequestType": bm_request_type,
                "bRequest": b_request,
                "wValue": w_value,
                "wIndex": w_index,
                "wLength": w_length,
            }

    # Extract payload data after header
    payload = packet_data[header_len:]
    result["payload"] = payload

    return result


def format_hex(data):
    """Format bytes as hex string."""
    return " ".join(f"{b:02x}" for b in data)


def analyze_file(filepath):
    """Analyze a single pcapng file."""
    print(f"\n{'='*80}")
    print(f"Analyzing: {filepath}")
    print(f"{'='*80}\n")

    transfers = parse_pcapng(filepath)
    print(f"Total packets: {len(transfers)}")

    hid_transfers = []
    seen_irps = {}

    for i, transfer in enumerate(transfers):
        parsed = parse_usbpcap_header(transfer["data"])
        if not parsed:
            continue

        # Filter for control transfers (type 2) or interrupt transfers (type 1)
        if parsed["transfer_type"] not in (1, 2):
            continue

        # Track by IRP ID for request/response pairing
        irp_id = parsed["irp_id"]

        if parsed["transfer_type"] == 2:  # Control transfer
            setup = parsed.get("setup")
            if setup:
                req_type = setup["bmRequestType"]
                request = setup["bRequest"]
                w_value = setup["wValue"]

                # HID class requests
                if (req_type & 0x60) == 0x20:  # Class request
                    report_type = (w_value >> 8) & 0xFF
                    report_id = w_value & 0xFF

                    if request == HID_SET_REPORT:
                        req_name = "SET_REPORT"
                    elif request == HID_GET_REPORT:
                        req_name = "GET_REPORT"
                    else:
                        req_name = f"REQ_0x{request:02x}"

                    type_names = {1: "Input", 2: "Output", 3: "Feature"}
                    type_name = type_names.get(report_type, f"Type_{report_type}")

                    entry = {
                        "index": i,
                        "timestamp": transfer["timestamp"],
                        "direction": parsed["direction"],
                        "request": req_name,
                        "report_type": type_name,
                        "report_id": report_id,
                        "payload": parsed["payload"],
                        "endpoint": parsed["endpoint"],
                        "device": parsed["device"],
                        "w_index": setup["wIndex"],
                    }
                    hid_transfers.append(entry)

                    # Store for response matching
                    seen_irps[irp_id] = entry

            elif irp_id in seen_irps:
                # This is the response to a previous request
                original = seen_irps[irp_id]
                if parsed["payload"]:
                    entry = {
                        "index": i,
                        "timestamp": transfer["timestamp"],
                        "direction": parsed["direction"],
                        "request": f"{original['request']}_RESPONSE",
                        "report_type": original["report_type"],
                        "report_id": original["report_id"],
                        "payload": parsed["payload"],
                        "endpoint": parsed["endpoint"],
                        "device": parsed["device"],
                        "w_index": original.get("w_index", 0),
                    }
                    hid_transfers.append(entry)

        elif parsed["transfer_type"] == 1 and parsed["payload"]:  # Interrupt
            entry = {
                "index": i,
                "timestamp": transfer["timestamp"],
                "direction": parsed["direction"],
                "request": "INTERRUPT",
                "report_type": "Interrupt",
                "report_id": parsed["payload"][0] if parsed["payload"] else 0,
                "payload": parsed["payload"],
                "endpoint": parsed["endpoint"],
                "device": parsed["device"],
                "w_index": 0,
            }
            hid_transfers.append(entry)

    print(f"HID transfers found: {len(hid_transfers)}\n")

    # Display transfers
    prev_ts = None
    for entry in hid_transfers:
        ts = entry["timestamp"]
        if prev_ts is not None:
            delta = ts - prev_ts
            if delta > 1_000_000:  # >1 second gap (assuming microsecond resolution)
                print(f"  --- gap: {delta / 1_000_000:.1f}s ---")
        prev_ts = ts

        payload_hex = format_hex(entry["payload"]) if entry["payload"] else "(empty)"
        direction_arrow = ">>" if "OUT" in entry["direction"] else "<<"

        print(
            f"  {direction_arrow} {entry['request']:25s} "
            f"{entry['report_type']:8s} "
            f"ID=0x{entry['report_id']:02x} "
            f"IF={entry['w_index']} "
            f"[{len(entry['payload']):3d}B] "
            f"{payload_hex}"
        )

    # Summary: group SET_REPORT payloads to find patterns
    print(f"\n{'─'*80}")
    print("SET_REPORT Summary (unique payloads):")
    print(f"{'─'*80}")

    set_reports = [e for e in hid_transfers if e["request"] == "SET_REPORT"]
    seen_payloads = {}
    for entry in set_reports:
        key = (entry["report_id"], bytes(entry["payload"]))
        if key not in seen_payloads:
            seen_payloads[key] = 0
        seen_payloads[key] += 1

    for (report_id, payload), count in sorted(seen_payloads.items()):
        payload_hex = format_hex(payload)
        print(f"  Report 0x{report_id:02x} (x{count}): {payload_hex}")

    return hid_transfers


def diff_payloads(transfers):
    """Find byte positions that change between consecutive SET_REPORT transfers
    with the same report ID."""
    print(f"\n{'─'*80}")
    print("Payload Diff Analysis (bytes that change between consecutive writes):")
    print(f"{'─'*80}")

    by_report = {}
    for entry in transfers:
        if entry["request"] == "SET_REPORT" and entry["payload"]:
            rid = entry["report_id"]
            if rid not in by_report:
                by_report[rid] = []
            by_report[rid].append(entry["payload"])

    for rid, payloads in sorted(by_report.items()):
        if len(payloads) < 2:
            continue

        print(f"\n  Report 0x{rid:02x} ({len(payloads)} writes):")
        max_len = max(len(p) for p in payloads)

        changing_positions = set()
        for i in range(1, len(payloads)):
            for pos in range(max_len):
                a = payloads[i - 1][pos] if pos < len(payloads[i - 1]) else 0
                b = payloads[i][pos] if pos < len(payloads[i]) else 0
                if a != b:
                    changing_positions.add(pos)

        if changing_positions:
            print(f"    Changing byte positions: {sorted(changing_positions)}")
            for i, payload in enumerate(payloads):
                highlighted = []
                for pos in range(len(payload)):
                    if pos in changing_positions:
                        highlighted.append(f"[{payload[pos]:02x}]")
                    else:
                        highlighted.append(f" {payload[pos]:02x} ")
                print(f"    Write {i}: {''.join(highlighted)}")
        else:
            print(f"    All writes identical: {format_hex(payloads[0])}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_captures.py <capture.pcapng> [...]")
        print("       python3 analyze_captures.py captures/*.pcapng")
        sys.exit(1)

    all_transfers = []
    for filepath in sys.argv[1:]:
        path = Path(filepath)
        if not path.exists():
            print(f"File not found: {filepath}")
            continue
        transfers = analyze_file(filepath)
        all_transfers.extend(transfers)

    if all_transfers:
        diff_payloads(all_transfers)


if __name__ == "__main__":
    main()
