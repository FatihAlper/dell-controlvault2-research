#!/usr/bin/env python3
"""Print a payload-free summary of ControlVault USB application messages."""

from __future__ import annotations

import argparse
from collections import Counter
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MessageStart:
    frame: int
    relative_time: float
    direction: str
    endpoint: int
    captured_length: int
    declared_length: int
    command: int
    command_flags: int


@dataclass(frozen=True)
class MessageCount:
    direction: str
    declared_length: int
    command: int
    command_flags: int
    count: int


def count_message_shapes(starts: list[MessageStart]) -> list[MessageCount]:
    """Group message headers without retaining or exposing payload bytes."""
    counts = Counter(
        (
            item.direction,
            item.declared_length,
            item.command,
            item.command_flags,
        )
        for item in starts
    )
    return [
        MessageCount(
            direction=direction,
            declared_length=declared_length,
            command=command,
            command_flags=command_flags,
            count=count,
        )
        for (
            direction,
            declared_length,
            command,
            command_flags,
        ), count in sorted(
            counts.items(),
            key=lambda entry: (
                entry[0][2],
                entry[0][0] == "IN",
                entry[0][1],
                entry[0][3],
            ),
        )
    ]


def parse_tshark_line(line: str) -> MessageStart | None:
    fields = line.rstrip("\n").split("|")
    if len(fields) != 6:
        return None

    frame_text, time_text, urb_type, endpoint_text, length_text, data = fields
    urb_type = urb_type.strip("'")
    try:
        payload = bytes.fromhex(data)
        endpoint = int(endpoint_text, 0)
        captured_length = int(length_text)
    except ValueError:
        return None

    if len(payload) < 12 or payload[:4] != b"\x01\x00\x00\x00":
        return None

    # usbmon records host-to-device data on submit and device-to-host data on
    # completion. Ignoring the opposite halves avoids duplicate transactions.
    if endpoint == 0x01 and urb_type == "S":
        direction = "OUT"
    elif endpoint == 0x81 and urb_type == "C":
        direction = "IN"
    else:
        return None

    declared_length = struct.unpack_from("<I", payload, 4)[0]
    command, command_flags = struct.unpack_from("<HH", payload, 8)
    return MessageStart(
        frame=int(frame_text),
        relative_time=float(time_text),
        direction=direction,
        endpoint=endpoint,
        captured_length=captured_length,
        declared_length=declared_length,
        command=command,
        command_flags=command_flags,
    )


def tshark_rows(pcap: Path, device_address: int) -> list[str]:
    display_filter = (
        f"usb.device_address == {device_address} && "
        "usb.capdata[0:4] == 01:00:00:00"
    )
    command = [
        "tshark",
        "-r",
        str(pcap),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=|",
        "-e",
        "frame.number",
        "-e",
        "frame.time_relative",
        "-e",
        "usb.urb_type",
        "-e",
        "usb.endpoint_address",
        "-e",
        "usb.data_len",
        "-e",
        "usb.capdata",
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return result.stdout.splitlines()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Summarize ControlVault message headers without printing USB payloads"
        )
    )
    parser.add_argument("pcap", type=Path)
    parser.add_argument(
        "--device-address",
        type=int,
        required=True,
        help="usbmon device address (for example 5 for bus conversation 1.5.x)",
    )
    parser.add_argument(
        "--counts",
        action="store_true",
        help=(
            "group headers by command, direction, declared length, and flags "
            "instead of printing the chronological sequence"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.pcap.is_file():
        print(f"error: PCAP does not exist: {args.pcap}", file=sys.stderr)
        return 2

    try:
        starts = [
            parsed
            for row in tshark_rows(args.pcap, args.device_address)
            if (parsed := parse_tshark_line(row)) is not None
        ]
    except FileNotFoundError:
        print("error: tshark is required", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as error:
        print(error.stderr.rstrip(), file=sys.stderr)
        return error.returncode or 2

    if args.counts:
        print("command direction declared_len flags count")
        for item in count_message_shapes(starts):
            print(
                f"0x{item.command:04x} {item.direction:>3} "
                f"{item.declared_length:12d} "
                f"0x{item.command_flags:04x} {item.count:5d}"
            )
        return 0

    print("time_s direction endpoint declared_len command flags")
    for item in starts:
        print(
            f"{item.relative_time:9.6f} {item.direction:>3} "
            f"0x{item.endpoint:02x} {item.declared_length:12d} "
            f"0x{item.command:04x} 0x{item.command_flags:04x}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
