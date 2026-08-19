#!/usr/bin/env python3
"""Compare ControlVault UpdateEnrollment traffic without exposing payloads.

The input PCAP may contain biometric material. Payload bytes are held only in
memory and are never printed, hashed, or written by this tool. Reports contain
only message ordering, lengths, flags, byte-offset ranges, and lengths of
high-variation byte ranges shared between a capture response and its following
update request.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from itertools import combinations
from pathlib import Path
import struct
import subprocess
import sys


APPLICATION_HEADER_SIZE = 12
CAPTURE_COMMAND = 0x66
UPDATE_COMMAND = 0x6C
MIN_LINK_SIZE = 20


@dataclass(frozen=True)
class UsbChunk:
    frame: int
    relative_time: float
    direction: str
    endpoint: int
    captured_length: int
    _data: bytes = field(repr=False)


@dataclass(frozen=True)
class UsbMessage:
    frame: int
    relative_time: float
    direction: str
    endpoint: int
    captured_length: int
    declared_length: int
    command: int
    command_flags: int
    _payload: bytes = field(repr=False)


@dataclass(frozen=True)
class UpdateExchange:
    request: UsbMessage
    response: UsbMessage | None
    preceding_commands: tuple[int, ...]
    capture_response: UsbMessage | None


def parse_tshark_line(line: str) -> UsbChunk | None:
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

    # usbmon records host-to-device data on submit and device-to-host data on
    # completion. Ignore the opposite halves to avoid duplicate transactions.
    if endpoint == 0x01 and urb_type == "S":
        direction = "OUT"
    elif endpoint == 0x81 and urb_type == "C":
        direction = "IN"
    else:
        return None

    return UsbChunk(
        frame=int(frame_text),
        relative_time=float(time_text),
        direction=direction,
        endpoint=endpoint,
        captured_length=captured_length,
        _data=payload,
    )


def reassemble_messages(chunks: list[UsbChunk]) -> list[UsbMessage]:
    """Reassemble application messages split across USB bulk transfers."""

    states: dict[str, dict[str, object]] = {}
    messages: list[UsbMessage] = []
    for chunk in chunks:
        state = states.get(chunk.direction)
        if state is None:
            if not chunk._data.startswith(b"\x01\x00\x00\x00"):
                continue
            state = {
                "frame": chunk.frame,
                "relative_time": chunk.relative_time,
                "endpoint": chunk.endpoint,
                "buffer": bytearray(),
            }
            states[chunk.direction] = state

        buffer = state["buffer"]
        assert isinstance(buffer, bytearray)
        buffer.extend(chunk._data)

        while len(buffer) >= APPLICATION_HEADER_SIZE:
            if buffer[:4] != b"\x01\x00\x00\x00":
                states.pop(chunk.direction, None)
                break
            declared_length = struct.unpack_from("<I", buffer, 4)[0]
            if declared_length < APPLICATION_HEADER_SIZE:
                states.pop(chunk.direction, None)
                break
            if len(buffer) < declared_length:
                break

            payload = bytes(buffer[:declared_length])
            del buffer[:declared_length]
            command, command_flags = struct.unpack_from("<HH", payload, 8)
            frame = state["frame"]
            relative_time = state["relative_time"]
            endpoint = state["endpoint"]
            assert isinstance(frame, int)
            assert isinstance(relative_time, float)
            assert isinstance(endpoint, int)
            messages.append(
                UsbMessage(
                    frame=frame,
                    relative_time=relative_time,
                    direction=chunk.direction,
                    endpoint=endpoint,
                    captured_length=len(payload),
                    declared_length=declared_length,
                    command=command,
                    command_flags=command_flags,
                    _payload=payload,
                )
            )

            if not buffer:
                states.pop(chunk.direction, None)
                break
            if buffer[:4] != b"\x01\x00\x00\x00":
                states.pop(chunk.direction, None)
                break
            state["frame"] = chunk.frame
            state["relative_time"] = chunk.relative_time
            state["endpoint"] = chunk.endpoint

    return sorted(messages, key=lambda message: message.frame)


def tshark_rows(pcap: Path, device_address: int) -> list[str]:
    display_filter = (
        f"usb.device_address == {device_address} && "
        "usb.capdata"
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


def contiguous_ranges(offsets: list[int]) -> list[tuple[int, int]]:
    if not offsets:
        return []

    ranges: list[tuple[int, int]] = []
    start = previous = offsets[0]
    for offset in offsets[1:]:
        if offset != previous + 1:
            ranges.append((start, previous + 1))
            start = offset
        previous = offset
    ranges.append((start, previous + 1))
    return ranges


def format_ranges(ranges: list[tuple[int, int]]) -> str:
    if not ranges:
        return "none"
    return ",".join(f"{start}:{end}" for start, end in ranges)


def differing_offsets(left: bytes, right: bytes) -> list[int]:
    common_length = min(len(left), len(right))
    offsets = [
        offset
        for offset in range(common_length)
        if left[offset] != right[offset]
    ]
    offsets.extend(range(common_length, max(len(left), len(right))))
    return offsets


def stable_offsets(payloads: list[bytes]) -> list[int]:
    if not payloads:
        return []
    minimum_length = min(len(payload) for payload in payloads)
    return [
        offset
        for offset in range(minimum_length)
        if all(payload[offset] == payloads[0][offset] for payload in payloads[1:])
    ]


def shared_variable_blocks(
    capture_payload: bytes,
    update_payload: bytes,
    minimum_size: int = MIN_LINK_SIZE,
) -> list[tuple[int, int, int]]:
    """Return offset/length metadata for likely opaque values copied verbatim.

    Long constant padding can otherwise look like a link. Requiring at least
    eight distinct byte values keeps the report focused on high-variation
    identifiers without revealing their content.
    """

    capture_body = capture_payload[APPLICATION_HEADER_SIZE:]
    update_body = update_payload[APPLICATION_HEADER_SIZE:]
    matcher = SequenceMatcher(None, capture_body, update_body, autojunk=False)
    blocks = []
    for block in matcher.get_matching_blocks():
        if block.size < minimum_size:
            continue
        value = capture_body[block.a : block.a + block.size]
        if len(set(value)) < 8:
            continue
        blocks.append(
            (
                block.a + APPLICATION_HEADER_SIZE,
                block.b + APPLICATION_HEADER_SIZE,
                block.size,
            )
        )
    return blocks


def trim_blocks_to_variable_request_offsets(
    blocks: list[tuple[int, int, int]],
    variable_request_offsets: set[int],
    minimum_size: int = MIN_LINK_SIZE,
) -> list[tuple[int, int, int]]:
    trimmed: list[tuple[int, int, int]] = []
    for capture_offset, request_offset, size in blocks:
        relative_offsets = [
            relative
            for relative in range(size)
            if request_offset + relative in variable_request_offsets
        ]
        for start, end in contiguous_ranges(relative_offsets):
            if end - start < minimum_size:
                continue
            trimmed.append(
                (
                    capture_offset + start,
                    request_offset + start,
                    end - start,
                )
            )
    return trimmed


def collect_update_exchanges(messages: list[UsbMessage]) -> list[UpdateExchange]:
    exchanges: list[UpdateExchange] = []
    previous_update_index = -1
    for index, message in enumerate(messages):
        if message.direction != "OUT" or message.command != UPDATE_COMMAND:
            continue

        response = next(
            (
                candidate
                for candidate in messages[index + 1 :]
                if candidate.direction == "IN"
                and candidate.command == UPDATE_COMMAND
            ),
            None,
        )
        interval = messages[previous_update_index + 1 : index]
        capture_response = next(
            (
                candidate
                for candidate in reversed(interval)
                if candidate.direction == "IN"
                and candidate.command == CAPTURE_COMMAND
            ),
            None,
        )
        preceding_commands = tuple(
            candidate.command
            for candidate in interval
            if candidate.direction == "OUT"
        )
        exchanges.append(
            UpdateExchange(
                request=message,
                response=response,
                preceding_commands=preceding_commands,
                capture_response=capture_response,
            )
        )
        previous_update_index = index
    return exchanges


def format_report(label: str, messages: list[UsbMessage]) -> str:
    exchanges = collect_update_exchanges(messages)
    lines = [f"capture={label}", f"updates={len(exchanges)}"]
    if not exchanges:
        return "\n".join(lines)

    request_payloads = [exchange.request._payload for exchange in exchanges]
    stable = stable_offsets(request_payloads)
    variable_request_offsets = set(range(min(map(len, request_payloads)))) - set(
        stable
    )
    lines.append(
        "request_lengths="
        + ",".join(str(exchange.request.declared_length) for exchange in exchanges)
    )
    lines.append(
        "response_lengths="
        + ",".join(
            str(exchange.response.declared_length)
            if exchange.response is not None
            else "missing"
            for exchange in exchanges
        )
    )
    lines.append(
        "stable_request_ranges="
        + format_ranges(contiguous_ranges(stable))
    )

    first_payload = request_payloads[0]
    for update_index, exchange in enumerate(exchanges, start=1):
        context = ",".join(
            f"0x{command:02x}" for command in exchange.preceding_commands
        ) or "none"
        response_length = (
            str(exchange.response.declared_length)
            if exchange.response is not None
            else "missing"
        )
        diff = differing_offsets(first_payload, exchange.request._payload)
        links = (
            trim_blocks_to_variable_request_offsets(
                shared_variable_blocks(
                    exchange.capture_response._payload,
                    exchange.request._payload,
                ),
                variable_request_offsets,
            )
            if exchange.capture_response is not None
            else []
        )
        link_text = (
            ",".join(
                f"capture[{capture_offset}:{capture_offset + size}]="
                f"request[{request_offset}:{request_offset + size}]"
                for capture_offset, request_offset, size in links
            )
            or "none"
        )
        lines.append(
            f"update={update_index} request_len={exchange.request.declared_length} "
            f"response_len={response_length} preceding_out={context} "
            f"diff_vs_first_count={len(diff)} "
            f"diff_vs_first_ranges={format_ranges(contiguous_ranges(diff))} "
            f"capture_links={link_text}"
        )
    return "\n".join(lines)


def first_shape_difference(
    left: list[UpdateExchange],
    right: list[UpdateExchange],
    response: bool,
) -> str:
    for index, (left_exchange, right_exchange) in enumerate(
        zip(left, right), start=1
    ):
        if response:
            left_shape = (
                left_exchange.response.declared_length,
                left_exchange.response.command_flags,
            ) if left_exchange.response is not None else None
            right_shape = (
                right_exchange.response.declared_length,
                right_exchange.response.command_flags,
            ) if right_exchange.response is not None else None
        else:
            left_shape = (
                left_exchange.request.declared_length,
                left_exchange.request.command_flags,
            )
            right_shape = (
                right_exchange.request.declared_length,
                right_exchange.request.command_flags,
            )
        if left_shape != right_shape:
            return str(index)
    if len(left) != len(right):
        return str(min(len(left), len(right)) + 1)
    return "none"


def format_cross_capture_report(
    captures: list[tuple[str, list[UsbMessage]]],
) -> str:
    exchanges_by_label = {
        label: collect_update_exchanges(messages) for label, messages in captures
    }
    lines = ["cross_capture_comparison=yes"]

    lengths: dict[int, list[tuple[str, list[UpdateExchange]]]] = {}
    for label, exchanges in exchanges_by_label.items():
        if not exchanges:
            continue
        request_lengths = {exchange.request.declared_length for exchange in exchanges}
        if len(request_lengths) != 1:
            continue
        length = next(iter(request_lengths))
        lengths.setdefault(length, []).append((label, exchanges))

    for length, group in sorted(lengths.items()):
        if len(group) < 2:
            continue
        labels = [label for label, _ in group]
        payloads = [
            exchange.request._payload
            for _, exchanges in group
            for exchange in exchanges
        ]
        lines.append(
            f"request_len={length} captures={','.join(labels)} "
            "stable_across_captures_ranges="
            f"{format_ranges(contiguous_ranges(stable_offsets(payloads)))}"
        )
        for (left_label, left), (right_label, right) in combinations(group, 2):
            lines.append(
                f"pair={left_label},{right_label} "
                f"request_shape_first_difference="
                f"{first_shape_difference(left, right, response=False)} "
                f"response_shape_first_difference="
                f"{first_shape_difference(left, right, response=True)}"
            )
    return "\n".join(lines)


def parse_capture_argument(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("capture must be LABEL=PCAP")
    label, path_text = value.split("=", 1)
    if not label or not path_text:
        raise argparse.ArgumentTypeError("capture must be LABEL=PCAP")
    return label, Path(path_text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compare ControlVault UpdateEnrollment structure without printing, "
            "hashing, or writing payload bytes"
        )
    )
    parser.add_argument(
        "--device-address",
        type=int,
        required=True,
        help="usbmon device address",
    )
    parser.add_argument(
        "captures",
        nargs="+",
        type=parse_capture_argument,
        metavar="LABEL=PCAP",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    reports = []
    captures = []
    for label, pcap in args.captures:
        if not pcap.is_file():
            print(f"error: PCAP does not exist: {pcap}", file=sys.stderr)
            return 2
        try:
            chunks = [
                parsed
                for row in tshark_rows(pcap, args.device_address)
                if (parsed := parse_tshark_line(row)) is not None
            ]
            messages = reassemble_messages(chunks)
        except FileNotFoundError:
            print("error: tshark is required", file=sys.stderr)
            return 2
        except subprocess.CalledProcessError as error:
            print(error.stderr.rstrip(), file=sys.stderr)
            return error.returncode or 2
        captures.append((label, messages))
        reports.append(format_report(label, messages))

    reports.append(format_cross_capture_report(captures))
    print("\n\n".join(reports))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
