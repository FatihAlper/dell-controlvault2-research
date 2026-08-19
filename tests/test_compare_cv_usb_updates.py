from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import sys
import unittest


MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "tools" / "compare_cv_usb_updates.py"
)
SPEC = importlib.util.spec_from_file_location("compare_cv_usb_updates", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def application_payload(
    command: int,
    declared_length: int,
    body: bytes,
    flags: int = 0x0440,
) -> bytes:
    return (
        b"\x01\x00\x00\x00"
        + struct.pack("<IHH", declared_length, command, flags)
        + body
    )


def message(
    frame: int,
    direction: str,
    command: int,
    body: bytes,
    declared_length: int | None = None,
) -> object:
    payload = application_payload(
        command,
        declared_length or 12 + len(body),
        body,
    )
    return MODULE.UsbMessage(
        frame=frame,
        relative_time=float(frame),
        direction=direction,
        endpoint=0x01 if direction == "OUT" else 0x81,
        captured_length=len(payload),
        declared_length=declared_length or len(payload),
        command=command,
        command_flags=0x0440 if direction == "OUT" else 0x0540,
        _payload=payload,
    )


class CompareCvUsbUpdatesTests(unittest.TestCase):
    def test_parse_tshark_line_keeps_chunk_data_out_of_repr(self) -> None:
        secret = bytes(range(32, 64))
        payload = application_payload(0x6C, 44, secret)
        parsed = MODULE.parse_tshark_line(
            f"7|1.25|'S'|0x01|{len(payload)}|{payload.hex()}"
        )
        self.assertIsNotNone(parsed)
        self.assertNotIn(secret.hex(), repr(parsed))

    def test_reassembles_split_application_message(self) -> None:
        secret = bytes(range(32, 112))
        payload = application_payload(0x6C, 92, secret)
        rows = [
            f"7|1.25|'S'|0x01|64|{payload[:64].hex()}",
            f"8|1.26|'S'|0x01|28|{payload[64:].hex()}",
        ]
        chunks = [MODULE.parse_tshark_line(row) for row in rows]
        messages = MODULE.reassemble_messages(
            [chunk for chunk in chunks if chunk is not None]
        )

        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].command, 0x6C)
        self.assertEqual(messages[0].declared_length, 92)
        self.assertEqual(messages[0]._payload, payload)

    def test_contiguous_ranges(self) -> None:
        self.assertEqual(
            MODULE.contiguous_ranges([1, 2, 3, 7, 9, 10]),
            [(1, 4), (7, 8), (9, 11)],
        )

    def test_shared_variable_blocks_reports_only_offsets(self) -> None:
        opaque = bytes(range(40, 60))
        capture = application_payload(0x66, 72, b"A" * 8 + opaque + b"Z" * 8)
        update = application_payload(0x6C, 92, b"B" * 13 + opaque + b"Y" * 8)
        blocks = MODULE.shared_variable_blocks(capture, update)
        self.assertIn((20, 25, 20), blocks)

    def test_trims_constant_prefix_from_shared_block(self) -> None:
        blocks = [(44, 56, 28)]
        trimmed = MODULE.trim_blocks_to_variable_request_offsets(
            blocks,
            set(range(64, 84)),
        )
        self.assertEqual(trimmed, [(52, 64, 20)])

    def test_report_correlates_updates_without_disclosing_bytes(self) -> None:
        opaque_one = bytes(range(40, 60))
        opaque_two = bytes(range(80, 100))
        messages = [
            message(1, "OUT", 0x66, b"start"),
            message(2, "IN", 0x66, b"A" * 8 + opaque_one),
            message(3, "OUT", 0x6C, b"B" * 13 + opaque_one),
            message(4, "IN", 0x6C, b"accepted", declared_length=96),
            message(5, "OUT", 0x8A, b"rearm"),
            message(6, "IN", 0x8A, b"ok"),
            message(7, "OUT", 0x66, b"start"),
            message(8, "IN", 0x66, b"A" * 8 + opaque_two),
            message(9, "OUT", 0x6C, b"B" * 13 + opaque_two),
            message(10, "IN", 0x6C, b"failure", declared_length=44),
        ]

        report = MODULE.format_report("fixture", messages)

        self.assertIn("updates=2", report)
        self.assertIn("response_lengths=96,44", report)
        self.assertIn("preceding_out=0x8a,0x66", report)
        self.assertIn("capture[20:40]=request[25:45]", report)
        self.assertNotIn(opaque_one.hex(), report)
        self.assertNotIn(opaque_two.hex(), report)
        self.assertNotIn("28292a2b", report)

    def test_capture_argument_requires_label(self) -> None:
        with self.assertRaises(Exception):
            MODULE.parse_capture_argument("capture.pcapng")

    def test_cross_capture_report_finds_first_response_shape_change(self) -> None:
        opaque_one = bytes(range(40, 60))
        opaque_two = bytes(range(80, 100))
        successful = [
            message(1, "OUT", 0x6C, opaque_one),
            message(2, "IN", 0x6C, b"accepted", declared_length=96),
            message(3, "OUT", 0x6C, opaque_two),
            message(4, "IN", 0x6C, b"accepted", declared_length=96),
        ]
        failed = [
            message(1, "OUT", 0x6C, opaque_one),
            message(2, "IN", 0x6C, b"accepted", declared_length=96),
            message(3, "OUT", 0x6C, opaque_two),
            message(4, "IN", 0x6C, b"failed", declared_length=44),
        ]

        report = MODULE.format_cross_capture_report(
            [("success", successful), ("failure", failed)]
        )

        self.assertIn("request_shape_first_difference=none", report)
        self.assertIn("response_shape_first_difference=2", report)
        self.assertNotIn(opaque_one.hex(), report)
        self.assertNotIn(opaque_two.hex(), report)


if __name__ == "__main__":
    unittest.main()
