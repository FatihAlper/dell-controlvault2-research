import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "tools" / "summarize_cv_usb_pcap.py"
SPEC = importlib.util.spec_from_file_location("summarize_cv_usb_pcap", MODULE_PATH)
summary = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = summary
SPEC.loader.exec_module(summary)


class PcapSummaryTests(unittest.TestCase):
    def test_parses_outbound_message_start_without_retaining_payload(self):
        row = (
            "2621|34.951331000|'S'|0x01|64|"
            "01000000bc0000006e004102" + "aa" * 52
        )
        parsed = summary.parse_tshark_line(row)
        self.assertEqual(parsed.direction, "OUT")
        self.assertEqual(parsed.endpoint, 0x01)
        self.assertEqual(parsed.declared_length, 0xBC)
        self.assertEqual(parsed.command, 0x6E)
        self.assertEqual(parsed.command_flags, 0x0241)
        self.assertFalse(hasattr(parsed, "payload"))

    def test_parses_inbound_message_start(self):
        row = (
            "2630|34.969705000|'C'|0x81|64|"
            "01000000ac0300006e004103" + "bb" * 52
        )
        parsed = summary.parse_tshark_line(row)
        self.assertEqual(parsed.direction, "IN")
        self.assertEqual(parsed.declared_length, 0x3AC)
        self.assertEqual(parsed.command, 0x6E)
        self.assertEqual(parsed.command_flags, 0x0341)

    def test_ignores_duplicate_usbmon_transaction_halves(self):
        outbound_complete = "1|1.0|C|0x01|0|010000002c00000039004000"
        inbound_submit = "2|1.1|S|0x81|0|010000002c00000039004001"
        self.assertIsNone(summary.parse_tshark_line(outbound_complete))
        self.assertIsNone(summary.parse_tshark_line(inbound_submit))

    def test_ignores_non_header_and_malformed_rows(self):
        self.assertIsNone(summary.parse_tshark_line("1|2|S|0x01|4|00000000"))
        self.assertIsNone(summary.parse_tshark_line("malformed"))

    def test_counts_payload_free_message_shapes(self):
        starts = [
            summary.MessageStart(1, 1.0, "OUT", 0x01, 64, 140, 0x6C, 0x0241),
            summary.MessageStart(2, 1.1, "IN", 0x81, 64, 124, 0x6C, 0x0341),
            summary.MessageStart(3, 2.0, "OUT", 0x01, 64, 140, 0x6C, 0x0241),
            summary.MessageStart(4, 2.1, "IN", 0x81, 64, 76, 0x6C, 0x0341),
        ]

        counts = summary.count_message_shapes(starts)

        self.assertEqual(
            counts,
            [
                summary.MessageCount("OUT", 140, 0x6C, 0x0241, 2),
                summary.MessageCount("IN", 76, 0x6C, 0x0341, 1),
                summary.MessageCount("IN", 124, 0x6C, 0x0341, 1),
            ],
        )
        self.assertFalse(hasattr(counts[0], "payload"))


if __name__ == "__main__":
    unittest.main()
