from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
ADAPTER_SOURCE = TOOLS / "bcm5880_linux_abi_adapter.c"
ADAPTER_HEADER = TOOLS / "bcm5880_linux_abi_adapter.h"
COMMIT_SOURCE = TOOLS / "bcm5880_generic_commit_sequence.c"
COORDINATOR_SOURCE = TOOLS / "bcm5880_enrollment_coordinator.c"
HARNESS = ROOT / "tests/fixtures/bcm5880_linux_abi_adapter_harness.c"


class Bcm5880LinuxAbiAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("gcc") is None:
            raise unittest.SkipTest("gcc is required")
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.tempdir.name) / "abi-adapter-harness"
        subprocess.run(
            [
                "gcc",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-DCV2_BCM5880_COORDINATOR_MOCK_ONLY",
                "-DCV2_BCM5880_LINUX_ABI_ADAPTER_MOCK_ONLY",
                "-DCV2_BCM5880_GENERIC_COMMIT_SEQUENCE_MOCK_ONLY",
                f"-I{TOOLS}",
                str(COORDINATOR_SOURCE),
                str(ADAPTER_SOURCE),
                str(COMMIT_SOURCE),
                str(HARNESS),
                "-o",
                str(cls.binary),
            ],
            check=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tempdir.cleanup()

    def run_scenario(self, scenario: str) -> str:
        result = subprocess.run(
            [str(self.binary), scenario],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_source_refuses_to_build_without_mock_only_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = subprocess.run(
                [
                    "gcc",
                    "-std=c11",
                    f"-I{TOOLS}",
                    "-c",
                    str(ADAPTER_SOURCE),
                    "-o",
                    str(Path(td) / "adapter.o"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Linux ABI adapter is mock-only", result.stderr)

    def test_adapter_has_no_loader_or_transport_surface(self) -> None:
        implementation = ADAPTER_SOURCE.read_text() + COMMIT_SOURCE.read_text()
        for forbidden in ("dlsym", "dlopen", "libusb", "cv_cmd_", "/dev/"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, implementation)

    def test_commit_sequence_refuses_to_build_without_mock_only_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = subprocess.run(
                [
                    "gcc",
                    "-std=c11",
                    f"-I{TOOLS}",
                    "-c",
                    str(COMMIT_SOURCE),
                    "-o",
                    str(Path(td) / "commit-sequence.o"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("generic commit sequence is mock-only", result.stderr)

    def test_header_expresses_recovered_export_abis(self) -> None:
        header = ADAPTER_HEADER.read_text()
        self.assertIn("Cv2Bcm5880CaptureGetResultNativeMock", header)
        self.assertIn("Cv2Bcm5880CreateTemplateNativeMock", header)
        self.assertIn("uint32_t feature3_size", header)
        self.assertIn("uint32_t *template_size_inout", header)
        self.assertIn("Cv2Bcm5880CommitEnrollmentNativeMock", header)
        self.assertIn("uint32_t *result_out", header)

    def test_capture_arguments_and_capacity_round_trip(self) -> None:
        output = self.run_scenario("capture")
        self.assertEqual(
            output,
            "capture status=0x0 size=288 first=0x61 calls=1\n",
        )

    def test_capture_preserves_valid_nonzero_native_status(self) -> None:
        output = self.run_scenario("capture-native-status")
        self.assertEqual(
            output,
            "capture status=0x8f size=288 first=0x61 calls=1\n",
        )

    def test_capture_overflow_is_cleared_and_rejected(self) -> None:
        output = self.run_scenario("capture-overflow")
        self.assertEqual(
            output,
            "capture status=0x47 size=0 first=0x00 calls=1\n",
        )

    def test_four_feature_native_order_integrates_but_commit_stays_blocked(self) -> None:
        output = self.run_scenario("coordinator")
        self.assertEqual(
            output,
            "coordinator outcome=2 ready=1 size=64 commit=0 terminal=1 "
            "error=none native=0x0 template_calls=1 random_calls=1\n",
        )

    def test_windows_shaped_generic_commit_runs_two_distinct_calls(self) -> None:
        self.assertEqual(
            self.run_scenario("commit"),
            "commit status=0x0 calls=2 phase1_status=0x0 "
            "phase1_result=0x1111 phase1_size=848 phase1_complete=1 "
            "phase2_status=0x0 phase2_result=0x2222 phase2_complete=1 "
            "first=0xa5\n",
        )

    def test_phase1_failure_stops_before_phase2_and_clears_output(self) -> None:
        self.assertEqual(
            self.run_scenario("commit-phase1-error"),
            "commit status=0x59 calls=1 phase1_status=0x59 "
            "phase1_result=0x0 phase1_size=0 phase1_complete=0 "
            "phase2_status=0x0 phase2_result=0x0 phase2_complete=0 "
            "first=0x00\n",
        )

    def test_phase1_overflow_is_rejected_before_phase2(self) -> None:
        self.assertEqual(
            self.run_scenario("commit-phase1-overflow"),
            "commit status=0x47 calls=1 phase1_status=0x47 "
            "phase1_result=0x1111 phase1_size=0 phase1_complete=0 "
            "phase2_status=0x0 phase2_result=0x0 phase2_complete=0 "
            "first=0x00\n",
        )

    def test_phase2_failure_clears_phase1_output(self) -> None:
        self.assertEqual(
            self.run_scenario("commit-phase2-error"),
            "commit status=0x17 calls=2 phase1_status=0x0 "
            "phase1_result=0x1111 phase1_size=0 phase1_complete=1 "
            "phase2_status=0x17 phase2_result=0x2222 phase2_complete=0 "
            "first=0x00\n",
        )

    def test_template_overflow_fails_closed_in_coordinator(self) -> None:
        output = self.run_scenario("template-overflow")
        self.assertEqual(
            output,
            "coordinator outcome=0 ready=0 size=0 commit=0 terminal=1 "
            "error=template-status native=0x47 template_calls=1 random_calls=0\n",
        )

    def test_runtime_mode_is_disabled_by_default(self) -> None:
        self.assertEqual(
            self.run_scenario("disabled"),
            "init=failed error=mock-mode-required capture_calls=0 "
            "template_calls=0\n",
        )

    def test_missing_native_function_is_rejected_before_calls(self) -> None:
        self.assertEqual(
            self.run_scenario("missing-native"),
            "init=failed error=invalid-argument capture_calls=0 "
            "template_calls=0\n",
        )


if __name__ == "__main__":
    unittest.main()
