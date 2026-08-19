from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/bcm5880_enrollment_coordinator.c"
HEADER = ROOT / "tools/bcm5880_enrollment_coordinator.h"
HARNESS = ROOT / "tests/fixtures/bcm5880_coordinator_harness.c"


class Bcm5880EnrollmentCoordinatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("gcc") is None:
            raise unittest.SkipTest("gcc is required")
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.tempdir.name) / "coordinator-harness"
        subprocess.run(
            [
                "gcc",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-DCV2_BCM5880_COORDINATOR_MOCK_ONLY",
                f"-I{ROOT / 'tools'}",
                str(SOURCE),
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
                    f"-I{ROOT / 'tools'}",
                    "-c",
                    str(SOURCE),
                    "-o",
                    str(Path(td) / "coordinator.o"),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("coordinator is mock-only", result.stderr)

    def test_core_has_no_driver_loader_or_transport_surface(self) -> None:
        source = SOURCE.read_text()
        for forbidden in (
            "dlsym",
            "dlopen",
            "libusb",
            "cv_fingerprint_",
            "cv_cmd_",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_public_operations_expose_no_commit_callback(self) -> None:
        header = HEADER.read_text()
        self.assertNotIn("CommitEnrollmentMock", header)
        self.assertNotIn("commit_enrollment", header)

    def test_three_features_buffer_without_template_or_commit(self) -> None:
        output = self.run_scenario("three-only")
        self.assertIn("feature=3 outcome=1", output)
        self.assertIn(
            "final buffered=3 ready=0 template_size=0 commit_permitted=0 "
            "terminal=0 error=none native=0x0 template_calls=0 random_calls=0",
            output,
        )

    def test_fourth_feature_creates_template_but_blocks_commit(self) -> None:
        output = self.run_scenario("happy")
        self.assertIn("feature=4 outcome=2", output)
        self.assertIn(
            "final buffered=0 ready=1 template_size=64 commit_permitted=0 "
            "terminal=1 error=none native=0x0 template_calls=1 random_calls=1",
            output,
        )
        self.assertIn("post-ready-outcome=0", output)
        self.assertIn("error=terminal", output)

    def test_id_mismatch_is_rejected_without_consuming_a_slot(self) -> None:
        output = self.run_scenario("id-mismatch")
        self.assertIn("mismatch_outcome=0", output)
        self.assertIn(
            "after-mismatch buffered=0 ready=0 template_size=0 "
            "commit_permitted=0 terminal=0 error=id-mismatch",
            output,
        )
        self.assertIn("feature=4 outcome=2", output)

    def test_oversize_feature_fails_closed_before_template(self) -> None:
        output = self.run_scenario("oversize")
        self.assertIn("oversize_outcome=0", output)
        self.assertIn(
            "terminal=1 error=feature-size native=0x0 "
            "template_calls=0 random_calls=0",
            output,
        )

    def test_template_error_is_terminal_and_never_generates_token(self) -> None:
        output = self.run_scenario("template-error")
        self.assertIn("feature=4 outcome=0", output)
        self.assertIn(
            "ready=0 template_size=0 commit_permitted=0 terminal=1 "
            "error=template-status native=0x59 template_calls=1 random_calls=0",
            output,
        )

    def test_invalid_template_size_fails_closed(self) -> None:
        output = self.run_scenario("template-oversize")
        self.assertIn("feature=4 outcome=0", output)
        self.assertIn(
            "ready=0 template_size=0 commit_permitted=0 terminal=1 "
            "error=template-size native=0x0 template_calls=1 random_calls=0",
            output,
        )

    def test_random_failure_does_not_mark_template_ready(self) -> None:
        output = self.run_scenario("random-error")
        self.assertIn("feature=4 outcome=0", output)
        self.assertIn(
            "ready=0 template_size=0 commit_permitted=0 terminal=1 "
            "error=token-random native=0x0 template_calls=1 random_calls=1",
            output,
        )

    def test_runtime_mode_is_disabled_by_default(self) -> None:
        output = self.run_scenario("disabled")
        self.assertEqual(
            output,
            "init=failed error=mock-mode-required template_calls=0 "
            "random_calls=0\n",
        )

    def test_missing_mock_operation_is_rejected_before_any_callback(self) -> None:
        output = self.run_scenario("missing-operations")
        self.assertEqual(
            output,
            "init=failed error=invalid-argument template_calls=0 "
            "random_calls=0\n",
        )


if __name__ == "__main__":
    unittest.main()
