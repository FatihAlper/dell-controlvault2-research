import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]


class CaptureGetResultProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.build = Path(cls.tempdir.name)
        cls.preload = cls.build / "probe.so"
        cls.driver = cls.build / "mock-driver.so"
        cls.loader = cls.build / "mock-loader"
        flags = subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "gmodule-2.0"],
            text=True,
        ).split()
        subprocess.run(
            [
                "gcc", "-std=c11", "-fPIC", "-shared", "-Wall", "-Wextra",
                "-Werror", str(REPO / "tools/capture_get_result_probe_preload.c"),
                "-Wl,-z,defs", "-ldl", "-pthread", "-o", str(cls.preload),
            ],
            check=True,
        )
        subprocess.run(
            [
                "gcc", "-std=c11", "-fPIC", "-shared", "-Wall", "-Wextra",
                "-Werror", str(REPO / "tests/fixtures/mock_capture_result_driver.c"),
                "-o", str(cls.driver),
            ],
            check=True,
        )
        subprocess.run(
            [
                "gcc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                str(REPO / "tests/fixtures/mock_capture_result_loader.c"),
                *flags, "-ldl", "-o", str(cls.loader),
            ],
            check=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tempdir.cleanup()

    def test_exact_abi_one_native_call_and_fail_closed_boundary(self) -> None:
        env = os.environ.copy()
        env["LD_PRELOAD"] = str(self.preload)
        env["CV2_CAPTURE_RESULT_TARGET_PATH"] = str(self.driver)
        result = subprocess.run(
            [str(self.loader), str(self.driver)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("ABI arguments valid", output)
        self.assertIn("native_status=0x0 selector=1 returned_size=32", output)
        self.assertIn("payload_logged=no", output)
        self.assertIn("payload_wiped=yes", output)
        self.assertIn("UpdateEnrollment_forwarded=no", output)
        self.assertIn("additional UpdateEnrollment blocked call=2", output)
        self.assertNotIn("ERROR original update was called", output)
        self.assertNotIn("a5a5", output.lower())
        self.assertNotIn("101112", output.lower())

    def test_export_and_loader_surface_is_minimal(self) -> None:
        symbols = subprocess.check_output(
            ["nm", "-D", "--defined-only", str(self.preload)], text=True
        )
        self.assertIn("cv_fingerprint_update_enrollment", symbols)
        self.assertIn("cv2_capture_result_probe_ready", symbols)
        self.assertIn("cv2_capture_result_probe_complete", symbols)
        self.assertNotIn("cv_fingerprint_create_template", symbols)
        self.assertNotIn("cv_fingerprint_commit_enrollment", symbols)
        source = (REPO / "tools/capture_get_result_probe_preload.c").read_text()
        self.assertIn("RTLD_NOLOAD", source)
        self.assertNotIn("RTLD_NEXT", source)
        self.assertNotIn('dlsym (resolver.handle, "cv_fingerprint_create_template"', source)
        self.assertNotIn('dlsym (resolver.handle, "cv_fingerprint_commit_enrollment"', source)

    def test_runner_requires_explicit_confirmation(self) -> None:
        result = subprocess.run(
            [str(REPO / "tools/run_capture_get_result_probe.sh")],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("refusing hardware access", result.stderr)


if __name__ == "__main__":
    unittest.main()
