import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
PROBE = ROOT / "prebuilt/libfprint-2-tod-1-broadcom-5833.probe.so"
sys.path.insert(0, str(TOOLS))

import audit_linux_bcm5880_abis as audit  # noqa: E402


def synthetic_artifact(profile: audit.ArtifactProfile) -> bytes:
    size = max(
        offset + len(profile.signatures[name])
        for name, offset in profile.expected_offsets.items()
    )
    data = bytearray(b"\xcc" * (size + 16))
    for name, signature in profile.signatures.items():
        offset = profile.expected_offsets[name]
        data[offset : offset + len(signature)] = signature
    return bytes(data)


class LinuxBcm5880AbiAuditTests(unittest.TestCase):
    def test_repository_probe_matches_exact_profile(self) -> None:
        if not PROBE.exists():
            self.skipTest("proprietary research artifact is not distributed")
        offsets = audit.validate_artifact(PROBE)
        self.assertEqual(offsets, audit.LINUX_PROBE_PROFILE.expected_offsets)

    def test_synthetic_profile_validates_at_expected_offsets(self) -> None:
        profile = audit.LINUX_PROBE_PROFILE
        data = synthetic_artifact(profile)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / profile.name
            path.write_bytes(data)
            offsets = audit.validate_artifact(
                path,
                profile,
                expected_sha256=hashlib.sha256(data).hexdigest(),
            )
        self.assertEqual(offsets, profile.expected_offsets)

    def test_wrong_hash_fails_before_signature_acceptance(self) -> None:
        profile = audit.LINUX_PROBE_PROFILE
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / profile.name
            path.write_bytes(synthetic_artifact(profile))
            with self.assertRaisesRegex(audit.AuditError, "unsupported"):
                audit.validate_artifact(path, profile)

    def test_cli_is_read_only(self) -> None:
        if not PROBE.exists():
            self.skipTest("proprietary research artifact is not distributed")
        before = PROBE.read_bytes()
        result = subprocess.run(
            [sys.executable, str(TOOLS / "audit_linux_bcm5880_abis.py"), str(PROBE)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("artifact_loaded=no", result.stdout)
        self.assertIn("artifact_write_performed=no", result.stdout)
        self.assertIn("derived.commit_enrollment.arguments=9", result.stdout)
        self.assertIn(
            "derived.commit_enrollment.output_modes=buffered_or_result_only",
            result.stdout,
        )
        self.assertIn(
            "derived.commit_enrollment.return_destinations=args_7_8_9",
            result.stdout,
        )
        self.assertEqual(before, PROBE.read_bytes())


if __name__ == "__main__":
    unittest.main()
