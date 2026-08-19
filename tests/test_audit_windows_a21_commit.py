import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import audit_windows_a21_commit as audit  # noqa: E402


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


class WindowsA21CommitAuditTests(unittest.TestCase):
    def test_synthetic_profiles_validate_at_expected_offsets(self):
        for profile in (audit.ENGINE_COMMIT_PROFILE, audit.BIP_COMMIT_PROFILE):
            with self.subTest(profile=profile.name), tempfile.TemporaryDirectory() as td:
                path = Path(td) / profile.name
                data = synthetic_artifact(profile)
                path.write_bytes(data)
                offsets = audit.validate_artifact(
                    path,
                    profile,
                    expected_sha256=hashlib.sha256(data).hexdigest(),
                )
                self.assertEqual(offsets, profile.expected_offsets)

    def test_cli_rejects_nonmatching_files_without_writing_them(self):
        with tempfile.TemporaryDirectory() as td:
            engine = Path(td) / "engine.dll"
            bip = Path(td) / "bip.dll"
            engine.write_bytes(b"not the Dell artifact")
            bip.write_bytes(b"nor is this one")
            before = (engine.read_bytes(), bip.read_bytes())
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "audit_windows_a21_commit.py"),
                    str(engine),
                    str(bip),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(before, (engine.read_bytes(), bip.read_bytes()))

    def test_profiles_encode_distinct_output_modes_and_shared_token(self):
        self.assertIn(
            "update_completion_capacity_and_commit",
            audit.ENGINE_COMMIT_PROFILE.signatures,
        )
        self.assertIn(
            "raw_commit_output_mode_validation",
            audit.BIP_COMMIT_PROFILE.signatures,
        )
        self.assertIn(
            "raw_commit_command_and_return_destinations",
            audit.BIP_COMMIT_PROFILE.signatures,
        )


if __name__ == "__main__":
    unittest.main()
