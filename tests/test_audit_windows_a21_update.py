import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import audit_windows_a21_update as audit  # noqa: E402


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


class WindowsA21UpdateAuditTests(unittest.TestCase):
    def test_synthetic_profiles_validate_at_expected_offsets(self):
        for profile in (
            audit.ENGINE_PROFILE,
            audit.SENSOR_PROFILE,
            audit.BIP_PROFILE,
        ):
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

    def test_wrong_hash_fails_before_signature_acceptance(self):
        profile = audit.ENGINE_PROFILE
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / profile.name
            path.write_bytes(synthetic_artifact(profile))
            with self.assertRaisesRegex(audit.AuditError, "unsupported"):
                audit.validate_artifact(path, profile)

    def test_duplicate_signature_is_rejected(self):
        profile = audit.ArtifactProfile(
            name="fixture.dll",
            sha256="",
            signatures={"anchor": b"anchor"},
            expected_offsets={"anchor": 4},
        )
        data = b"xxxxanchor-yyyy-anchor"
        profile = audit.ArtifactProfile(
            name=profile.name,
            sha256=hashlib.sha256(data).hexdigest(),
            signatures=profile.signatures,
            expected_offsets=profile.expected_offsets,
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / profile.name
            path.write_bytes(data)
            with self.assertRaisesRegex(audit.AuditError, "occurs 2 times"):
                audit.validate_artifact(path, profile)

    def test_cli_rejects_nonmatching_files_without_writing_them(self):
        with tempfile.TemporaryDirectory() as td:
            engine = Path(td) / "engine.dll"
            sensor = Path(td) / "sensor.dll"
            bip = Path(td) / "bip.dll"
            engine.write_bytes(b"not the Dell artifact")
            sensor.write_bytes(b"nor is this one")
            bip.write_bytes(b"also not the Dell artifact")
            before = (engine.read_bytes(), sensor.read_bytes(), bip.read_bytes())
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "audit_windows_a21_update.py"),
                    str(engine),
                    str(sensor),
                    str(bip),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(
                before,
                (engine.read_bytes(), sensor.read_bytes(), bip.read_bytes()),
            )


if __name__ == "__main__":
    unittest.main()
