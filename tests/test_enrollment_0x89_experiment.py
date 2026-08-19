from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
INTERPOSER_SOURCE = REPO / "tools/enrollment_0x89_rearm_preload.c"
MODULE_PATH = REPO / "tools/enrollment_0x89_target.py"
FIXTURES = REPO / "tests/fixtures"

SPEC = importlib.util.spec_from_file_location("enrollment_target", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
TARGET_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TARGET_MODULE)


class Enrollment089ExperimentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        for command in ("gcc", "nm", "pkg-config"):
            if shutil.which(command) is None:
                raise unittest.SkipTest(f"{command} is required")
        if subprocess.run(
            ["pkg-config", "--exists", "gmodule-2.0"], check=False
        ).returncode:
            raise unittest.SkipTest("gmodule-2.0 is required")

        cls.tempdir = tempfile.TemporaryDirectory()
        cls.build = Path(cls.tempdir.name)
        cls.mock_driver = cls.build / "libmockcv2.so"
        cls.preload = cls.build / "libcv2-enrollment-0x89-rearm.so"
        cls.old_preload = cls.build / "libold-rtld-next.so"
        cls.loader = cls.build / "mock-local-loader"
        cls.wrong_owner = cls.build / "libwrong-owner.so"
        cls.wrong_owner_driver = cls.build / "libmock-wrong-owner.so"
        cls.self_driver = cls.build / "libmock-self-resolution.so"
        cls.synthetic_target = cls.build / "synthetic-target.bin"

        synthetic = bytearray(b"CV2-INTEROPERABILITY-TEST\0")
        synthetic.extend(bytes.fromhex(TARGET_MODULE.EXPECTED_BUILD_ID))
        synthetic.extend(b"\0BUILD-ID-END\0")
        for name, signature in TARGET_MODULE.SIGNATURES.items():
            synthetic.extend(name.encode("ascii"))
            synthetic.extend(b"\0")
            synthetic.extend(signature)
            synthetic.extend(b"\0SIGNATURE-END\0")
        cls.synthetic_target.write_bytes(synthetic)
        cls.synthetic_target_sha256 = hashlib.sha256(synthetic).hexdigest()

        common = ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror"]
        subprocess.run(
            [
                *common,
                "-fPIC",
                "-shared",
                str(FIXTURES / "mock_cv2_driver.c"),
                "-Wl,-z,defs",
                "-o",
                str(cls.mock_driver),
            ],
            check=True,
        )
        subprocess.run(
            [
                *common,
                "-fPIC",
                "-shared",
                str(INTERPOSER_SOURCE),
                "-Wl,-z,defs",
                "-ldl",
                "-pthread",
                "-o",
                str(cls.preload),
            ],
            check=True,
        )
        subprocess.run(
            [
                *common,
                "-fPIC",
                "-shared",
                str(FIXTURES / "old_rtld_next_preload.c"),
                "-Wl,-z,defs",
                "-ldl",
                "-o",
                str(cls.old_preload),
            ],
            check=True,
        )
        gmodule_flags = subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "gmodule-2.0"],
            text=True,
        ).split()
        subprocess.run(
            [
                *common,
                str(FIXTURES / "mock_local_loader.c"),
                *gmodule_flags,
                "-ldl",
                "-o",
                str(cls.loader),
            ],
            check=True,
        )
        subprocess.run(
            [
                *common,
                "-fPIC",
                "-shared",
                str(FIXTURES / "mock_wrong_owner.c"),
                "-o",
                str(cls.wrong_owner),
            ],
            check=True,
        )
        subprocess.run(
            [
                *common,
                "-fPIC",
                "-shared",
                "-DOMIT_REARM",
                str(FIXTURES / "mock_cv2_driver.c"),
                f"-L{cls.build}",
                "-Wl,--no-as-needed",
                "-lwrong-owner",
                "-Wl,-rpath,$ORIGIN",
                "-o",
                str(cls.wrong_owner_driver),
            ],
            check=True,
        )
        subprocess.run(
            [
                *common,
                "-fPIC",
                "-shared",
                str(FIXTURES / "mock_self_resolution.c"),
                "-ldl",
                "-o",
                str(cls.self_driver),
            ],
            check=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tempdir.cleanup()

    def run_loader(
        self,
        *,
        plugin: Path | None = None,
        preload: Path | None = None,
        target: Path | None = None,
        mode: str = "ready-success",
        **values: str,
    ) -> subprocess.CompletedProcess[str]:
        selected_plugin = plugin or self.mock_driver
        env = os.environ.copy()
        env.update(values)
        env["LD_PRELOAD"] = str(preload or self.preload)
        env["CV2_0X89_TARGET_PATH"] = str(target or selected_plugin.resolve())
        return subprocess.run(
            [str(self.loader), str(selected_plugin), mode],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=5,
        )

    def test_old_rtld_next_reproduces_local_scope_failure(self) -> None:
        result = self.run_loader(
            preload=self.old_preload,
            mode="run-without-ready",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "RTLD_NEXT failed for local-scope target", result.stdout
        )
        self.assertNotIn("command 0x6C", result.stdout)

    def test_local_scope_target_handle_and_symbols_are_ready(self) -> None:
        result = self.run_loader(MOCK_FIRST_UPDATE_STATUS="0")
        self.assertEqual(result.returncode, 0, result.stdout)
        for marker in (
            "plugin loaded with G_MODULE_BIND_LOCAL",
            "expected target path:",
            "loaded target discovered:",
            "RTLD_NOLOAD handle acquired",
            "original symbol resolved from target handle: "
            "cv_fingerprint_update_enrollment",
            "original symbol resolved from target handle: "
            "cv_cmd_enrollment_started",
            "dladdr target verification passed",
            "local-scope forwarding ready",
            "readiness=ready",
            "command 0x6C status=0x0",
        ):
            self.assertIn(marker, result.stdout)
        self.assertNotIn("RTLD_NEXT failed", result.stdout)

    def test_plugin_not_loaded_fails_closed_without_loading_it(self) -> None:
        result = self.run_loader(mode="no-load-ready-failure")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("expected target is not present", result.stdout)
        self.assertIn("refusing operation before hardware command", result.stdout)
        self.assertIn("target remains unloaded after readiness", result.stdout)
        self.assertNotIn("command 0x6C", result.stdout)

    def test_wrong_target_path_is_rejected_before_run(self) -> None:
        result = self.run_loader(
            target=self.build / "does-not-exist.so",
            mode="ready-failure",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("invalid or missing CV2_0X89_TARGET_PATH", result.stdout)
        self.assertIn("readiness=failed", result.stdout)
        self.assertNotIn("command 0x6C", result.stdout)

    def test_symbol_from_dependency_is_rejected_by_dladdr(self) -> None:
        result = self.run_loader(
            plugin=self.wrong_owner_driver,
            mode="ready-failure",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "cv_cmd_enrollment_started belongs to unexpected DSO",
            result.stdout,
        )
        self.assertIn("readiness=failed", result.stdout)
        self.assertNotIn("unexpected 0x8A dependency called", result.stdout)

    def test_wrapper_self_resolution_is_rejected_without_recursion(self) -> None:
        result = self.run_loader(
            plugin=self.self_driver,
            mode="ready-failure",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "resolved to the interposer wrapper; refusing recursion",
            result.stdout,
        )
        self.assertEqual(result.stdout.count("symbol resolution failed:"), 1)
        self.assertNotIn("command 0x6C", result.stdout)

    def test_0x89_rearms_then_normal_plugin_capture_runs_0x66_and_0x6c(
        self,
    ) -> None:
        result = self.run_loader(
            MOCK_FIRST_UPDATE_STATUS="0x89",
            MOCK_REARM_STATUS="0",
            MOCK_SECOND_UPDATE_STATUS="0",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        markers = [
            "command 0x6C status=0x89",
            "0x89 bad capture received",
            "re-arming enrollment with command 0x8A",
            "command 0x8A status=0x0",
            "0x8A completed successfully",
            "callback status=0x89 state=1",
            "command 0x66 status=0x0",
            "command 0x6C status=0x0",
            "final_status=0x0",
        ]
        positions = [result.stdout.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions), result.stdout)
        self.assertNotIn("fatal discard", result.stdout)

    def test_native_success_calls_update_once_and_is_bit_exact(self) -> None:
        result = self.run_loader(MOCK_FIRST_UPDATE_STATUS="0")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("final_status=0x0", result.stdout)
        self.assertIn("counters update=1 enrollment_started=0", result.stdout)
        self.assertEqual(result.stdout.count("command 0x6C"), 1)
        self.assertNotIn("0x59 UpdateEnrollment result received", result.stdout)

    def test_invalid_update_policy_fails_before_hardware_command(self) -> None:
        result = self.run_loader(
            CV2_ENROLLMENT_UPDATE_POLICY="not-a-policy",
            mode="ready-failure",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("invalid CV2_ENROLLMENT_UPDATE_POLICY", result.stdout)
        self.assertIn("readiness=failed", result.stdout)
        self.assertNotIn("command 0x6C", result.stdout)

    def test_metadata_trace_is_disabled_by_default(self) -> None:
        result = self.run_loader(MOCK_FIRST_UPDATE_STATUS="0")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("[cv2-update-metadata] selected=disabled", result.stdout)
        self.assertNotIn("phase=before", result.stdout)
        self.assertNotIn("phase=after", result.stdout)

    def test_invalid_metadata_trace_fails_before_hardware_command(self) -> None:
        result = self.run_loader(
            CV2_UPDATE_METADATA_TRACE="verbose",
            mode="ready-failure",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("invalid CV2_UPDATE_METADATA_TRACE", result.stdout)
        self.assertIn("readiness=failed", result.stdout)
        self.assertNotIn("command 0x6C", result.stdout)

    def test_metadata_trace_reports_relations_without_values(self) -> None:
        result = self.run_loader(
            CV2_UPDATE_METADATA_TRACE="1",
            CV2_ENROLLMENT_UPDATE_POLICY=(
                "fresh-rearm-stop-before-commit"
            ),
            MOCK_FIRST_UPDATE_STATUS="0",
            MOCK_SECOND_UPDATE_STATUS="0x59",
            MOCK_FIRST_COMPLETION="0",
            MOCK_SEQUENTIAL_UPDATE_COUNT="2",
            MOCK_ZERO_AUXILIARY_INPUT="1",
            MOCK_CHANGE_ENROLLMENT_ID_EACH_UPDATE="1",
            MOCK_FIRST_OUTPUT_BYTE="0x53",
            MOCK_FIRST_OUTPUT_VALUE="0x54555657",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        metadata = "\n".join(
            line
            for line in result.stdout.splitlines()
            if "[cv2-update-metadata]" in line
        )
        for marker in (
            "selected=enabled",
            "call=1 phase=before handle_relation=first",
            "enrollment_id_content_relation=first",
            "auxiliary_size=0 auxiliary_presence=null",
            "call=1 phase=after native_status=0x0",
            "completion_post_zero=yes completion_changed=yes",
            "enrollment_output_changed=yes",
            "output_value_changed=yes",
            "call=2 phase=before handle_relation=same",
            "enrollment_id_pointer_relation=same",
            "enrollment_id_content_relation=changed",
            "enrollment_id_matches_previous_output=no",
            "call=2 phase=after native_status=0x59",
        ):
            self.assertIn(marker, metadata)
        self.assertNotIn("0x53", metadata)
        self.assertNotIn("0x54555657", metadata)

    def test_metadata_trace_detects_previous_output_as_next_id(self) -> None:
        result = self.run_loader(
            CV2_UPDATE_METADATA_TRACE="1",
            CV2_ENROLLMENT_UPDATE_POLICY=(
                "fresh-rearm-stop-before-commit"
            ),
            MOCK_FIRST_UPDATE_STATUS="0",
            MOCK_SECOND_UPDATE_STATUS="0x59",
            MOCK_FIRST_COMPLETION="0",
            MOCK_SEQUENTIAL_UPDATE_COUNT="2",
            MOCK_COPY_OUTPUT_TO_NEXT_ID="1",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "call=2 phase=before handle_relation=same",
            result.stdout,
        )
        self.assertIn(
            "enrollment_id_matches_previous_output=yes",
            result.stdout,
        )

    def test_fresh_policy_preserves_0x59_without_replay(self) -> None:
        result = self.run_loader(
            CV2_ENROLLMENT_UPDATE_POLICY="fresh-stop-before-commit",
            MOCK_FIRST_UPDATE_STATUS="0x59",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        for marker in (
            "selected=fresh-stop-before-commit",
            "native UpdateEnrollment status=0x59",
            "preserving native 0x59 without same-update replay",
            "callback status=0x59 state=1",
            "counters update=1 enrollment_started=0 capture=0 "
            "cancel=1 discard=1",
            "final_status=0x59",
        ):
            self.assertIn(marker, result.stdout)
        self.assertEqual(result.stdout.count("command 0x6C"), 1)
        self.assertNotIn("retrying the same UpdateEnrollment", result.stdout)

    def test_fresh_policy_passes_incomplete_native_success(self) -> None:
        result = self.run_loader(
            CV2_ENROLLMENT_UPDATE_POLICY="fresh-stop-before-commit",
            MOCK_FIRST_UPDATE_STATUS="0",
            MOCK_FIRST_COMPLETION="0",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("native UpdateEnrollment status=0x0", result.stdout)
        self.assertIn("final_status=0x0", result.stdout)
        self.assertIn("counters update=1", result.stdout)
        self.assertNotIn("blocking state 2", result.stdout)
        self.assertNotIn("fatal discard", result.stdout)

    def test_fresh_policy_blocks_native_completion_before_commit(self) -> None:
        result = self.run_loader(
            CV2_ENROLLMENT_UPDATE_POLICY="fresh-stop-before-commit",
            MOCK_FIRST_UPDATE_STATUS="0",
            MOCK_FIRST_COMPLETION="1",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        markers = [
            "command 0x6C status=0x0",
            "native completion=0x01",
            "native completion boundary observed; blocking state 2 and "
            "generic commit",
            "existing fatal capture-cancel path",
            "callback status=0x100003 state=1",
            "existing fatal discard path",
            "counters update=1 enrollment_started=0 capture=0 "
            "cancel=1 discard=1",
            "final_status=0x100003",
        ]
        positions = [result.stdout.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions), result.stdout)
        self.assertEqual(result.stdout.count("command 0x6C"), 1)

    def test_fresh_rearm_policy_rearms_accepted_incomplete_update(self) -> None:
        result = self.run_loader(
            CV2_ENROLLMENT_UPDATE_POLICY=(
                "fresh-rearm-stop-before-commit"
            ),
            MOCK_FIRST_UPDATE_STATUS="0",
            MOCK_FIRST_COMPLETION="0",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        markers = [
            "command 0x6C status=0x0",
            "accepted incomplete update; accepted=1/4",
            "re-arming accepted incomplete enrollment with command 0x8A",
            "command 0x8A status=0x0",
            "0x8A completed successfully",
            "callback status=0x0 state=1",
            "counters update=1 enrollment_started=1 capture=0 "
            "cancel=0 discard=0",
            "final_status=0x0",
        ]
        positions = [result.stdout.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions), result.stdout)

    def test_fresh_rearm_policy_blocks_completion_before_rearm(self) -> None:
        result = self.run_loader(
            CV2_ENROLLMENT_UPDATE_POLICY=(
                "fresh-rearm-stop-before-commit"
            ),
            MOCK_FIRST_UPDATE_STATUS="0",
            MOCK_FIRST_COMPLETION="1",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("blocking state 2 and generic commit", result.stdout)
        self.assertIn("final_status=0x100003", result.stdout)
        self.assertIn(
            "counters update=1 enrollment_started=0 capture=0 "
            "cancel=1 discard=1",
            result.stdout,
        )
        self.assertNotIn("command 0x8A", result.stdout)

    def test_fresh_rearm_policy_fails_closed_on_rearm_error(self) -> None:
        result = self.run_loader(
            CV2_ENROLLMENT_UPDATE_POLICY=(
                "fresh-rearm-stop-before-commit"
            ),
            MOCK_FIRST_UPDATE_STATUS="0",
            MOCK_FIRST_COMPLETION="0",
            MOCK_REARM_STATUS="0x42",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("0x8A failed with status 0x42", result.stdout)
        self.assertIn("final_status=0x42", result.stdout)
        self.assertIn(
            "counters update=1 enrollment_started=1 capture=0 "
            "cancel=1 discard=1",
            result.stdout,
        )

    def test_fresh_rearm_policy_stops_at_four_incomplete_updates(self) -> None:
        result = self.run_loader(
            CV2_ENROLLMENT_UPDATE_POLICY=(
                "fresh-rearm-stop-before-commit"
            ),
            MOCK_FIRST_UPDATE_STATUS="0",
            MOCK_FIRST_COMPLETION="0",
            MOCK_SECOND_UPDATE_STATUS="0",
            MOCK_SECOND_COMPLETION="0",
            MOCK_SEQUENTIAL_UPDATE_COUNT="4",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("accepted incomplete update; accepted=4/4", result.stdout)
        self.assertIn(
            "accepted-update limit reached without native completion; "
            "blocking another capture",
            result.stdout,
        )
        self.assertIn("final_status=0x100003", result.stdout)
        self.assertIn(
            "counters update=4 enrollment_started=3 capture=3 "
            "cancel=1 discard=1",
            result.stdout,
        )
        self.assertEqual(result.stdout.count("command 0x8A status=0x0"), 3)
        self.assertEqual(result.stdout.count("command 0x66 status=0x0"), 3)

    def test_zero_input_policy_substitutes_one_stable_zero_buffer(self) -> None:
        result = self.run_loader(
            CV2_ENROLLMENT_UPDATE_POLICY=(
                "zero-input-fresh-rearm-stop-before-commit"
            ),
            CV2_UPDATE_METADATA_TRACE="1",
            MOCK_REQUIRE_ZERO_ENROLLMENT_ID="1",
            MOCK_MUTATE_FIRST_ENROLLMENT_ID="1",
            MOCK_INITIAL_ENROLLMENT_ID_BYTE="0x7a",
            MOCK_CHANGE_ENROLLMENT_ID_EACH_UPDATE="1",
            MOCK_FIRST_UPDATE_STATUS="0",
            MOCK_SECOND_UPDATE_STATUS="0",
            MOCK_FIRST_COMPLETION="0",
            MOCK_SECOND_COMPLETION="0",
            MOCK_SEQUENTIAL_UPDATE_COUNT="2",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        for marker in (
            "selected=zero-input-fresh-rearm-stop-before-commit",
            "native UpdateEnrollment call=1/24 input=stable-zero-20 "
            "source_bytes_read=no",
            "native UpdateEnrollment call=2/24 input=stable-zero-20 "
            "source_bytes_read=no",
            "call=2 phase=before handle_relation=same",
            "enrollment_id_pointer_relation=same",
            "enrollment_id_content_relation=same",
            "mutated first update input",
            "accepted incomplete update; accepted=2/4",
            "counters update=2 enrollment_started=2 capture=1 "
            "cancel=0 discard=0",
        ):
            self.assertIn(marker, result.stdout)
        self.assertEqual(result.stdout.count("update input_zero=yes"), 2)
        self.assertNotIn("0x7a", result.stdout.lower())
        self.assertNotIn("retrying the same UpdateEnrollment", result.stdout)

    def test_zero_input_policy_blocks_completion_before_commit(self) -> None:
        result = self.run_loader(
            CV2_ENROLLMENT_UPDATE_POLICY=(
                "zero-input-fresh-rearm-stop-before-commit"
            ),
            MOCK_REQUIRE_ZERO_ENROLLMENT_ID="1",
            MOCK_INITIAL_ENROLLMENT_ID_BYTE="0x7a",
            MOCK_FIRST_UPDATE_STATUS="0",
            MOCK_FIRST_COMPLETION="1",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("update input_zero=yes", result.stdout)
        self.assertIn("blocking state 2 and generic commit", result.stdout)
        self.assertIn("final_status=0x100003", result.stdout)
        self.assertIn(
            "counters update=1 enrollment_started=0 capture=0 "
            "cancel=1 discard=1",
            result.stdout,
        )
        self.assertNotIn("command 0x8A", result.stdout)

    def test_zero_input_policy_preserves_native_0x59_without_replay(self) -> None:
        result = self.run_loader(
            CV2_ENROLLMENT_UPDATE_POLICY=(
                "zero-input-fresh-rearm-stop-before-commit"
            ),
            MOCK_REQUIRE_ZERO_ENROLLMENT_ID="1",
            MOCK_INITIAL_ENROLLMENT_ID_BYTE="0x7a",
            MOCK_FIRST_UPDATE_STATUS="0x59",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        for marker in (
            "update input_zero=yes",
            "native UpdateEnrollment status=0x59",
            "preserving native 0x59 without same-update replay",
            "counters update=1 enrollment_started=0 capture=0 "
            "cancel=1 discard=1",
            "final synthetic outputs completion=0x31 output_byte=0x40 "
            "output_value=0x51525354",
            "final_status=0x59",
        ):
            self.assertIn(marker, result.stdout)
        self.assertEqual(result.stdout.count("command 0x6C"), 1)
        self.assertNotIn("retrying the same UpdateEnrollment", result.stdout)
        self.assertNotIn("command 0x8A", result.stdout)

    def test_zero_input_policy_rejects_null_source_before_native_call(self) -> None:
        result = self.run_loader(
            CV2_ENROLLMENT_UPDATE_POLICY=(
                "zero-input-fresh-rearm-stop-before-commit"
            ),
            MOCK_NULL_ENROLLMENT_ID="1",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("required source input is null", result.stdout)
        self.assertIn("final_status=0x100003", result.stdout)
        self.assertIn(
            "counters update=0 enrollment_started=0 capture=0 "
            "cancel=1 discard=1",
            result.stdout,
        )
        self.assertNotIn("command 0x6C", result.stdout)

    def test_0x8a_failure_uses_existing_fatal_paths_once(self) -> None:
        result = self.run_loader(
            MOCK_FIRST_UPDATE_STATUS="0x89",
            MOCK_REARM_STATUS="0x42",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("0x8A failed with status 0x42", result.stdout)
        self.assertEqual(
            result.stdout.count("existing fatal capture-cancel path"), 1
        )
        self.assertEqual(result.stdout.count("existing fatal discard path"), 1)
        self.assertNotIn("command 0x66", result.stdout)
        self.assertEqual(result.stdout.count("command 0x6C"), 1)

    def test_retry_class_0x8a_failure_is_fatalized(self) -> None:
        result = self.run_loader(
            MOCK_FIRST_UPDATE_STATUS="0x89",
            MOCK_REARM_STATUS="0x89",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("callback status=0x100003 state=1", result.stdout)
        self.assertEqual(
            result.stdout.count("existing fatal capture-cancel path"), 1
        )
        self.assertEqual(result.stdout.count("existing fatal discard path"), 1)
        self.assertNotIn("command 0x66", result.stdout)

    def test_unrelated_update_statuses_are_bit_exact(self) -> None:
        for status in (0, 0xA4, 0x8D, 0x24, 0x8F, 0xFFFFFFFF):
            with self.subTest(status=hex(status)):
                result = self.run_loader(
                    MOCK_FIRST_UPDATE_STATUS=hex(status)
                )
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertIn(f"final_status=0x{status:x}", result.stdout)
                self.assertIn("counters update=1", result.stdout)
                self.assertNotIn("command 0x8A", result.stdout)
                self.assertNotIn("re-arming enrollment", result.stdout)

    def test_0x59_then_success_calls_same_update_twice(self) -> None:
        result = self.run_loader(
            MOCK_FIRST_UPDATE_STATUS="0x59",
            MOCK_SECOND_UPDATE_STATUS="0",
            MOCK_FIRST_COMPLETION="0x52",
            MOCK_FIRST_OUTPUT_BYTE="0x53",
            MOCK_FIRST_OUTPUT_VALUE="0x54555657",
            MOCK_SECOND_COMPLETION="0x62",
            MOCK_SECOND_OUTPUT_BYTE="0x63",
            MOCK_SECOND_OUTPUT_VALUE="0x64656667",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        markers = [
            "command 0x6C status=0x59",
            "0x59 UpdateEnrollment result received",
            "first completion=0x52 enrollment_output=<redacted> "
            "output_value=<redacted>",
            "retrying the same UpdateEnrollment once",
            "update argument identity=same",
            "command 0x6C status=0x0",
            "second UpdateEnrollment status=0x0",
            "second completion=0x62 enrollment_output=<redacted> "
            "output_value=<redacted>",
            "passing second native status to existing Linux state machine",
            "callback status=0x0 state=1",
            "counters update=2 enrollment_started=0 capture=0 "
            "cancel=0 discard=0",
            "final_status=0x0",
        ]
        positions = [result.stdout.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions), result.stdout)
        self.assertNotIn("command 0x8A", result.stdout)

    def test_0x59_retry_does_not_modify_output_fields_itself(self) -> None:
        result = self.run_loader(
            MOCK_FIRST_UPDATE_STATUS="0x59",
            MOCK_SECOND_UPDATE_STATUS="0",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        expected = (
            "completion=0x31 enrollment_output=<redacted> "
            "output_value=<redacted>"
        )
        self.assertIn(f"first {expected}", result.stdout)
        self.assertIn(f"second {expected}", result.stdout)
        self.assertIn(
            "final synthetic outputs completion=0x31 output_byte=0x40 "
            "output_value=0x51525354",
            result.stdout,
        )

    def test_0x59_then_0x89_rearms_once_and_returns_native_0x89(
        self,
    ) -> None:
        result = self.run_loader(
            MOCK_FIRST_UPDATE_STATUS="0x59",
            MOCK_SECOND_UPDATE_STATUS="0x89",
            MOCK_REARM_STATUS="0",
            MOCK_DEFER_CAPTURE_COMPLETION="1",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        markers = [
            "command 0x6C status=0x59",
            "retrying the same UpdateEnrollment once",
            "command 0x6C status=0x89",
            "second UpdateEnrollment status=0x89",
            "passing second native status to existing Linux state machine",
            "0x89 bad capture received",
            "command 0x8A status=0x0",
            "0x8A completed successfully",
            "callback status=0x89 state=1",
            "command 0x66 status=0x0",
            "counters update=2 enrollment_started=1 capture=1 "
            "cancel=0 discard=0",
            "final_status=0x89",
        ]
        positions = [result.stdout.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions), result.stdout)
        self.assertEqual(
            result.stdout.count("[mock-cv2] command 0x8A status=0x0"), 1
        )

    def test_0x59_then_0xa4_is_bit_exact_without_third_update(self) -> None:
        result = self.run_loader(
            MOCK_FIRST_UPDATE_STATUS="0x59",
            MOCK_SECOND_UPDATE_STATUS="0xA4",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("second UpdateEnrollment status=0xa4", result.stdout)
        self.assertIn("final_status=0xa4", result.stdout)
        self.assertIn(
            "counters update=2 enrollment_started=0 capture=0 "
            "cancel=0 discard=0",
            result.stdout,
        )
        self.assertEqual(result.stdout.count("command 0x6C"), 2)
        self.assertNotIn("command 0x8A", result.stdout)

    def test_second_0x59_reaches_existing_fatal_paths_once(self) -> None:
        result = self.run_loader(
            MOCK_FIRST_UPDATE_STATUS="0x59",
            MOCK_SECOND_UPDATE_STATUS="0x59",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "second 0x59 received; retry limit reached", result.stdout
        )
        self.assertIn("final_status=0x59", result.stdout)
        self.assertIn(
            "counters update=2 enrollment_started=0 capture=0 "
            "cancel=1 discard=1",
            result.stdout,
        )
        self.assertEqual(result.stdout.count("command 0x6C"), 2)
        self.assertEqual(
            result.stdout.count("existing fatal capture-cancel path"), 1
        )
        self.assertEqual(result.stdout.count("existing fatal discard path"), 1)
        self.assertNotIn("command 0x8A", result.stdout)

    def test_0x59_then_other_fatal_status_is_unchanged(self) -> None:
        result = self.run_loader(
            MOCK_FIRST_UPDATE_STATUS="0x59",
            MOCK_SECOND_UPDATE_STATUS="0x42",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("second UpdateEnrollment status=0x42", result.stdout)
        self.assertIn("final_status=0x42", result.stdout)
        self.assertIn(
            "counters update=2 enrollment_started=0 capture=0 "
            "cancel=1 discard=1",
            result.stdout,
        )
        self.assertEqual(result.stdout.count("command 0x6C"), 2)
        self.assertNotIn("command 0x8A", result.stdout)

    def test_interposition_surface_excludes_capture_commit_and_verify(
        self,
    ) -> None:
        symbols = subprocess.check_output(
            ["nm", "-D", "--defined-only", str(self.preload)],
            text=True,
        )
        self.assertIn("cv_fingerprint_update_enrollment", symbols)
        self.assertIn("cv2_0x89_forwarding_ready", symbols)
        for excluded in (
            "cv_fingerprint_capture_start",
            "cvif_fingerprint_start_enrollment",
            "cvif_fingerprint_commit_enrollment",
            "cvif_fingerprint_verify",
            "cv_fingerprint_capture_cancel",
            "cv_fingerprint_discard_enrollment",
        ):
            self.assertNotIn(excluded, symbols)
        self.assertNotIn(
            "dlsym (RTLD_NEXT", INTERPOSER_SOURCE.read_text(encoding="utf-8")
        )

    def test_hardware_harness_requires_readiness_before_usb_enumeration(
        self,
    ) -> None:
        harness = (
            REPO / "tools/cv_tod_enrollment_experiment.c"
        ).read_text(encoding="utf-8")
        runner = (
            REPO / "tools/run_local_enrollment_0x89_test.sh"
        ).read_text(encoding="utf-8")
        positions = [
            harness.index("context = fp_context_new"),
            harness.index("if (!forwarding_ready ())"),
            harness.index("fp_context_enumerate (context)"),
            harness.index("fp_device_open_sync"),
            harness.index("fp_device_enroll ("),
        ]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('TARGET_CANONICAL="$(realpath -e "$TARGET")"', runner)
        self.assertIn(
            'export CV2_0X89_TARGET_PATH="$TARGET_CANONICAL"', runner
        )
        self.assertIn(
            "enrollment-0x59-single-update-retry-$STAMP.log", runner
        )
        self.assertIn(
            "experiment=bounded single repeated UpdateEnrollment after "
            "native 0x59",
            runner,
        )
        self.assertIn(
            "multiple enrollment boundary modes selected; refusing ambiguity",
            runner,
        )
        self.assertIn("--trace-update-metadata", runner)
        self.assertIn(
            'export CV2_UPDATE_METADATA_TRACE="$TRACE_METADATA"',
            runner,
        )

    def test_exact_target_validates_and_restore_is_a_noop(self) -> None:
        before = hashlib.sha256(self.synthetic_target.read_bytes()).hexdigest()
        offsets = TARGET_MODULE.validate_target(
            self.synthetic_target,
            expected_sha256=self.synthetic_target_sha256,
        )
        after = hashlib.sha256(self.synthetic_target.read_bytes()).hexdigest()

        self.assertEqual(before, self.synthetic_target_sha256)
        self.assertEqual(after, before)
        self.assertEqual(set(offsets), set(TARGET_MODULE.SIGNATURES))
        self.assertEqual(list(offsets.values()), sorted(offsets.values()))

    def test_wrong_binary_hash_is_rejected(self) -> None:
        changed = self.build / "changed-target.bin"
        data = bytearray(self.synthetic_target.read_bytes())
        data[-1] ^= 1
        changed.write_bytes(data)
        with self.assertRaises(TARGET_MODULE.TargetValidationError):
            TARGET_MODULE.validate_target(
                changed,
                expected_sha256=self.synthetic_target_sha256,
            )

    def test_wrong_build_id_is_rejected_even_with_matching_test_hash(
        self,
    ) -> None:
        changed = self.build / "changed-build-id.bin"
        data = bytearray(self.synthetic_target.read_bytes())
        build_id = bytes.fromhex(TARGET_MODULE.EXPECTED_BUILD_ID)
        offset = data.index(build_id)
        data[offset] ^= 1
        changed.write_bytes(data)
        with self.assertRaisesRegex(
            TARGET_MODULE.TargetValidationError, "Build ID"
        ):
            TARGET_MODULE.validate_target(
                changed,
                expected_sha256=hashlib.sha256(data).hexdigest(),
            )

    def test_duplicate_preload_is_rejected(self) -> None:
        existing = f"{self.build / 'unrelated.so'}:{self.preload}"
        with self.assertRaises(TARGET_MODULE.TargetValidationError):
            TARGET_MODULE.prepend_once(existing, self.preload)

    def test_two_builds_are_idempotent_and_preserve_target(self) -> None:
        target_before = hashlib.sha256(
            self.synthetic_target.read_bytes()
        ).hexdigest()
        artifacts = [self.build / "build-one.so", self.build / "build-two.so"]
        for artifact in artifacts:
            subprocess.run(
                [
                    "gcc",
                    "-std=c11",
                    "-fPIC",
                    "-shared",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(INTERPOSER_SOURCE),
                    "-Wl,-z,defs",
                    "-Wl,-z,relro",
                    "-Wl,-z,now",
                    "-ldl",
                    "-pthread",
                    "-o",
                    str(artifact),
                ],
                check=True,
                timeout=30,
            )
        first = hashlib.sha256(artifacts[0].read_bytes()).hexdigest()
        second = hashlib.sha256(artifacts[1].read_bytes()).hexdigest()
        target_after = hashlib.sha256(
            self.synthetic_target.read_bytes()
        ).hexdigest()
        self.assertEqual(first, second)
        self.assertEqual(target_before, target_after)
        self.assertEqual(target_after, self.synthetic_target_sha256)


if __name__ == "__main__":
    unittest.main(verbosity=2)
