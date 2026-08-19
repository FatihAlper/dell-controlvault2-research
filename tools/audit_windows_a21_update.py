#!/usr/bin/env python3
"""Validate static UpdateEnrollment dataflow anchors in Dell's Windows A21 binaries.

The tool is deliberately read-only.  It does not extract, execute, patch, or
copy any proprietary binary; callers must provide their own extracted
files from the supported Dell package.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from pathlib import Path


class AuditError(RuntimeError):
    """An input is not the exact artifact covered by the static analysis."""


@dataclass(frozen=True)
class ArtifactProfile:
    name: str
    sha256: str
    signatures: dict[str, bytes]
    expected_offsets: dict[str, int]


ENGINE_PROFILE = ArtifactProfile(
    name="BrcmEngineAdapter.dll",
    sha256="622b1a12566cb313cde264869ca5a4b410e3d5b2b604f5dd628c4a6b709b19ae",
    signatures={
        # HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x290)
        "zeroed_engine_context_allocation": bytes.fromhex(
            "ff158da50100ba0800000041b890020000488bc8ff1591a50100"
        ),
        # arg1=&EngineContext[0x18], arg3=&inner[0x2c], arg4=false,
        # arg2/arg5 are stack outputs, then call CSS_FingerprintUpdateEnrollment.
        "update_call_arguments": bytes.fromhex(
            "488d4424704533c9488d4f184889442420"
            "4c8d452c488d542460ff15f9f80200"
        ),
    },
    expected_offsets={
        "zeroed_engine_context_allocation": 0xF65,
        "update_call_arguments": 0x25A7,
    },
)


SENSOR_PROFILE = ArtifactProfile(
    name="BrcmSensorAdapter.dll",
    sha256="dfb30d81de42e726477b103412fba2c88abd9b675ead7141f25063a3ac8d4e6c",
    signatures={
        # BrcmSensorAdapterStartCapture loads Pipeline->SensorContext and
        # Pipeline->EngineContext from offsets 0x30 and 0x38 respectively.
        "pipeline_context_loads": bytes.fromhex("488b79304c8b6938"),
        # WBFUSH_StartCapture receives SensorContext+0x5c as its output and
        # capture mode 0x22/0x23 in edx.
        "capture_start_output": bytes.fromhex(
            "4c8d475c418bd7c74750010000008bebe8780b0000"
        ),
        # WBFUSH_StartCapture preserves that pointer in r8 when it invokes
        # the dynamically resolved CSS_FingerprintCaptureStart export.
        "css_capture_start_call": bytes.fromhex(
            "4c8bc78d48018bd6ff150b9f0200"
        ),
        # In Advanced mode (2), copy the 20-byte capture ID from
        # SensorContext+0x5c to EngineContext+0x18.
        "advanced_capture_id_copy": bytes.fromhex(
            "837f2002488b6c244075100f10475c410f114518"
            "8b476c41894528"
        ),
        # The WBF sensor adapter initializes the CaptureGetResult capacity to
        # 0x17000 bytes before allocating the result buffer.
        "capture_get_result_capacity": bytes.fromhex(
            "c744246000700100ff159b790100ba08"
        ),
        # In basic mode, CSS_FingerprintCaptureGetResult is called with
        # selector 1, SensorContext+0x5c (the 20-byte CaptureStart output),
        # &capacity, and the freshly allocated result buffer.
        "capture_get_result_arguments": bytes.fromhex(
            "488d575c4d8bce4c8d442460b101"
            "ff15c1a702008be88bd5488d0d7e"
        ),
    },
    expected_offsets={
        "pipeline_context_loads": 0x15BB,
        "capture_start_output": 0x1663,
        "css_capture_start_call": 0x224F,
        "advanced_capture_id_copy": 0x16B6,
        "capture_get_result_capacity": 0x1AEF,
        "capture_get_result_arguments": 0x1B43,
    },
)


BIP_PROFILE = ArtifactProfile(
    name="bipdll.dll",
    sha256="30c556a9b542d0fcf29a6822b3bb81fe23ce2917b403b3f25af9384e0e31e524",
    signatures={
        # CSS_FingerprintUpdateEnrollment forwards handle, 20-byte input,
        # auxiliary size/pointer, and its three output pointers to 0x2d110.
        "wrapper_dispatch_arguments": bytes.fromhex(
            "488b4424584c8bcb8b4e20448bc54c89742430"
            "498bd448894424284c896c2420e872700100"
        ),
        # The generic dispatcher registers arg2 as a 0x14-byte input.
        "generic_input_20_bytes": bytes.fromhex(
            "4c8d4c24784d8bc6ba1400000033c9e8bcb40100"
        ),
        # A zero auxiliary length is represented by a null pointer and size.
        "generic_zero_auxiliary": bytes.fromhex(
            "4533c033d24c8d8c2480000000b902000000e84cb40100"
        ),
        # The generic path builds native command 0x6c.
        "generic_command_0x6c": bytes.fromhex(
            "b86c00000066894424384533e44489642430"
            "8b44245c894424284c89642420"
        ),
        # The generic UpdateEnrollment dispatcher calls is5880, tests AL,
        # selects the BCM5880 host-template helper when true, and otherwise
        # falls through to the generic command-0x6c path.
        "bcm5880_update_selector": bytes.fromhex(
            "e829dc01008bcb84c074194c8bce4d8bc7498bd6e895fcff"
        ),
        # The exported CSS_FingerprintCaptureStart preserves its incoming
        # output pointer in r14 and forwards it to the internal dispatcher.
        "capture_start_output_forwarding": bytes.fromhex(
            "488b47504d8bce8b4f20448bc54889442428"
            "8bd6488b47484889442420e86e5f0100"
        ),
        # When the 5880 selector is true, the internal CaptureStart
        # dispatcher passes that output pointer to its selected helper.
        "capture_start_5880_dispatch": bytes.fromhex(
            "498bd68bcbe856fdffff"
        ),
        # The generic branch registers the same pointer as a 0x14-byte
        # structured-response output.
        "capture_start_generic_output_20_bytes": bytes.fromhex(
            "4c8d4c24684d8bc6ba1400000033c9e82dd20100"
        ),
        # In that selected helper, capture mode bit 0x20 makes CaptureStart
        # generate the shared 20-byte capture/enrollment ID at 0xaf030.
        "capture_start_5880_id_generation": bytes.fromhex(
            "488d0d073e0800e82a6d020085c07416"
        ),
        # Copy 16+4 bytes of that ID into the caller-provided output buffer.
        "capture_start_5880_id_copy": bytes.fromhex(
            "0f1005e13d0800488d4c24300f1107"
            "8b05e33d0800894710"
        ),
    },
    expected_offsets={
        "wrapper_dispatch_arguments": 0x15479,
        "generic_input_20_bytes": 0x2C730,
        "generic_zero_auxiliary": 0x2C79D,
        "generic_command_0x6c": 0x2C8A5,
        "bcm5880_update_selector": 0x2C642,
        "capture_start_output_forwarding": 0x147D0,
        "capture_start_5880_dispatch": 0x2A880,
        "capture_start_generic_output_20_bytes": 0x2A9BF,
        "capture_start_5880_id_generation": 0x2A622,
        "capture_start_5880_id_copy": 0x2A648,
    },
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_artifact(
    path: Path,
    profile: ArtifactProfile,
    *,
    expected_sha256: str | None = None,
) -> dict[str, int]:
    data = path.read_bytes()
    wanted_hash = expected_sha256 or profile.sha256
    actual_hash = sha256_bytes(data)
    if actual_hash != wanted_hash:
        raise AuditError(
            f"unsupported {profile.name} SHA-256: expected {wanted_hash}, "
            f"got {actual_hash}"
        )

    offsets: dict[str, int] = {}
    for name, signature in profile.signatures.items():
        count = data.count(signature)
        if count != 1:
            raise AuditError(
                f"{profile.name} signature {name!r} occurs {count} times; "
                "expected exactly once"
            )
        offset = data.index(signature)
        expected_offset = profile.expected_offsets[name]
        if offset != expected_offset:
            raise AuditError(
                f"{profile.name} signature {name!r} is at 0x{offset:x}; "
                f"expected 0x{expected_offset:x}"
            )
        offsets[name] = offset
    return offsets


def report(profile: ArtifactProfile, offsets: dict[str, int]) -> None:
    print(f"artifact.{profile.name}.sha256={profile.sha256}")
    for name, offset in offsets.items():
        print(f"artifact.{profile.name}.signature.{name}=0x{offset:x}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only validation of Windows A21 UpdateEnrollment dataflow "
            "anchors. The supported files come from Dell package N23KC A21."
        )
    )
    parser.add_argument("engine_adapter", type=Path)
    parser.add_argument("sensor_adapter", type=Path)
    parser.add_argument("bipdll", type=Path)
    args = parser.parse_args()

    try:
        engine_offsets = validate_artifact(args.engine_adapter, ENGINE_PROFILE)
        sensor_offsets = validate_artifact(args.sensor_adapter, SENSOR_PROFILE)
        bip_offsets = validate_artifact(args.bipdll, BIP_PROFILE)
    except (OSError, AuditError) as error:
        parser.error(str(error))

    report(ENGINE_PROFILE, engine_offsets)
    report(SENSOR_PROFILE, sensor_offsets)
    report(BIP_PROFILE, bip_offsets)
    print("derived.engine_context_allocation=zeroed")
    print("derived.update_input=engine_context_plus_0x18_length_20")
    print("derived.update_input_pointer=stable_engine_context_field")
    print("derived.update_input_content=refreshed_by_advanced_start_capture")
    print("derived.update_input_source=css_capture_start_output")
    print("derived.bcm5880_capture_start_selected_path=generates_shared_20_byte_id")
    print("derived.capture_get_result.selector=1")
    print("derived.capture_get_result.capture_id=sensor_context_plus_0x5c")
    print("derived.capture_get_result.initial_capacity=0x17000")
    print("derived.update_auxiliary=false_size_0_pointer_null")
    print("derived.generic_command=0x6c")
    print("derived.update_selector.test_rva=0x2d249")
    print("derived.update_selector.false_path=generic_0x6c")
    print("artifact_write_performed=no")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
