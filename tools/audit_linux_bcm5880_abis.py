#!/usr/bin/env python3
"""Validate the recovered BCM5880 Linux export ABI anchors.

This audit is deliberately read-only.  It recognizes one repository-local
probe artifact by SHA-256 and validates unique instruction sequences at the
file offsets covered by the static analysis.  It never loads or patches the
shared object.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from pathlib import Path


class AuditError(RuntimeError):
    """The input is not the exact artifact covered by the analysis."""


@dataclass(frozen=True)
class ArtifactProfile:
    name: str
    sha256: str
    build_id: str
    signatures: dict[str, bytes]
    expected_offsets: dict[str, int]


LINUX_PROBE_PROFILE = ArtifactProfile(
    name="libfprint-2-tod-1-broadcom-5833.probe.so",
    sha256="c7dbb44e25aa5127515cb4de23868358d7b170d2625227131a88bce39f3e8ef6",
    build_id="66134403db205c7c1ac682885229224790aedc0e",
    signatures={
        # SysV args: edi=handle, sil=selector, rdx=20-byte ID,
        # rcx=size in/out, r8=output bytes.
        "capture_argument_mapping": bytes.fromhex(
            "f30f1efa4157660fefc041564989d641554989cd4154554c89c5"
            "5389fb4881ec88000000408874240c"
        ),
        "capture_required_outputs": bytes.fromhex(
            "4885ed0f84580100004d85ed0f844f010000"
        ),
        # Selector is registered as one byte and capture ID as 0x14 bytes.
        "capture_selector_and_id_inputs": bytes.fromhex(
            "488d4c2458488d54240cbe0100000031ffe8506dfeff4189c485c0"
            "0f855d010000488d4c24604c89f2be1400000031ffe8316dfeff"
        ),
        # The same initial *size is used for the size and byte outputs.
        "capture_capacity_outputs": bytes.fromhex(
            "418b7500488d4c246831d2bf03000000e80c6dfeffb9900b0000"
            "4189c485c00f8519010000418b75004c8d7424384889eabf03000000"
            "4c89f1e8e36cfeff"
        ),
        "capture_command_0x69": bytes.fromhex(
            "6a69ba010000004189d94c89f16a004c89febf040000004c8d442430"
        ),
        # SysV register and stack argument preservation for four feature
        # size/pointer pairs plus template size/output.
        "template_argument_mapping": bytes.fromhex(
            "4189ccb95f1000005589f54c89f65389fb488d3d42d70000"
            "4881ec98000000488b8424d000000048895424084c89fa4c89442410"
            "4889442418488b8424e000000044890c244889442420"
            "488b8424e80000004889442428488b8424f0000000"
        ),
        "template_validation": bytes.fromhex(
            "85ed745b4585e474568b342485f6744f8b8c24d800000085c97444"
            "48837c240800743c48837c241000743448837c241800742c"
            "48837c2420007424488b4424284885c0741a48837c2430007412"
            "8138008001000f86ce000000"
        ),
        "template_four_inputs": bytes.fromhex(
            "488b542408488d4c246889eebf020000004c89542438e88757feff"
            "4c8b54243885c04189c50f8580010000488b542410488d4c2470"
            "4489e6bf020000004c89542408e85b57feff4c8b54240885c0"
            "4189c50f855f010000488b5424188b3424488d4c2478bf02000000"
            "4c89542408e82f57feff4c8b542408b99610000085c04189c5"
            "4c8914240f85ff000000488b5424208bb424d8000000bf02000000"
            "488d8c2480000000e8f856feff4c8b1424b99b10000085c0"
            "4189c50f85cd000000"
        ),
        "template_output_and_command_0x6f": bytes.fromhex(
            "488b442428488b542430488d6c2448bf030000004889e94c891424"
            "8b30e8c256feff4c8b142485c04189c50f85d20000006a6f4531c0"
            "ba010000004c89d66a024189d94889e9bf050000004c89542410"
        ),
        # SysV args 1..6 use edi/rsi/edx/rcx/r8/r9.  The three stack
        # arguments are preserved as output-size, output-buffer, and
        # four-byte result pointers respectively.
        "commit_argument_mapping": bytes.fromhex(
            "4157660fefc041564c8d35cde00000415541544989f455"
            "488d2daed80000534889ee89fb488d3d61dd00004881eca8000000"
            "488b8424e0000000895424204c89f248894c2408b9840e0000"
            "48890424488b8424e800000044894424244889442418"
            "488b8424f00000004c894c2428"
        ),
        # A non-zero output capacity requires an output buffer and is capped
        # at 0x18000.  Zero capacity is legal only with the result pointer.
        "commit_output_mode_validation": bytes.fromhex(
            "48833c24000f84470200004d85e40f843e020000488b04248b00"
            "85c00f84200200003d008001000f872502000048837c241800"
            "0f8419020000"
        ),
        # Token is a 20-byte input.  The two optional input blobs use type 2;
        # output size/buffer use type 3 and the final result is four bytes.
        "commit_token_and_optional_inputs": bytes.fromhex(
            "488d4c24784c89e2be1400000031ffe8d75efeffb9d10e0000"
            "4189c585c00f854f0200008b742420488d8c248000000085f6"
            "0f84a3020000488b5424084885d20f8495020000bf02000000"
            "e89b5efeff"
        ),
        "commit_outputs_and_command_0x6e": bytes.fromhex(
            "488b0424488d8c249000000031d2bf030000008b30e82c5efeff"
            "b9fd0e00004189c585c00f85a4010000488b0424488b542418"
            "4c8d642440bf030000004c89e18b30e8ff5dfeff4189c585c0"
            "0f8532020000488b542410488d4c2448be0400000031ffe8de5dfeff"
            "4189c585c00f852d0200006a6e"
        ),
        # Successful response decoding writes only args 7, 8, and 9.  The
        # 20-byte token (arg 2) is not a return destination.
        "commit_return_destinations": bytes.fromhex(
            "488b1c24488b7c241831f68b13e88e50feff488b442410"
            "c703000000004885c00f84f0010000c70000000000488b0424"
            "488d7c24504c89e14489eabe020000004889442450"
            "488b4424184889442458488b4424104889442460e85257feff"
        ),
    },
    expected_offsets={
        "capture_argument_mapping": 0x258D0,
        "capture_required_outputs": 0x2594F,
        "capture_selector_and_id_inputs": 0x2598A,
        "capture_capacity_outputs": 0x259CF,
        "capture_command_0x69": 0x25A18,
        "template_argument_mapping": 0x26D2E,
        "template_validation": 0x26DF9,
        "template_four_inputs": 0x26F4E,
        "template_output_and_command_0x6f": 0x2700C,
        "commit_argument_mapping": 0x266A4,
        "commit_output_mode_validation": 0x26786,
        "commit_token_and_optional_inputs": 0x26805,
        "commit_outputs_and_command_0x6e": 0x268AA,
        "commit_return_destinations": 0x26950,
    },
)


def validate_artifact(
    path: Path,
    profile: ArtifactProfile = LINUX_PROBE_PROFILE,
    *,
    expected_sha256: str | None = None,
) -> dict[str, int]:
    data = path.read_bytes()
    wanted_hash = expected_sha256 or profile.sha256
    actual_hash = hashlib.sha256(data).hexdigest()
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only validation of the recovered capture-result, "
            "create-template, and commit-enrollment SysV ABI anchors"
        )
    )
    parser.add_argument("shared_object", type=Path)
    args = parser.parse_args()

    try:
        offsets = validate_artifact(args.shared_object)
    except (OSError, AuditError) as error:
        parser.error(str(error))

    profile = LINUX_PROBE_PROFILE
    print(f"artifact.name={profile.name}")
    print(f"artifact.sha256={profile.sha256}")
    print(f"artifact.build_id={profile.build_id}")
    for name, offset in offsets.items():
        print(f"artifact.signature.{name}=0x{offset:x}")
    print("derived.capture_get_result.rva=0x258d0")
    print("derived.capture_get_result.command=0x69")
    print("derived.capture_get_result.capture_id_size=20")
    print("derived.capture_get_result.output=capacity_in_actual_size_out")
    print("derived.create_template.rva=0x26d10")
    print("derived.create_template.command=0x6f")
    print("derived.create_template.feature_pairs=4")
    print("derived.create_template.output=capacity_in_actual_size_out")
    print("derived.commit_enrollment.rva=0x266a0")
    print("derived.commit_enrollment.command=0x6e")
    print("derived.commit_enrollment.arguments=9")
    print("derived.commit_enrollment.token_input_size=20")
    print("derived.commit_enrollment.output_modes=buffered_or_result_only")
    print("derived.commit_enrollment.return_destinations=args_7_8_9")
    print("artifact_loaded=no")
    print("artifact_write_performed=no")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
