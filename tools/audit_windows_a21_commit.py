#!/usr/bin/env python3
"""Validate static double-CommitEnrollment anchors in Dell's Windows A21 DLLs.

The tool is deliberately read-only. It does not extract, execute, patch, or
copy any proprietary binary; callers must provide their own extracted files
from the supported Dell package.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from audit_windows_a21_update import (
    ArtifactProfile,
    AuditError,
    report,
    validate_artifact,
)


ENGINE_COMMIT_PROFILE = ArtifactProfile(
    name="BrcmEngineAdapter.dll",
    sha256="622b1a12566cb313cde264869ca5a4b410e3d5b2b604f5dd628c4a6b709b19ae",
    signatures={
        # Adapter attach allocates a zeroed 0x48-byte inner state object.
        "inner_state_allocation": bytes.fromhex(
            "ff1555a50100ba08000000488bc8448d4240ff155ba50100"
            "4889064885c00f849800"
        ),
        # A separate zeroed 0x800-byte allocation is stored at inner+0x18.
        "phase1_output_allocation": bytes.fromhex(
            "ff1510a50100ba0800000041b800080000488bc8ff1514a50100"
            "488bc8488b0648894818"
        ),
        # The successful-completion block in EngineAdapterUpdateEnrollment
        # constructs four internal-state arguments and calls the common
        # WBFUSH_CommitEnrollment helper at RVA 0x4950.
        "update_completion_commit": bytes.fromhex(
            "4c8b074c8d4c2478498d5020498d482c4d8b4018e8ec160000"
        ),
        # The first call resets inner+0x20 to the full 0x800-byte capacity,
        # then supplies the shared token, size, buffer, and result pointers.
        "update_completion_capacity_and_commit": bytes.fromhex(
            "c7402000080000e8f50f00004c8b074c8d4c2478498d5020"
            "498d482c4d8b4018e8ec160000"
        ),
        # EngineAdapterCommitEnrollment selects either the WithUserApp wrapper
        # or the common helper. Both paths reduce to one call of RVA 0x4950.
        "framework_commit_dispatch": bytes.fromhex(
            "488b0f4c8d4f504c8d8774020000488d54243c488d4140"
            "4883c12c4889442428e83e0c0000eb24488d0de5350200"
            "e810060000488b0f488d54243c4533c04c8d49404883c12c"
            "e8080d0000"
        ),
        # The common helper supplies five fixed CSS arguments, forwards its
        # four incoming values in CSS positions 1/6/7/8, and has exactly one
        # indirect CSS_FingerprintCommitEnrollment call.
        "css_commit_argument_construction": bytes.fromhex(
            "4c897c2438488d45f74c89742430448d4b154889742428"
            "4c8d450f8d53084889442420488bcfff1502e20200"
        ),
        # The common helper constructs the same two input blobs for both
        # calls: an 8-byte block and a 21-byte BroadcomWBF-tagged block.
        "css_commit_fixed_inputs": bytes.fromhex(
            "f20f100503350200488d0dfc410200b804000000c7450f00000400"
            "89451333c0488945f7488945ff8945078b05e2340200894508"
            "0fb605dc34020088450cc745f70101ff00c745fb00000d00"
            "c645ff0cf20f114500"
        ),
        # GetProcAddress resolves CSS_FingerprintCommitEnrollment and stores
        # the result in the slot used by the call above.
        "css_commit_export_resolution": bytes.fromhex(
            "488b0d69c80200488d15da400200488905d3c60200"
            "ff158d580100488b0d4ec80200488d15df400200"
            "48890590c40200"
        ),
    },
    expected_offsets={
        "inner_state_allocation": 0xF9D,
        "phase1_output_allocation": 0xFE2,
        "update_completion_commit": 0x264B,
        "update_completion_capacity_and_commit": 0x263F,
        "framework_commit_dispatch": 0x2FFD,
        "css_commit_argument_construction": 0x3EAA,
        "css_commit_fixed_inputs": 0x3E45,
        "css_commit_export_resolution": 0x5C18,
    },
)


BIP_COMMIT_PROFILE = ArtifactProfile(
    name="bipdll.dll",
    sha256="30c556a9b542d0fcf29a6822b3bb81fe23ce2917b403b3f25af9384e0e31e524",
    signatures={
        # CSS_FingerprintCommitEnrollment forwards its eight inputs to the
        # exported raw commit function at RVA 0x2da30 exactly once.
        "css_to_raw_commit_forwarding": bytes.fromhex(
            "488b4424584d8bcf8b4f20458bc64889442440488bd5"
            "488b442460488944243848897424304c896c24284489642420"
            "e893750100"
        ),
        # Generic raw commit validates a required 20-byte token and one of
        # two output modes: non-zero size+buffer, or zero size+result pointer.
        "raw_commit_output_mode_validation": bytes.fromhex(
            "4d85e4750ebb47000000895c2450e9930300004885f6750e"
            "bb47000000895c2450e9800300008b0685c0741a4885db7407"
            "3d008001007621bb47000000895c2450e9600300004d85ff750e"
            "bb47000000895c2450e94d030000"
        ),
        # Args 7 and 8 form the type-3 size/buffer output pair.  Arg 9 is a
        # separate four-byte output.
        "raw_commit_output_registration": bytes.fromhex(
            "4c8d8c24a80000004533c08b16418d4803e8dba901008bd8"
            "8944245085c0742141b92e1400004c8bc7488d1509e20400"
            "488d0d0add0400e8f55cfdffe9850100004c8d4c2468"
            "4c8ba424800000004d8bc48b16b903000000e894a90100"
            "8bd88944245085c0742141b9351400004c8bc7488d15c2e10400"
            "488d0dc3dc0400e8ae5cfdffe93e0100004c8d4c24704d8bc7"
            "ba0400000033c9e855a901008bd889442450"
        ),
        # Command 0x6e is followed by response decoding into args 7/8/9.
        # The 20-byte token argument is not a return destination.
        "raw_commit_command_and_return_destinations": bytes.fromhex(
            "b86e0000006689442438c7442430020000008b44245489442428"
            "4533ed4c896c24204c8d4c2468458d4502488d942488000000"
            "418d4d05e87e9a00008bd88944245085c0741c83f8347417"
            "448bc0488bd7488d0d52dc0400e8cd5cfdffe99d000000"
            "448bf0448b0633d2498bcce8b8e9010044892e4d85ff7403"
            "45892f4889b424b00000004c89a424b8000000488d442478"
            "4d85ff490f45c748898424c00000004c8d4c2468448bc3"
            "ba02000000488d8c24b0000000e8cfba0000"
        ),
    },
    expected_offsets={
        "css_to_raw_commit_forwarding": 0x15869,
        "raw_commit_output_mode_validation": 0x2D02F,
        "raw_commit_output_registration": 0x2D20F,
        "raw_commit_command_and_return_destinations": 0x2D2D6,
    },
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only validation of Windows A21 double-CommitEnrollment "
            "control-flow anchors. The supported files come from Dell "
            "package N23KC A21."
        )
    )
    parser.add_argument("engine_adapter", type=Path)
    parser.add_argument("bipdll", type=Path)
    args = parser.parse_args()

    try:
        engine_offsets = validate_artifact(args.engine_adapter, ENGINE_COMMIT_PROFILE)
        bip_offsets = validate_artifact(args.bipdll, BIP_COMMIT_PROFILE)
    except (OSError, AuditError) as error:
        parser.error(str(error))

    report(ENGINE_COMMIT_PROFILE, engine_offsets)
    report(BIP_COMMIT_PROFILE, bip_offsets)
    print("derived.commit.common_helper_rva=0x4950")
    print("derived.commit.css_call_rva=0x4ad0")
    print("derived.commit.first_origin=update_completion_rva_0x325f")
    print("derived.commit.second_origin=framework_commit_callback_rva_0x3900")
    print("derived.commit.second_dispatch=rva_0x3c43_or_user_app_rva_0x3c1d")
    print("derived.commit.identical_calls=no")
    print("derived.commit.raw_calls_per_css_call=1")
    print("derived.commit.token_input=inner_plus_0x2c_size_20")
    print("derived.commit.first_output=inner_plus_0x18_capacity_0x800")
    print("derived.commit.first_result=temporary_dword")
    print("derived.commit.second_output=none_capacity_zero")
    print("derived.commit.second_result=inner_plus_0x40")
    print("derived.commit.raw_return_destinations=args_7_8_9")
    print("artifact_write_performed=no")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
