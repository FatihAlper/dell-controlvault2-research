#!/usr/bin/env python3
"""Validate the one binary profile supported by the 0x89 experiment."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path


EXPECTED_SHA256 = "c7dbb44e25aa5127515cb4de23868358d7b170d2625227131a88bce39f3e8ef6"
EXPECTED_BUILD_ID = "66134403db205c7c1ac682885229224790aedc0e"

# These are validation anchors, not replacement bytes.  The experiment never
# writes the target DSO.
SIGNATURES = {
    "start_enrollment_trampoline_to_0x8a": bytes.fromhex(
        "f30f1efae94705feff"
    ),
    "update_wrapper_0x89_branch": bytes.fromhex(
        "4181fca400000074754181fc89000000746c"
    ),
    "outer_callback_0x89_retry_branch": bytes.fromhex(
        "4181fda40000000f84fd0100004181fd890000000f84f0010000"
    ),
    "enrollment_state_transition_command_0x8a": bytes.fromhex(
        "688a00000031d24531c94531c06a0031c94c89f6bf01000000"
    ),
    "capture_command_0x66": bytes.fromhex("6a66"),
    "update_command_0x6c": bytes.fromhex("6a6c"),
}


class TargetValidationError(RuntimeError):
    """The artifact is not the exact analyzed target."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_target(
    path: Path,
    *,
    expected_sha256: str = EXPECTED_SHA256,
    expected_build_id: str = EXPECTED_BUILD_ID,
    signatures: dict[str, bytes] = SIGNATURES,
) -> dict[str, int]:
    data = path.read_bytes()
    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash != expected_sha256:
        raise TargetValidationError(
            f"unsupported target SHA-256: expected {expected_sha256}, "
            f"got {actual_hash}"
        )
    if data.count(bytes.fromhex(expected_build_id)) != 1:
        raise TargetValidationError(
            f"ELF Build ID {expected_build_id} is missing or ambiguous"
        )

    offsets: dict[str, int] = {}
    for name, signature in signatures.items():
        count = data.count(signature)
        if count != 1:
            raise TargetValidationError(
                f"signature {name!r} occurs {count} times; expected exactly once"
            )
        offsets[name] = data.index(signature)
    return offsets


def prepend_once(existing: str, candidate: Path) -> str:
    """Add candidate to LD_PRELOAD, rejecting a duplicate experiment."""
    resolved_candidate = candidate.resolve()
    entries = [item for item in existing.split(":") if item]
    for entry in entries:
        if Path(entry).resolve() == resolved_candidate:
            raise TargetValidationError(
                f"experimental preload is already active: {resolved_candidate}"
            )
    return ":".join([str(resolved_candidate), *entries])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument(
        "--preload",
        type=Path,
        help="also validate that this library is not already in LD_PRELOAD",
    )
    args = parser.parse_args()

    try:
        offsets = validate_target(args.artifact)
        if args.preload is not None:
            value = prepend_once(os.environ.get("LD_PRELOAD", ""), args.preload)
            print(f"validated_LD_PRELOAD={value}")
    except (OSError, TargetValidationError) as error:
        parser.error(str(error))

    print(f"validated_sha256={EXPECTED_SHA256}")
    print(f"validated_build_id={EXPECTED_BUILD_ID}")
    for name, offset in offsets.items():
        print(f"signature.{name}=0x{offset:x}")
    print("target_write_performed=no")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
