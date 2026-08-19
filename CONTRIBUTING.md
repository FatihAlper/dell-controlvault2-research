# Contributing

Thank you for helping document Dell ControlVault2 hardware. This project
welcomes careful reverse engineering, hardware reports, protocol analysis,
tests, and future driver work.

## Before opening an issue

Choose the closest issue form and include:

- exact Dell model and relevant service-manual context;
- USB VID:PID and interface identity;
- operating system, kernel, fprintd/libfprint versions;
- firmware or vendor-driver package version when known;
- the exact command, script, or bounded stage run;
- expected and observed behavior; and
- whether the device recovered after USB reset, reboot, or complete power
  removal.

Status codes without their call site and stage are frequently ambiguous.

## Evidence hygiene

Safe public artifacts include:

- SHA-256 hashes and version metadata;
- disassembly offsets and short identifying instruction signatures;
- command/status ordering and USB message lengths;
- device/interface descriptors; and
- logs produced by the repository's payload-redacting tools.

Do **not** publish:

- fingerprint images, features, templates, or protected enrollment payloads;
- passwords, PINs, Windows account identifiers, service tags, serial numbers,
  USB serials, or user-profile paths;
- cryptographic keys or authentication material;
- proprietary driver/firmware binaries; or
- a complete decompilation or copyrighted vendor source reconstruction.

If unsure, describe the structure and retain the raw capture privately.

## Research standard

Every behavior-changing proposal should state:

1. what is directly observed;
2. what is statically proven and against which artifact hash;
3. what remains inference;
4. how failure and cleanup behave; and
5. how the result can be reproduced without weakening the default safety
   boundary.

Prefer a mock regression before a live hardware experiment. Stateful USB,
enrollment commit, firmware, and persistence operations must remain explicit,
bounded, and fail closed.

## Tests

Run:

```sh
python3 -m unittest discover -s tests -v
git diff --check
```

C helpers are compiled by the unit tests with `-Wall -Wextra -Werror`. New
mock-only components should require an explicit compile-time gate and must not
contain an implicit loader or real USB transport.

## Future driver work

New driver code should be cleanly separated from proprietary binary patching
and evidence tooling. A driver proposal should document ownership, session
lifetime, cancellation, rollback, error mapping, template privacy, and test
strategy before enabling enrollment or authentication on real systems.

## Attribution

Keep source links, artifact hashes, and the attribution attached to individual
external references intact. Do not turn a citation into a claim that an
external project or author contributed to this repository.
