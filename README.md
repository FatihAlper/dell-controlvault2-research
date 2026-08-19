# Dell ControlVault2 research

Independent interoperability research, reproducible experiments, and Linux
bring-up tooling for Dell ControlVault2 devices based on the Broadcom BCM5880
family.

> **Project status:** research prototype, not a production fingerprint driver.
> Probe, open/close, capture, and several enrollment transitions work on the
> tested hardware. Linux enrollment and verification are not complete.

This project is not affiliated with Dell, Broadcom, Canonical, Microsoft, or
any earlier ControlVault2 driver repository. It is intended for developers
studying lawfully owned hardware and for a possible future open Linux driver.

## Mission

The repository has three priorities:

1. preserve high-quality public documentation about an unusually opaque
   hardware family;
2. turn observations into reproducible, privacy-safe evidence instead of
   folklore or one-off binary patches; and
3. provide a safe foundation for a future driver when the protocol and state
   machine are understood well enough.

The project deliberately distinguishes runtime observations, static binary
analysis, and inference. Unknowns are documented as unknowns.

## Hardware in scope

| USB identity | Known context | Current project status |
|---|---|---|
| `0a5c:5833` | Dell Latitude 7390 ControlVault2 combination device: fingerprint, smart-card, and NFC interfaces | Main hardware research target; Linux probe/capture validated, Windows reference enrollment captured |
| `0a5c:5834` | Broadcom 5880 units reported by other hardware owners | Related family member; behavior and firmware status codes may differ by unit |
| `0a5c:5831` | Recovery/degraded identity observed after one interrupted ControlVault session | Documented recovery state; full power removal restored `5833` on the tested unit |

USB product IDs are not sufficient to describe every firmware branch. Reports
must include the laptop model, USB identity, firmware/driver context, and the
exact stage that was exercised.

## Research snapshot

The strongest current findings are:

- The `5833` device enumerates as a composite ControlVault device and survives
  the proprietary TOD driver's probe, public open, capture, cancellation, and
  clean close paths.
- Native enrollment update uses generic command `0x6c`. Status `0x89` is a
  real retry/bad-capture class and must not be repurposed as success.
- On repeatable Linux controls, three accepted updates were followed by
  native `0x59` on the fourth update even with correct `0x8a` re-arming.
- A successful Windows A21 reference enrollment performed four successful
  UpdateEnrollment calls followed by **two distinct** command-`0x6e`
  CommitEnrollment calls.
- The first Windows commit reuses the 20-byte UpdateEnrollment token and asks
  for a large output with `0x800` capacity. The second reuses the same token,
  asks for no byte buffer, and receives only a four-byte result.
- The pinned Linux library already exports the same nine-argument generic
  commit ABI and supports both output modes. The remaining gap is state/token
  integration and lifecycle handling, not invention of a new commit command.
- Windows can enroll and identify on the physical unit, so the tested sensor
  is not bricked. Linux verification remains unresolved.

The 940-byte and 92-byte Windows commit replies differ by 848 bytes, making
848 the strongest current candidate for the first commit's returned blob
length. The protected content itself has not been published or interpreted.

Start with the [current status and roadmap](docs/current-status.md), then use
the [architecture and terminology guide](docs/architecture.md) and
[documentation and evidence map](docs/README.md). The compact command/status
dictionary is
[docs/controlvault2-command-status-reference.md](docs/controlvault2-command-status-reference.md),
the device-specific record is
[docs/evidence/latitude-7390-0a5c-5833.md](docs/evidence/latitude-7390-0a5c-5833.md),
and runnable research utilities are indexed in the
[tooling guide](tools/README.md).

## Safety and privacy boundary

This repository does not contain proprietary Broadcom/Dell binaries,
firmware, cryptographic material, raw fingerprint features, biometric
templates, credentials, or personally identifying captures.

Experiments are staged and fail closed:

- read-only/static validation is preferred;
- mock-only components refuse compilation without explicit compile gates;
- hardware runners require explicit confirmation for stateful operations;
- payloads and pointer values are redacted by default; and
- live commit/persistence paths are not enabled merely because their ABI is
  known.

Do not publish raw USB payloads from enrollment or verification. See
[CONTRIBUTING.md](CONTRIBUTING.md) before submitting hardware evidence.

## Repository layout

```text
docs/                       status, architecture, protocol notes, evidence map
docs/evidence/              bounded static/runtime evidence records
tools/                      indexed audits, tracers, mock models, test harnesses
tests/                      regression and safety-boundary tests
```

This repository intentionally does not include an inherited driver, binary
patch set, vendor fetcher, installer, packaging rules, or system integration.
Future original driver code should live separately from the evidence tooling
and must not silently depend on proprietary artifacts.

## Reproduce the safe checks

Run the repository test suite:

```sh
python3 -m unittest discover -s tests -v
```

Run the hash-pinned static ABI audit against a privately obtained local
artifact:

```sh
python3 tools/audit_linux_bcm5880_abis.py \
  /private/path/libfprint-2-tod-1-broadcom-5833.probe.so
```

Windows A21 audits likewise accept user-supplied extracted DLL paths and fail
closed unless hashes and unique instruction anchors match the documented
artifacts. They never load, execute, patch, or copy those files.

Several historical hardware harnesses expect a privately supplied, ignored
artifact under `prebuilt/` and an isolated local TOD build under
`.local-test/`. They are retained to make the published experiments
reproducible, not as a turnkey driver installation path. Read the associated
evidence note and confirmation boundary before running one.

Validate only the mock/static subset explicitly when hardware prerequisites
are unavailable:

```sh
python3 -m unittest -v \
  tests.test_audit_windows_a21_update \
  tests.test_audit_windows_a21_commit \
  tests.test_bcm5880_enrollment_coordinator \
  tests.test_bcm5880_linux_abi_adapter
```

## Contributing

Useful contributions include:

- hardware inventory and reproducible behavior from another Dell model;
- privacy-safe traces containing lengths, status codes, ordering, and hashes;
- independent confirmation or falsification of a documented inference;
- static-analysis anchors tied to an exact artifact hash; and
- mock-first protocol/state-machine implementations with regression tests.

Use the repository issue forms and follow [CONTRIBUTING.md](CONTRIBUTING.md).
Please do not submit generic “fingerprint does not work” reports without the
requested hardware and experiment context.

## Ownership and license

This repository begins with a clean root commit and hosts the original
ControlVault2 research, documentation, analysis tools, and mock models authored
for this investigation. It is not a fork and does not carry another project's
Git history or driver implementation. See [NOTICE.md](NOTICE.md).

Repository content is MIT licensed as described in [LICENSE](LICENSE). Vendor
drivers and firmware remain proprietary and are outside that license.
