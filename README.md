<div align="center">

# Dell ControlVault2 research

**Independent interoperability research and Linux bring-up work for Dell
ControlVault2 devices based on the Broadcom BCM5880 family.**

[![Status: research prototype](https://img.shields.io/badge/status-research%20prototype-f59e0b)](docs/current-status.md)
[![Hardware: BCM5880](https://img.shields.io/badge/hardware-BCM5880-4f46e5)](docs/evidence/latitude-7390-0a5c-5833.md)
[![Platform: Linux research](https://img.shields.io/badge/platform-Linux%20research-0ea5e9)](docs/architecture.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-22c55e)](LICENSE)

[Current status](docs/current-status.md) ·
[Architecture](docs/architecture.md) ·
[Protocol dictionary](docs/controlvault2-command-status-reference.md) ·
[Evidence map](docs/README.md) ·
[Tooling](tools/README.md)

</div>

> [!IMPORTANT]
> This is a research prototype, **not a production fingerprint driver**.
> Probe, lifecycle, capture, and retry behavior work on the tested hardware.
> Linux enrollment and verification are not complete.

## Why this project exists

ControlVault2 combines fingerprint, smart-card, NFC, and security-controller
functions behind an unusually opaque vendor stack. This repository turns
black-box behavior into public, reproducible, privacy-safe engineering
evidence so that an original Linux driver can eventually be built on something
stronger than folklore and one-off binary patches.

The project has three priorities:

1. document the hardware and protocol with explicit confidence levels;
2. reproduce findings through hash-pinned audits, bounded traces, and mocks;
3. design a safe foundation for a future driver without distributing or
   silently depending on proprietary artifacts.

Runtime observation, static proof, inference, and hypothesis are kept
separate. Unknowns stay documented as unknowns.

## At a glance

_Research snapshot: 2026-08-19_

| Area | Current state | What that means |
|---|---|---|
| Hardware health | **Proven** | The tested `0a5c:5833` unit enrolls and identifies under the reference Windows A21 stack |
| Linux probe and lifecycle | **Validated** | Version query, probe, open, capture, cancellation, and clean close have completed on hardware |
| Capture retry | **Validated** | Native `0x89` recovers through `0x8a → 0x66` |
| Linux enrollment | **Partial** | Accepted updates progress, but the next update reaches native `0x59` before completion |
| Commit path | **Structurally recovered** | Windows performs two distinct `0x6e` commits; the matching Linux ABI is known and mock-tested |
| Verification | **Unresolved** | Windows distinguishes samples; the Linux-facing match/no-match result is not yet recovered |
| Original Linux driver | **Design phase** | Enough is known for a safe probe/open/close skeleton, not for authentication or template persistence |

See the full [capability matrix and ranked roadmap](docs/current-status.md).

## Key findings

- The tested Latitude 7390 sensor is healthy and remains a complete
  `0a5c:5833` composite ControlVault2 device.
- Generic enrollment update uses command `0x6c`.
- Native status `0x89` is a real bad-capture/retry class. Repurposing it as
  success breaks legitimate recovery behavior.
- Explicit `0x8a` re-arm fixes Linux capture continuation after an
  accepted-incomplete update, but does not eliminate the later `0x59`
  boundary.
- A successful Windows A21 enrollment performs four successful updates and
  then **two non-identical** command-`0x6e` commits.
- The first commit reuses a 20-byte token and requests `0x800` bytes of output
  capacity. The second reuses the token, requests no byte buffer, and receives
  a four-byte result.
- The analyzed Linux artifact exposes compatible capture-result,
  four-feature template, and nine-argument commit ABIs. Compatible call shapes
  do not yet prove compatible state or data semantics.

The 940-byte and 92-byte Windows commit replies differ by 848 bytes, making
848 the strongest current candidate for the first commit's returned blob
length. Its protected contents have not been published or interpreted.

## Protocol landmarks

| Code | Current interpretation | Confidence boundary |
|---|---|---|
| `0x39` | Query ControlVault/USH version data | Completed on hardware |
| `0x66` | Start enrollment capture | Linux CFG and hardware |
| `0x68` | Cancel capture | Export and cleanup flow |
| `0x6c` | UpdateEnrollment | Linux and Windows runtime |
| `0x6d` | DiscardEnrollment | Linux CFG and Windows failure flow |
| `0x6e` | CommitEnrollment | Windows runtime plus Linux/Windows ABI analysis |
| `0x73` | Identify/verify operation family | Operation family known; protected result semantics unresolved |
| `0x8a` | Re-arm/prepare the next capture | Retry transition confirmed on hardware |
| `0x59` | Repeatable Linux enrollment boundary | Behavior known; exact firmware meaning unknown |
| `0x89` | Bad capture / retry | Windows mapping and hardware recovery confirmed |
| `0x8f` | Synthetic Linux “more progress” state | Host-generated, not a raw firmware status in this path |

The complete dictionary currently tracks 18 command codes and five status
codes, including evidence type, confidence, inferred terminology, and known
next transitions. See the
[ControlVault2 command and status reference](docs/controlvault2-command-status-reference.md).

## Hardware in scope

| USB identity | Known context | Project status |
|---|---|---|
| `0a5c:5833` | Latitude 7390 combination device with fingerprint, smart-card, and NFC functions | Main target; Linux probe/capture and Windows reference enrollment validated |
| `0a5c:5834` | Related BCM5880 units reported by other hardware owners | Same family; firmware/status behavior may differ by unit |
| `0a5c:5831` | Recovery/degraded identity observed after an interrupted session | Full power removal restored `5833` on the tested unit |

VID:PID alone is not enough to identify a firmware branch. Hardware reports
should include laptop model, interfaces, OS/driver versions, and the exact
experiment stage.

## Start reading

| If you want to… | Start here |
|---|---|
| See what works and what blocks a driver | [Current status and roadmap](docs/current-status.md) |
| Understand the stack and enrollment flow | [Architecture and terminology](docs/architecture.md) |
| Look up a command or status | [Command and status reference](docs/controlvault2-command-status-reference.md) |
| Review the tested Latitude 7390 | [`0a5c:5833` device evidence](docs/evidence/latitude-7390-0a5c-5833.md) |
| Follow the successful Windows path | [Windows A21 runtime evidence](docs/evidence/windows-a21-enrollment-runtime.md) |
| Understand the two commits | [Double-commit static comparison](docs/evidence/windows-a21-double-commit-static.md) |
| Find every research record | [Documentation and evidence map](docs/README.md) |
| Run an audit, mock, or bounded trace | [Tooling guide](tools/README.md) |
| Contribute hardware evidence | [Contributing guide](CONTRIBUTING.md) |

## Safety and privacy

> [!CAUTION]
> Do not publish raw enrollment or verification payloads. USB captures may
> contain fingerprint features, templates, tokens, credentials, serials, or
> other protected data even when the analysis report does not.

This repository contains no proprietary Dell/Broadcom binaries or firmware,
cryptographic material, raw fingerprint features, biometric templates,
credentials, or personally identifying captures.

The research boundary is fail-closed:

- offline/static validation is preferred;
- mock-only code requires explicit compile and runtime gates;
- live hardware runners require explicit confirmation;
- payload and pointer values are redacted by default;
- target artifacts are hash-pinned and never patched by the audit tools;
- live persistence is not enabled merely because an ABI has been recovered.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before collecting or submitting
hardware evidence.

## Quick validation

Run the complete repository test suite without hardware:

```sh
python3 -m unittest discover -s tests -v
```

Validate the recovered Linux ABIs against a lawfully obtained, private local
artifact:

```sh
python3 tools/audit_linux_bcm5880_abis.py \
  /private/path/libfprint-2-tod-1-broadcom-5833.probe.so
```

Windows audits likewise accept caller-supplied extracted DLL paths and refuse
unknown hashes or ambiguous instruction anchors. They do not load, execute,
patch, or copy those files.

Live runners have additional prerequisites and recovery implications. Do not
invoke one from an isolated snippet; use the [tooling guide](tools/README.md).

## Repository map

```text
docs/                       status, architecture, protocol notes, evidence map
docs/evidence/              bounded static and runtime evidence records
tools/                      audits, PCAP analysis, mocks, bounded live runners
tests/                      regression and safety-boundary tests
```

The repository intentionally has no inherited driver, binary patch set,
vendor downloader, installer, packaging rules, or system integration. Future
original driver code must remain clearly separated from evidence tooling and
must not silently depend on proprietary files.

## Contributing

Useful contributions include:

- a reproducible inventory from another Dell model or BCM5880 identity;
- privacy-safe traces containing lengths, statuses, ordering, and hashes;
- independent confirmation or falsification of a documented inference;
- static-analysis anchors tied to an exact artifact hash;
- mock-first state-machine work with regression and failure tests.

Use the repository's
[hardware and research issue forms](https://github.com/FatihAlper/dell-controlvault2-research/issues/new/choose).
Generic “fingerprint does not work” reports without hardware and experiment
context are not actionable.

## Independence and license

This is an independent project authored by Fatih Alper. It is not a fork,
continuation, redistribution, or packaged derivative of another ControlVault2
driver repository. It begins with a clean root commit and contains original
research notes, analysis tools, mock models, tests, and independently derived
protocol/ABI observations. See [NOTICE.md](NOTICE.md).

Repository content is available under the [MIT License](LICENSE). Vendor
drivers and firmware remain proprietary and outside that license.
