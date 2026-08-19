# Tooling guide

This directory contains research and validation tools, not a driver installer.
The tools are deliberately split by risk and execution boundary. Read the
linked evidence note before using a live runner.

## Safety classes

| Class | Meaning | Hardware or process access |
|---|---|---|
| Offline read-only | Hash/signature validation or PCAP structure analysis | None |
| Mock-only | C state/ABI models compiled only against injected test callbacks | None; compile and runtime gates refuse real operation |
| Repository-local build | Builds an interposer or harness under `.local-test/` | No hardware during build; reads a private pinned artifact without modifying it |
| Live Linux hardware | Runs a bounded experiment against `0a5c:5833` | Yes; explicit confirmation required |
| Live Windows instrumentation | Attaches Frida to the A21 biometric host | Yes; no payload logging or binary modification, but the service/VM can require recovery |

No tool authorizes firmware writing. No proprietary binary belongs in version
control. Live experiments can disrupt a biometric session or leave the USB
function needing a service restart, VM recovery, or complete power removal.

## Quick start: no hardware

Run all repository tests:

```sh
python3 -m unittest discover -s tests -v
```

The default tests use synthetic fixtures and repository-local mocks. A test
that needs an unavailable private artifact may skip; it must not download one.

## Offline static audits

These scripts read caller-supplied files, require exact known hashes and
unique instruction anchors, and never load, patch, or copy the input.

| Tool | Purpose | Inputs | Evidence |
|---|---|---|---|
| `audit_linux_bcm5880_abis.py` | Validate recovered Linux capture-result, create-template, and commit SysV ABIs | Hash-pinned private Linux probe DSO | [Linux export ABIs](../docs/evidence/linux-bcm5880-export-abis.md) |
| `audit_windows_a21_update.py` | Validate A21 UpdateEnrollment, capture, selector, and dataflow anchors | Private `BrcmEngineAdapter.dll`, `BrcmSensorAdapter.dll`, `bipdll.dll` | [Windows update arguments](../docs/evidence/windows-a21-update-arguments-static.md) |
| `audit_windows_a21_commit.py` | Validate the two distinct A21 CommitEnrollment call shapes | Private `BrcmEngineAdapter.dll` and `bipdll.dll` | [Double-commit analysis](../docs/evidence/windows-a21-double-commit-static.md) |
| `enrollment_0x89_target.py` | Validate the exact Linux research artifact and optionally an interposer/`LD_PRELOAD` boundary | Private Linux probe DSO; optional local preload | [`0x89` static evidence](../docs/evidence/0x89-rearm-static.md) |

Examples:

```sh
python3 tools/audit_linux_bcm5880_abis.py /private/path/probe.so

python3 tools/audit_windows_a21_update.py \
  /private/path/BrcmEngineAdapter.dll \
  /private/path/BrcmSensorAdapter.dll \
  /private/path/bipdll.dll

python3 tools/audit_windows_a21_commit.py \
  /private/path/BrcmEngineAdapter.dll \
  /private/path/bipdll.dll
```

## Offline PCAP structure tools

Both tools call `tshark` and keep USB payload bytes out of their reports.
Captures themselves may still contain protected data and must remain private.

| Tool | Purpose | Public output boundary |
|---|---|---|
| `summarize_cv_usb_pcap.py` | Print chronological or grouped ControlVault message headers | Direction, command, declared length, flags, and counts |
| `compare_cv_usb_updates.py` | Compare UpdateEnrollment message structure across labeled captures | Ordering, shapes, and changing/stable offset ranges without byte values or payload hashes |

```sh
python3 tools/summarize_cv_usb_pcap.py \
  --device-address 5 --counts PRIVATE_CAPTURE.pcapng

python3 tools/compare_cv_usb_updates.py --device-address 5 \
  windows=PRIVATE_WINDOWS.pcapng \
  linux=PRIVATE_LINUX.pcapng
```

See the [runtime trace](../docs/evidence/windows-a21-enrollment-runtime.md)
and [structural comparison](../docs/evidence/update-enrollment-structural-comparison.md).

## Mock-only models

These sources make recovered layouts executable against test callbacks only.
They contain no USB transport, driver loader, or implicit symbol resolution.

| Files | Modeled behavior | Compile gate |
|---|---|---|
| `bcm5880_enrollment_coordinator.[ch]` | Three buffered features plus a fourth live feature, template creation, terminal commit-blocked state | `CV2_BCM5880_COORDINATOR_MOCK_ONLY` |
| `bcm5880_linux_abi_adapter.[ch]` | Recovered Linux capture-result, create-template, and generic commit call layouts | `CV2_BCM5880_LINUX_ABI_ADAPTER_MOCK_ONLY` |
| `bcm5880_generic_commit_sequence.[ch]` | Two Windows-shaped generic commit calls using one injected mock | `CV2_BCM5880_GENERIC_COMMIT_SEQUENCE_MOCK_ONLY` |

The unit tests supply the required gates and injected functions:

```sh
python3 -m unittest -v \
  tests.test_bcm5880_enrollment_coordinator \
  tests.test_bcm5880_linux_abi_adapter
```

Read the [mock coordinator](../docs/evidence/bcm5880-coordinator-mock.md) and
[Linux ABI](../docs/evidence/linux-bcm5880-export-abis.md) notes before
changing these contracts.

## Repository-local Linux experiment builds

The build scripts require a privately supplied exact probe artifact under
`prebuilt/` and, for the hardware harness, an isolated libfprint TOD build
under `.local-test/libfprint-build/`. They compile only into `.local-test/`,
compare the target hash before/after, and install nothing.

| Build script | Produced research component | Associated sources |
|---|---|---|
| `build_enrollment_0x89_experiment.sh` | Enrollment-update interposer and optional TOD harness | `enrollment_0x89_rearm_preload.c`, `cv_tod_enrollment_experiment.c` |
| `build_capture_get_result_probe.sh` | Capture-result interposer and TOD harness | `capture_get_result_probe_preload.c`, `cv_tod_capture_result_experiment.c` |

Building is not permission to run against hardware.

## Live Linux hardware runners

These runners are for an isolated research machine with the exact tested
`0a5c:5833` setup. They are not an installation path.

### Capture-result probe

```sh
tools/run_capture_get_result_probe.sh --confirm-capture-only
```

This performs one normal capture and one
`CaptureGetResult(selector=1)` call. It logs only status and returned length,
wipes the private output buffer, prevents UpdateEnrollment forwarding, and
does not resolve template or commit functions. It refuses to run while
`fprintd` is active. See the
[capture-result evidence](../docs/evidence/capture-get-result-probe.md).

### Enrollment boundary runner

```sh
tools/run_local_enrollment_0x89_test.sh \
  --confirm-real-enrollment \
  --fresh-rearm-boundary \
  --trace-update-metadata
```

This is a real enrollment experiment. Depending on the selected mode and
underlying state machine, a successful unbounded path could persist a
template. Prefer the documented fail-closed boundary modes:

| Option | Behavior |
|---|---|
| `--fresh-boundary` | One update per fresh capture; preserve `0x59`; block native completion before commit |
| `--fresh-rearm-boundary` | Also issue one native `0x8a` after accepted-incomplete updates; stop at the fourth acceptance |
| `--zero-input-boundary` | Additionally substitute one stable zero 20-byte update input; cap total/accepted updates |
| `--trace-update-metadata` | Log only lengths, equality/relationship classes, and zero/changed classes |

Select at most one boundary mode. The runner requires
`--confirm-real-enrollment`, validates the exact target, installs nothing,
and writes a redacted logical log under `test-results/`. See the
[fresh-boundary evidence](../docs/evidence/fresh-boundary-static.md),
[metadata trace](../docs/evidence/update-enrollment-call-metadata.md), and
[zero-input control](../docs/evidence/zero-update-input-hardware.md).

## Live Windows A21 instrumentation

`run_windows_a21_enrollment_trace.ps1` validates the loaded A21 module hashes
before attaching Frida. It requires elevated Windows PowerShell and explicit
`-ConfirmPrivacySafeTrace`. It does not patch binaries, write process memory,
or log payload/pointer values.

Use the reduced completion trace for normal completion research:

```powershell
powershell.exe -ExecutionPolicy Bypass `
  -File .\tools\run_windows_a21_enrollment_trace.ps1 `
  -ConfirmPrivacySafeTrace `
  -MinimalCompletionTrace `
  -OutputDirectory "$PWD\test-results"
```

| File | Instrumentation boundary |
|---|---|
| `windows_a21_completion_trace.js` | Update return statuses plus commit/discard call order and statuses; no memory reads or capture hooks |
| `windows_a21_enrollment_trace.js` | Full metadata relationships and route classification; higher timing sensitivity on the legacy stack |

The full tracer previously interfered with Windows Hello progress on the
tested VM. Frida or target failure may interrupt Windows Biometric Service;
save work first, detach with `exit`, close or cancel Hello, and verify the
session is idle before shutting down the VM. See the complete
[Windows metadata procedure](../docs/evidence/windows-a21-enrollment-metadata-trace.md).

## Prerequisites by task

| Task | Typical prerequisites |
|---|---|
| Unit tests/static audits | Python 3; a C compiler for mock tests |
| PCAP summaries/comparison | Python 3 and `tshark`; private usbmon/USBPcap capture |
| Linux build-only experiments | `gcc`, `python3`, `sha256sum`, exact private artifact; local libfprint TOD build for harnesses |
| Live Linux experiments | Above plus `lsusb`, exclusive device access, stopped `fprintd`, tested `0a5c:5833` hardware |
| Windows A21 trace | Exact A21 stack, elevated PowerShell, matching x64 Frida CLI, healthy passed-through biometric device |

## Generated and private paths

| Path | Purpose | Version-control status |
|---|---|---|
| `prebuilt/` | User-supplied private, hash-pinned research artifact | Ignored; never publish |
| `.local-test/` | Repository-local builds and isolated runtime dependencies | Ignored |
| `test-results/` | Redacted logs and local experiment output | Ignored; review before sharing |

Do not assume that an ignored file is privacy-safe. Raw captures, service
tags, serials, user paths, fingerprint data, templates, and protected tokens
must remain private. Follow [CONTRIBUTING.md](../CONTRIBUTING.md).
