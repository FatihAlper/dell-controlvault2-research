# Current status and roadmap

_Research snapshot: 2026-08-19_

This page answers three practical questions: what works, what is proven, and
what still blocks an original Linux driver. It is a status summary, not a
replacement for the underlying evidence records.

## Short answer

The tested Dell Latitude 7390 `0a5c:5833` device is healthy and usable with
the reference Windows A21 stack. Linux can enumerate it, query its version,
open and close the proprietary TOD path, capture, recover from bad captures,
and reach several enrollment updates.

Linux enrollment and verification are **not complete**. The project has
enough evidence to design an original driver skeleton and its state/lifetime
model, but not enough to enable template persistence or authentication safely.

## Capability matrix

| Area | Tested result | Evidence level | Remaining gate |
|---|---|---|---|
| USB enumeration | `0a5c:5833` composite device and expected transport endpoints observed | Runtime observed | Generalize discovery beyond the tested unit |
| Version/probe | Command `0x39`, interrupt completion, and bulk reply succeed | Runtime observed | Replace proprietary probe dependencies with an original transport implementation |
| Session lifecycle | Repository-local TOD probe/open/close completes cleanly | Runtime observed | Specify ownership, cancellation, timeout, and recovery in original code |
| Capture | Native capture starts and completes; capture-only result probing is bounded | Runtime observed and statically proven ABI | Determine which returned object, selector, and format are suitable for enrollment/verification |
| Bad-capture recovery | `0x89 → 0x8a → fresh 0x66` works repeatedly | Runtime observed | Integrate retry limits and framework error mapping |
| Enrollment update | Three accepted Linux updates can continue with explicit re-arm; the next update reaches native `0x59` | Runtime observed | Explain the fourth-update Linux/Windows divergence |
| Windows enrollment | Four successful updates followed by two distinct `0x6e` commit calls | Runtime observed plus static call-shape proof | Reproduce the required state/token lifecycle on Linux |
| Linux commit ABI | Nine-argument ABI and large-output/result-only modes recovered and tested against mocks | Statically proven and mock-tested | No live commit until ownership, rollback, cleanup, and persistence semantics are established |
| Host template path | Four-feature capture/template shapes recovered from a selected Windows path and Linux exports | Statically proven for call layout | Prove that this path and its data formats apply to the tested runtime path |
| Linux enrollment | Not complete | Partial runtime evidence | Resolve update boundary, commit ownership, and failure rollback |
| Identification/verification | Successful and rejected Windows samples observed; Linux result remains unresolved | Windows runtime observed | Recover result semantics and implement correct match/no-match/error propagation |
| Recovery | Interrupted sessions recovered through service restart, VM recovery, or full power removal; `5831` returned to `5833` after full power removal | Runtime observed | Define bounded automatic recovery without relying on full power removal |

The compact command/status meanings are maintained in the
[command and status reference](controlvault2-command-status-reference.md).

## Strongest established findings

1. The tested sensor is not bricked: Windows enrolled and identified a finger,
   and Linux still enumerates the complete `5833` composite device.
2. Status `0x89` is a real retry/bad-capture result. Treating it as enrollment
   success breaks a legitimate recovery branch.
3. Explicit `0x8a` re-arm after accepted-incomplete Linux updates fixes a
   capture-continuation problem, but does not remove the later `0x59` boundary.
4. Successful Windows A21 enrollment uses the generic-looking `0x6c` update
   route four times and then invokes two non-identical `0x6e` commits.
5. The first commit accepts the shared 20-byte token and `0x800` bytes of
   output capacity. The second reuses the token, requests no byte output, and
   receives a four-byte result.
6. The Linux artifact exposes compatible capture/template/commit calling
   conventions, but a compatible ABI does not prove compatible state or data
   semantics.

Start with the
[Latitude 7390 device record](evidence/latitude-7390-0a5c-5833.md),
[Windows enrollment runtime](evidence/windows-a21-enrollment-runtime.md), and
[double-commit comparison](evidence/windows-a21-double-commit-static.md) for
the supporting evidence.

## Critical unknowns

### Enrollment boundary

Why does the tested Linux path reach native `0x59` after three accepted
updates while Windows completes four successful updates? Candidate causes
include initialization state, capture mode/input, accumulated device state,
or a host-side lifecycle difference. Protected payload bytes are deliberately
not used as a shortcut.

### Capture-result semantics

The capture-result ABI and Windows selector are known, but the meaning and
cross-platform compatibility of the returned object are not. A successful
call must not be treated as a feature record until size, ownership, lifetime,
and consumer are independently established.

### Commit ownership and rollback

The two generic commit call shapes are known. The project still needs a safe
answer for who owns the first returned blob, when it is cleared, what the
second result means, how cancellation behaves between phases, and how a
partially persisted enrollment is rolled back.

### Verification result

The Windows reference stack proves that the hardware can distinguish samples,
but the Linux-facing match/no-match field and its marshaling are unresolved.
Returning a hardcoded result or mapping an unknown native status would not be
a valid driver implementation.

## Driver readiness

| Driver component | Readiness | Notes |
|---|---|---|
| Research corpus and reproducibility | Mature for the tested unit | Hash-pinned evidence, privacy boundaries, tools, and regression tests exist |
| Original USB transport | Not implemented | Current live Linux evidence still uses a privately supplied proprietary TOD artifact |
| Device/session object model | Designable | Required ownership and cleanup questions are documented, but not implemented in an original driver |
| Probe and basic lifecycle | Protocol evidence available | Suitable first target for an original, non-biometric skeleton |
| Capture/retry state machine | Partial | Core command ordering is known; result object semantics remain open |
| Enrollment | Research prototype only | Update boundary and two-phase commit lifecycle block real integration |
| Verification | Blocked | Match result semantics are unknown |
| libfprint integration | Not started as an original driver | Existing harnesses are experiments, not a distributable driver |
| Production security and recovery | Not started | Threat model, secure deletion, rollback, rate limits, and fuzzing are still required |

In practical terms: the project is close enough to begin an original
probe/open/close driver skeleton, but it is not one patch away from a usable
fingerprint driver.

## Ranked roadmap

### 1. Freeze the protocol and lifecycle model

- Keep command/status associations tied to named evidence.
- Specify session ownership, cancellation, timeout, and power recovery.
- Turn the successful Windows update/commit sequence into a fail-closed mock
  state machine without enabling live persistence.

### 2. Resolve the fourth-update divergence

- Compare Windows and Linux initialization/capture metadata before `0x6c`.
- Prefer bounded metadata and structural comparisons over protected payloads.
- Require an explicit cleanup path and a healthy post-test enumeration check.

### 3. Start an original non-biometric transport skeleton

- Enumerate only allow-listed identities and interfaces.
- Implement version query, open/close, cancellation, and timeouts first.
- Keep capture, enrollment, commit, and verification disabled behind explicit
  development gates.

### 4. Integrate capture and retry behavior

- Model interrupt and bulk completion ordering.
- Map `0x89` to bounded retry without losing the real error status.
- Prove result-buffer bounds and secure clearing before exposing sample data.

### 5. Gate experimental enrollment

- Enable only after the update boundary and two-phase commit ownership are
  reproduced in mocks and independently reviewed.
- Preserve rollback and secure deletion for every intermediate state.
- Never publish biometric/template payloads while debugging.

### 6. Recover verification semantics and harden

- Identify the real match/no-match/error result field.
- Add malformed-response, cancellation, hot-unplug, timeout, and fuzz tests.
- Only then consider normal libfprint/fprintd integration and packaging.

## Safe ways to contribute now

- Submit another model/USB identity through the hardware-report issue form.
- Reproduce a static anchor against the exact documented artifact hash.
- Improve mock state transitions and failure tests.
- Review the architecture and challenge an inference with bounded evidence.
- Run offline checks from the [tooling guide](../tools/README.md).

Real enrollment, live commit, firmware operations, and unredacted captures are
not beginner contribution tasks. Read [CONTRIBUTING.md](../CONTRIBUTING.md)
before collecting or publishing evidence.
