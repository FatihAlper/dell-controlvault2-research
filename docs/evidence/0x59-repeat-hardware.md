# Privacy-safe hardware evidence for `0x59`

This document contains only derived event counts and state transitions. The
timestamped source logs remain local and are not part of this repository.
Raw USB payloads, biometric features, templates, enrollment tokens, device
nodes, memory addresses, and personal identifiers are excluded.

## Initial repeatability result

Two controlled runs used the same verified probe target and repository-local
interposer:

```text
accepted 1/10
accepted 2/10
accepted 3/10
native UpdateEnrollment status 0x59
fatal capture-cancel/discard path
device close
```

The driver formats the final value with `%d`; the displayed decimal `89` is
hexadecimal `0x59`. It is distinct from hexadecimal `0x89`, decimal 137.

In the second run, nine native `0x89` results were observed. Every result was
followed by exactly one successful `0x8a` transition and a new capture.

## Bounded repeated-update result

A later single controlled run tested one additional native UpdateEnrollment
after each first `0x59`:

```text
accepted 1, 2, 3
0x59 → second 0x6c returns 0x89 → one successful 0x8a → continue
accepted 4, 5, 6
0x59 → second 0x6c returns 0x89 → one successful 0x8a → continue
accepted 7, 8, 9
0x59 → second 0x6c returns 0x89 → one successful 0x8a → continue
accepted 10, 11, 12
0x59 → second 0x6c returns 0x89 → one successful 0x8a → continue
accepted 13
controlled cancellation and device close
```

Four first-`0x59` events therefore produced four native second-`0x89`
results. Every one caused exactly one successful `0x8a` transition.

Completion remained `0x00`; the enrollment output remained unpopulated.
No output bytes are published. State 2 and command `0x6e` were not reached.

## Evidence classification

### Proven on hardware

- `0x89 → 0x8a → new capture` succeeds on the tested device.
- One bounded repeated `0x6c` after `0x59` returns `0x89`.
- This diagnostic transition allows progress beyond the former three-sample
  boundary.
- The host stage counter can exceed its displayed total of ten.
- Completion stays zero.
- Cancellation, discard, and close complete.

### Not proven

- A semantic name for `0x59`.
- Enrollment completion.
- Template creation or commit.
- Verification.

The stage counter is host-side progress reporting, not firmware completion
evidence.
