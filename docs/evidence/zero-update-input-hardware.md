# Stable-zero UpdateEnrollment input hardware test

## Question

Static A21 analysis showed Windows EngineAdapter passing the fixed address
`EngineContext+0x18` as the required 20-byte generic UpdateEnrollment input.
Because the containing allocation uses `HEAP_ZERO_MEMORY` and no direct
adapter-side writer was found, this test asked whether Linux's fresh
capture-derived input was the mismatch and whether a stable all-zero input
would reproduce Windows behavior.

## Safety boundary

The repository-local interposer gained the explicit policy
`zero-input-fresh-rearm-stop-before-commit`. It:

- changes only the pointer passed as the required 20-byte native update input;
- uses one stable all-zero buffer and does not read or log replaced source
  bytes;
- never repeats a rejected UpdateEnrollment;
- retains the proven `0x8a` re-arm after accepted-incomplete updates and
  ordinary `0x89` bad captures;
- permits at most 24 native updates and four accepted-incomplete updates;
- returns an experimental fatal status before the unchanged state machine can
  enter commit if native completion becomes nonzero; and
- leaves all native output pointers and values untouched.

Mock coverage proved the zero substitution with an intentionally nonzero
source buffer, stable effective pointer/content, null-source rejection before
the native call, unchanged outputs on native `0x59`, no same-update replay,
and completion blocking before commit. The complete repository suite contained
70 passing tests before hardware use. The validated target DSO hash remained
unchanged before and after the build.

## Hardware result

The tested device was `0a5c:5833`. Two adjacent sessions requested the same
right-index finger and used identical re-arm, metadata, completion-blocking,
and cleanup boundaries. Their only interposer policy difference was the
20-byte input substitution.

### Stable-zero session

Native UpdateEnrollment results were:

```text
0x89, 0x89, 0x89, 0x89, 0x89, 0x89, 0x89, 0x88
```

All seven `0x89` results re-armed successfully with native `0x8a`. No update
was accepted. Completion stayed zero, the 20-byte output stayed zero, and the
32-bit output was unchanged on every call. Native `0x88` then entered the
existing fatal cancel/discard cleanup and closed the device.

From the second call onward, metadata reported the effective input pointer and
content as stable. It also reported that the zero input equaled the previous
zero output. That equality is a consequence of both buffers remaining zero;
it is not evidence that output was fed back.

### Fresh-input control

After a short idle interval, the existing
`fresh-rearm-stop-before-commit` policy retained the original
capture-derived input. Native results were:

```text
0x00, 0x00, 0x89, 0x00, 0x59
```

The three `0x00` calls were accepted-incomplete updates. Each produced a
nonzero 20-byte output and cleared the 32-bit output while completion remained
zero. The intervening `0x89` re-armed successfully. The final `0x59` was
preserved without replay and entered the existing fatal cleanup. Input pointer
and content changed on every control call and never equaled the previous
20-byte output.

Neither session observed native completion, state 2, template commit, or an
enrollment record.

## Interpretation

The adjacent control rules out poor finger placement as a sufficient
explanation for the stable-zero failures: the unmodified input accepted three
samples under the same requested-finger procedure, while stable zero accepted
none. Therefore continuously replacing the Linux input with zero is not the
Windows-equivalent fix and should not be carried into a driver.

Subsequent cross-adapter analysis resolves the reason. In Advanced mode,
Windows SensorAdapter copies the 20-byte output of
`CSS_FingerprintCaptureStart` from `SensorContext+0x5c` into
`EngineContext+0x18`; EngineAdapter then passes that same field to
UpdateEnrollment. The pointer is stable, but its content is refreshed with a
capture/enrollment ID. Stable zero therefore removed a required identifier.
See [the complete Windows dataflow](windows-a21-update-input-dataflow.md).

The result is now conclusive for this hypothesis: another input-lifetime or
replacement-value experiment is not justified. The next implementation target
is the BCM5880 host enrollment coordinator and its selected completion/commit
path.

## Private source-log identity

The redacted logical logs remain outside version control:

```text
34ce984523fd8e7d834fc10c63c7f951c0ebc42b6f5b06ef65fca333b43d74e8
  stable-zero session

fb3abf67a1769934d69bb494d90ae005783340fe55c1110005ae268087bf6c7c
  fresh-input control
```

The repository publishes no buffer pointer addresses, capture/enrollment IDs,
fingerprint features, templates, or payload bytes from these logs.
