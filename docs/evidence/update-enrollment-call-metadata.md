# Redacted UpdateEnrollment call metadata

This record covers one opt-in Linux hardware run using
`fresh-rearm-stop-before-commit` plus call-level metadata tracing on the tested
`0a5c:5833` device. The trace does not contain pointer addresses, enrollment or
capture IDs, fingerprint features, output bytes, templates, or payload hashes.

## Instrumentation boundary

The existing repository-local interposer still defines only
`cv_fingerprint_update_enrollment()`. Metadata tracing is enabled separately:

```sh
tools/run_local_enrollment_0x89_test.sh \
  --confirm-real-enrollment \
  --fresh-rearm-boundary \
  --trace-update-metadata
```

The native call and all return statuses are unchanged. The trace records only:

- call number and native status;
- null/non-null state and input length;
- `first`/`same`/`changed` pointer and content relations;
- equality of a current 20-byte input with the previous 20-byte output;
- zero/nonzero and changed/unchanged classifications for output buffers.

No pointer address or buffer value is formatted. Invalid trace configuration
fails resolver readiness before USB enumeration. Mock tests prove both the
positive equality case and that configured sentinel values do not occur in
metadata lines.

## Hardware sequence

The bounded session contained twenty native updates:

| Native result | Count | Output behavior |
|---|---:|---|
| `0x89` | 16 | No output field changed. |
| `0x00`, completion zero | 3 | 20-byte output became nonzero; 32-bit output became zero. |
| `0x59` | 1 | No output field changed. |

All `0x89` recoveries and all three accepted-incomplete re-arms succeeded. The
next update after three accepted samples returned native `0x59`; the policy
preserved it without replay, synthetic completion, state forcing, or commit.
Existing cleanup closed the device normally.

## Input and buffer provenance

The following relations held across all twenty calls:

- the device handle remained the same;
- the enrollment/capture-ID pointer changed after the first call;
- the 20-byte enrollment/capture-ID content changed after the first call;
- no current enrollment/capture ID equaled the preceding call's 20-byte
  enrollment output;
- auxiliary-input length was always zero;
- the auxiliary pointer was non-null and stable, but no bytes were in scope;
- the completion pointer was stable and its byte was zero before every call;
- the enrollment-output pointer changed after the first call and its 20-byte
  buffer was zero before every call;
- the 32-bit output pointer was stable, began nonzero on every call, and was
  written to zero only by the three native successes.

For each accepted update, the 20-byte output changed from all-zero to nonzero.
Before the next update, the caller supplied a different all-zero output buffer.
There was no explicit auxiliary input and the fresh capture ID did not equal
the previous output. Thus intermediate accepted output is not fed into the
next generic update through any argument visible in this ABI.

On the final native `0x59`, completion remained zero, the 20-byte output stayed
zero, and the 32-bit output retained its pre-call nonzero value. The call did
not produce a completion marker or commit input.

## Interpretation boundary

The trace proves call-level provenance, not the semantics of the opaque
20-byte output. The device may maintain its own internal accumulator, so the
absence of explicit host feedback is not by itself proof of the root cause.
It does, however, rule out an unseen auxiliary-input handoff in the Linux
wrapper and confirms that forcing commit after `0x59` would use no native final
output.

The next high-value comparison is the Windows adapter immediately before its
protected `0x6c` request is built, or equivalent static recovery of the generic
Windows update arguments. Only lengths, selectors, pointer provenance, and
state transitions should be recorded.

The private redacted log is retained outside the repository with SHA-256
`ff39894b58d92a64bd5674872e1be294b9c4562504232dada4e0bd605a308498`.
