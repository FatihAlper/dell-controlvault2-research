# Evidence for the fresh-sample enrollment boundary policy

## Scope

This record covers repository-local source, mock tests, and one bounded
hardware run on the tested Latitude 7390. The run did not install a driver,
write firmware, reach template commit, or expose biometric payload bytes.

The policy is selected explicitly:

```text
CV2_ENROLLMENT_UPDATE_POLICY=fresh-stop-before-commit
```

The historical `legacy-repeat` behavior remains the default so existing
evidence remains reproducible.

## Control flow

The interposer continues to wrap only
`cv_fingerprint_update_enrollment`. Under the fresh-boundary policy:

```text
native update status 0x59
  -> log redacted output metadata
  -> return native 0x59 unchanged
  -> unchanged outer callback performs fatal cleanup/discard
  -> no same-update replay

native update status 0x00, completion 0
  -> return native 0x00 unchanged
  -> unchanged state machine requests the next fresh capture

native update status 0x00, completion nonzero
  -> log the native completion boundary
  -> return experiment-fatal status before state 2
  -> unchanged outer callback performs one cancel and one discard
  -> generic commit is not entered
```

A null completion pointer on native success is also blocked because the
experiment cannot validate the commit boundary in that case. Native `0x89`
retains the already tested `0x8a` re-arm behavior.

## Mock evidence

Repository-local tests prove:

- an invalid policy fails resolver readiness before an update command;
- native `0x59` causes exactly one real `0x6c` and one existing cleanup;
- native success with completion zero passes unchanged;
- native success with completion one is converted to experiment-fatal before
  state 2 and causes exactly one existing cancel/discard;
- capture, commit, verify, cancel, and discard functions are not interposed;
- the target DSO remains hash-validated and is not modified.

The full suite currently reports 62 passing tests.

## Hardware result

The first hardware run was limited to one attempt. Its privacy-safe command
sequence was:

```text
0x8a -> 0x66 -> 0x6c = 0x89
     -> 0x8a -> 0x66 -> 0x6c = 0x00, completion 0
              -> 0x66 -> wait
```

The second update produced accepted progress `1/10`. The unchanged state
machine then issued a genuinely fresh `0x66` capture within milliseconds, so
the policy did establish a fresh-sample boundary. It did not issue `0x8a`
between the accepted incomplete update and that next capture. Four physical
lift-and-touch attempts produced no further completed capture or `0x6c`.

Clean cancellation was requested after the bounded wait. The trace contains
one `0x68` cancellation request and no `0x6d`, `0x6e`, or `0x6f`. The
proprietary call did not return from cancellation, so the repository-local
process was terminated. The USB capture retained 760 packets with zero drops,
and the device remained enumerated as `0a5c:5833` afterward.

This result narrows the next hypothesis: an accepted update with completion
zero may require `0x8a` re-arm before the next native `0x66`, matching the
three between-capture `0x8a` operations in the successful four-update Windows
control.

## Accepted-incomplete re-arm policy

The follow-up policy is selected separately so the first hardware result
remains reproducible:

```text
CV2_ENROLLMENT_UPDATE_POLICY=fresh-rearm-stop-before-commit
```

Mock tests prove that it:

- calls native `0x8a` exactly once after status zero/completion zero;
- blocks native nonzero completion before `0x8a` and generic commit;
- routes an `0x8a` failure to existing fatal cleanup;
- permits only three accepted-incomplete re-arms and stops on a fourth
  completion-zero update before another capture;
- preserves native `0x59` without same-update replay.

The first hardware control for this policy did not reach the new branch. Five
physical samples each returned native `0x89`; every rejection was followed by
a successful `0x8a` and a fresh `0x66`. The user then cancelled the bounded
attempt. The structural trace ended with `0x68`, two `0x6d` operations, and
`0x04`; the public harness reported cancellation and clean device close. The
capture contained 378 packets with zero drops, and the device remained
`0a5c:5833`.

This control proves repeated bad-capture recovery and clean cancellation, but
it neither supports nor refutes re-arming after accepted incomplete progress.

## Accepted-incomplete hardware result

A second bounded control exercised the new branch. Ignoring intervening native
`0x89` quality rejections, its privacy-safe accepted-update sequence was:

```text
0x6c = 0x00, completion 0 -> 0x8a -> fresh 0x66
0x6c = 0x00, completion 0 -> 0x8a -> fresh 0x66
0x6c = 0x00, completion 0 -> 0x8a -> fresh 0x66
0x6c = 0x59                    -> existing cleanup and close
```

All three accepted-incomplete re-arms succeeded. More importantly, every
following fresh capture completed and produced another update call; the hang
seen when `0x8a` was absent did not recur. The fourth-boundary update still
returned native `0x59`. It was preserved as-is, with no same-update replay,
synthesized success, state-2 transition, `0x6e`, or `0x6f`.

The structural trace contained nine `0x66` captures and nine `0x6c` updates.
Three update replies had the longer accepted-progress shape; the final update
reply had the shorter native-error shape. The run ended through `0x68`,
`0x6d`, and `0x04`, with 378 captured packets, zero drops, clean device close,
and the device still enumerated as `0a5c:5833`.

This demonstrates two independent boundaries in the tested runs: the
between-capture `0x8a` restores progress after accepted incomplete updates,
while reproducing that Windows command shape alone does not resolve the native
fourth-update `0x59`.

## Independent replication (2026-08-19)

A preceding same-day control used two different fingers with explicit lift
cycles and produced sixteen consecutive native `0x89` results. All sixteen
ordinary `0x89 -> 0x8a -> 0x66` recoveries succeeded; explicit cancellation
and close were clean. Its USB capture contained 560 packets with zero drops,
seventeen `0x66`, sixteen `0x6c`, and seventeen `0x8a` request/response pairs.
This rules out a continuously-present finger as the explanation for that
all-`0x89` session, but does not reinterpret `0x89` as an accepted sample.

A later session on the same `0a5c:5833` unit independently reproduced the
accepted-incomplete result. The logical sequence contained four intervening
native `0x89` quality rejections and three accepted status-zero/completion-zero
updates. Every one of those seven nonterminal updates was followed by a
successful native `0x8a`; each subsequent fresh capture completed. The eighth
update returned native `0x59`, which was preserved and routed through existing
cleanup without replay, synthesis, state forcing, `0x6e`, or `0x6f`.

The USB capture contained eight `0x66`, eight `0x6c`, and eight `0x8a`
request/response pairs. Three `0x6c` replies used the 96-byte accepted-progress
shape; four `0x89` replies and the final `0x59` used the 44-byte non-success
shape. All 318 packets were captured with zero drops. The device closed cleanly
and continued to enumerate as `0a5c:5833`.

The private redacted log and raw USB capture are retained outside the
repository with SHA-256 values
`3ad3895e260785284371c11bdde690fe4e631528649411a58cd38c7ff1488f02` and
`f410f096607fa57a1d629d2bd9063872be05e3605eb5c1a82e2c82cdc6a3ee24`,
respectively. No capture payload is included here.

The preceding all-`0x89` control's private redacted log and capture hashes are
`7bcba1210bfc8a14a580d03d5d15f38d281d905d9975ee3a4fdb17753ff8aae7` and
`e76771ce71be04a785047ba4b8c46e53d6820220aff3f717ca5fd0c9472cbbb8`.
