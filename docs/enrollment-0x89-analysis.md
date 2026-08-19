# Enrollment `0x89` retry analysis and experiment

## Scope

This experiment targets only the infinite bad-capture loop tracked by issue
#4. It does not alter probe/open/close, USB IDs, verify, enrollment commit, or
the existing patch 4/5 experiments. In particular, no conclusion here applies
to the separate `0x8d`/`0x24` commit failures in issues #2 and #3.

The analyzed artifact is:

```text
prebuilt/libfprint-2-tod-1-broadcom-5833.probe.so
SHA-256 c7dbb44e25aa5127515cb4de23868358d7b170d2625227131a88bce39f3e8ef6
ELF Build ID 66134403db205c7c1ac682885229224790aedc0e
```

## Reconstructed Linux state machine

The names below are exported symbols. Addresses are virtual addresses in the
analyzed ELF.

```text
TOD enrollment entry
  |
  +-- state 0 (worker 0xcac0, branch 0xcae8)
  |     cvif_fingerprint_start_enrollment()       call 0xcafb
  |       -> cv_cmd_enrollment_started()          trampoline 0x2afc0
  |       -> cvhManageCVAPICall(command=0x8a)     0x27a06
  |     callback success:
  |       device enrollment state := 1            0xdf10
  |       queue next GTask                         0xdf17 -> 0xdb30
  |
  +-- state 1 (worker branch 0xcb40)
  |     cvif_fingerprint_capture_start()           call 0xcb5c
  |       -> cv_fingerprint_capture_start(
  |            handle, 2, 0x23, capture_id, 0, 0) call 0x2b069
  |       -> CV command 0x66
  |     process interrupt loop                     0xcb7c
  |     cvif_fingerprint_update_enrollment()       call 0xcb91
  |       -> cv_fingerprint_update_enrollment()    call 0x2b143
  |       -> CV command 0x6c                       0x262f7
  |       -> status handling:
  |            success + incomplete -> 0x8f
  |            success + complete   -> 0
  |            0xa4 or 0x89         -> unchanged
  |            other error          -> capture cancel, unchanged error
  |     callback:
  |       0x8f -> increment accepted-sample count, queue state 1
  |       0xa4 -> queue state 1
  |       0x89 -> queue state 1                     0xdd1a -> 0xdf17
  |       other nonzero -> discard + fatal complete 0xdf78
  |       zero -> device enrollment state := 2      0xe010
  |
  +-- state 2
        cvif_fingerprint_commit_enrollment()         call 0xcb2d
        -> CV command 0x6e
```

The helper at `0xdb30` copies device state offset `+0x24` into the new task's
state offset `+0x04`. The `0x89` branch does not modify either value.
Therefore state `1`, the enrollment object, capture identifier, and accepted
sample counter are preserved. The new task enters `0xcb40` and calls
`cvif_fingerprint_capture_start()` directly. No `0x8a` occurs on this path in
the unmodified Linux flow.

The worker at `0xcb5c` does not test the return value from
`cvif_fingerprint_capture_start()` before entering the interrupt loop. That
makes capture-start itself an unsafe insertion point: an `0x8a` failure there
could still leave the worker waiting for a capture interrupt that was never
started.

Cancellation is independent: while waiting, cancellation reaches `0xcba0`,
calls capture-cancel, then discard, and finishes with cancellation status
`0x2f`.

## Windows behavior used by the hypothesis

Static analysis of the Windows adapter establishes this higher-level
sequence:

```text
SensorAdapterStartCapture(enrollment)
  -> command 0x8a
  -> command 0x66
capture completion
UpdateEnrollment
  -> command 0x6c
```

When update returns `0x89`, the adapter maps it to
`WINBIO_E_BAD_CAPTURE` with `WINBIO_FP_POOR_QUALITY`. It does not send
CaptureCancel, DiscardEnrollment, or FingerprintReset. If WBF continues the
enrollment, the next `SensorAdapterStartCapture` repeats `0x8a -> 0x66`.

`0x8a` is described here only as the enrollment re-arm/state transition
observed in the Windows control flow. Its exact firmware semantic name is not
proven.

## Selected experiment

The experiment is a repository-local source interposer, not a binary rewrite.
The plugin's internal call to `cv_fingerprint_update_enrollment` uses a PLT
entry, and the DSO has no `DF_SYMBOLIC` flag. This permits that one symbol to
be preempted by a deliberately loaded experiment library.

The interposer performs:

```text
real cv_fingerprint_update_enrollment() / command 0x6c
  |
  +-- result != 0x89: return it unchanged
  |
  `-- result == 0x89:
        log attempt
        call existing cv_cmd_enrollment_started() / command 0x8a
          |
          +-- success: return the original 0x89
          |     existing callback preserves state 1 and queues next task
          |     next task calls command 0x66
          |
          `-- failure: return a fatal status
                existing cvif wrapper runs capture-cancel
                existing callback discards and completes with an error
```

Calling `cv_cmd_enrollment_started()` reuses the exact function used by the
initial state-0 path. Returning the original `0x89` after successful `0x8a`
also reuses the existing GTask scheduling and retry path, so the experimental
library does not create or own a GTask.

If `0x8a` itself returns one of the outer callback's retry-only statuses
(`0x89`, `0xa4`, or synthetic `0x8f`), the experiment maps that result to the
driver's generic command failure `0x100003`. Other nonzero statuses pass
through. This prevents an `0x8a` failure from becoming an infinite retry and
routes it through the existing capture-cancel and fatal discard path.

The interposer does not export `cv_fingerprint_capture_start`. The normal
target-local capture path and command `0x66` are not intercepted. Initial
enrollment, commit, verify, cancellation, capture-cancel, and discard
functions are likewise outside the interposition surface.

## Local-scope symbol forwarding

The repository-local TOD loader opens drivers with:

```c
g_module_open (module_path, G_MODULE_BIND_LAZY | G_MODULE_BIND_LOCAL);
```

The first hardware attempt proved that the preload can intercept a call from
this local DSO, but `dlsym(RTLD_NEXT, ...)` cannot find the target-local
original symbol. The first capture therefore did not start, and the protocol
hypothesis was not exercised.

The corrected resolver receives the canonical target path through
`CV2_0X89_TARGET_PATH` and performs, once per process:

1. Canonicalize and `stat()` the expected target.
2. Use `dl_iterate_phdr()` to require an already-loaded object with the same
   canonical path, device, and inode.
3. Acquire a target-specific handle using
   `dlopen(path, RTLD_LAZY | RTLD_NOLOAD)`. No object is newly loaded and no
   object is promoted to global scope.
4. Resolve `cv_fingerprint_update_enrollment` and
   `cv_cmd_enrollment_started` with `dlsym(target_handle, name)`.
5. Validate each returned address with `dladdr()`, again requiring the same
   canonical path, device, and inode. The update address is additionally
   rejected if it is the interposer wrapper.
6. Cache the retained handle and pointers with `pthread_once()`. The handle
   is not closed while the plugin is in use.

The hardware harness calls the exported readiness check immediately after
`fp_context_new()` has loaded the TOD modules and before USB enumeration,
device open, or enrollment. Failure exits with status 2 instead of allowing a
worker to enter its interrupt wait.

Detailed first-attempt and local-scope test evidence is in
`docs/evidence/local-scope-forwarding.md`.

## Behavior intentionally unchanged

- Initial state-0 enrollment and its first `0x8a`
- Successful incomplete sample (`0x8f`) and progress counting
- Successful completed sample and transition to state 2
- Commit and command `0x6e`
- Cancellation
- `0xa4`, `0x8d`, and `0x24`
- Verify
- Probe, open, close, USB IDs, and 5833/5834 selection
- Existing patch 4 and patch 5

## Evidence classification

### Proven by static analysis

- Windows issues `0x8a -> 0x66` for each enrollment capture start.
- Linux issues the initial `0x8a`, but after update status `0x89` queues state
  1 and returns directly to `0x66`.
- Linux state 1 and the accepted-sample counter are not reset by the `0x89`
  branch.
- Non-special nonzero callback results use the existing discard/fatal path.

### Hypothesis under test

- Repeating the Windows-observed `0x8a` state transition before Linux's
  existing `0x89` capture retry will end the infinite `0x89` loop.

### Subsequently proven on hardware

- The corrected resolver reached real commands `0x66` and `0x6c`.
- Nine observed `0x89 -> 0x8a -> capture` cycles completed successfully.

### Still unproven

- The exact on-wire Windows packet bytes for `0x8a`.
- Whether the Windows kernel/framework inserts another transfer.
- Whether enrollment reaches and successfully completes commit.
- Whether this affects the separate `0x8d`/`0x24` problems in issues #2/#3;
  no such claim is made.

## Hardware boundary

`tools/run_local_enrollment_0x89_test.sh` refuses to run without
`--confirm-real-enrollment`. A successful real test can reach the driver's
commit state and may leave a template inside ControlVault. Hardware evidence
was collected only in explicitly authorized local runs; the repository test
suite never invokes this runner. It must not be run without separate explicit
user approval.
