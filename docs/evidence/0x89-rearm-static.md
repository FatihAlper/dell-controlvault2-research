# Static evidence for the `0x89 -> 0x8a -> 0x66` experiment

## Reproducible target validation

Command:

```sh
python3 tools/enrollment_0x89_target.py \
  prebuilt/libfprint-2-tod-1-broadcom-5833.probe.so
```

Observed:

```text
validated_sha256=c7dbb44e25aa5127515cb4de23868358d7b170d2625227131a88bce39f3e8ef6
validated_build_id=66134403db205c7c1ac682885229224790aedc0e
signature.start_enrollment_trampoline_to_0x8a=0x2afc0
signature.update_wrapper_0x89_branch=0x2b152
signature.outer_callback_0x89_retry_branch=0xdd0d
signature.enrollment_state_transition_command_0x8a=0x27a06
signature.capture_command_0x66=0x25516
signature.update_command_0x6c=0x262f7
target_write_performed=no
```

The validator accepts one SHA-256 profile and requires each CFG signature to
occur exactly once. A changed byte is rejected before loading. The target is
never opened for writing.

## Relevant disassembly facts

| Address | Observation |
|---|---|
| `0xcafb` | state 0 calls `cvif_fingerprint_start_enrollment` |
| `0x2afc0` | that wrapper jumps to `cv_cmd_enrollment_started@plt` |
| `0x27a06` | `cv_cmd_enrollment_started` supplies command `0x8a` |
| `0xcb5c` | state 1 calls `cvif_fingerprint_capture_start` |
| `0x2b069` | wrapper calls `cv_fingerprint_capture_start@plt` |
| `0x25516` | capture implementation supplies command `0x66` |
| `0xcb91` | state 1 calls `cvif_fingerprint_update_enrollment` |
| `0x2b143` | wrapper calls `cv_fingerprint_update_enrollment@plt` |
| `0x262f7` | update implementation supplies command `0x6c` |
| `0x2b15b` | update wrapper compares its result with `0x89` |
| `0xdd1a` | outer callback compares task status with `0x89` |
| `0xdf17` | `0x89` queues the next task without changing state |
| `0xdf78` | other nonzero status calls discard and fatal completion |
| `0xcba0` | cancellation has its own capture-cancel/discard path |

At callback entry, task state is copied into device offset `+0x24`. The
`0x89` branch jumps directly to the task-queue helper. The helper copies that
same device state back into the next task. It is therefore state `1`.

## Experiment build preservation check

Command:

```sh
tools/build_enrollment_0x89_experiment.sh
```

Relevant observed output:

```text
experiment_artifact=.local-test/enrollment-0x89/libcv2-enrollment-0x89-rearm.so
target_sha256_before=c7dbb44e25aa5127515cb4de23868358d7b170d2625227131a88bce39f3e8ef6
target_sha256_after=c7dbb44e25aa5127515cb4de23868358d7b170d2625227131a88bce39f3e8ef6
target_write_performed=no
```

No original/patched binary disassembly pair is applicable because the target
binary is not patched. Its pre- and post-build hash is identical. The
experiment is a separate ELF interposer built from source.

## Mock-loader control-flow evidence

The tests build a mock CV2 shared library and load it with
`g_module_open(..., G_MODULE_BIND_LAZY | G_MODULE_BIND_LOCAL)`, matching the
real TOD loader. The TOD-like caller lives inside that local DSO. The actual
experimental interposer is exercised through ELF symbol preemption rather
than by a Python-only state model.

The old resolver is retained only as a test fixture. It proves that
`RTLD_NEXT` cannot forward to the local-scope original. The production
interposer contains no `dlsym(RTLD_NEXT, ...)` call.

The new fixture requires this readiness sequence:

```text
expected target path
loaded target discovered through dl_iterate_phdr
RTLD_NOLOAD handle acquired
update symbol resolved and dladdr ownership verified
enrollment-started symbol resolved and dladdr ownership verified
local-scope forwarding ready
```

Success case:

```text
mock command 0x6c returns 0x89
interposer observes 0x89 and calls command 0x8a
mock command 0x8a succeeds
existing mock callback retains state 1
next capture calls command 0x66
next update calls command 0x6c
```

Failure case:

```text
mock command 0x6c returns 0x89
mock command 0x8a fails
no command 0x66 is issued
existing fatal capture-cancel path is called once
existing fatal discard path is called once
process terminates without another update
```

Statuses `0`, `0xa4`, `0x8d`, `0x24`, `0x8f`, and `0xffffffff` are asserted
to pass bit-exact and never issue `0x8a`. The later bounded `0x59`
experiment is documented separately in
`docs/evidence/0x59-single-update-retry-static.md`.

These results prove the repository-local interposer's control flow. They are
not hardware or firmware evidence.
