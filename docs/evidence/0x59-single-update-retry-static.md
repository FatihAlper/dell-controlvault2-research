# Static evidence for the bounded `0x59` UpdateEnrollment experiment

## Scope

This document covers a repository-local ELF interposer and mock fixture. No
hardware enrollment was run, no proprietary binary was modified, patch 4
was not enabled, and no system path was changed.

Target identity:

```text
SHA-256 c7dbb44e25aa5127515cb4de23868358d7b170d2625227131a88bce39f3e8ef6
Build ID 66134403db205c7c1ac682885229224790aedc0e
```

## ABI and pointer preservation

Disassembly of the raw Linux function at RVA/file offset `0x26130` proves
this seven-argument System V call shape:

```text
handle
20-byte enrollment-id input
optional input size
optional input pointer
completion output pointer (TOD consumes the low byte)
20-byte enrollment-data output pointer
4-byte output-value pointer
```

The successful raw path clears/saves the three outputs at
`0x26330`--`0x263a0`. An ordinary nonzero result branches at `0x2632a`
directly to cleanup, so a first `0x59` does not establish fresh output
contents. The interposer therefore performs no reset. The second call uses
the same cached real function pointer and repeats all seven arguments
unchanged.

The fixture starts with known synthetic nonzero output values and records all
pointer identities. The public interposer deliberately redacts output bytes:

```text
[mock-cv2] update argument identity=first
[mock-cv2] command 0x6C status=0x59
[cv2-0x59-experiment] first completion=0x31 enrollment_output=<redacted> output_value=<redacted>
[mock-cv2] update argument identity=same
[mock-cv2] command 0x6C status=0x0
[cv2-0x59-experiment] second completion=0x31 enrollment_output=<redacted> output_value=<redacted>
```

This proves the interposer itself neither changes the output pointers nor
writes their contents.

## Bounded control flow

```text
real update
  status != 0x59
    -> existing 0x89 handling, if applicable
    -> otherwise return bit-exact status

  status == 0x59
    -> log first completion/output state
    -> call the same real update once with identical arguments
    -> log second native status and completion/output state
    -> never issue a third update from this wrapper invocation
    -> if second status is 0x89, run the existing single 0x8a transition
    -> return the second native status unchanged
```

No status is synthesized for the `0x59` path. It does not alter enrollment
state, sample count, capture, commit, verify, or cleanup. A second `0x59`
therefore reaches the unchanged Linux capture-cancel/discard path.

## Local-scope and status matrix

The fixture loads its target with:

```c
g_module_open(plugin_path, G_MODULE_BIND_LAZY | G_MODULE_BIND_LOCAL);
```

The production resolver still requires the already-loaded canonical target,
device/inode identity, `RTLD_NOLOAD`, target-handle `dlsym`, and `dladdr`
ownership. It has no `RTLD_NEXT` fallback.

The mock tests prove:

| First status | Second status | Real update calls | `0x8a` calls | Result |
|---|---:|---:|---:|---|
| `0x00` | n/a | 1 | 0 | native `0x00` |
| `0x8f`, `0xa4`, other | n/a | 1 | 0 | bit-exact first status |
| `0x89` | n/a | 1 | 1 | original `0x89`, existing capture retry |
| `0x59` | `0x00` | 2 | 0 | native `0x00` |
| `0x59` | `0x89` | 2 | 1 | original second `0x89`, existing capture retry |
| `0x59` | `0xa4` | 2 | 0 | native `0xa4` |
| `0x59` | `0x59` | 2 | 0 | native `0x59`, one cancel and one discard |
| `0x59` | other fatal | 2 | 0 | bit-exact fatal status, normal cleanup |

The production DSO defines only the driver wrapper
`cv_fingerprint_update_enrollment` plus the harness readiness control
`cv2_0x89_forwarding_ready`. Capture, commit, verify, discard, cancel, probe,
and open/close are not interposed.

## Windows-reference correction

Rechecking the exact official A21 package (SHA-256
`e157fbe548bfd2b6b1ee4410b5dc93255409b329bbe4d75da9d7c1684fa1db4e`)
does not support the previously documented generic backedge:

```text
BrcmEngineAdapter.dll RVA 0x32bf:
  jne 0x3175

RVA 0x3175:
  mov ebx,0x8009800f
  jmp 0x32f7
```

RVA `0x3175` is an error return, not the call at RVA `0x31c1`. The bounded
repeat is consequently an independent diagnostic hypothesis, not proven
generic Windows behavior. The separate `cvFingerprintUpdateEnrollment5880`
path remains statically present, but runtime selection on this Latitude is
unproven.

## Original repository-local test result

```text
Ran 36 tests in 1.106s
OK

target_sha256_before=c7dbb44e25aa5127515cb4de23868358d7b170d2625227131a88bce39f3e8ef6
target_sha256_after=c7dbb44e25aa5127515cb4de23868358d7b170d2625227131a88bce39f3e8ef6
deterministic_and_target_unchanged=yes
```

These are static, loader, and mock control-flow results. They are not
hardware or firmware evidence.

## Evidence classes

### Proven on hardware before this change

- Three samples were accepted in each of two runs.
- Both runs ended at native `0x59` after 3/10.
- Nine observed `0x89 -> 0x8a -> capture` cycles succeeded.

### Proven by repository-local tests

- Local-scope forwarding remains ready and fail-closed.
- One and only one additional real update follows a first `0x59`.
- All call arguments are identical.
- Output values are observed but not synthesized or reset.
- Existing `0x89` handling and unrelated status behavior remain intact.

### Subsequently proven on hardware

- One immediate additional native `0x6c` after `0x59` returned `0x89`.
- The existing `0x89 -> 0x8a -> capture` path then continued progress beyond
  the former three-sample boundary.
- Completion remained zero and state 2 was not reached.

### Still unproven

- Enrollment completion, command `0x6e`, template commit, and verify.
- Whether Windows selects the generic or BCM5880-specific path at runtime on
  the Latitude 7390.
