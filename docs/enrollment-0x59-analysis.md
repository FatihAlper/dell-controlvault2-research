# Enrollment status `0x59` analysis

## Scope and identities

This analysis concerns the reproducible enrollment result `0x59` (decimal
`89`) on the Dell Latitude 7390 BCM5880 (`0a5c:5833`). No new hardware test,
binary rewrite, or patch application was performed. A repository-local
interposer and mock fixture were built; no system path was touched.

Linux target:

```text
prebuilt/libfprint-2-tod-1-broadcom-5833.probe.so
SHA-256 c7dbb44e25aa5127515cb4de23868358d7b170d2625227131a88bce39f3e8ef6
Build ID 66134403db205c7c1ac682885229224790aedc0e
```

The target contains probe patches 1--3 only. Its `.text` section has equal
virtual and file offsets (`VA 0xc870`, file offset `0xc870`), so the Linux
addresses below are also file offsets.

Windows reference:

```text
Dell ControlVault2 4.12.5.8 A21 package
SHA-256 e157fbe548bfd2b6b1ee4410b5dc93255409b329bbe4d75da9d7c1684fa1db4e
```

An ephemeral, hash-verified extraction outside the repository was used. No
installer or extracted proprietary component is included here.

## Status provenance

The seven relevant layers are:

1. The ControlVault response status returned by the command transport.
2. The Broadcom CV API return value from
   `cv_fingerprint_update_enrollment`.
3. The Linux `cvif_fingerprint_update_enrollment` return value.
4. A host-synthetic status: Linux creates `0x8f` after CV status `0x00`
   when the returned completion byte is zero.
5. The Windows EngineAdapter return value.
6. The WBF HRESULT and reject-detail output.
7. The decimal user-facing Linux message.

For the failing Linux path, command `0x6c` is built at `0x262f7`.
`cvhManageCVAPICall` returns into `eax` at `0x26311`; `eax` is copied to
`ebx` at `0x26316`. Apart from a distinct `0x9a` path, a nonzero result jumps
at `0x2632a` to `0x263ba`, is saved, and is returned unchanged at
`0x263ee`--`0x26419`.

The hardware evidence predates the bounded `0x59` experiment. In those
runs, the interposer changed only raw `0x89` and returned `0x59` bit-for-bit.
Therefore the observed final `0x59` first appears in the captured execution
as the Broadcom CV API result of the real command `0x6c`.
There is no Linux enrollment compare against immediate `0x59` anywhere in
the probe artifact. The Linux wrapper can synthesize `0x8f`, but cannot
synthesize `0x59`.

“Raw” below means unmodified at the CV API/interposer boundary. No USB packet
capture accompanied these tests, so layer 2 is directly proven while layer 1
is a strong inference: the command transport supplied `0x59`, and neither
the raw API function, interposer, nor wrapper contains a conversion which
could create it. Its exact on-wire field has not been observed.

The final message uses:

```text
Enrollment failed : Device status = (%d)
```

at file offset `0x2f468`. Consequently `(89)` is decimal `89`, which is
hexadecimal `0x59`. It is not the interposer's explicitly hexadecimal raw
`0x89` (decimal `137`).

## Linux enrollment CFG

The state-1 worker is:

```text
0xcb40 state 1
  -> 0xcb5c cvif_fingerprint_capture_start
       -> 0x25516 command 0x66
  -> 0xcb7c interrupt loop
  -> 0xcb91 cvif_fingerprint_update_enrollment
       -> 0x2b143 cv_fingerprint_update_enrollment
       -> 0x262f7 command 0x6c
  -> task result at task+0x34
  -> outer callback at 0xdcf3
```

The wrapper status dispatch is:

| Status | Exact instruction and target | Effect |
|---|---|---|
| `0x00` | `0x2b14d: test r12d,r12d`; `0x2b150: je 0x2b1a0` | Reads the completion byte. Zero completion creates synthetic `0x8f` at `0x2b1f6`; nonzero completion returns `0x00`. |
| `0xa4` (decimal 164) | `0x2b152: cmp r12d,0xa4`; `0x2b159: je 0x2b1d0` | Returns `0xa4` unchanged; no capture-cancel here. |
| `0x89` (decimal 137) | `0x2b15b: cmp r12d,0x89`; `0x2b162: je 0x2b1d0` | Returns `0x89` unchanged; no capture-cancel here. The experiment injects one successful `0x8a` before this return. |
| `0x59` (decimal 89) | No dedicated compare; falls through after `0x2b162` | Logs the fatal message at `0x2b164`, calls capture-cancel at `0x2b177`, and returns `0x59` unchanged at `0x2b190`. |
| Other nonzero | Same fall-through | Capture-cancel, then unchanged return. |

The outer callback loads the unchanged status at `0xdcf3`, loads the task
state at `0xdcfa`, and copies it to device enrollment state `+0x24` at
`0xdcfd`. Its dispatch is:

| Status | Exact instruction and branch target | State/counter effect | Next command and cleanup |
|---|---|---|---|
| synthetic `0x8f` (decimal 143) | `0xdd00: cmp r13d,0x8f`; `0xdd07: je 0xdf50` | Accepted-sample counter `+0x20` increments at `0xdf53`--`0xdf56`; state remains 1 | Reports progress and queues state 1 at `0xdf6d`: next command `0x66`. |
| `0xa4` (decimal 164) | `0xdd0d: cmp r13d,0xa4`; `0xdd14: je 0xdf17` | State and counter unchanged | Queues state 1: next command `0x66`; no discard. |
| `0x89` (decimal 137) | `0xdd1a: cmp r13d,0x89`; `0xdd21: je 0xdf17` | State and counter unchanged | Queues state 1: next command `0x66`; with the experiment, `0x8a` has already succeeded. |
| `0x00`, state 0 | `0xdd27: test r13d,r13d`, fall-through; `0xdd30`; `0xdd32: je 0xdf10` | Device state becomes 1 at `0xdf10` | Queues state 1: next command `0x66`. |
| `0x00`, state 1 | `0xdd38: cmp eax,1`; `0xdd3b: je 0xe010` | Device state becomes 2 at `0xe010`; command outputs are retained | Queues state 2. Worker `0xcb10` calls commit at `0xcb2d`; low-level command `0x6e` is built at `0x2691d`. |
| `0x00`, state 2 | `0xdd41: cmp eax,2`, fall-through to `0xdd4a` | Completes enrollment and creates the libfprint print | No new enrollment command. |
| `0x59` or other nonzero | `0xdd27`; `0xdd2a: jne 0xdf78` | State reset to 0 at `0xdf7d`; counter does not increment | `0xdf78` calls `cv_fingerprint_discard_enrollment`; that function builds command `0x6d` at `0x265e6`. Fatal completion follows at `0xdf9f`. |

Thus the exact compare preventing `0x59` from reaching commit is the generic
nonzero test at `0xdd27`/branch at `0xdd2a`, after it failed the three
special comparisons. Capture-cancel has already run at `0x2b177`; discard
then runs unconditionally at `0xdf78`. The evidence logs do not print a
separate discard line, but the static branch contains an unconditional call
to the exported discard function, whose command is `0x6d`.

There is no hidden or unreachable `0x59` enrollment branch in this artifact.

## Confirmed Linux function signature and mutable outputs

The exported function has no retained C type information. Its x86-64 System
V ABI was reconstructed from the callee at RVA/file offset `0x26130` and its
TOD wrapper caller at `0x2b0f0`:

```c
uint32_t cv_fingerprint_update_enrollment(
    uint32_t handle,
    const void *enrollment_id,       /* required 20-byte input */
    uint32_t auxiliary_input_size,   /* 0 or at most 0x1064 */
    const void *auxiliary_input,     /* input of the preceding size */
    uint8_t *completion_out,         /* required; low byte consumed by TOD */
    void *enrollment_data_out,       /* required 20-byte output */
    uint32_t *output_value_out);     /* 4-byte output */
```

The evidence is:

- `rsi` is registered as a 20-byte input at `0x26243`--`0x26252`.
- `edx` is retained as a size, checked for zero and bounded by `0x1064` at
  `0x2625f`--`0x2627e`; `rcx` is its corresponding input pointer.
- `r8` is registered as a 4-byte output at `0x2629d`--`0x262af`. The
  successful path initializes and finally stores its low byte at
  `0x26338` and `0x263a0`.
- `r9` is registered as a 20-byte output at `0x262bc`--`0x262cc`, cleared
  at `0x26330`--`0x26343`, and passed to `cvhSaveReturnValues`.
- stack argument 7 is registered as a 4-byte output at
  `0x262d9`--`0x262ea`, cleared at `0x26346`--`0x26354`, and passed to
  `cvhSaveReturnValues`.

For an ordinary nonzero status such as `0x59`, the raw function branches at
`0x2632a` directly to cleanup at `0x263ba`; it does not run the
success-only output clearing and save block. Consequently the first `0x59`
may leave all three output areas unchanged. The interposer neither clears
nor synthesizes any output. Its second call uses the exact same function
pointer, scalar values, and pointer identities.

## Windows EngineAdapter CFG

`WbioQueryEngineInterface` returns an interface record at RVA `0x2eaa0`.
The interface slot ordering identifies:

```text
CreateEnrollment  RVA 0x30d0
UpdateEnrollment  RVA 0x3130
GetEnrollmentStatus RVA 0x3320
CommitEnrollment  RVA 0x3900
DiscardEnrollment RVA 0x3d60
```

At `BrcmEngineAdapter.dll` RVA `0x3130` (file offset `0x2530`),
UpdateEnrollment calls the dynamically resolved
`CSS_FingerprintUpdateEnrollment` pointer at RVA `0x31c1` (file offset
`0x25c1`). The loader assigns that pointer from the literal export name.

The result in `esi` is handled as follows:

```text
RVA 0x3202  test esi,esi
  zero:
    increment accepted count
    if completion byte == 0:
      return 0x00090001 (WINBIO_I_MORE_DATA)
    else:
      state := 2 and continue the completion/commit preparation

RVA 0x328f  lea eax,[esi-0x90]
RVA 0x3295  cmp eax,9
  0x90..0x99:
    reject detail := esi-0x8f
    return 0x80098008 (WINBIO_E_BAD_CAPTURE)
    state := 3

RVA 0x32b9  cmp esi,0x89
  0x89:
    reject detail := 7
    return 0x80098008 (WINBIO_E_BAD_CAPTURE)
    state := 3

  any other nonzero, including 0x59:
    RVA 0x32bf jne 0x3175
    return 0x8009800f
```

This corrects an earlier control-flow interpretation. The signed displacement
at `0x32bf` is `0xfffffeb0`, whose exact target is `0x3175`. At that target,
`0x3175: mov ebx,0x8009800f` is followed by `jmp 0x32f7`, the function
epilogue. It is not a backedge to the call at `0x31c1`. The official package
itself was rechecked at SHA-256
`e157fbe548bfd2b6b1ee4410b5dc93255409b329bbe4d75da9d7c1684fa1db4e`,
so this is not an extraction mismatch.

No adapter binary contains a dedicated status comparison against immediate
`0x59`. Generic handling therefore maps it to HRESULT `0x8009800f`, leaves
reject detail zero from `0x317f`, and exits. It does not issue another
UpdateEnrollment, SensorAdapter capture, discard, or commit within this
function.

A scan of all six requested Windows components found incidental immediate
`0x59` uses, but not an UpdateEnrollment status comparison. In particular,
`bipdll.dll` RVA `0x464d4` writes `0x59` into a command-word parameter in an
unrelated function, and `cvusbdrv.sys` RVA `0xfb04` loads `0x59` as a call
argument. Neither instruction is reachable from the update CFG above, and
neither compares a returned status. They are not semantic evidence for this
result.

The generic `bipdll.dll` command path returns an unrecognized nonzero
`cvhManageCVAPICall` result unchanged to `CSS_FingerprintUpdateEnrollment`,
which returns it unchanged to EngineAdapter. Thus Linux and Windows use the
same Broadcom CV API status domain at this boundary. Equality of the exact
on-wire status representation remains unproven without USB capture.

### Recovered generic Windows call arguments

The A21 EngineAdapter's call at RVA `0x31c1` supplies:

```text
argument 1  EngineContext + 0x18      fixed 20-byte input
argument 2  stack                     completion output
argument 3  inner context + 0x2c      fixed 20-byte output
argument 4  false                     disable optional auxiliary data
argument 5  stack                     4-byte output
```

Attach allocates the 0x290-byte EngineContext with `HEAP_ZERO_MEMORY`.
EngineAdapter itself does not directly populate the 20-byte range, but the
cross-adapter writer is now recovered: in Advanced mode SensorAdapter copies
the 20-byte `CSS_FingerprintCaptureStart` output from `SensorContext+0x5c` to
`EngineContext+0x18` before UpdateEnrollment.

Because argument 4 is false, `CSS_FingerprintUpdateEnrollment` forwards
auxiliary size zero and pointer null. Its internal generic dispatcher
registers argument 1 as a 20-byte input and builds command `0x6c`. This has the
same seven-argument shape as Linux and the same semantic input source. Linux
received a fresh capture-derived 20-byte value on every hardware call, while
Windows refreshes a fixed context field from each Advanced capture-start
output.

This rules out optional auxiliary input as the missing Windows state on the
generic path. A fail-closed hardware test subsequently showed that a stable
zero Linux input accepts no updates (`0x89` seven times, then `0x88`), while an
adjacent fresh-input control accepts three before returning `0x59`. Stable zero
is therefore not the Windows-equivalent fix. See
[the hardware record](evidence/zero-update-input-hardware.md),
[the corrected Windows A21 argument record](evidence/windows-a21-update-arguments-static.md),
and [the cross-adapter dataflow](evidence/windows-a21-update-input-dataflow.md).

## Windows BCM5880-specific update path

The generic conclusion above needs an important qualification. In
`bipdll.dll`, exported `CSS_FingerprintUpdateEnrollment` is at RVA `0x15f10`.
It calls an internal dispatcher at RVA `0x2d110`. That dispatcher has two
paths:

- the generic path builds CV command `0x6c` at RVA `0x2d4a5`;
- a selected path calls RVA `0x2cef0`. Its embedded diagnostic name is
  `cvFingerprintUpdateEnrollment5880`.

The 5880-named path does not build command `0x6c`. It accumulates three
feature records:

```text
RVA 0x2cfb3: cmp esi,3
  count < 3: copy the current feature, increment the count, return success
  count >= 3: run the accumulated enrollment processing
              set the completion byte at RVA 0x2d09e
              return the processing status
```

The fourth UpdateEnrollment invocation is therefore the transition after
three accepted feature records. EngineAdapter sees the completion byte and
enters its completion path on success. This exactly matches the hardware
boundary at which Linux accepted samples 1, 2, and 3 and then received
`0x59` from its fourth command `0x6c`.

This is strong evidence that the relevant Windows architecture treats
BCM5880 enrollment differently from Linux's generic firmware-side `0x6c`
loop. It is not proof that the selector takes this branch on the Latitude
7390 at runtime; proving that requires a Windows execution/USB trace. It
also does not assign a firmware semantic name to `0x59`.

SensorAdapter provides corroborating command order. Its StartCapture entry
is RVA `0x2180`. In enrollment purpose/mode 4 it calls the dynamically
resolved `cv_cmd_enrollment_started` pointer at RVA `0x2212`, then the
capture helper calls `CSS_FingerprintCaptureStart` at RVA `0x2e57`.
Consequently each Windows enrollment capture begins with the observed
`0x8a` state transition followed by capture `0x66`.

## Patch 4 autopsy

Patch 4 is absent from the probe-only target and present in
`prebuilt/libfprint-2-tod-1-broadcom.PATCHED.so`.

At file offset/RVA `0xdd0d`, its complete signature is:

```text
original:
41 81 fd a4 00 00 00 0f 84 fd 01 00 00

replacement:
41 81 fd 59 00 00 00 0f 84 16 00 00 00
```

Before:

```text
0xdd0d cmp r13d,0xa4
0xdd14 je  0xdf17
```

After:

```text
0xdd0d cmp r13d,0x59
0xdd14 je  0xdd30
```

The statement “patch 4 changes the `0xa4` comparison to `0x59`” is exactly
correct, but incomplete: it also changes the branch displacement and target.
It does not jump directly to commit. It makes `0x59` enter the common
status-zero state dispatch at `0xdd30`. Because an update runs in state 1,
the subsequent `cmp eax,1` at `0xdd38`/`je 0xe010` sets state 2; the next
queued worker then calls command `0x6e`.

Patch 4 has two semantic effects:

1. `0x59` is treated like success. In state 1 this advances to state 2 and
   then commit.
2. `0xa4` loses its retry branch and becomes a generic fatal result:
   capture-cancel in the wrapper, then command `0x6d` discard in the outer
   callback.

It therefore does not preserve other status behavior.

The original commit describes `0x59` as “enrollment data ready” and says the
change lets commit run. Its accompanying documentation says the statuses
were recovered empirically on a Latitude 7490. No retained log, Windows CFG,
successful commit trace, issue #2/#3 evidence, or protocol definition proves
that semantic name. The current probe-only artifact deliberately excludes
patches 4 and 5.

## Meaning classification

The best-supported classification is:

**F. Mode- or firmware-path-dependent special condition.**

Confidence:

- high that Linux receives raw `0x59` from command `0x6c`;
- high that Linux currently treats it as fatal;
- high that generic Windows EngineAdapter does **not** repeat UpdateEnrollment
  in the inspected A21 build and instead returns `0x8009800f`;
- high that the Windows package contains a distinct 5880-named path which
  completes its three-record aggregation on the fourth update without
  constructing `0x6c`;
- medium that this architectural mismatch explains the repeatable Linux
  `0x59` boundary;
- low for any exact semantic name.

Evidence supporting “enrollment complete/data ready” is the exact
three-record boundary, the 5880-specific Windows completion boundary, and
the old Latitude 7490 empirical patch. Evidence against treating it as
already proven complete is that generic EngineAdapter maps an unrecognized
`0x59` to an error. There is no evidence for quality/retry,
duplicate/policy, reset, or fatal-device semantics.

Accordingly classifications A--E are not established, and classification G
would understate the strong mode-dependent evidence while correctly
describing the still-unknown exact name.

## Bounded experiment result

The bounded one-repeat experiment was run once on hardware. It did not
produce completion. Four times, after accepted counts 3, 6, 9, and 12:

```text
first real command 0x6c -> 0x59
second real command 0x6c -> 0x89
real command 0x8a -> 0x00
existing state-1 capture retry
```

All four pairs retained completion `0x00`; the enrollment output remained
unpopulated. Raw output bytes are not published.

Enrollment progress reached 13/10 before controlled cancellation. No state
2 transition or commit occurred. This disproves the bounded repeat as a
completion mechanism and further supports a missing host-side path.

The Linux raw update only writes `output_value_out` on native success, while
the wrapper initializes only its completion byte. The repeated unchanged
value is therefore stale stack storage, not a firmware-derived value; its raw
value is omitted.

Full reconstruction of the A21 BCM5880 selected update and commit paths,
including the three-plus-one feature aggregation and command `0x6f`, is in
`docs/enrollment-bcm5880-completion-analysis.md`.

The highest-value missing reference evidence is a Windows USBPcap plus
adapter debug/ETW trace on the same Latitude 7390. It would prove whether the
5880-specific path is selected, whether any `0x6c` is actually sent, and
what operation follows the third accepted capture.

## Evidence classes

### Proven on hardware

- The bounded run accepted 13 samples and passed the advertised 10 stages.
- Four first `0x59` results were each followed by one native `0x89`.
- Each second `0x89` was followed by a successful `0x8a` and capture retry.
- Completion remained zero and enrollment output remained empty.
- Command `0x6e` commit did not occur.

### Proven by static analysis

- Linux `0x59` provenance and CFG described above.
- Windows generic unknown-status error exit and 5880-specific update path
  described above.
- Patch 4 exact bytes and its effects on both `0x59` and `0xa4`.
- Linux update ABI, mutable outputs, and the success-only output writes.
- Windows BCM5880 completion requires three buffered features plus a fourth
  live feature and successful template-create command `0x6f`.
- The selected Windows commit retains the template in host state and does
  not use the generic `0x6e` path.
- The Linux DSO has the `0x6f` primitive but lacks the integrated
  accumulation/completion/selected-commit coordinator.

### Proven by repository-local tests

- A G_MODULE_BIND_LOCAL target is resolved through its verified
  RTLD_NOLOAD handle.
- The first `0x59` causes exactly one additional call with identical scalar
  arguments and pointer identities.
- The interposer does not independently mutate completion or output fields.
- Second results `0x00`, `0x89`, `0xa4`, `0x59`, and another fatal status
  follow the bounded dispatch in the static evidence document.
- The existing `0x89 -> 0x8a` behavior remains intact.

### Hypothesis

- The repeatable three-sample boundary reflects use of Linux's generic
  command-`0x6c` path where the A21 Windows stack would select its
  BCM5880 host-side feature-aggregation path.
- A safe Linux implementation must reproduce the matched feature
  acquisition, command-`0x6f` template creation, token lifetime, and selected
  commit behavior rather than only changing a status or completion byte.

### Still unproven

- The exact semantic name of `0x59`.
- The exact Windows runtime branch and on-wire packet sequence on this unit.
- The exact Linux API contract for acquiring the same feature records.
- A correct Linux host-side completion and selected commit implementation.
- 10/10 completion, command `0x6e` commit, verify, or desktop integration.
