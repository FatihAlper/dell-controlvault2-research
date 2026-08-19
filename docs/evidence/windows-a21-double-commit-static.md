# Windows A21 double-CommitEnrollment comparison

## Scope

A successful privacy-safe Windows trace recorded four successful
`CSS_FingerprintUpdateEnrollment` returns followed by two successful nested
`CSS_FingerprintCommitEnrollment` / `cv_fingerprint_commit_enrollment` pairs.
The reduced tracer intentionally read no arguments, so the trace alone could
not distinguish a duplicate call from two different commit phases.

This record answers that question with read-only static analysis of the exact
Dell A21 x64 files used by the trace:

```text
622b1a12566cb313cde264869ca5a4b410e3d5b2b604f5dd628c4a6b709b19ae
  BrcmEngineAdapter.dll

30c556a9b542d0fcf29a6822b3bb81fe23ce2917b403b3f25af9384e0e31e524
  bipdll.dll
```

The proprietary files are not stored in this repository and were not
modified or executed during this comparison.

## Result

The two commits are **not identical duplicate submissions**. They reach the
same common helper and the same CSS/raw exports, but originate in two distinct
phases and supply different trailing arguments:

1. `EngineAdapterUpdateEnrollment` calls the common commit helper internally
   as soon as its final update reports completion.
2. The Windows Biometric Framework subsequently calls the adapter's formal
   `EngineAdapterCommitEnrollment` callback. That callback performs its
   identity/application processing and calls the common helper again.

There is no loop around the CSS call. Each invocation of the common helper
contains exactly one `CSS_FingerprintCommitEnrollment` call, and the CSS
wrapper contains exactly one `cv_fingerprint_commit_enrollment` call. This
explains the two nested pairs in the runtime trace exactly.

## First call: completion inside UpdateEnrollment

Adapter attach allocates the outer engine context as a zeroed `0x290`-byte
object and its separate inner context as a zeroed `0x48`-byte object. It then
allocates a zeroed `0x800`-byte buffer and stores that pointer at
`inner+0x18`. This establishes that `inner+0x18` is not an inline scalar or
token; it is the first commit's large output buffer. The adjacent dword at
`inner+0x20` is its capacity/returned-length field.

The successful-completion block in `EngineAdapterUpdateEnrollment` is:

```text
RVA 0x3238  inner := *EngineContext
RVA 0x323f  inner+0x20 := 0x800
RVA 0x324b  r8  := inner
RVA 0x324e  r9  := &local_78
RVA 0x3253  rdx := inner+0x20
RVA 0x3257  rcx := inner+0x2c
RVA 0x325b  r8  := *(inner+0x18)
RVA 0x325f  call common_commit (RVA 0x4950)
RVA 0x3270  inner state := 2
```

Therefore the common helper receives this structural tuple:

```text
(&inner[0x2c], &inner[0x20], inner[0x18], &stack_local)
```

The first member is a 20-byte token input, the middle pair is a
capacity-in/actual-size-out plus output buffer, and the final pointer receives
a four-byte result. The buffer begins with a capacity of `0x800`; its actual
returned length is written back to `inner+0x20`.

The call is made only after the CSS update itself has returned zero and its
completion byte is nonzero. The minimal tracer hooks the CSS update rather
than the outer WBF callback, so it necessarily prints the fourth
`update-leave` before this first commit begins. The vendor path logs the
internal commit result and advances its inner state to 2; the outer
UpdateEnrollment return remains the already-established successful update
result. The later formal callback is where final commit failure can be
returned to WBF.

## Second call: the framework CommitEnrollment callback

The formal WBF callback is at RVA `0x3900`. It validates the pipeline,
identity, subfactor, and enrollment state; derives user/application metadata;
and then selects one of two paths:

```text
RVA 0x3c1d  call CommitEnrollmentWithUserApp wrapper
             or
RVA 0x3c43  call common_commit directly
```

The user-application wrapper only installs the associated metadata before
reducing to the same common helper. Both branches give that helper the same
effective structural tuple:

```text
(&inner[0x2c], &zero_local, 0, &inner[0x40])
```

This differs from the first call in three of the four helper inputs. In
particular, the first phase points at `inner+0x20` after storing `0x800`,
forwards the value at `inner+0x18`, and uses a temporary output location. The
formal framework phase instead supplies a zero local, a null third value, and
the persistent `inner+0x40` location.

The raw function explicitly permits this second mode: when the supplied
output capacity is zero, the output buffer may be null provided the four-byte
result pointer is present. Thus the second tuple is intentional, valid ABI
usage rather than a partially initialized first-phase call.

[Microsoft documents](https://learn.microsoft.com/en-us/windows/win32/api/winbio_adapter/nc-winbio_adapter-pibio_engine_commit_enrollment_fn)
the five inputs to the outer callback as `Pipeline`, `Identity`, `SubFactor`,
optional `PayloadBlob`, and `PayloadBlobSize`. The adapter processes those
WBF-level values before constructing the internal four-value tuple above; the
tuple must not be mislabeled as the public WBF ABI.

## Common CSS construction

The common helper at RVA `0x4950` has one CSS call at RVA `0x4ad0`. It supplies
the same five leading values in both phases and forwards its four inputs into
CSS positions 1, 6, 7, and 8:

| CSS position | Both calls | First/update-completion call | Second/framework call |
|---:|---|---|---|
| 1 | `inner+0x2c` | same | same |
| 2 | scalar `8` | same | same |
| 3 | address of fixed local descriptor | same | same |
| 4 | scalar `0x15` | same | same |
| 5 | address of fixed local descriptor | same | same |
| 6 | forwarded helper input 2 | `inner+0x20` containing `0x800` | zero-valued local |
| 7 | forwarded helper input 3 | value from `inner+0x18` | zero/null |
| 8 | forwarded helper input 4 | temporary stack location | persistent `inner+0x40` location |

The helper builds the same two input blobs for both calls. Their exact bytes
in this pinned build are:

```text
input 0 (8 bytes):  00 00 04 00 04 00 00 00
input 1 (21 bytes): 01 01 ff 00 00 00 0d 00 0c "BroadcomWBF\0"
```

These are reported as opaque fixed metadata, not assigned an undocumented
protocol meaning.

At `bipdll.dll` RVA `0x16498`, the CSS wrapper calls the exported raw commit
at RVA `0x2da30` once while preserving this argument distinction. Both runtime
operations can therefore use native command `0x6e` without being
semantically equivalent.

The generic raw export's recovered nine-argument shape is:

```c
status commit_enrollment(
  handle,
  token20_in,
  input0_size, input0,
  input1_size, input1,
  output_size_inout, output,
  result4_out);
```

`token20_in` is registered only as a 20-byte request input. Successful
response decoding writes only the last three arguments: output size, output
bytes, and the four-byte result. Consequently `inner+0x2c` is the unchanged
UpdateEnrollment token reused by both commits; it is **not** rewritten by the
first commit and does not carry the first commit's returned blob into the
second.

The concrete two-call comparison is therefore:

| Raw field | First/internal completion | Second/formal finalization |
|---|---|---|
| token input | `inner+0x2c` (20 bytes) | same token |
| input blob 0 | fixed 8-byte block | same |
| input blob 1 | fixed 21-byte block | same |
| output capacity | `0x800` | `0` |
| output buffer | allocated `inner+0x18` | null |
| result output | temporary dword | persistent `inner+0x40` dword |

## Relation to the two USB replies

The earlier successful USB capture ordered the two `0x6e` exchanges as a
940-byte response followed by a 92-byte response. The static order and output
modes now provide a direct structural explanation: the first exchange asks
for a large byte array, while the second asks for no byte array. The response
size difference is exactly 848 bytes (`940 - 92`), making 848 the strongest
current candidate for the first call's returned blob length.

The exact value association remains a cross-session inference: the USB and
function traces were separate successful sessions, protected payloads were
not parsed, and the reduced function trace did not record output lengths.
What is proven statically is which phase has the large output and which has
none, plus the phase order and one-to-one CSS/raw call nesting.

## Linux implication

The pinned Linux probe already exports the same nine-argument generic commit
ABI at RVA `0x266a0`, builds command `0x6e`, accepts the same two output
modes, and decodes response values into arguments 7, 8, and 9. Calling it
twice with identical arguments would still not reproduce Windows. A faithful
implementation needs the two distinct calls:

- completion-time large-output materialization using the UpdateEnrollment
  token; then
- result-only finalization using the same token and fixed input blobs.

The first returned 848-byte candidate blob is not passed explicitly to the
second call. Any dependency between the phases is therefore carried by the
device/session state and shared input token, not by a host pointer handoff.
Its protected content and the meanings of the two four-byte results remain
unknown.

`tools/bcm5880_generic_commit_sequence.[ch]` now expresses this exact call
shape against injected mocks only. It has no loader or USB transport and
fails closed between phases. This closes the host calling-convention gap but
does not authorize a live commit: a real adapter still needs lifecycle,
rollback, ownership, and success-status integration with the Linux TOD path.

## Reproduction

After extracting the two files outside the repository:

```sh
python3 tools/audit_windows_a21_commit.py \
  /private/path/BrcmEngineAdapter.dll \
  /private/path/bipdll.dll
```

The audit fails closed on an unexpected hash, signature count, or file
offset, and reports `artifact_write_performed=no`.
