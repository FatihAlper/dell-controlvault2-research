# Recovered Linux BCM5880 capture/template/commit export ABIs

## Scope and artifact identity

This note records a read-only x86-64 SysV ABI recovery for three exports in:

```text
prebuilt/libfprint-2-tod-1-broadcom-5833.probe.so
SHA-256  c7dbb44e25aa5127515cb4de23868358d7b170d2625227131a88bce39f3e8ef6
Build ID 66134403db205c7c1ac682885229224790aedc0e
```

The conclusions are tied to that exact artifact. The analysis did not load,
patch, or call the shared object. `tools/audit_linux_bcm5880_abis.py` checks
the hash and unique instruction anchors at their expected file offsets.

## `cv_fingerprint_capture_get_result`

The export is at RVA/file offset `0x258d0` and has the recovered prototype:

```c
uint32_t cv_fingerprint_capture_get_result (
  uint32_t handle,
  uint8_t result_selector,
  const uint8_t capture_id[20],
  uint32_t *feature_size_inout,
  uint8_t *feature_out);
```

The entry sequence preserves the SysV inputs as follows:

| Input | Entry location | Static use |
|---|---:|---|
| `handle` | `edi` | handle validation and internal-handle lookup |
| `result_selector` | `sil` | copied as one byte; registered as a 1-byte input |
| `capture_id` | `rdx` | registered as a `0x14`-byte input |
| `feature_size_inout` | `rcx` | required pointer; initial value supplies output capacity |
| `feature_out` | `r8` | required output pointer |

The native request uses command `0x69` at `0x25a18`. The same initial
`*feature_size_inout` is registered for the returned length and returned byte
array. Before response deserialization, the implementation clears the output
capacity and sets the returned size to zero. `cvhSaveReturnValues` then writes
the actual size and bytes. Status `0`, `0x34`, and `0x8f` enter this response
decode path; their higher-level meanings are not established here.

## `cv_fingerprint_create_template`

The export is at RVA/file offset `0x26d10` and has eleven SysV arguments:

```c
uint32_t cv_fingerprint_create_template (
  uint32_t handle,
  uint32_t feature0_size,
  const uint8_t *feature0,
  uint32_t feature1_size,
  const uint8_t *feature1,
  uint32_t feature2_size,
  const uint8_t *feature2,
  uint32_t feature3_size,
  const uint8_t *feature3,
  uint32_t *template_size_inout,
  uint8_t *template_out);
```

The first six arguments arrive in `edi`, `esi`, `rdx`, `ecx`, `r8`, and
`r9`. After the prologue, entry stack arguments 7 through 11 are recovered at
the adjusted stack locations `+0xd0`, `+0xd8`, `+0xe0`, `+0xe8`, and `+0xf0`.
The function rejects a zero feature size, null feature pointer, null template
size/output pointer, or an initial template capacity above `0x18000` with
native invalid-parameter status `0x47`.

All four features are registered as input byte arrays in their original
order. The output capacity and byte buffer form the fifth parameter-list
entry. Native command `0x6f` is assembled at `0x2703d`. On status `0` or
`0x34`, the output is cleared, the size is reset, and the structured response
is decoded into the caller's output pair.

The Windows-selected coordinator's observed template capacity `0x708` is
comfortably below this Linux primitive's `0x18000` input ceiling. That numeric
compatibility does not itself prove that both sides use the same feature or
template representation.

## `cv_fingerprint_commit_enrollment`

The export is at RVA/file offset `0x266a0` and has nine SysV arguments:

```c
uint32_t cv_fingerprint_commit_enrollment (
  uint32_t handle,
  const uint8_t token[20],
  uint32_t input0_size,
  const uint8_t *input0,
  uint32_t input1_size,
  const uint8_t *input1,
  uint32_t *output_size_inout,
  uint8_t *output,
  uint32_t *result_out);
```

The first six arrive in `edi`, `rsi`, `edx`, `rcx`, `r8`, and `r9`; the last
three are recovered from the entry stack. The token is a required 20-byte
request input. The two optional size/pointer pairs are also request inputs.
Only the final three arguments are response destinations.

Two output modes are accepted:

- non-zero `*output_size_inout`, a non-null output buffer, and a maximum
  capacity of `0x18000`; or
- zero `*output_size_inout`, a null output buffer, and a non-null four-byte
  result pointer.

The export builds command `0x6e` at `0x2691d`. On status `0` or `0x34`, it
clears the caller's output buffer using the initial capacity, resets the
size/result, and deserializes the response into the size, buffer, and result
destinations. The 20-byte token is not a response destination and is not
rewritten.

This ABI is structurally the same as Dell A21 Windows' generic raw commit
export. On the successful Windows `0a5c:5833` path it is invoked twice with
the same token and fixed input blobs: first with `0x800` bytes of output
capacity, then with zero output capacity and only the four-byte result. See
`windows-a21-double-commit-static.md`.

## Mock-only adapter

`tools/bcm5880_linux_abi_adapter.[ch]` makes these three prototypes executable
only against caller-injected C mocks. It:

- refuses compilation without
  `CV2_BCM5880_LINUX_ABI_ADAPTER_MOCK_ONLY`;
- refuses initialization unless runtime mode is explicitly `MOCK_ONLY`;
- contains no loader, symbol resolver, USB transport, or device path;
- forwards capture arguments in the recovered five-argument order;
- expands coordinator arrays into the recovered eleven-argument template
  order;
- forwards the recovered nine-argument generic commit order and validates
  its buffered/result-only output modes; and
- rejects and clears an output if an injected mock reports a length beyond
  the original caller capacity.

The template adapter can be injected into the mock coordinator. Its tests
prove argument order and size round-trips, while the coordinator still ends at
`TEMPLATE_READY_COMMIT_BLOCKED` with `commit_permitted=false`.

The separately gated `tools/bcm5880_generic_commit_sequence.[ch]` models the
two Windows-shaped generic commit calls using only that injected mock. It
verifies the shared token/fixed inputs, `0x800` then zero capacities, failure
short-circuit, and output clearing. It is intentionally not wired into the
selected-path coordinator because the selected Windows 5880 branch uses a
different retained-template commit path.

## What this does not prove

This ABI recovery closes the calling-convention question, not the runtime
integration question:

- no direct internal call/xref from the current TOD enrollment control flow to
  the capture/template exports was found in the artifact;
- one separately bounded real `capture_get_result` call used selector `1`
  after a normal capture and returned native `0x89` with its `0x17000` in/out
  length unchanged;
- selector `1` is statically confirmed for the Windows basic-mode WBF path,
  but which successful `0x69` record, if any, corresponds to the Windows
  selected-path feature remains unknown;
- Linux and Windows feature/template byte-format equivalence remains unknown;
- the selected BCM5880 coordinator may not be the path responsible for the
  successful generic-looking Windows `0x6c`/`0x6e` trace; and
- commit ownership, persistence, cleanup, and rollback remain unresolved.

Consequently, this change does not authorize a real callback adapter. The
generic commit ABI and Windows call shape are now known, but live integration
still needs session ownership, cleanup/rollback, and status propagation.

## Reproduction

Run the read-only anchor audit:

```sh
python3 tools/audit_linux_bcm5880_abis.py \
  prebuilt/libfprint-2-tod-1-broadcom-5833.probe.so
```

Run the mock adapter and audit tests:

```sh
python3 -m unittest -v \
  tests.test_audit_linux_bcm5880_abis \
  tests.test_bcm5880_linux_abi_adapter
```
