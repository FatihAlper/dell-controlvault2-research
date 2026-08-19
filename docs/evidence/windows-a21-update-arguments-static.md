# Windows A21 generic UpdateEnrollment argument construction

## Scope and artifact identity

This is a read-only static analysis of three x64 DLLs extracted from Dell
ControlVault2 package `N23KC`, version `4.12.5.8 A21`. The package obtained
for the tested Latitude and the independently downloaded copy were identical:

```text
e157fbe548bfd2b6b1ee4410b5dc93255409b329bbe4d75da9d7c1684fa1db4e
  Dell-ControlVault2-Driver-and-Firmware_N23KC_WIN64_4.12.5.8_A21_03.EXE

622b1a12566cb313cde264869ca5a4b410e3d5b2b604f5dd628c4a6b709b19ae
  BrcmEngineAdapter.dll

dfb30d81de42e726477b103412fba2c88abd9b675ead7141f25063a3ac8d4e6c
  BrcmSensorAdapter.dll

30c556a9b542d0fcf29a6822b3bb81fe23ce2917b403b3f25af9384e0e31e524
  bipdll.dll
```

The DLLs were neither executed nor modified and are not stored in this
repository. `tools/audit_windows_a21_update.py` lets an owner validate the
short instruction anchors against their own extracted copies without copying,
patching, or executing them.

## WBF EngineAdapter call

`WbioQueryEngineInterface` returns the WBF engine interface at RVA `0x2eaa0`.
Its callback table places `CreateEnrollment` at RVA `0x30d0` and
`UpdateEnrollment` at RVA `0x3130`.

The relevant `UpdateEnrollment` call construction is:

```text
RVA 0x31a7  lea rax,[rsp+0x70]       ; 4-byte output pointer (stack arg 5)
RVA 0x31ac  xor r9d,r9d              ; argument 4 = false
RVA 0x31af  lea rcx,[rdi+0x18]       ; argument 1 = EngineContext + 0x18
RVA 0x31b3  mov [rsp+0x20],rax       ; argument 5
RVA 0x31b8  lea r8,[rbp+0x2c]        ; argument 3 = inner state + 0x2c
RVA 0x31bc  lea rdx,[rsp+0x60]       ; argument 2 = completion output
RVA 0x31c1  call [CSS_FingerprintUpdateEnrollment]
```

Here `rdi` is the 0x290-byte EngineContext loaded from the WBF pipeline's
`EngineContext` slot, and `rbp` is its separately allocated 0x48-byte inner
state object.

The outer EngineContext allocation at RVA `0x1b65` is equivalent to:

```c
HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x290);
```

Attach fills pointers at offsets `0x00` and `0x08`, stores `1` at `0x10`,
and later fills fields beginning at `0x30`; it does not initialize the 20-byte
range `0x18`--`0x2b` separately. `CreateEnrollment` only changes fields in the
inner state.

An EngineAdapter-only scan found no direct writer to that 20-byte range. The
cross-adapter analysis subsequently found the writer in SensorAdapter:
Advanced StartCapture copies the 20-byte output of
`CSS_FingerprintCaptureStart` from `SensorContext+0x5c` to
`EngineContext+0x18`. Thus the address is fixed but its content is refreshed
with a capture/enrollment ID before UpdateEnrollment. See
[the complete dataflow record](windows-a21-update-input-dataflow.md).

The adapter also hard-codes argument 4 to false. Therefore the optional
auxiliary-data construction inside the CSS wrapper is not selected by this
Windows WBF path.

## CSS wrapper and generic dispatcher

`CSS_FingerprintUpdateEnrollment` is exported by `bipdll.dll` at RVA
`0x15f10`. Its incoming and forwarded arguments map as follows:

| EngineAdapter argument | CSS meaning recovered from use | Dispatcher argument |
|---|---|---|
| `EngineContext+0x18` | required 20-byte input | `rdx` |
| stack completion pointer | completion output | stack 5 |
| `inner+0x2c` | required 20-byte output | stack 6 |
| `false` | request optional auxiliary construction | auxiliary size/pointer |
| stack 4-byte pointer | required 4-byte output | stack 7 |

When argument 4 is false, the wrapper reaches RVA `0x16079` with auxiliary
size zero and auxiliary pointer null. It then calls the internal dispatcher at
RVA `0x2d110`.

The generic dispatcher:

- registers the first pointer as a required 20-byte input at RVA `0x2d330`;
- represents a zero auxiliary length with size zero and a null pointer at RVA
  `0x2d39d`;
- registers the completion, 20-byte, and 4-byte output areas; and
- builds CV command `0x6c` at RVA `0x2d4a5` before calling
  `cvhManageCVAPICall`.

The recovered seven-argument ABI is consequently the same shape as the Linux
generic function:

```c
uint32_t update_enrollment(
    uint32_t handle,
    const void *input_20,
    uint32_t auxiliary_size,
    const void *auxiliary_pointer,
    uint8_t *completion_out,
    void *output_20,
    uint32_t *output_value_out);
```

The generic path is conditional: the same dispatcher can instead call the
separate `cvFingerprintUpdateEnrollment5880` host-template helper. Successful
Windows USB captures on this device contained four visible `0x6c` requests,
so this record compares the generic construction actually consistent with
that runtime sequence; it does not claim the alternate helper is unreachable
in every configuration.

## Comparison with the Linux runtime trace

The redacted Linux call trace already established that every generic update
used:

- a fresh pointer and fresh 20-byte capture-derived input;
- auxiliary size zero;
- a fresh, initially zero 20-byte output buffer; and
- stable completion and 4-byte output pointers.

The Windows static call construction rules out an unseen optional auxiliary
handoff as the difference: the WBF adapter explicitly disables it. It instead
exposes a concrete argument-lifetime mismatch:

| Property | Linux observed runtime | Windows A21 generic static path |
|---|---|---|
| 20-byte input storage | fresh per update | fixed `EngineContext+0x18` |
| Call-time content | capture-derived | capture-start output copied by SensorAdapter |
| Auxiliary input | size 0 | false -> size 0, pointer null |
| 20-byte output storage | fresh per update | fixed `inner+0x2c` |

The bounded stable-zero hardware experiment is now complete. It accepted zero
updates (`0x89` seven times, then `0x88`), while an adjacent fresh-input control
accepted three updates before reaching the known `0x59` boundary. Neither
session completed or committed. Thus stable zero is not the Windows-equivalent
fix; see [the hardware record](zero-update-input-hardware.md).

The recovered SensorAdapter dataflow explains that result. Stable zero
discarded the required capture/enrollment ID; it did not reproduce Windows.
Windows and Linux differ in storage lifetime, not in the semantic source of
the 20-byte input. The next implementation target is the already recovered
BCM5880 host enrollment coordinator rather than another input substitution.

## Reproduction

After extracting the three files outside the repository:

```sh
python3 tools/audit_windows_a21_update.py \
  /private/path/BrcmEngineAdapter.dll \
  /private/path/BrcmSensorAdapter.dll \
  /private/path/bipdll.dll
```

The command reports hashes, file offsets of the validated instruction anchors,
derived non-sensitive facts, and `artifact_write_performed=no`. Any hash,
missing-signature, duplicate-signature, or offset mismatch fails closed.
