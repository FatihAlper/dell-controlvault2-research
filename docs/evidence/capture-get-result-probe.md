# CaptureGetResult selector and capture-only probe

This experiment isolates one unresolved primitive without treating its output
as a feature, template, or match result. It performs one normal capture, calls
the pinned Linux export once, records only native status and returned length,
then forces the unchanged TOD flow into cleanup before UpdateEnrollment.

## Static selector and capacity evidence

The user-supplied Dell A21 Windows 10 x64 `BrcmSensorAdapter.dll` has SHA-256
`dfb30d81de42e726477b103412fba2c88abd9b675ead7141f25063a3ac8d4e6c`.
The read-only validator pins two additional unique instruction sequences:

| File offset | Evidence |
|---:|---|
| `0x1aef` | initializes the result capacity to `0x17000` bytes |
| `0x1b43` | calls `CSS_FingerprintCaptureGetResult` with selector `1`, the 20-byte `CaptureStart` output at sensor-context offset `0x5c`, the size pointer, and result buffer |

Run `tools/audit_windows_a21_update.py` against a privately extracted A21
artifact to validate these anchors. The proprietary file is not stored here.

This proves the Windows WBF adapter's arguments. It does **not** prove that the
returned object is the selected BCM5880 helper's maximum-`0x258` feature
record. The much larger capacity means the result may instead be a WBF sample
or image container. The probe therefore never feeds it to CreateTemplate.

The pinned Linux DSO separately establishes the SysV ABI and command pairing:

```c
uint32_t cv_fingerprint_capture_get_result(
    uint32_t handle,
    uint8_t selector,
    const uint8_t capture_id[20],
    uint32_t *size,
    uint8_t *output);
```

The export at RVA/file offset `0x258d0` builds command `0x69`.

## Fail-closed runtime boundary

`tools/capture_get_result_probe_preload.c` interposes only
`cv_fingerprint_update_enrollment`. At its first invocation, a completed
normal capture has supplied both the live handle and 20-byte capture ID. The
interposer:

1. verifies the exact already-loaded target DSO by canonical path, device and
   inode, using only an `RTLD_NOLOAD` handle;
2. resolves and owner-checks `cv_fingerprint_capture_get_result`;
3. allocates a private zeroed `0x17000`-byte buffer;
4. makes one selector-1 native call;
5. logs only status, returned length, capacity and bounds validity;
6. wipes the entire private allocation before freeing it;
7. returns an experimental fatal status without forwarding UpdateEnrollment.

Any second UpdateEnrollment boundary is rejected without another native call.
The interposer does not resolve or call CreateTemplate or CommitEnrollment.
The harness treats an unexpectedly successful enrollment as a boundary
violation.

The runner also refuses hardware access unless the user supplies
`--confirm-capture-only`, the exact `0a5c:5833` device is present, and fprintd
is inactive. It changes no service or system configuration:

```sh
tools/run_capture_get_result_probe.sh --confirm-capture-only
```

Mock coverage validates the five-argument ABI, selector, capacity, one-call
limit, payload-redacting log, private-buffer wipe, local-scope DSO resolution,
and explicit-confirmation gate.

## Runtime result

One controlled run completed on the Latitude 7390 `0a5c:5833` device on
2026-08-19. The normal capture reached the first UpdateEnrollment boundary,
where the interposer made its single native call:

```text
native_status=0x89 selector=1 returned_size=94208
capacity=94208 size_valid=yes payload_logged=no
```

The in/out length therefore remained at its initial `0x17000` capacity. The
probe deliberately did not inspect the private output bytes, so an unchanged
length is not evidence about whether the callee touched the buffer. The entire
allocation was wiped regardless.

The harness then observed its expected fatal cleanup, reported
`enrollment_completed=no`, closed the device successfully, and exited zero.
The USB composite device remained enumerated as `0a5c:5833` afterward.

This result proves the recovered Linux ABI is callable with the Windows basic
mode arguments at a real post-capture boundary. It does not establish usable
feature retrieval: `0x89` is non-success and its exact meaning in this export
and context remains unresolved. In particular, the same numeric status is a
bad-capture/retry class elsewhere in the driver, but numeric reuse alone does
not prove identical semantics here. The unchanged length and non-success
status provide no basis for wiring this result into the mock coordinator or
CreateTemplate.
