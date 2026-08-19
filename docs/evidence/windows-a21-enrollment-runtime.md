# Windows A21 enrollment and verification runtime evidence

This is a privacy-safe structural summary of one successful Windows Hello
enrollment using the Dell/Broadcom A21 package and a passed-through
`0a5c:5833` ControlVault2 device. Raw USB payloads, fingerprint features,
templates, tokens, device serials, absolute timestamps, and user identifiers
are intentionally excluded.

## Virtual USB prerequisite

The legacy `wbfcvusbdrv` lower filter initially failed device start with
`STATUS_POWER_STATE_INVALID` while QEMU's `usb-host` device used its default
`suppress-remote-wake=on`. Removing the lower filter changed the failure to
`ERROR_NOT_SUPPORTED`, showing that the filter was required but participated
in the failing power path.

Setting `suppress-remote-wake=false` for only the passed-through ControlVault
device allowed the complete stack to start:

```text
MI_03 biometric device: OK
WUDFRd service: active for the device
wbfcvusbdrv lower filter: running
```

This is a VM transport compatibility requirement, not a device firmware
change.

## Capture integrity and transport

The successful enrollment was recorded through host `usbmon` on the device's
USB bus. The capture reported zero dropped packets. The expected transport
endpoints were active:

```text
0x01  bulk OUT
0x81  bulk IN
0x85  interrupt IN
```

Only application-message headers and declared lengths were retained in the
structural analysis. Message payload bytes are not included in the repository.

## Observable enrollment sequence

After version/status setup and one cancelled initial capture, the successful
path contained:

```text
CaptureStart 0x66
UpdateEnrollment 0x6c  request 140 bytes, response 124 bytes
Re-arm 0x8a
CaptureStart 0x66
UpdateEnrollment 0x6c  request 140 bytes, response 124 bytes
Re-arm 0x8a
CaptureStart 0x66
UpdateEnrollment 0x6c  request 140 bytes, response 124 bytes
Re-arm 0x8a
CaptureStart 0x66
UpdateEnrollment 0x6c  request 140 bytes, response 124 bytes
0x6e request 188 bytes, response 940 bytes
new transport/session exchange
0x6e request 188 bytes, response 92 bytes
Windows Hello reports successful enrollment
```

Counts in the successful visible path:

| Command | Count | Runtime observation |
|---|---:|---|
| `0x6c` | 4 | One after each accepted capture. |
| `0x8a` | 3 | Between accepted captures. |
| `0x6e` | 2 | Two differently sized replies; later function-level tracing identified both calls as CommitEnrollment. |
| `0x6f` | 0 | No visible application-message header used this opcode. |

The fourth accepted update is followed directly by the completion-stage
traffic. No extra `0x6c` retry is visible.

## Failed re-enrollment controls

Two later, independent re-enrollment attempts reached the same failure shape.
Both captures reported zero dropped packets:

```text
UpdateEnrollment 0x6c  request 140 bytes, response 124 bytes
UpdateEnrollment 0x6c  request 140 bytes, response 124 bytes
UpdateEnrollment 0x6c  request 140 bytes, response 124 bytes
UpdateEnrollment 0x6c  request 140 bytes, response  76 bytes
DiscardEnrollment 0x6d request  56 bytes, response  44 bytes
Windows Hello reports that enrollment failed
```

The 76-byte fourth reply is structurally distinct from an accepted 124-byte
reply. Its protected payload was not interpreted, so this record does **not**
assert that it contains Linux native status `0x59`. It does establish a
reproducible three-accepted-sample boundary followed by a rejected fourth
`0x6c`, which is the closest Windows runtime analogue yet observed for the
Linux boundary.

Windows did not repeat the rejected `0x6c`, re-arm capture, call `0x6f`, or
enter the two-`0x6e` completion stage. It closed the enrollment with `0x6d`.
This makes the repository's bounded same-update retry useful as a historical
diagnostic, but not a Windows-faithful recovery algorithm.

## Verification control

A separate Windows Hello verification capture contained 22 protected
`0x73` requests of 156 bytes. Twenty replies were 124 bytes and two were 76
bytes. Windows biometric events correlated the same session with both
successful identifications and rejected/bad samples. No bulk transport error
occurred. This provides high-confidence ordering evidence that `0x73` is the
identify/verify operation on this stack, while reply semantics remain
protected.

## Runtime reset and fallback identity

A third re-enrollment control accepted one `0x6c`, prepared the next capture,
then lost the `0a5c:5833` USB function. Outstanding interrupt endpoints ended
with host shutdown status. The device re-enumerated as `0a5c:5831`, revision
`1.02`, exposing one application-specific ControlVault interface and no
biometric `MI_03` interface.

A standard USB bus reset left the device in the `5831` identity. A complete
host power-off restored `0a5c:5833` and all CVAULT, smart-card, composite, and
biometric interfaces returned without a device problem. No firmware-write
operation was issued in the captured enrollment sequence. The observation is
therefore recorded as a recoverable runtime reset/fallback identity, not as a
firmware update or permanent device failure.

## Interpretation boundary

This runtime trace does not support the earlier expectation that successful
enrollment on this exact device/firmware selection must expose command `0x6f`
on USB. The analyzed Windows binary still contains the statically recovered
four-feature/`0x6f` path, but this successful run did not visibly select it.

Later minimal function-level tracing observed a successful Hello enrollment
perform four successful UpdateEnrollment calls followed by two nested
`CSS_FingerprintCommitEnrollment` / `cv_fingerprint_commit_enrollment` pairs,
all returning zero.  This identifies both `0x6e` operations as the
CommitEnrollment family.  Read-only static comparison subsequently resolved
their origin: the first is an internal completion-time call made by
EngineAdapterUpdateEnrollment, while the second comes from WBF's formal
EngineAdapterCommitEnrollment callback.  The common CSS call receives
different trailing arguments in the two phases.  See
[the double-commit comparison](windows-a21-double-commit-static.md).  The
shared 20-byte value is an unchanged input token, not a first-call output.
The first call requests a large output while the second requests only a
four-byte result; the first output is not explicitly passed to the second.
Protected output meanings remain unresolved.

The successful and failed controls narrow the immediate question to why a
fourth generic-looking `0x6c` is sometimes accepted and sometimes rejected.
They do not support treating the three-sample boundary itself as proof that a
host-side `0x6f` transition was required. Initialization parameters,
capture-result inputs, accumulator state, and session/mode selection require
comparison before changing Linux completion or commit behavior.

A later payload-redacting comparison reassembled the split USB messages and
confirmed that all three Windows sessions use the same four-request
header/length/flag shape. Their first structural divergence is the fourth
response: 124 bytes on success and 76 bytes in both failures. See
[the UpdateEnrollment structural comparison](update-enrollment-structural-comparison.md).

## Reproduction helper

`tools/summarize_cv_usb_pcap.py` prints only message-header metadata from a
local usbmon PCAP. It deliberately does not print or retain payload bytes:

```text
python tools/summarize_cv_usb_pcap.py CAPTURE.pcapng --device-address N
```
