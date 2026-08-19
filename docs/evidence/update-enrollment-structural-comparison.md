# Privacy-safe UpdateEnrollment structural comparison

This record compares one successful Windows enrollment, two failed Windows
enrollments, and two independent Linux `fresh-rearm-stop-before-commit`
sessions on the same `0a5c:5833` device. Raw USB payloads, payload hashes,
fingerprint features, templates, enrollment tokens, device identifiers, and
absolute timestamps are not included.

## Tool and privacy boundary

`tools/compare_cv_usb_updates.py` reassembles application messages that span
multiple USB bulk transfers. Payload bytes exist only in process memory. The
tool does not print, hash, or write them. Its report is restricted to:

- command order, flags, and declared lengths;
- stable and changing byte-offset ranges, without byte values;
- response-shape boundaries;
- offsets and lengths of high-variation ranges copied verbatim from a capture
  response into the following update request.

Example:

```sh
tools/compare_cv_usb_updates.py --device-address 5 \
  windows-success=WINDOWS_SUCCESS.pcapng \
  windows-failure=WINDOWS_FAILURE.pcapng \
  linux-control=LINUX_CONTROL.pcapng
```

The parser tests include split-message reassembly and assertions that opaque
fixture bytes do not occur in generated reports.

## Linux result

The 2026-08-03 and 2026-08-19 decisive Linux sessions contained nine and eight
updates respectively. Every request declared 92 bytes. In both sessions:

```text
stable request ranges: 0:64, 84:92
changing request range: 64:84
capture-to-update link: capture[52:72] = request[64:84]
```

The 20-byte changing request range was copied verbatim from the immediately
preceding `0x66` response for every `0x6c`. This includes all native `0x89`
quality retries, the three accepted status-zero/completion-zero updates, and
the final update correlated by the redacted logical log with native `0x59`.

Accepted Linux update replies declared 96 bytes. Native `0x89` and `0x59`
replies both used the shorter 44-byte shape; response size alone does not
distinguish those statuses, so their classification comes from the separate
redacted runtime log.

This eliminates a stale, reused, or mismatched capture ID as the explanation
for the repeatable fourth-update `0x59` boundary.

## Windows result

All three Windows sessions contained four 140-byte `0x6c` requests. The
successful session received four 124-byte replies. Both failed sessions
received three 124-byte replies followed by a 76-byte fourth reply.

Across success and failure, the request header/length/flag shape did not
diverge. The stable request ranges across all three captures were 0:24 and
40:44; the remaining regions changed as protected content. No plaintext
capture-to-update link is expected or claimed for those protected regions.

The first observable structural difference between Windows success and either
failure is therefore response number four, not the request header, request
length, request flags, or number of updates.

## Interpretation

The captures establish that Linux supplies a fresh, correctly linked 20-byte
capture value on the update that returns `0x59`. They do not reveal the
semantics of Windows protected request fields and cannot prove that Windows
and Linux select the same capture mode or accumulator policy.

The next comparison must move above the Windows protection boundary or remain
inside the Linux call layer. It should record only input lengths, selectors,
pointer provenance/equality, output initialization, accepted-update counters,
and session-state transitions. Buffer contents must remain unlogged. Mapping
`0x59` to success, repurposing the native `0x89` retry branch, or forcing a
commit remains unsupported.
