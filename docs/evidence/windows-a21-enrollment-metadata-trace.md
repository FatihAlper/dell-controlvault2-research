# Windows A21 enrollment metadata trace

This is the next reference experiment after the USB-header-only Windows
enrollment capture.  It observes the exact Dell/Broadcom A21 x64 biometric
stack at function boundaries so that a successful Windows enrollment can be
compared with the Linux path without recording fingerprint or template bytes.

The first runtime result below is an intentionally incomplete enrollment
control.  It establishes dispatch and retry behavior but exited before
completion or commit, so it must not be cited as successful-enrollment
evidence.

## Pinned artifacts and hook site

The runner accepts only these loaded Windows 10 x64 files from Dell package
`N23KC`, version `4.12.5.8 A21`:

| Loaded module | SHA-256 |
|---|---|
| `bipdll.dll` | `30c556a9b542d0fcf29a6822b3bb81fe23ce2917b403b3f25af9384e0e31e524` |
| `BrcmEngineAdapter.dll` | `622b1a12566cb313cde264869ca5a4b410e3d5b2b604f5dd628c4a6b709b19ae` |
| `BrcmSensorAdapter.dll` | `dfb30d81de42e726477b103412fba2c88abd9b675ead7141f25063a3ac8d4e6c` |

The internal route observation is at `bipdll.dll` RVA `0x2d249`, the
`test al,al` immediately after the A21 `is5880` call in the
UpdateEnrollment dispatcher.  The exact surrounding signature occurs once
at file offset `0x2c642`.  `tools/audit_windows_a21_update.py` now validates
that anchor before the RVA is used as evidence.

The tracer also resolves the following exports by name from the same pinned
`bipdll.dll`:

- capture start and capture-mode selection;
- UpdateEnrollment;
- CSS and raw commit-enrollment/commit-feature-set calls; and
- CSS and raw discard-enrollment calls.

This identifies whether the runtime selected the generic command-`0x6c` or
BCM5880 host-template branch and which named operation produced the two
completion-stage calls seen in the successful USB trace.

## Privacy and mutation boundary

`tools/windows_a21_enrollment_trace.js` deliberately has no bulk-memory,
string-reading, hex-dump, memory-scan, memory-write, or Frida message-send
primitive.  It reads at most the known scalar fields and twenty individual
bytes solely to reduce a buffer to one of these labels:

```text
zero  nonzero  null  unreadable
```

It emits only:

- call order and symbol name;
- return status;
- zero/nonzero classifications;
- whether two pointers are the same, without printing either address;
- whether two twenty-byte regions are equal, without retaining or printing
  either region; and
- the generic-versus-BCM5880 route decision.

It never prints or retains capture IDs, fingerprint samples, feature sets,
templates, tokens, user identifiers, device serials, or pointer addresses.
Static tests reject the payload-reading/writing APIs listed above.

The tracer does not patch a DLL on disk, write process memory, change the
registry, restart a service, install a driver, or issue a firmware command.
Frida attachment is nevertheless process instrumentation: a Frida or target
process failure can interrupt Windows Biometric Service for that VM session.
A service or VM restart is the recovery action.  Run this only after saving
other work in the VM.

## Windows VM procedure

Prerequisites:

1. The exact A21 stack above is installed and the biometric device is healthy.
2. For the previously tested QEMU pass-through setup,
   `suppress-remote-wake=false` remains required for this legacy lower-filter
   stack.
3. Matching x64 Frida CLI tools are already installed in the Windows VM.
4. An elevated Windows PowerShell is open in a checkout of this repository.

Open Windows Hello fingerprint setup far enough to load the adapter pipeline,
but do not leave an outstanding capture while attaching.  Cancel that setup
screen without touching the sensor, then immediately run:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\tools\run_windows_a21_enrollment_trace.ps1 -ConfirmPrivacySafeTrace
```

The runner searches for a process containing all three pinned A21 modules,
then hashes the loaded module files before attaching.  If automatic discovery
finds more than one candidate, pass the displayed PID explicitly:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\tools\run_windows_a21_enrollment_trace.ps1 -ConfirmPrivacySafeTrace -TargetProcessId 1234
```

Wait for:

```text
cv2win event=trace-ready action=start_Windows_Hello_enrollment
```

Perform exactly one enrollment attempt.  After Windows reports success or
failure, type `exit` at Frida's prompt to detach cleanly.  The metadata-only
log is written under
`test-results/`.  Use separate trace processes for a successful control and
a failed control; do not concatenate multiple attempts into one session.

## First runtime: incomplete generic-path control

The first live run used Frida `17.17.0` and the three pinned A21 modules above
on the passed-through Latitude 7390 `0a5c:5833`.  It ran in the same Windows
boot session after an earlier Frida detach and `WbioSrvc` restart; it was not a
cold-boot baseline.

The privacy-safe event sequence was:

```text
CaptureStart success, output20 nonzero
CaptureStart success, output20 nonzero
Update 1: generic-0x6c, status 0x00, completion zero
CaptureStart success, output20 nonzero
Update 2: generic-0x6c, status 0x89, completion zero
CaptureStart success, output20 nonzero
Update 3: generic-0x6c, status 0x89, completion zero
CaptureStart success, output20 nonzero
Update 4: generic-0x6c, status 0x89, completion zero
CaptureStart success, output20 nonzero
Update 5: generic-0x6c, status 0x00, completion zero
CaptureStart success, output20 nonzero
manual detach before the next UpdateEnrollment call
```

Every observed UpdateEnrollment input matched the most recent CaptureStart
twenty-byte output.  The caller reused its input and output storage addresses
after the first call.  The twenty-byte update output changed from zero to
nonzero on the first successful update and remained classified nonzero; the
four-byte output and completion byte remained zero throughout.

No commit or discard hook fired before manual detach.  Because the run ended
after a seventh CaptureStart and before the corresponding update, it proves
neither completion behavior nor commit selection.

The route hook is direct runtime evidence that this A21 session selected the
generic command-`0x6c` branch, not the statically recovered BCM5880
host-template helper.  The three `0x89` returns were each followed by a fresh,
successful CaptureStart instead of enrollment termination.  This independently
confirms on `0a5c:5833` that `0x89` is a live retry/bad-capture class and must
not be repurposed as an alternate success-status comparison slot.

## Post-run recovery observation

The tracer detached while Windows Hello still had an unfinished enrollment
operation.  A later guest reboot stalled; libvirt force-off completed only
after a delay.  The ControlVault USB function was then absent on the Linux
host (neither `5833` nor fallback `5831`) until a complete host shutdown and
power cycle restored normal `0a5c:5833` enumeration.

This is a recoverable USB/power-state observation, not brick evidence.  The
trace contains no firmware-write operation.  It also does not isolate whether
the stall was caused by the unfinished Hello operation, Frida detachment,
legacy WUDF/lower-filter power handling, QEMU USB pass-through, or their
interaction.  Future runs must complete or explicitly cancel Hello, detach
Frida with `exit`, and verify the biometric session is idle before guest
shutdown.

## Reduced completion-only follow-up

A second full-tracer attempt reached two successful CaptureStart returns but
Windows Hello did not advance to UpdateEnrollment.  Exiting Frida, closing
Settings, and restarting `WbioSrvc` recovered the session without a guest
reboot.  This repetition makes the full tracer unsuitable for further live
completion attempts on this legacy stack, even though it does not establish
which individual hook or timing change caused the stall.

The explicit `-MinimalCompletionTrace` runner mode instead loads
`windows_a21_completion_trace.js`.  It installs no CaptureStart, capture-mode,
buffer, pointer, or internal-route observation.  It reads no process memory
and emits only UpdateEnrollment return statuses plus commit/discard function
ordering and return statuses:

```powershell
powershell.exe -ExecutionPolicy Bypass `
  -File .\tools\run_windows_a21_enrollment_trace.ps1 `
  -ConfirmPrivacySafeTrace `
  -MinimalCompletionTrace
```

The reduced mode relies on the first trace for the already-established
generic route and CaptureStart-to-Update input relationship.  It is intended
only to answer which commit/discard calls follow a complete enrollment while
minimizing synchronous instrumentation on the capture path.

## Successful minimal completion trace

A live reduced-mode run completed Windows Hello enrollment successfully.  Its
entire observed operation sequence was:

```text
UpdateEnrollment -> 0x00
UpdateEnrollment -> 0x00
UpdateEnrollment -> 0x00
UpdateEnrollment -> 0x00
CSS_FingerprintCommitEnrollment
  cv_fingerprint_commit_enrollment -> 0x00
CSS_FingerprintCommitEnrollment -> 0x00
CSS_FingerprintCommitEnrollment
  cv_fingerprint_commit_enrollment -> 0x00
CSS_FingerprintCommitEnrollment -> 0x00
Windows Hello enrollment success
```

The nested CSS/raw hook pairs represent two commit operations, not four.
Neither `CSS_FingerprintCommitFeatureSet` nor
`cv_fingerprint_commit_feature_set` ran.  No discard hook ran.  Thus this A21
success used exactly four successful UpdateEnrollment calls followed by two
successful CommitEnrollment calls.

The raw commit export is the statically identified generic command-`0x6e`
builder.  This names the operation family behind the two `0x6e` completion
calls seen in the earlier successful USB trace.  Subsequent static comparison
proved that these are two different phases: the final UpdateEnrollment path
performs an internal commit first, then WBF's formal CommitEnrollment callback
performs a second commit with different trailing arguments.  See
[the double-commit comparison](windows-a21-double-commit-static.md).  A Linux
implementation must therefore not duplicate one identical commit call merely
from the observed count. The recovered raw ABI instead requires one
`0x800`-capacity output call followed by one zero-capacity/result-only call,
both using the same 20-byte token and fixed input blocks.

After Hello closed and Frida detached with `exit`, the `0a5c:5833` host device
was live-detached from the still-running VM.  Linux immediately enumerated the
same `5833` identity.  This provides a clean post-test control and avoids
asking the legacy Windows lower-filter stack to process guest shutdown while
it still owns the USB function.

## Evidence interpretation

The most important fields are:

| Event/field | Question answered |
|---|---|
| `capture-start-leave output20_class` | Did A21 produce a nonzero twenty-byte capture/enrollment value? |
| `update-enter input_matches_capture_start` | Did UpdateEnrollment receive the exact CaptureStart output? |
| `update-route route` | Did this live `0a5c:5833` session use generic `0x6c` or the BCM5880 host-template helper? |
| `update-leave completion_post` | On which accepted update did the completion byte become nonzero? |
| `update-leave output20_post/output4_post` | Which output classes changed at that boundary? |
| `commit-enter/leave symbol` | Which CSS/raw commit function actually followed the updates? |
| `discard-enter/leave symbol` | Which discard path closed a failed attempt? |

Zero/nonzero or equality evidence does not establish the semantic contents of
an opaque field.  A nonzero output must not be copied into the Linux driver
until its ownership, length, and downstream consumer are separately proven.
