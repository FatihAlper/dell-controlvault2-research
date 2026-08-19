# ControlVault2 command and status reference

## Research scope

This repository contains independently derived interoperability research for
Linux support of lawfully owned Broadcom ControlVault2 hardware.

Command names marked as inferred are not official Broadcom terminology.

No proprietary binaries, firmware, cryptographic keys, raw fingerprint
features, biometric templates, personal identifiers, or authentication
credentials are included.

## Interpretation rules

“Export pairing” means a short wrapper in the analyzed Broadcom library passes
the listed constant to its common CV transport routine. It establishes the
code-to-wrapper relationship but does not make the descriptive name official
vendor terminology.

“Hardware” records only command/status order and aggregate state changes. Raw
USB payloads and biometric data are not included.

## Commands

| Code | Observed behavior | Evidence type | Confidence | Terminology | Known next transition |
|---|---|---|---|---|---|
| `0x20` | Used by exported `cv_fingerprint_enroll` wrapper. | Linux export pairing | High for pairing | Inferred: fingerprint enroll operation | Function-dependent completion/status |
| `0x30` | Used by exported `cv_fingerprint_configure` wrapper. | Linux export pairing | High for pairing | Inferred: fingerprint configuration | Returns native status |
| `0x39` | Queries USH version data; request/reply completed on `0a5c:5833`. | Linux export pairing and hardware | High | Inferred from `cv_get_ush_ver` export | Version response, then probe classification |
| `0x41` | Used by exported `cv_enable_fingerprint` wrapper. | Linux export pairing | High for pairing | Inferred: enable fingerprint function | Returns native status |
| `0x5c` | Used by exported `cv_fingerprint_capture` wrapper. | Linux export pairing | High for pairing | Inferred: synchronous/native capture | Returns capture-dependent outputs |
| `0x5d` | Used by exported `cv_fingerprint_reset` wrapper. | Linux export pairing | High for pairing | Inferred: fingerprint reset operation | Returns native status |
| `0x66` | Starts an enrollment capture in the analyzed TOD path. | Linux CFG and hardware | High | Inferred: CaptureStart | Interrupt completion, then update |
| `0x68` | Used by exported `cv_fingerprint_capture_cancel` wrapper. | Linux export pairing and cleanup CFG | High | Inferred: CaptureCancel | Cleanup or discard |
| `0x69` | Used by exported `cv_fingerprint_capture_get_result` wrapper. | Linux export pairing | High for pairing | Inferred: capture-result retrieval | Returns capture-dependent outputs |
| `0x6a` | Used by exported `cv_fingerprint_create_feature_set` wrapper. | Linux export pairing | High for pairing | Inferred: create feature set | Returns native status/output |
| `0x6b` | Used by exported `cv_fingerprint_commit_feature_set` wrapper. | Linux export pairing | High for pairing | Inferred: commit feature set | Returns native status |
| `0x6c` | Generic Linux UpdateEnrollment operation. | Linux CFG and hardware | High | Inferred: UpdateEnrollment | Status/completion dispatch |
| `0x6d` | Generic Linux enrollment discard operation. | Linux CFG | High | Inferred: DiscardEnrollment | Fatal/cancellation cleanup |
| `0x6e` | Generic Linux enrollment commit operation; successful Windows A21 tracing observed two nested CSS/raw CommitEnrollment calls after four successful updates, matching the earlier two-opcode USB sequence. Static A21 comparison identifies the first as UpdateEnrollment's internal large-output phase and the second as WBF's formal result-only phase. The Linux export has the same nine-argument ABI and supports both modes. | Linux/Windows ABI and CFG, Windows USB runtime, Windows function trace | High for operation family, order, call shape, and non-equivalence; low for protected output semantics | CommitEnrollment | Both returned zero and reuse one 20-byte input token. First capacity is `0x800`; second capacity is zero. The 848-byte USB response-size delta is the strongest candidate for the first returned blob length. |
| `0x6f` | Four-feature template primitive in Linux and Windows static analysis; absent as a visible header in one successful Windows A21 runtime trace. | Linux/Windows CFG and Windows runtime absence | High for static pairing and captured absence | Inferred: CreateTemplate in the recovered static path | On statically selected Windows success, retained template and completion |
| `0x70` | Used by exported `cv_fingerprint_enroll_dup_check` wrapper. | Linux export pairing | High for pairing | Inferred: enrollment duplicate check | Returns native status |
| `0x73` | Twenty-two protected requests appeared during a Windows Hello verification session containing both successful identifications and rejected samples. | Windows runtime and biometric event correlation | High for operation family; low for protected reply semantics | Inferred: Identify/Verify | 124- or 76-byte protected reply |
| `0x8a` | Prepares/re-arms the next enrollment capture. | Windows CFG and hardware retry order | High for observed transition | **Inferred:** enrollment capture re-arm/preparation command | Successful call is followed by `0x66` |

`0x8a` is not called “rollback”, “reset”, or “acknowledge” here because those
names are not established by the available evidence.

## Statuses

| Code | Observed behavior | Evidence type | Confidence | Terminology | Known next transition |
|---|---|---|---|---|---|
| `0x00` | Native call success. During generic Linux update, completion zero is converted to synthetic `0x8f`; completion one can reach state 2. | Linux CFG and mock tests | High | Generic success; not necessarily enrollment complete | Depends on completion output |
| `0x59` | Appears after groups of three accepted Linux samples. One bounded repeated `0x6c` returned `0x89`; generic Linux otherwise treats it as fatal. Two Windows controls independently accepted three 124-byte `0x6c` replies, rejected the fourth with a shorter protected reply, then discarded. Protected Windows content prevents equating that reply to `0x59`. | Linux hardware and Windows structural runtime comparison | High for each observed sequence; low for cross-platform status equivalence | Exact semantic name unknown; final-sample/accumulator rejection is a hypothesis | Windows analogue discarded with `0x6d`; bounded Linux retry remains diagnostic only |
| `0x89` | Windows maps it to bad-capture/poor-quality framework results. On tested hardware, one `0x8a` followed by normal retry capture succeeds. | Windows CFG and hardware | High for behavior | Firmware semantic name not asserted | `0x8a → 0x66` |
| `0x8f` | Synthesized by the Linux host wrapper when native update succeeds but completion is zero. It is not a raw firmware status in this path. | Linux CFG | High | Synthetic host “more enrollment progress” state | Increment host counter and issue next `0x66` |
| `0xa4` | Has a dedicated retry branch in the unmodified Linux outer callback. | Linux CFG and regression tests | High for branch, low for semantic meaning | Exact semantic name unknown | Preserve state 1 and issue next `0x66` |

## Scope limits

The table documents code associations and observed transitions, not a complete
vendor protocol specification. The successful Windows runtime sequence is
documented separately in `evidence/windows-a21-enrollment-runtime.md`. Linux
enrollment completion, matched commit behavior, template persistence, and
verification remain unproven.
