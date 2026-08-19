# Documentation and evidence map

This index is the recommended entry point for ControlVault2 research in this
repository. Documents intentionally separate observed behavior from inferred
protocol meaning.

## Start here

- [Current status and roadmap](current-status.md)
  — capability matrix, strongest findings, blockers, driver readiness, and
  ranked next work.
- [Architecture and terminology](architecture.md)
  — system layers, USB/message model, enrollment flow, data boundaries, and a
  glossary for project terminology.
- [Tooling guide](../tools/README.md)
  — offline audits, privacy-safe PCAP analysis, mock-only models, and the
  explicit boundaries around live hardware instrumentation.
- [Latitude 7390 / `0a5c:5833` evidence record](evidence/latitude-7390-0a5c-5833.md)
  — tested hardware, validated lifecycle, failures, and recovery controls.
- [Command and status reference](controlvault2-command-status-reference.md)
  — compact dictionary of observed/inferred native commands and status codes.
- [BCM5880 enrollment completion analysis](enrollment-bcm5880-completion-analysis.md)
  — long-form reconstruction of the enrollment paths and competing models.

## Successful Windows reference path

- [Windows A21 enrollment runtime](evidence/windows-a21-enrollment-runtime.md)
  — privacy-safe USB message shapes from successful and failed controls.
- [Windows A21 enrollment metadata trace](evidence/windows-a21-enrollment-metadata-trace.md)
  — bounded function-level trace and exact loaded-module hashes.
- [Windows A21 double-commit analysis](evidence/windows-a21-double-commit-static.md)
  — proves that the two commits are distinct large-output and result-only
  phases rather than duplicate calls.
- [Windows UpdateEnrollment arguments](evidence/windows-a21-update-arguments-static.md)
  and [input dataflow](evidence/windows-a21-update-input-dataflow.md) — static
  reconstruction of the update call boundary.

## Linux enrollment experiments

- [`0x89` re-arm static analysis](evidence/0x89-rearm-static.md)
- [`0x59` single-update retry analysis](evidence/0x59-single-update-retry-static.md)
- [`0x59` repeat hardware control](evidence/0x59-repeat-hardware.md)
- [Fresh-boundary state analysis](evidence/fresh-boundary-static.md)
- [Zero update-input hardware control](evidence/zero-update-input-hardware.md)
- [Update call metadata](evidence/update-enrollment-call-metadata.md)
- [Cross-session structural comparison](evidence/update-enrollment-structural-comparison.md)

The older long-form status investigations remain available as
[enrollment `0x59`](enrollment-0x59-analysis.md) and
[enrollment `0x89`](enrollment-0x89-analysis.md).

## Recovered native ABIs and mock models

- [Linux capture/template/commit export ABIs](evidence/linux-bcm5880-export-abis.md)
- [CaptureGetResult probe boundary](evidence/capture-get-result-probe.md)
- [Mock enrollment coordinator](evidence/bcm5880-coordinator-mock.md)
- [Static completion-path reconstruction](evidence/bcm5880-completion-static.md)
- [Local symbol-scope forwarding](evidence/local-scope-forwarding.md)

Mock-only code expresses recovered calling conventions and state transitions;
it is not permission to call persistence operations on real hardware.

## Evidence vocabulary

Documents use the following practical confidence classes:

- **Runtime observed:** recorded on named hardware with the stated controls.
- **Statically proven:** instruction/dataflow result tied to an exact binary
  hash and reproducible offsets or signatures.
- **Cross-session inference:** the best explanation joining independent traces;
  useful, but not treated as direct proof.
- **Hypothesis:** a candidate for a bounded future experiment.

When a command name is marked “inferred,” it is project terminology rather
than an official Broadcom protocol name.

## Publication rules

Public evidence may contain hashes, offsets, command identifiers, statuses,
message lengths, timing/order, and redacted pointer relationships. It must not
contain raw fingerprint features/templates, credentials, keys, proprietary
binaries, or unreviewed protected payloads.
