# BCM5880 enrollment coordinator mock scaffold

## Purpose

`tools/bcm5880_enrollment_coordinator.c` is a mock-only reconstruction of the
host state machine visible in Dell's Windows A21 selected BCM5880 path. It
models the proven data ownership and three-plus-one feature transition without
binding any proprietary Linux symbol or sending a hardware command.

This is not evidence that the selected A21 path is active on the tested
Latitude. The successful Windows USB control used visible generic-looking
`0x6c`/`0x6e` traffic, so the selected coordinator remains an alternate static
implementation lead rather than the highest-confidence runtime explanation.

## Enforced safety boundary

The scaffold:

- fails compilation unless `CV2_BCM5880_COORDINATOR_MOCK_ONLY` is explicitly
  defined;
- rejects initialization unless execution mode is explicitly `MOCK_ONLY`;
- contains no `dlsym`, driver loader, USB transport, capture, UpdateEnrollment,
  or commit call;
- accepts only caller-injected mock template and random callbacks;
- exposes no commit callback or commit function;
- reports `commit_permitted=false` in every state;
- becomes terminal when template creation succeeds, returning
  `TEMPLATE_READY_COMMIT_BLOCKED`; and
- clears sensitive working state immediately on terminal failure and clears
  its enrollment ID, feature slots, template, and token before freeing state.

No biometric bytes are printed by the implementation or test harness.

## Modeled state transition

The context owns:

```text
expected capture/enrollment ID     20 bytes
buffered feature slots             3 * 0x258 bytes
buffered variable lengths          3 * uint32
template buffer/capacity           0x708 bytes
commit token                       20 bytes (4-byte random prefix)
```

Each accepted feature must have the expected 20-byte enrollment ID and a
length from 1 through `0x258`:

```text
feature 1 -> copy slot 0 -> ACCEPTED_MORE
feature 2 -> copy slot 1 -> ACCEPTED_MORE
feature 3 -> copy slot 2 -> ACCEPTED_MORE
feature 4 -> remain live -> call injected four-feature template mock
                         -> validate status and returned length
                         -> generate four-byte mock token prefix
                         -> TEMPLATE_READY_COMMIT_BLOCKED
```

An ID mismatch consumes no slot. An oversized feature, nonzero template
status, invalid returned template size, or token-generation failure enters a
terminal fail-closed state. The token-generation rule is intentionally
stricter than the recovered Windows helper, which logs RNG failure but
continues; a future implementation must not weaken this boundary implicitly.

## Test coverage

`tests/test_bcm5880_enrollment_coordinator.py` compiles the scaffold and a
local mock harness with `-Wall -Wextra -Werror`. It verifies:

- compilation is refused without the mock-only macro;
- runtime initialization is disabled by default;
- missing mock operations are rejected before any callback;
- three features do not call template creation;
- the fourth feature is passed after the three buffered features in order;
- successful template creation still cannot commit;
- a second call after template readiness is rejected;
- ID mismatch does not consume state;
- feature overflow fails before any callback;
- template status and size errors are terminal; and
- token RNG failure never marks a template ready.

## Remaining gates before any hardware integration

Read-only static analysis now recovers the exact five-argument Linux
`cv_fingerprint_capture_get_result` ABI and eleven-argument
`cv_fingerprint_create_template` ABI. A separately compile-gated adapter
exercises both layouts against injected mocks; see
`docs/evidence/linux-bcm5880-export-abis.md`. This answers the calling-
convention part of the first two questions, but not their data semantics or
runtime suitability.

The remaining gates are:

1. Which `capture_get_result` selector/status yields the Windows-equivalent
   variable-length feature record, and is its byte format actually identical?
2. Does the Linux template primitive accept those four feature records
   semantically, rather than merely accepting the recovered ABI layout?
3. Is the selected coordinator actually appropriate for this device's Linux
   failure, given the successful Windows generic-looking runtime sequence?
4. What is the full selected commit ABI, retained-template ownership, cleanup,
   and persistence behavior?

Those require a separately reviewed, capture-only evidence step. A real symbol
resolver, hardware flag, or commit path remains outside this scaffold.
