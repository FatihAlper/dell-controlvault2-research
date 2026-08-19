# Static evidence: BCM5880 host-side completion

## Scope

Read-only `objdump`, `readelf`, `nm`, `strings`, and evidence-log analysis
was performed. No binary was written, no source/test artifact was changed,
no build ran, and no hardware command was sent.

Verified artifacts:

```text
c7dbb44e25aa5127515cb4de23868358d7b170d2625227131a88bce39f3e8ef6
  prebuilt/libfprint-2-tod-1-broadcom-5833.probe.so
Build ID 66134403db205c7c1ac682885229224790aedc0e

e157fbe548bfd2b6b1ee4410b5dc93255409b329bbe4d75da9d7c1684fa1db4e
  Dell ControlVault2 4.12.5.8 A21 package

30c556a9b542d0fcf29a6822b3bb81fe23ce2917b403b3f25af9384e0e31e524
  extracted bipdll.dll

dfb30d81de42e726477b103412fba2c88abd9b675ead7141f25063a3ac8d4e6c
  extracted BrcmSensorAdapter.dll
```

## Hardware log facts

The raw source log remains local. Derived event order:

```text
accepted: 1,2,3
first 0x59 -> second 0x6c 0x89 -> 0x8a success
accepted: 4,5,6
first 0x59 -> second 0x6c 0x89 -> 0x8a success
accepted: 7,8,9
first 0x59 -> second 0x6c 0x89 -> 0x8a success
accepted: 10,11,12
first 0x59 -> second 0x6c 0x89 -> 0x8a success
accepted: 13
```

For all four `0x59`/second-`0x89` pairs, completion was `0x00` and the
enrollment output remained unpopulated. Output bytes are intentionally not
published.

The test was cancelled, cleanup completed, and no commit ran.

## Decisive Windows instructions

`bipdll.dll` `.text`: file offset = RVA - `0xc00`.

| Function | RVA | File | Evidence |
|---|---:|---:|---|
| update dispatcher | `0x2d242` | `0x2c642` | Calls `is5880`. |
| selected update call | `0x2d256` | `0x2c656` | Calls RVA `0x2cef0`. |
| selected update | `0x2cef0` | `0x2c2f0` | Four-argument helper. |
| count comparison | `0x2cfb3` | `0x2c3b3` | `cmp esi,3`. |
| feature stride | `0x2cfcf` | `0x2c3cf` | `imul rcx,rsi,0x258`. |
| feature copy | `0x2cfdd` | `0x2c3dd` | Copies current feature into slot. |
| count increment/store | `0x2cfec` | `0x2c3ec` | Increments buffered count. |
| fourth-feature call | `0x2d084` | `0x2c484` | Calls create-template RVA `0x2e0c0`. |
| template success test | `0x2d08c` | `0x2c48c` | Nonzero bypasses completion. |
| template-ready write | `0x2d097` | `0x2c497` | Writes shared ready byte 1. |
| completion write | `0x2d09e` | `0x2c49e` | Writes caller completion byte 1. |
| token RNG | `0x2d0a2` | `0x2c4a2` | Calls 4-byte RNG wrapper. |
| token copy | `0x2d0c1` | `0x2c4c1` | Copies 20-byte token to caller. |
| create-template | `0x2e0c0` | `0x2d4c0` | Four-feature primitive. |
| command `0x6f` | `0x2e49d` | `0x2d89d` | Builds native template-create command. |
| commit selector | `0x2db75` | `0x2cf75` | Calls the same `is5880`. |
| selected commit call | `0x2dbaf` | `0x2cfaf` | Calls RVA `0x2d8f0`. |
| selected discard reset | `0x2d78c` | `0x2cb8c` | Clears count without generic `0x6d`. |

The selected update condition is:

```text
is5880
AND current capture valid and in time
AND 20-byte enrollment/capture ID matches
AND three buffered feature records exist
AND a fourth live feature exists
AND cv_fingerprint_create_template / 0x6f returns 0
-> template_ready=1
-> completion_out=1
-> create and return 20-byte token
```

No `cv_fingerprint_enroll_dup_check` call occurs in this CFG.

## Selector evidence

| RVA | File | Evidence |
|---:|---:|---|
| `0x4ae70` | `0x4a270` | `is5880` entry. |
| `0x4aebc` | `0x4a2bc` | Gets USH version text. |
| `0x4aef9` | `0x4a2f9` | Searches for `USH_CHIPID:5880`. |
| `0x4af15` | `0x4a315` | Caches true. |

No PID, registry, INF, SMBIOS, ACPI, or chip-type-`0x1c` comparison controls
this selector. The actual Latitude runtime string remains unobserved.

## Decisive Linux instructions

Linux `.text` RVA equals file offset.

| RVA/file | Evidence |
|---:|---|
| `0xfed0`--`0xfed6` | `is5880` unconditionally returns false. |
| `0x2632a` | Native nonzero update skips every output write. |
| `0x26330`--`0x263a0` | Outputs are cleared/saved only on native success. |
| `0x2b117` | Wrapper initializes completion byte only. |
| `0x2b1b3` | Completion zero test. |
| `0x2b1f6` | Completion zero creates synthetic `0x8f`. |
| `0xdf53`--`0xdf56` | Host accepted counter increments with no cap. |
| `0xd2bc` | Class metadata hard-codes ten stages. |
| `0xe010` | Native-zero/completion-one state transition to state 2. |
| `0x2691d` | Generic commit builds `0x6e`. |
| `0x26d10` | Exported four-feature create-template primitive. |
| `0x2703d` | Linux primitive builds command `0x6f`. |

No call/xref from the TOD enrollment CFG reaches `is5880`,
`cv_fingerprint_capture_get_result`, `cv_fingerprint_create_template`, or
the feature-set helpers. No integrated three-feature accumulation or
selected commit path exists in this target.

## `output_value_out` provenance

The Linux wrapper's 4-byte stack output is not initialized before the raw
call. A native nonzero result bypasses the raw success block which would
clear/fill it. The observed unchanged value is therefore stale stack content
and has no proven protocol meaning; its raw value is omitted.

## Patch 4 mismatch

Patch 4 routes raw `0x59` into the status-zero state dispatcher. It does not:

- acquire any feature record;
- call command `0x6f`;
- retain a returned template;
- generate a valid token;
- set completion through native processing; or
- select a matching 5880 commit path.

It also removes the prior `0xa4` retry branch. It is not an implementation of
the A21 selected path.

## Conclusion

The missing unit is the BCM5880 host enrollment coordinator, not a single
status substitution. It encompasses feature acquisition, three-plus-one
aggregation, native template creation, token/ready-state lifetime, and a
matching special commit operation. The existing Linux `0x6f` primitive is
potentially reusable, but its inputs and commit counterpart must be proven
before any hardware experiment.

Later cross-adapter analysis also proves that Windows supplies the same kind
of capture-derived 20-byte UpdateEnrollment input as Linux: Advanced
SensorAdapter capture copies `CSS_FingerprintCaptureStart` output into the
fixed EngineContext field consumed by UpdateEnrollment. Pointer lifetime and
zero substitution are therefore eliminated as missing mechanisms; see
[the A21 input dataflow](windows-a21-update-input-dataflow.md).
