# Windows A21 UpdateEnrollment input dataflow

## Scope and artifact identity

This is a read-only static analysis of three x64 DLLs extracted from Dell
ControlVault2 package `N23KC`, version `4.12.5.8 A21`. The package and DLL
hashes are:

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

None of the binaries was executed, patched, or copied into this repository.
For all three PE files in the ranges below, `.text` file offset equals
`RVA - 0xc00`.

## Cross-adapter ownership

The earlier EngineAdapter-only scan correctly found no direct writer to
`EngineContext+0x18`, but it missed the writer because Windows gives both
adapter contexts to the SensorAdapter through the WBF pipeline. The public
[`WINBIO_PIPELINE`](https://learn.microsoft.com/en-us/windows/win32/api/winbio_adapter/ns-winbio_adapter-winbio_pipeline)
layout identifies these as the pipeline's `SensorContext` and
`EngineContext` fields.

`BrcmSensorAdapterStartCapture` loads both contexts and supplies a 20-byte
SensorContext field to the CSS capture-start operation:

```text
Sensor RVA 0x21bb  mov rdi,[rcx+0x30]     ; Pipeline->SensorContext
Sensor RVA 0x21bf  mov r13,[rcx+0x38]     ; Pipeline->EngineContext
Sensor RVA 0x21d6  mov r15d,0x23          ; default capture mode
Sensor RVA 0x21df  cmp [rdi+0x20],1       ; Basic sensor mode?
Sensor RVA 0x21f1  mov r15d,0x22          ; Basic-mode capture value
Sensor RVA 0x2263  lea r8,[rdi+0x5c]      ; 20-byte capture-start output
Sensor RVA 0x2267  mov edx,r15d
Sensor RVA 0x2273  call WBFUSH_StartCapture
```

`WBFUSH_StartCapture` preserves this pointer in `r8` when it invokes the
dynamically resolved `CSS_FingerprintCaptureStart` export at SensorAdapter
RVA `0x2e57`. `bipdll.dll` exports that function at RVA `0x15290`, preserves
the incoming `r8` pointer in `r14`, and forwards it as an output pointer to
its internal capture-start dispatcher at RVA `0x153ed`.

After capture-start returns, SensorAdapter performs the previously missing
cross-adapter write:

```text
Sensor RVA 0x22b6  cmp [rdi+0x20],2       ; Advanced sensor mode?
Sensor RVA 0x22c1  movups xmm0,[rdi+0x5c]
Sensor RVA 0x22c5  movups [r13+0x18],xmm0 ; first 16 bytes
Sensor RVA 0x22ca  mov eax,[rdi+0x6c]
Sensor RVA 0x22cd  mov [r13+0x28],eax     ; remaining 4 bytes
```

Therefore the UpdateEnrollment pointer is stable, but its 20-byte content is
not allocation-time zero. Advanced StartCapture refreshes it from the CSS
capture-start output before EngineAdapter uses it.

## BCM5880 capture-start branch

The internal `bipdll.dll` capture-start dispatcher at RVA `0x2b360` calls
`is5880`. Its selected branch passes the same caller output pointer to RVA
`0x2b1e0`. For capture value `0x23`, bit `0x20` is set and the selected helper:

```text
BIP RVA 0x2b20f  test cl,0x20
BIP RVA 0x2b222  lea rcx,[0xaf030]
BIP RVA 0x2b229  call RNG wrapper
BIP RVA 0x2b248  load 16 bytes from 0xaf030
BIP RVA 0x2b254  store 16 bytes to caller output
BIP RVA 0x2b257  load 4 bytes from 0xaf040
BIP RVA 0x2b25d  store 4 bytes to caller output+0x10
```

This is the same shared 20-byte enrollment/capture ID that the selected
BCM5880 UpdateEnrollment helper later validates before buffering a feature.
The generic capture-start branch also treats this argument as a 20-byte
output, but obtains it through its structured CV response instead. Static
existence of the selected branch does not by itself prove the runtime value
of `is5880`; the cross-adapter copy is decisive independently of which CSS
branch produced the output.

## UpdateEnrollment consumer

EngineAdapter later reads exactly the copied field:

```text
Engine RVA 0x31af  lea rcx,[rdi+0x18]
Engine RVA 0x31c1  call [CSS_FingerprintUpdateEnrollment]
```

The CSS wrapper registers this pointer as a required 20-byte input. The full
flow is consequently:

```text
CSS_FingerprintCaptureStart output
  -> SensorContext+0x5c (20 bytes)
  -> Advanced StartCapture copy
  -> EngineContext+0x18 (same 20 bytes, stable address)
  -> CSS_FingerprintUpdateEnrollment input
```

The Windows Biometrics operational trace from the tested installation called
this sensor mode `Advanced`, matching the mode-2 copy branch. No fingerprint
payload bytes are needed or published to establish the pointer and copy
dataflow.

## Consequence for the Linux experiments

This resolves the stable-zero experiment: replacing Linux's fresh
capture-derived 20-byte input with zeros removed a required capture/enrollment
ID, so zero accepted updates is the expected failure. Windows and Linux both
feed capture-derived 20-byte content to UpdateEnrollment. Their storage
lifetime differs—fixed context field versus fresh allocation—but pointer
identity is not the missing behavior.

It also strengthens the existing conclusion that the unsolved unit is the
BCM5880 host enrollment coordinator: selected-path feature acquisition,
three-plus-one aggregation, template creation, token/ready-state lifetime,
and matching special commit. Another guessed UpdateEnrollment input value is
not justified by this evidence.

## Reproduction

After extracting the three DLLs outside the repository:

```sh
python3 tools/audit_windows_a21_update.py \
  /private/path/BrcmEngineAdapter.dll \
  /private/path/BrcmSensorAdapter.dll \
  /private/path/bipdll.dll
```

The command checks exact hashes plus unique instruction anchors and fails
closed on any mismatch. It only reads the supplied files and reports
`artifact_write_performed=no`.
