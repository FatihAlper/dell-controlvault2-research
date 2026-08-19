[CmdletBinding()]
param(
    [int]$TargetProcessId = 0,
    [switch]$ConfirmPrivacySafeTrace,
    [switch]$MinimalCompletionTrace,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"

if (-not $ConfirmPrivacySafeTrace) {
    throw "Refusing process instrumentation without -ConfirmPrivacySafeTrace"
}

# Windows PowerShell 5.1 does not reliably initialize $PSScriptRoot while
# evaluating default expressions inside param(...).  Resolve the default only
# after parameter binding has completed.
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $PSScriptRoot "..\test-results"
}

$ExpectedHashes = @{
    "bipdll.dll" = "30c556a9b542d0fcf29a6822b3bb81fe23ce2917b403b3f25af9384e0e31e524"
    "BrcmEngineAdapter.dll" = "622b1a12566cb313cde264869ca5a4b410e3d5b2b604f5dd628c4a6b709b19ae"
    "BrcmSensorAdapter.dll" = "dfb30d81de42e726477b103412fba2c88abd9b675ead7141f25063a3ac8d4e6c"
}

function Get-LoadedModules([int]$ProcessId) {
    try {
        return @(
            Get-Process -Id $ProcessId -ErrorAction Stop |
                Select-Object -ExpandProperty Modules
        )
    }
    catch {
        throw "Cannot enumerate target modules. Run elevated and verify the process ID."
    }
}

function Find-A21HostProcess {
    $candidateIds = @()
    $service = Get-CimInstance Win32_Service -Filter "Name='WbioSrvc'"
    if ($null -ne $service -and $service.ProcessId -ne 0) {
        $candidateIds += [int]$service.ProcessId
    }

    $candidateIds += @(
        Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -ne $PID } |
            Select-Object -ExpandProperty Id
    )

    $matches = @()
    foreach ($candidateId in ($candidateIds | Select-Object -Unique)) {
        try {
            $candidateModules = @(
                Get-Process -Id $candidateId -ErrorAction Stop |
                    Select-Object -ExpandProperty Modules
            )
        }
        catch {
            continue
        }

        $loadedNames = @($candidateModules | ForEach-Object { $_.ModuleName })
        $complete = $true
        foreach ($requiredName in $ExpectedHashes.Keys) {
            if (-not ($loadedNames -icontains $requiredName)) {
                $complete = $false
                break
            }
        }
        if ($complete) {
            $matches += [int]$candidateId
        }
    }

    $matches = @($matches | Select-Object -Unique)
    if ($matches.Count -eq 0) {
        throw "No process has the exact A21 biometric modules loaded. Open Windows Hello fingerprint settings, touch the sensor once, and retry."
    }
    if ($matches.Count -gt 1) {
        throw "More than one A21 biometric host was found. Re-run with -TargetProcessId and one of: $($matches -join ', ')"
    }
    return [int]$matches[0]
}

if ($TargetProcessId -eq 0) {
    $TargetProcessId = Find-A21HostProcess
}

$modules = Get-LoadedModules $TargetProcessId
foreach ($entry in $ExpectedHashes.GetEnumerator()) {
    $module = $modules | Where-Object { $_.ModuleName -ieq $entry.Key } |
        Select-Object -First 1
    if ($null -eq $module) {
        throw "Required A21 module is not loaded: $($entry.Key). The target PID may be wrong."
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $module.FileName).Hash.ToLowerInvariant()
    if ($actual -ne $entry.Value) {
        throw "Unsupported $($entry.Key) SHA-256: $actual"
    }
    Write-Host "validated_module=$($entry.Key) sha256=$actual"
}

$frida = Get-Command frida -ErrorAction SilentlyContinue
if ($null -eq $frida) {
    throw "frida CLI not found. Install matching frida-tools in the Windows VM."
}

$scriptName = if ($MinimalCompletionTrace) {
    "windows_a21_completion_trace.js"
}
else {
    "windows_a21_enrollment_trace.js"
}
$script = Join-Path $PSScriptRoot $scriptName
if (-not (Test-Path -LiteralPath $script)) {
    throw "Trace script is missing: $script"
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$traceKind = if ($MinimalCompletionTrace) { "minimal-completion" } else { "full-metadata" }
$log = Join-Path $OutputDirectory "windows-a21-$traceKind-$stamp.log"

Write-Host "payload_logging=disabled"
Write-Host "pointer_logging=disabled"
Write-Host "binary_modification=none"
Write-Host "trace_kind=$traceKind"
Write-Host "target_process_id=$TargetProcessId"
Write-Host "evidence_file=$log"
Write-Host "Attach is read-only instrumentation but may restart WbioSrvc if it crashes."
Write-Host "Wait for event=trace-ready, then perform one Windows Hello enrollment."
Write-Host "Press Ctrl+C after Windows reports success or failure."

& $frida.Source --runtime=v8 -p $TargetProcessId -l $script -o $log
exit $LASTEXITCODE
