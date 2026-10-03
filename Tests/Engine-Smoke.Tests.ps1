$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$Modules = Join-Path $RepoRoot "Modules"

Import-Module (Join-Path $Modules "VaultGuard.Vault.psm1") -Force
Import-Module (Join-Path $Modules "VaultGuard.PaintGeacata.psm1") -Force
Import-Module (Join-Path $Modules "VaultGuard.ShortcutWorm.psm1") -Force
Import-Module (Join-Path $Modules "VaultGuard.Expiro.psm1") -Force
Import-Module (Join-Path $Modules "VaultGuard.Detection.psm1") -Force

$TempRoot = Join-Path $env:RUNNER_TEMP "VaultGuardSmoke"
Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $TempRoot -Force | Out-Null

try {
    $CleanSource = Join-Path $env:WINDIR "System32\where.exe"
    if (-not (Test-Path -LiteralPath $CleanSource)) { throw "Smoke-test clean source not found." }

    $CleanCopy = Join-Path $TempRoot "clean.exe"
    Copy-Item -LiteralPath $CleanSource -Destination $CleanCopy -Force

    # Family detector should not convict a known Windows utility copied to a clean name.
    $PaintVerdict = Test-PaintGeacataThreat -FilePath $CleanCopy
    if ($PaintVerdict.Verdict -eq "Infected") { throw "Paint/Geacata detector false-positive on smoke-test clean executable." }

    $ExpiroVerdict = Test-ExpiroThreat -FilePath $CleanCopy -DeepPass
    if ($ExpiroVerdict.Verdict -eq "Infected") { throw "Expiro detector false-positive on smoke-test clean executable." }

    # Capture one independent baseline blob and authenticate it.
    $Baseline = New-VaultGuardBaseline -TargetPaths @($TempRoot)
    if (-not $Baseline.Success -or $Baseline.TotalCaptured -lt 1) { throw "Baseline capture failed." }

    $Integrity = Test-VaultGuardIntegrity
    if (-not $Integrity.Success) { throw "Baseline authentication/integrity check failed: $($Integrity.Message)" }

    # Quarantine and restore a disposable copy to validate metadata/hash lifecycle.
    $Disposable = Join-Path $TempRoot "quarantine-test.exe"
    Copy-Item -LiteralPath $CleanSource -Destination $Disposable -Force
    $OriginalHash = (Get-FileHash -LiteralPath $Disposable -Algorithm SHA256).Hash

    $Quarantine = Protect-FileToQuarantine -FilePath $Disposable -Reason "CI smoke test"
    if (-not $Quarantine.Success) { throw "Quarantine failed: $($Quarantine.Message)" }
    if (Test-Path -LiteralPath $Disposable) { throw "Quarantine did not isolate the disposable file." }

    $Restore = Restore-QuarantinedItem -QuarantineId $Quarantine.QuarantineId
    if (-not $Restore.Success) { throw "Quarantine restore failed: $($Restore.Message)" }
    if (-not (Test-Path -LiteralPath $Disposable)) { throw "Restored file is missing." }

    $RestoredHash = (Get-FileHash -LiteralPath $Disposable -Algorithm SHA256).Hash
    if ($RestoredHash -ne $OriginalHash) { throw "Restored quarantine payload hash mismatch." }

    # Scanner invocation must execute successfully against the disposable directory.
    $Scan = Invoke-VaultGuardScan -Paths @($TempRoot) -DryRun
    if ($null -eq $Scan.TotalScanned) { throw "Scanner did not return telemetry." }

    Write-Host "VaultGuard engine smoke test passed." -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
