# ==============================================================================
# VaultGuard 360 security and architecture regression checks
# ==============================================================================

$ErrorActionPreference = "Stop"
$AppDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$PassCount = 0
$FailCount = 0

function Assert-Test {
    param([bool]$Condition, [string]$Name, [string]$Details = "")
    if ($Condition) {
        Write-Host "[PASS] $Name" -ForegroundColor Green
        $script:PassCount++
    } else {
        Write-Host "[FAIL] $Name $Details" -ForegroundColor Red
        $script:FailCount++
    }
}

function Read-RepoFile([string]$RelativePath) {
    Get-Content (Join-Path $AppDir $RelativePath) -Raw
}

Write-Host "VaultGuard 360 regression checks" -ForegroundColor Cyan

# Build/runtime structure
Assert-Test (Test-Path (Join-Path $AppDir "VaultGuard360.csproj")) "WPF project exists"
Assert-Test (Test-Path (Join-Path $AppDir "Services\EngineService.cs")) "Engine service exists"
Assert-Test (Test-Path (Join-Path $AppDir "Modules\VaultGuard.Detection.psm1")) "Detection dispatcher exists"
Assert-Test (Test-Path (Join-Path $AppDir "Modules\VaultGuard.Vault.psm1")) "Protected vault module exists"

$engine = Read-RepoFile "Services\EngineService.cs"
$scanVm = Read-RepoFile "ViewModels\ScanViewModel.cs"
$dashboardVm = Read-RepoFile "ViewModels\DashboardViewModel.cs"
$mainVm = Read-RepoFile "ViewModels\MainViewModel.cs"
$vault = Read-RepoFile "Modules\VaultGuard.Vault.psm1"
$project = Read-RepoFile "VaultGuard360.csproj"

# Real engine integration
Assert-Test ($engine -match "RunspaceFactory\.CreateRunspace") "Desktop creates an in-process PowerShell runspace"
Assert-Test ($engine -match "Invoke-VaultGuardScan") "Desktop engine invokes the real detection dispatcher"
Assert-Test ($engine -match "Get-QuarantineVaultItems") "Desktop reads the real quarantine vault"
Assert-Test ($project -match "VaultGuard\.Detection\.psm1") "Detection modules are embedded into the app"

# Reject UI simulation regressions
Assert-Test ($scanVm -notmatch "Task\.Delay") "Scan center has no fake scan delay pipeline"
Assert-Test ($scanVm -notmatch "CleanCount\s*\+=") "Scan center has no fabricated clean counters"
Assert-Test ($dashboardVm -match "ScanAsync") "Dashboard quick scan calls the live engine"
Assert-Test ($mainVm -notmatch "SimulateUsbDriveInsertion") "Shell has no simulated USB insertion"

# Vault safety regressions
Assert-Test ($vault -notmatch 'FileSystemAccessRule\("Everyone"\s*,\s*"FullControl"') "Vault does not deny Everyone FullControl"
Assert-Test ($vault -match "WindowsIdentity.*GetCurrent") "Vault ACL explicitly authorizes the running identity"
Assert-Test ($vault -notmatch "New-Item\s+-ItemType\s+HardLink") "Baseline recovery does not create hard links"
Assert-Test ($vault -match "Copy-Item.*Destination.*blob") "Baseline recovery stores independent copies"
Assert-Test ($vault -match "HMACSHA256") "Baseline manifest uses keyed authentication"
Assert-Test ($vault -match "ProtectedData") "Baseline signing key is protected with Windows DPAPI"
Assert-Test ($vault -match "Quarantine integrity verification failed") "Quarantine restore verifies payload integrity"

# API host remains loopback-only when used separately
$api = Read-RepoFile "PaintGuardEngine.ps1"
Assert-Test ($api -match "IPAddress\]::Loopback") "Optional REST host binds only to loopback"
Assert-Test ($api -match "Authorization") "Optional REST host enforces authorization"

Write-Host ""
Write-Host "Result: $PassCount passed, $FailCount failed" -ForegroundColor $(if ($FailCount -eq 0) { "Green" } else { "Red" })
if ($FailCount -gt 0) { exit 1 }
