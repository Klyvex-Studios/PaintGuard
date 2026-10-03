# ==============================================================================
# Module: VaultGuard.Vaccine.psm1
# Purpose: Conservative removable-media vaccination, AutoRun policy and USB watcher
# ==============================================================================

$script:PolicyStateDir = Join-Path $env:LOCALAPPDATA "Klyvex Studios\VaultGuard 360"
$script:PolicyStateFile = Join-Path $script:PolicyStateDir "autorun-policy-state.json"
$script:VaccineMarkerName = ".vaultguard-vaccine"

function Get-VaultGuardRemovableVolumes {
    @(Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 2 -and $_.DeviceID })
}

function Set-VaultGuardAutoRunPolicy {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)][bool]$Enabled,
        [switch]$DryRun
    )

    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if ($DryRun -or $WhatIfPreference) {
        return @{ Success = $true; Enabled = $Enabled; Message = "DryRun: Would set per-user AutoRun hardening to $Enabled." }
    }

    try {
        if ($Enabled) {
            if (-not (Test-Path -LiteralPath $script:PolicyStateFile)) {
                New-Item -ItemType Directory -Path $script:PolicyStateDir -Force | Out-Null
                $previousExists = $false
                $previousValue = $null
                try {
                    $property = Get-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -ErrorAction Stop
                    $previousExists = $true
                    $previousValue = [int]$property.NoDriveTypeAutoRun
                } catch {}

                [PSCustomObject]@{
                    PreviousExists = $previousExists
                    PreviousValue  = $previousValue
                    CapturedAt     = (Get-Date).ToString("o")
                } | ConvertTo-Json | Out-File -LiteralPath $script:PolicyStateFile -Encoding utf8 -Force
            }

            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord -Force
            return @{ Success = $true; Enabled = $true; Message = "Per-user AutoRun disabled for all drive types." }
        }

        if (Test-Path -LiteralPath $script:PolicyStateFile) {
            $state = Get-Content -LiteralPath $script:PolicyStateFile -Raw | ConvertFrom-Json
            if ($state.PreviousExists) {
                if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                Set-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -Value ([int]$state.PreviousValue) -Type DWord -Force
            } else {
                Remove-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
            }
            Remove-Item -LiteralPath $script:PolicyStateFile -Force -ErrorAction SilentlyContinue
        } else {
            # No VaultGuard state means we cannot safely assume ownership of an existing policy.
            $current = $null
            try { $current = (Get-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -ErrorAction Stop).NoDriveTypeAutoRun } catch {}
            if ($current -eq 255) {
                return @{ Success = $false; Enabled = $false; Message = "AutoRun policy is hardened but VaultGuard did not record the previous value; leaving it unchanged." }
            }
        }

        return @{ Success = $true; Enabled = $false; Message = "VaultGuard AutoRun policy change reverted." }
    } catch {
        return @{ Success = $false; Enabled = $Enabled; Message = "AutoRun policy update failed: $($_.Exception.Message)" }
    }
}

function Set-VaultGuardUsbVaccine {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [string]$DrivePath = "",
        [switch]$DryRun
    )

    $results = @()
    $volumes = @()
    if ($DrivePath) {
        $deviceId = $DrivePath.TrimEnd('\')
        $volumes = @(Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 2 -and $_.DeviceID -eq $deviceId })
    } else {
        $volumes = Get-VaultGuardRemovableVolumes
    }

    foreach ($volume in $volumes) {
        $root = "$($volume.DeviceID)\"
        $autorunDir = Join-Path $root "autorun.inf"
        $marker = Join-Path $autorunDir $script:VaccineMarkerName

        if ($DryRun -or $WhatIfPreference) {
            $results += [PSCustomObject]@{ Drive = $volume.DeviceID; Path = $autorunDir; Success = $true; Status = "DryRun" }
            continue
        }

        try {
            if (Test-Path -LiteralPath $autorunDir) {
                $existing = Get-Item -LiteralPath $autorunDir -Force
                if (-not $existing.PSIsContainer) {
                    $results += [PSCustomObject]@{ Drive = $volume.DeviceID; Path = $autorunDir; Success = $false; Status = "Existing autorun.inf file; vaccine did not overwrite it" }
                    continue
                }
                if (Test-Path -LiteralPath $marker) {
                    $results += [PSCustomObject]@{ Drive = $volume.DeviceID; Path = $autorunDir; Success = $true; Status = "Already vaccinated" }
                    continue
                }

                $results += [PSCustomObject]@{ Drive = $volume.DeviceID; Path = $autorunDir; Success = $false; Status = "Existing autorun.inf directory not owned by VaultGuard" }
                continue
            }

            New-Item -ItemType Directory -Path $autorunDir -Force -ErrorAction Stop | Out-Null
            "VaultGuard 360 removable-media vaccine marker. Do not execute." | Out-File -LiteralPath $marker -Encoding ascii -Force
            $item = Get-Item -LiteralPath $autorunDir -Force
            $item.Attributes = [System.IO.FileAttributes]::Directory -bor [System.IO.FileAttributes]::ReadOnly -bor [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System

            $results += [PSCustomObject]@{ Drive = $volume.DeviceID; Path = $autorunDir; Success = $true; Status = "Vaccinated" }
        } catch {
            $results += [PSCustomObject]@{ Drive = $volume.DeviceID; Path = $autorunDir; Success = $false; Status = $_.Exception.Message }
        }
    }

    return ,$results
}

function Remove-VaultGuardUsbVaccine {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [string]$DrivePath = "",
        [switch]$DryRun
    )

    $results = @()
    $volumes = if ($DrivePath) {
        $deviceId = $DrivePath.TrimEnd('\')
        @(Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 2 -and $_.DeviceID -eq $deviceId })
    } else {
        Get-VaultGuardRemovableVolumes
    }

    foreach ($volume in @($volumes)) {
        $autorunDir = "$($volume.DeviceID)\autorun.inf"
        $marker = Join-Path $autorunDir $script:VaccineMarkerName
        if (-not (Test-Path -LiteralPath $marker)) { continue }

        if ($DryRun -or $WhatIfPreference) {
            $results += [PSCustomObject]@{ Drive = $volume.DeviceID; Success = $true; Status = "DryRun" }
            continue
        }

        try {
            $item = Get-Item -LiteralPath $autorunDir -Force
            $item.Attributes = [System.IO.FileAttributes]::Directory
            Remove-Item -LiteralPath $autorunDir -Recurse -Force -ErrorAction Stop
            $results += [PSCustomObject]@{ Drive = $volume.DeviceID; Success = $true; Status = "Removed" }
        } catch {
            $results += [PSCustomObject]@{ Drive = $volume.DeviceID; Success = $false; Status = $_.Exception.Message }
        }
    }

    return ,$results
}

# Compatibility wrapper used by existing remediation/API code.
function Set-VaultGuardVaccine {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [switch]$HardenAutoRunPolicy,
        [switch]$VaccinateConnectedUSB,
        [switch]$DryRun
    )

    $results = @()
    if ($HardenAutoRunPolicy) {
        $results += [PSCustomObject](Set-VaultGuardAutoRunPolicy -Enabled $true -DryRun:$DryRun)
    }
    if ($VaccinateConnectedUSB) {
        $results += @(Set-VaultGuardUsbVaccine -DryRun:$DryRun)
    }
    return ,$results
}

function Remove-VaultGuardVaccine {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([switch]$DryRun)

    $results = @()
    $results += @(Remove-VaultGuardUsbVaccine -DryRun:$DryRun)
    $results += [PSCustomObject](Set-VaultGuardAutoRunPolicy -Enabled $false -DryRun:$DryRun)
    return ,$results
}

function Get-VaultGuardVaccineStatus {
    [CmdletBinding()]
    param()

    $driveStatuses = @()
    foreach ($volume in Get-VaultGuardRemovableVolumes) {
        $autorunDir = "$($volume.DeviceID)\autorun.inf"
        $marker = Join-Path $autorunDir $script:VaccineMarkerName
        $driveStatuses += [PSCustomObject]@{
            Drive        = $volume.DeviceID
            IsVaccinated = (Test-Path -LiteralPath $marker)
            Details      = if (Test-Path -LiteralPath $marker) { "VaultGuard marker present" } elseif (Test-Path -LiteralPath $autorunDir) { "autorun.inf already exists; not modified" } else { "Not vaccinated" }
        }
    }

    $autoRunLocked = $false
    try {
        $value = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction Stop).NoDriveTypeAutoRun
        $autoRunLocked = ($value -eq 255)
    } catch {}

    return @{
        FullyVaccinated     = ($driveStatuses.Count -eq 0 -or @($driveStatuses | Where-Object { -not $_.IsVaccinated }).Count -eq 0)
        AutoRunPolicyLocked = $autoRunLocked
        DriveStatuses       = $driveStatuses
    }
}

$script:UsbWatcher = $null

function Start-VaultGuardUsbWatcher {
    [CmdletBinding()]
    param()

    if ($script:UsbWatcher) { return @{ Success = $true; Message = "USB watcher is already running." } }

    try {
        $query = "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2"
        $script:UsbWatcher = Register-CimIndicationEvent -Query $query -SourceIdentifier "VaultGuard_USB_Arrival" -Action {
            $drive = $Event.SourceEventArgs.NewEvent.DriveName
            if ($drive) { Set-VaultGuardUsbVaccine -DrivePath $drive | Out-Null }
        }
        return @{ Success = $true; Message = "USB arrival watcher started."; SourceId = "VaultGuard_USB_Arrival" }
    } catch {
        return @{ Success = $false; Message = "USB watcher failed to start: $($_.Exception.Message)" }
    }
}

function Stop-VaultGuardUsbWatcher {
    [CmdletBinding()]
    param()

    try {
        Unregister-Event -SourceIdentifier "VaultGuard_USB_Arrival" -ErrorAction SilentlyContinue
        Get-Job -Name "VaultGuard_USB_Arrival" -ErrorAction SilentlyContinue | Remove-Job -Force -ErrorAction SilentlyContinue
        $script:UsbWatcher = $null
        return @{ Success = $true; Message = "USB watcher stopped." }
    } catch {
        return @{ Success = $false; Message = "USB watcher stop failed: $($_.Exception.Message)" }
    }
}

Export-ModuleMember -Function Set-VaultGuardAutoRunPolicy, Set-VaultGuardUsbVaccine, Remove-VaultGuardUsbVaccine, Set-VaultGuardVaccine, Remove-VaultGuardVaccine, Get-VaultGuardVaccineStatus, Start-VaultGuardUsbWatcher, Stop-VaultGuardUsbWatcher
