# ==============================================================================
# Module: VaultGuard.Persistence.psm1
# Purpose: Conservative persistence audit and confirmed-family remediation
# ==============================================================================

Import-Module (Join-Path $PSScriptRoot "VaultGuard.Vault.psm1") -ErrorAction SilentlyContinue

function Test-VaultGuardKnownPaintPath {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }

    $knownPaths = @(
        "C:\paint.exe",
        (Join-Path $env:APPDATA "paint.exe")
    )
    foreach ($path in $knownPaths) {
        if ($Value.IndexOf($path, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}

function New-VaultGuardPersistenceFinding {
    param(
        [string]$Location,
        [string]$Name,
        [string]$Value,
        [string]$Type,
        [string]$Verdict,
        [string]$Reason
    )

    [PSCustomObject]@{
        Location = $Location
        Name     = $Name
        Value    = $Value
        Type     = $Type
        Verdict  = $Verdict
        Severity = if ($Verdict -eq "Infected") { "HIGH" } else { "REVIEW" }
        Reason   = $Reason
    }
}

function Get-VaultGuardPersistenceAudit {
    [CmdletBinding()]
    param()

    $findings = @()
    $regPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($regPath in $regPaths) {
        if (-not (Test-Path $regPath)) { continue }
        try {
            $props = Get-ItemProperty -Path $regPath -ErrorAction Stop
            foreach ($property in $props.PSObject.Properties) {
                if ($property.Name -match '^PS') { continue }
                $value = [string]$property.Value

                if (Test-VaultGuardKnownPaintPath -Value $value) {
                    $findings += New-VaultGuardPersistenceFinding -Location $regPath -Name $property.Name -Value $value -Type "Registry Run Hook" -Verdict "Infected" -Reason "Run entry references a known Paint/Geacata persistence path"
                } elseif ($value -match '(?i)(wscript|cscript|powershell|pwsh)\.exe.+\.(vbs|vbe|js|jse|wsf|ps1)') {
                    $findings += New-VaultGuardPersistenceFinding -Location $regPath -Name $property.Name -Value $value -Type "Registry Run Hook" -Verdict "Suspicious" -Reason "Script-interpreter persistence requires manual review"
                }
            }
        } catch {}
    }

    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\StartUp"
    )

    foreach ($startupPath in $startupPaths) {
        if (-not (Test-Path -LiteralPath $startupPath)) { continue }
        foreach ($lnk in Get-ChildItem -LiteralPath $startupPath -Filter "*.lnk" -File -ErrorAction SilentlyContinue) {
            try {
                $shell = New-Object -ComObject WScript.Shell
                $shortcut = $shell.CreateShortcut($lnk.FullName)
                $target = [string]$shortcut.TargetPath
                $args = [string]$shortcut.Arguments

                if (Test-VaultGuardKnownPaintPath -Value $target) {
                    $findings += New-VaultGuardPersistenceFinding -Location $startupPath -Name $lnk.Name -Value $lnk.FullName -Type "Startup Shortcut" -Verdict "Infected" -Reason "Startup shortcut points to a known Paint/Geacata persistence path"
                } elseif ($target -match '(?i)(wscript|cscript|powershell|pwsh)\.exe$' -and $args -match '(?i)\.(vbs|vbe|js|jse|wsf|ps1)') {
                    $findings += New-VaultGuardPersistenceFinding -Location $startupPath -Name $lnk.Name -Value $lnk.FullName -Type "Startup Shortcut" -Verdict "Suspicious" -Reason "Script-based startup shortcut requires manual review"
                }
            } catch {}
        }
    }

    try {
        foreach ($task in Get-ScheduledTask -ErrorAction Stop) {
            foreach ($action in @($task.Actions)) {
                $command = "$($action.Execute) $($action.Arguments)"
                if (Test-VaultGuardKnownPaintPath -Value $command) {
                    $findings += New-VaultGuardPersistenceFinding -Location $task.TaskPath -Name $task.TaskName -Value $command -Type "Scheduled Task" -Verdict "Infected" -Reason "Scheduled task references a known Paint/Geacata persistence path"
                } elseif ($command -match '(?i)(wscript|cscript|powershell|pwsh).+\.(vbs|vbe|js|jse|wsf|ps1)') {
                    $findings += New-VaultGuardPersistenceFinding -Location $task.TaskPath -Name $task.TaskName -Value $command -Type "Scheduled Task" -Verdict "Suspicious" -Reason "Script-based scheduled task requires manual review"
                }
            }
        }
    } catch {}

    # WMI subscriptions are high-impact to delete incorrectly. Surface them for review,
    # but do not automatically remove them in this release.
    try {
        foreach ($consumer in Get-CimInstance -Namespace "root\subscription" -ClassName "CommandLineEventConsumer" -ErrorAction Stop) {
            $command = [string]$consumer.CommandLineTemplate
            if ((Test-VaultGuardKnownPaintPath -Value $command) -or $command -match '(?i)(wscript|cscript|powershell|pwsh).+\.(vbs|vbe|js|jse|wsf|ps1)') {
                $findings += New-VaultGuardPersistenceFinding -Location "WMI Subscription" -Name $consumer.Name -Value $command -Type "WMI Hook" -Verdict "Suspicious" -Reason "Persistent WMI command requires manual review; automatic deletion is disabled"
            }
        }
    } catch {}

    $confirmed = @($findings | Where-Object { $_.Verdict -eq "Infected" })
    $review = @($findings | Where-Object { $_.Verdict -eq "Suspicious" })
    return @{
        ThreatsFound = $confirmed.Count
        ReviewCount  = $review.Count
        Findings     = $findings
    }
}

function Repair-VaultGuardPersistence {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([switch]$DryRun)

    $audit = Get-VaultGuardPersistenceAudit
    $confirmed = @($audit.Findings | Where-Object { $_.Verdict -eq "Infected" })
    $actions = @()
    $failures = @()
    $remediated = 0

    if ($DryRun -or $WhatIfPreference) {
        return @{
            Success         = $true
            RemediatedCount = $confirmed.Count
            ReviewCount     = $audit.ReviewCount
            Message         = "DryRun: Would repair $($confirmed.Count) confirmed persistence hook(s); $($audit.ReviewCount) item(s) remain review-only."
            Actions         = $confirmed | ForEach-Object { "Would remove confirmed $($_.Type): $($_.Name) at $($_.Location)" }
            Failures        = @()
        }
    }

    foreach ($finding in $confirmed) {
        try {
            if ($finding.Type -eq "Registry Run Hook") {
                Remove-ItemProperty -Path $finding.Location -Name $finding.Name -Force -ErrorAction Stop
                $actions += "Removed confirmed Registry Run hook: $($finding.Name)"
                $remediated++
            } elseif ($finding.Type -eq "Startup Shortcut") {
                $q = Protect-FileToQuarantine -FilePath $finding.Value -Reason "Confirmed malicious startup shortcut"
                if (-not $q.Success) { throw $q.Message }
                $actions += "Quarantined confirmed malicious startup shortcut: $($finding.Name)"
                $remediated++
            } elseif ($finding.Type -eq "Scheduled Task") {
                Unregister-ScheduledTask -TaskName $finding.Name -TaskPath $finding.Location -Confirm:$false -ErrorAction Stop
                $actions += "Removed confirmed malicious scheduled task: $($finding.Location)$($finding.Name)"
                $remediated++
            }
        } catch {
            $failures += "Failed to repair $($finding.Type) '$($finding.Name)': $($_.Exception.Message)"
        }
    }

    return @{
        Success         = ($failures.Count -eq 0)
        RemediatedCount = $remediated
        ReviewCount     = $audit.ReviewCount
        Actions         = $actions
        Failures        = $failures
        Message         = if ($failures.Count -eq 0) { "Persistence remediation completed." } else { "Persistence remediation completed with failures." }
    }
}

Export-ModuleMember -Function Get-VaultGuardPersistenceAudit, Repair-VaultGuardPersistence
