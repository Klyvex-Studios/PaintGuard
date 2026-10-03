# ==============================================================================
# Module: VaultGuard.ShortcutWorm.psm1
# Purpose: Conservative detector/remediator for shortcut-worm families
# ==============================================================================

Import-Module (Join-Path $PSScriptRoot "VaultGuard.Vault.psm1") -ErrorAction SilentlyContinue

$script:SystemDirWhitelist = @(
    "System Volume Information",
    '$RECYCLE.BIN',
    "System Recovery",
    "Recovery",
    "MSOCache",
    "Config.Msi"
)

function Get-ShortcutWormSignature {
    return @{
        Family      = "Shortcut Worm"
        Aliases     = @("Worm:Win32/Vobfus", "Win32/Dorkbot", "Win32/Gamarue", "1KB Shortcut Worm")
        Description = "Removable-drive worm patterns involving malicious shortcuts, hidden folders and icon hijacking."
        Severity    = "HIGH"
    }
}

function Test-ShortcutWormThreat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [switch]$DeepPass
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return @{ Verdict = "Clean"; ConfidenceScore = 0; Indicators = @() }
    }

    $targetDir = Get-Item -LiteralPath $Path -Force
    if (-not $targetDir.PSIsContainer) {
        return @{ Verdict = "Clean"; ConfidenceScore = 0; Indicators = @() }
    }

    $indicators = @()
    $confidence = 0
    $suspiciousLnkFiles = @()

    # A desktop.ini icon reference alone is weak evidence; keep the weight low.
    $desktopIni = Join-Path $targetDir.FullName "desktop.ini"
    if (Test-Path -LiteralPath $desktopIni) {
        try {
            $iniContent = Get-Content -LiteralPath $desktopIni -Raw -ErrorAction Stop
            if ($iniContent -match "(?i)SHELL32\.dll,7") {
                $indicators += "desktop.ini contains the shortcut-worm icon-swap pattern"
                $confidence += 20
            }
        } catch {}
    }

    # Inspect each shortcut and retain ONLY shortcuts with suspicious execution targets.
    foreach ($lnk in Get-ChildItem -LiteralPath $targetDir.FullName -Filter "*.lnk" -File -ErrorAction SilentlyContinue) {
        try {
            $wshShell = New-Object -ComObject WScript.Shell
            $shortcut = $wshShell.CreateShortcut($lnk.FullName)
            $target = [string]$shortcut.TargetPath
            $arguments = [string]$shortcut.Arguments

            $interpreterTarget = $target -match "(?i)(cmd\.exe|wscript\.exe|cscript\.exe|powershell\.exe|pwsh\.exe)$"
            $scriptPayload = $arguments -match "(?i)\.(vbs|vbe|js|jse|wsf|bat|cmd|ps1)(\s|$|\")"
            $hiddenExecution = $arguments -match "(?i)(-windowstyle\s+hidden|//b|/c\s+start\s+/min)"

            if (($interpreterTarget -and $scriptPayload) -or ($interpreterTarget -and $hiddenExecution)) {
                $suspiciousLnkFiles += $lnk
            }
        } catch {}
    }

    if ($suspiciousLnkFiles.Count -gt 0) {
        $indicators += "Detected $($suspiciousLnkFiles.Count) shortcut(s) launching script interpreters with suspicious payload arguments"
        $confidence += [Math]::Min(55, 35 + (($suspiciousLnkFiles.Count - 1) * 10))
    }

    $hiddenSubdirs = @(Get-ChildItem -LiteralPath $targetDir.FullName -Directory -Force -ErrorAction SilentlyContinue | Where-Object {
        $_.Attributes -match "Hidden" -and ($script:SystemDirWhitelist -notcontains $_.Name)
    })

    if ($hiddenSubdirs.Count -gt 0) {
        $indicators += "Found $($hiddenSubdirs.Count) hidden non-system directorie(s)"
        $confidence += [Math]::Min(25, 10 + ($hiddenSubdirs.Count * 5))
    }

    # Require corroborating behavior for an automatic infected verdict.
    $verdict = "Clean"
    if ($suspiciousLnkFiles.Count -gt 0 -and $confidence -ge 70) {
        $verdict = "Infected"
    } elseif ($confidence -ge 35) {
        $verdict = "Suspicious"
    }

    return @{
        Family          = "Shortcut Worm"
        Verdict         = $verdict
        ConfidenceScore = $confidence
        Indicators      = $indicators
        TargetDir       = $targetDir.FullName
        SuspiciousLnks  = $suspiciousLnkFiles
        HiddenDirs      = $hiddenSubdirs
    }
}

function Invoke-ShortcutWormRemediation {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)][object]$Threat,
        [switch]$DryRun
    )

    if ($Threat.Verdict -ne "Infected") {
        return @{ Success = $false; Family = "Shortcut Worm"; Actions = @(); Message = "Automatic remediation blocked for non-infected verdict." }
    }

    $actions = @()
    if ($DryRun -or $WhatIfPreference) {
        return @{
            Success = $true
            Message = "DryRun: Would remediate confirmed Shortcut Worm artifacts."
            Actions = @("Would quarantine $(@($Threat.SuspiciousLnks).Count) confirmed malicious shortcut(s)", "Would restore hidden user directories")
        }
    }

    foreach ($lnk in @($Threat.SuspiciousLnks)) {
        try {
            $result = Protect-FileToQuarantine -FilePath $lnk.FullName -Reason "Confirmed Shortcut Worm .lnk trap"
            if ($result.Success) { $actions += "Quarantined malicious shortcut: $($lnk.Name)" }
        } catch {}
    }

    foreach ($dir in @($Threat.HiddenDirs)) {
        try {
            $dir.Attributes = ($dir.Attributes -band (-bnot [System.IO.FileAttributes]::Hidden) -band (-bnot [System.IO.FileAttributes]::System))
            $actions += "Restored directory visibility: $($dir.Name)"
        } catch {}
    }

    # Remove desktop.ini only when it contained the exact corroborating icon-swap pattern.
    $desktopIni = Join-Path $Threat.TargetDir "desktop.ini"
    if (Test-Path -LiteralPath $desktopIni) {
        try {
            $content = Get-Content -LiteralPath $desktopIni -Raw -ErrorAction Stop
            if ($content -match "(?i)SHELL32\.dll,7") {
                Protect-FileToQuarantine -FilePath $desktopIni -Reason "Shortcut Worm icon hijack" | Out-Null
                $actions += "Quarantined shortcut-worm desktop.ini icon hijack"
            }
        } catch {}
    }

    return @{ Success = $true; Family = "Shortcut Worm"; Actions = $actions }
}

Export-ModuleMember -Function Get-ShortcutWormSignature, Test-ShortcutWormThreat, Invoke-ShortcutWormRemediation
