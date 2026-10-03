# ==============================================================================
# Module: VaultGuard.Vault.psm1
# Purpose: Clean baseline vault, quarantine, recovery and self-protection
# ==============================================================================

$script:VaultRoot = "C:\ProgramData\VaultGuard"
try {
    if (-not (Test-Path $script:VaultRoot)) {
        New-Item -ItemType Directory -Path $script:VaultRoot -Force -ErrorAction Stop | Out-Null
    }
} catch {
    $script:VaultRoot = Join-Path $env:LOCALAPPDATA "VaultGuard"
    if (-not (Test-Path $script:VaultRoot)) {
        New-Item -ItemType Directory -Path $script:VaultRoot -Force | Out-Null
    }
}

$script:BaselinePath = Join-Path $script:VaultRoot "Baseline"
$script:QuarantinePath = Join-Path $script:VaultRoot "Quarantine"
$script:GoldenPath = Join-Path $script:VaultRoot "GoldenVault"

function Initialize-VaultGuardProtection {
    [CmdletBinding()]
    param()

    $CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $Dirs = @($script:VaultRoot, $script:BaselinePath, $script:QuarantinePath, $script:GoldenPath)

    foreach ($Dir in $Dirs) {
        if (-not (Test-Path $Dir)) {
            try { New-Item -ItemType Directory -Path $Dir -Force -ErrorAction Stop | Out-Null } catch {}
        }

        if (Test-Path $Dir) {
            try {
                $Acl = Get-Acl -Path $Dir
                # Remove inherited write paths instead of using an Everyone:Deny ACE.
                # Explicit Deny entries can also deny Administrators/SYSTEM and previously
                # caused VaultGuard to lock itself out of its own storage.
                $Acl.SetAccessRuleProtection($true, $false)

                foreach ($Rule in @($Acl.Access)) {
                    [void]$Acl.RemoveAccessRuleAll($Rule)
                }

                $SystemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
                $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
                $UserRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $CurrentIdentity, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")

                $Acl.AddAccessRule($SystemRule)
                $Acl.AddAccessRule($AdminRule)
                $Acl.AddAccessRule($UserRule)
                Set-Acl -Path $Dir -AclObject $Acl -ErrorAction Stop
            } catch {
                Write-Verbose "Vault ACL hardening warning for $Dir : $($_.Exception.Message)"
            }
        }
    }
}

function Get-VaultGuardSigningKey {
    $KeyFile = Join-Path $script:BaselinePath "vault.key"
    if (Test-Path $KeyFile) {
        try {
            $Protected = [Convert]::FromBase64String((Get-Content $KeyFile -Raw).Trim())
            return [System.Security.Cryptography.ProtectedData]::Unprotect(
                $Protected, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        } catch {
            throw "Unable to unlock VaultGuard baseline signing key."
        }
    }

    $Key = New-Object byte[] 32
    $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $Rng.GetBytes($Key)
    $Rng.Dispose()
    $ProtectedKey = [System.Security.Cryptography.ProtectedData]::Protect(
        $Key, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [Convert]::ToBase64String($ProtectedKey) | Out-File -FilePath $KeyFile -Encoding ascii -Force
    return $Key
}

function Get-VaultGuardManifestSignature {
    param([Parameter(Mandatory=$true)][string]$ManifestFile)
    $Key = Get-VaultGuardSigningKey
    $Bytes = [System.IO.File]::ReadAllBytes($ManifestFile)
    $Hmac = New-Object System.Security.Cryptography.HMACSHA256
    $Hmac.Key = $Key
    try {
        return ([Convert]::ToHexString($Hmac.ComputeHash($Bytes)))
    } finally {
        $Hmac.Dispose()
    }
}

Initialize-VaultGuardProtection

function Get-VaultPaths {
    return @{
        Root       = $script:VaultRoot
        Baseline   = $script:BaselinePath
        Quarantine = $script:QuarantinePath
        Golden     = $script:GoldenPath
    }
}

# ------------------------------------------------------------------------------
# 1. Quarantine Vault
# ------------------------------------------------------------------------------

function Protect-FileToQuarantine {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [string]$Reason = "Threat Remediation",
        [switch]$DryRun
    )

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        return @{ Success = $false; Message = "File does not exist: $FilePath" }
    }

    $Guid = [Guid]::NewGuid().ToString()
    $BinPath = Join-Path $script:QuarantinePath "$Guid.bin"
    $JsonPath = Join-Path $script:QuarantinePath "$Guid.json"
    $Item = Get-Item -LiteralPath $FilePath -Force
    $Hash = ""
    try { $Hash = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash } catch {}

    $Metadata = [PSCustomObject]@{
        Id            = $Guid
        OriginalPath  = $Item.FullName
        OriginalName  = $Item.Name
        QuarantinedAt = (Get-Date).ToString("o")
        SHA256        = $Hash
        FileSize      = $Item.Length
        Attributes    = $Item.Attributes.ToString()
        Reason        = $Reason
    }

    if ($DryRun -or $WhatIfPreference) {
        return @{ Success = $true; QuarantineId = $Guid; OriginalPath = $FilePath; Message = "DryRun: Would quarantine file to $BinPath" }
    }

    if ($PSCmdlet.ShouldProcess($FilePath, "Move to Quarantine Vault ($Guid)")) {
        try {
            Move-Item -LiteralPath $FilePath -Destination $BinPath -Force -ErrorAction Stop
            $Metadata | ConvertTo-Json -Depth 3 | Out-File -FilePath $JsonPath -Encoding utf8 -Force
            return @{ Success = $true; QuarantineId = $Guid; OriginalPath = $FilePath }
        } catch {
            if (Test-Path $BinPath -and -not (Test-Path $FilePath)) {
                try { Move-Item -LiteralPath $BinPath -Destination $FilePath -Force -ErrorAction SilentlyContinue } catch {}
            }
            return @{ Success = $false; Message = "Quarantine operation failed: $($_.Exception.Message)" }
        }
    }
    return @{ Success = $true; QuarantineId = $Guid; Message = "WhatIf: Skipping file move." }
}

function Get-QuarantineVaultItems {
    [CmdletBinding()]
    param()

    $Items = @()
    $JsonFiles = Get-ChildItem -LiteralPath $script:QuarantinePath -Filter "*.json" -ErrorAction SilentlyContinue
    foreach ($JsonFile in $JsonFiles) {
        try {
            $Content = Get-Content -LiteralPath $JsonFile.FullName -Raw | ConvertFrom-Json
            $BinPath = Join-Path $script:QuarantinePath "$($Content.Id).bin"
            $Content | Add-Member -NotePropertyName "PayloadExists" -NotePropertyValue (Test-Path $BinPath) -Force
            $Items += $Content
        } catch {}
    }
    return ,$Items
}

function Restore-QuarantinedItem {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)][string]$QuarantineId,
        [switch]$DryRun
    )

    if ($QuarantineId -notmatch '^[0-9a-fA-F-]{36}$') {
        return @{ Success = $false; Message = "Invalid quarantine identifier." }
    }

    $BinPath = Join-Path $script:QuarantinePath "$QuarantineId.bin"
    $JsonPath = Join-Path $script:QuarantinePath "$QuarantineId.json"
    if (-not (Test-Path -LiteralPath $JsonPath) -or -not (Test-Path -LiteralPath $BinPath)) {
        return @{ Success = $false; Message = "Quarantine payload or metadata record not found." }
    }

    $Meta = Get-Content -LiteralPath $JsonPath -Raw | ConvertFrom-Json
    try {
        $CurrentHash = (Get-FileHash -LiteralPath $BinPath -Algorithm SHA256).Hash
        if ($Meta.SHA256 -and $CurrentHash -ne $Meta.SHA256) {
            return @{ Success = $false; Message = "Quarantine integrity check failed. Restore blocked." }
        }
    } catch {
        return @{ Success = $false; Message = "Unable to verify quarantine payload integrity." }
    }

    $TargetFolder = Split-Path -Path $Meta.OriginalPath -Parent
    if ($DryRun -or $WhatIfPreference) {
        return @{ Success = $true; RestoredPath = $Meta.OriginalPath; Message = "DryRun: Would restore quarantined item." }
    }

    if ($PSCmdlet.ShouldProcess($Meta.OriginalPath, "Restore Quarantined File from Vault")) {
        try {
            if (-not (Test-Path -LiteralPath $TargetFolder)) {
                New-Item -ItemType Directory -Path $TargetFolder -Force | Out-Null
            }
            if (Test-Path -LiteralPath $Meta.OriginalPath) {
                return @{ Success = $false; Message = "Restore blocked because a file already exists at the original path." }
            }
            Move-Item -LiteralPath $BinPath -Destination $Meta.OriginalPath -Force -ErrorAction Stop
            try { (Get-Item -LiteralPath $Meta.OriginalPath -Force).Attributes = $Meta.Attributes } catch {}
            Remove-Item -LiteralPath $JsonPath -Force -ErrorAction SilentlyContinue
            return @{ Success = $true; RestoredPath = $Meta.OriginalPath }
        } catch {
            return @{ Success = $false; Message = "Failed to restore file: $($_.Exception.Message)" }
        }
    }
    return @{ Success = $true; Message = "WhatIf: Skipping restore." }
}

function Remove-QuarantinedItem {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)][string]$QuarantineId,
        [switch]$DryRun
    )

    if ($QuarantineId -notmatch '^[0-9a-fA-F-]{36}$') {
        return @{ Success = $false; Message = "Invalid quarantine identifier." }
    }

    $BinPath = Join-Path $script:QuarantinePath "$QuarantineId.bin"
    $JsonPath = Join-Path $script:QuarantinePath "$QuarantineId.json"
    if ($DryRun -or $WhatIfPreference) {
        return @{ Success = $true; Id = $QuarantineId; Message = "DryRun: Would purge quarantined item." }
    }

    if ($PSCmdlet.ShouldProcess($QuarantineId, "Permanently Purge from Quarantine Vault")) {
        try {
            if (Test-Path -LiteralPath $BinPath) { Remove-Item -LiteralPath $BinPath -Force -ErrorAction Stop }
            if (Test-Path -LiteralPath $JsonPath) { Remove-Item -LiteralPath $JsonPath -Force -ErrorAction Stop }
            return @{ Success = $true; Id = $QuarantineId }
        } catch {
            return @{ Success = $false; Message = "Purge failed: $($_.Exception.Message)" }
        }
    }
    return @{ Success = $true; Message = "WhatIf: Skipping purge." }
}

# ------------------------------------------------------------------------------
# 2. Clean-File Baseline Vault
# ------------------------------------------------------------------------------

function New-VaultGuardBaseline {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [string[]]$TargetPaths = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "C:\Program Files"),
        [switch]$HardlinkMode,
        [switch]$DryRun
    )

    if ($HardlinkMode) {
        Write-Warning "HardlinkMode is deprecated and ignored. Recovery blobs must be independent copies."
    }

    $BlobsDir = Join-Path $script:BaselinePath "blobs"
    if (-not (Test-Path $BlobsDir)) { New-Item -ItemType Directory -Path $BlobsDir -Force | Out-Null }

    $ManifestFile = Join-Path $script:BaselinePath "manifest.json"
    $SigFile = Join-Path $script:BaselinePath "vault.sig"
    $Entries = @()
    $Captured = 0
    $Skipped = 0

    foreach ($TargetPath in $TargetPaths) {
        if (-not (Test-Path -LiteralPath $TargetPath)) { continue }
        $Exes = Get-ChildItem -LiteralPath $TargetPath -Filter "*.exe" -Recurse -File -ErrorAction SilentlyContinue

        foreach ($Exe in $Exes) {
            # These are family-specific suspicion indicators. Never seed them into a clean baseline automatically.
            if ($Exe.Length -eq 844288 -or $Exe.Name -match "^(v|gvg|vvg).+\.exe$") { $Skipped++; continue }

            try {
                $Hash = (Get-FileHash -LiteralPath $Exe.FullName -Algorithm SHA256).Hash
                $BlobPath = Join-Path $BlobsDir "$Hash.exe"

                if (-not ($DryRun -or $WhatIfPreference) -and -not (Test-Path -LiteralPath $BlobPath)) {
                    Copy-Item -LiteralPath $Exe.FullName -Destination $BlobPath -Force -ErrorAction Stop
                    $CopiedHash = (Get-FileHash -LiteralPath $BlobPath -Algorithm SHA256).Hash
                    if ($CopiedHash -ne $Hash) {
                        Remove-Item -LiteralPath $BlobPath -Force -ErrorAction SilentlyContinue
                        throw "Baseline copy hash mismatch."
                    }
                }

                $Entries += [PSCustomObject]@{
                    OriginalPath = $Exe.FullName
                    FileName     = $Exe.Name
                    SHA256       = $Hash
                    FileSize     = $Exe.Length
                    LastWrite    = $Exe.LastWriteTime.ToString("o")
                    Attributes   = $Exe.Attributes.ToString()
                }
                $Captured++
            } catch {
                $Skipped++
            }
        }
    }

    if (-not ($DryRun -or $WhatIfPreference)) {
        $Entries | ConvertTo-Json -Depth 4 | Out-File -FilePath $ManifestFile -Encoding utf8 -Force
        $Signature = Get-VaultGuardManifestSignature -ManifestFile $ManifestFile
        $Signature | Out-File -FilePath $SigFile -Encoding ascii -Force
    }

    return @{ Success = $true; TotalCaptured = $Captured; TotalSkipped = $Skipped; VaultPath = $script:BaselinePath }
}

function Test-VaultGuardIntegrity {
    [CmdletBinding()]
    param()

    $ManifestFile = Join-Path $script:BaselinePath "manifest.json"
    $SigFile = Join-Path $script:BaselinePath "vault.sig"
    if (-not (Test-Path $ManifestFile) -or -not (Test-Path $SigFile)) {
        return @{ Success = $false; Message = "Baseline manifest/signature missing. Capture baseline first." }
    }

    try {
        $CurrentSig = Get-VaultGuardManifestSignature -ManifestFile $ManifestFile
        $ExpectedSig = (Get-Content -LiteralPath $SigFile -Raw).Trim()
        if ($CurrentSig -ne $ExpectedSig) {
            return @{ Success = $false; Message = "Baseline authentication failed. Manifest may have been tampered with." }
        }
    } catch {
        return @{ Success = $false; Message = "Baseline authentication could not be verified: $($_.Exception.Message)" }
    }

    $Entries = @(Get-Content -LiteralPath $ManifestFile -Raw | ConvertFrom-Json)
    $Triage = @()
    $Compromised = 0

    foreach ($Entry in $Entries) {
        $DiskPath = $Entry.OriginalPath
        $Status = "CLEAN"
        $CurrentHash = "MISSING"
        if (Test-Path -LiteralPath $DiskPath) {
            try {
                $CurrentHash = (Get-FileHash -LiteralPath $DiskPath -Algorithm SHA256).Hash
                if ($CurrentHash -ne $Entry.SHA256) {
                    $Item = Get-Item -LiteralPath $DiskPath -Force
                    $Status = if ($Item.Length -eq 844288) { "PAINT_INFECTED_PAYLOAD" } else { "MODIFIED" }
                    $Compromised++
                }
            } catch {
                $Status = "UNREADABLE"
                $Compromised++
            }
        } else {
            $Status = "DELETED_OR_RENAMED"
            $Compromised++
        }

        $Triage += [PSCustomObject]@{
            OriginalPath = $DiskPath
            BaselineHash = $Entry.SHA256
            CurrentHash  = $CurrentHash
            Status       = $Status
        }
    }

    return @{ Success = $true; TotalMonitored = $Entries.Count; CompromisedCount = $Compromised; Triage = $Triage }
}

function Restore-FileFromVault {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)][string]$OriginalPath,
        [switch]$DryRun
    )

    $Integrity = Test-VaultGuardIntegrity
    if (-not $Integrity.Success) {
        return @{ Success = $false; Level = "Blocked"; Message = $Integrity.Message }
    }

    $ManifestFile = Join-Path $script:BaselinePath "manifest.json"
    $Entries = @(Get-Content -LiteralPath $ManifestFile -Raw | ConvertFrom-Json)
    $TargetEntry = $Entries | Where-Object { $_.OriginalPath -eq $OriginalPath } | Select-Object -First 1
    if (-not $TargetEntry) {
        return @{ Success = $false; Level = "Unrecoverable"; Message = "File not present in clean baseline manifest." }
    }

    $ParentDir = Split-Path -Path $OriginalPath -Parent
    $FileName = Split-Path -Path $OriginalPath -Leaf
    $HiddenTwinPath = Join-Path $ParentDir "v$FileName"

    if (Test-Path -LiteralPath $HiddenTwinPath) {
        try {
            $TwinHash = (Get-FileHash -LiteralPath $HiddenTwinPath -Algorithm SHA256).Hash
            if ($TwinHash -eq $TargetEntry.SHA256) {
                if ($DryRun -or $WhatIfPreference) {
                    return @{ Success = $true; Level = "Level-1-Twin-Repair"; RestoredPath = $OriginalPath; Message = "DryRun: Would restore verified twin." }
                }
                if (Test-Path -LiteralPath $OriginalPath) {
                    $Q = Protect-FileToQuarantine -FilePath $OriginalPath -Reason "Replaced during twin restoration"
                    if (-not $Q.Success) { throw $Q.Message }
                }
                (Get-Item -LiteralPath $HiddenTwinPath -Force).Attributes = "Normal"
                Rename-Item -LiteralPath $HiddenTwinPath -NewName $FileName -Force -ErrorAction Stop
                return @{ Success = $true; Level = "Level-1-Twin-Repair"; RestoredPath = $OriginalPath }
            }
        } catch {}
    }

    $BlobPath = Join-Path $script:BaselinePath "blobs\$($TargetEntry.SHA256).exe"
    if (Test-Path -LiteralPath $BlobPath) {
        try {
            $BlobHash = (Get-FileHash -LiteralPath $BlobPath -Algorithm SHA256).Hash
            if ($BlobHash -ne $TargetEntry.SHA256) {
                return @{ Success = $false; Level = "Blocked"; Message = "Recovery blob integrity check failed." }
            }

            if ($DryRun -or $WhatIfPreference) {
                return @{ Success = $true; Level = "Level-2-Vault-Blob"; RestoredPath = $OriginalPath; Message = "DryRun: Would restore verified baseline blob." }
            }

            if (Test-Path -LiteralPath $OriginalPath) {
                $Q = Protect-FileToQuarantine -FilePath $OriginalPath -Reason "Replaced during Vault restoration"
                if (-not $Q.Success) { throw $Q.Message }
            }
            Copy-Item -LiteralPath $BlobPath -Destination $OriginalPath -Force -ErrorAction Stop
            $RestoredHash = (Get-FileHash -LiteralPath $OriginalPath -Algorithm SHA256).Hash
            if ($RestoredHash -ne $TargetEntry.SHA256) { throw "Restored file hash mismatch." }
            return @{ Success = $true; Level = "Level-2-Vault-Blob"; RestoredPath = $OriginalPath }
        } catch {
            return @{ Success = $false; Level = "Failed"; Message = "Blob restore failed: $($_.Exception.Message)" }
        }
    }

    return @{ Success = $false; Level = "Level-4-Unrecoverable"; Message = "Clean binary blob missing from Vault. Reinstall required." }
}

# ------------------------------------------------------------------------------
# 3. Off-box baseline backup/import
# ------------------------------------------------------------------------------

function Export-VaultGuardBaseline {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)][string]$DestinationPath,
        [switch]$DryRun
    )

    if ($DryRun -or $WhatIfPreference) {
        return @{ Success = $true; ExportLocation = $DestinationPath; Message = "DryRun: Would export Vault to $DestinationPath" }
    }
    if (-not (Test-Path -LiteralPath $DestinationPath)) {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    }

    try {
        Copy-Item -Path "$script:BaselinePath\*" -Destination $DestinationPath -Recurse -Force -ErrorAction Stop
        return @{ Success = $true; ExportLocation = $DestinationPath }
    } catch {
        return @{ Success = $false; Message = "Vault export failed: $($_.Exception.Message)" }
    }
}

function Import-VaultGuardBaseline {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)][string]$SourceVaultPath,
        [switch]$DryRun
    )

    if (-not (Test-Path -LiteralPath $SourceVaultPath)) {
        return @{ Success = $false; Message = "Source vault path not found: $SourceVaultPath" }
    }
    if ($DryRun -or $WhatIfPreference) {
        return @{ Success = $true; Message = "DryRun: Would import vault from $SourceVaultPath" }
    }

    try {
        Copy-Item -Path "$SourceVaultPath\*" -Destination $script:BaselinePath -Recurse -Force -ErrorAction Stop
        $Integrity = Test-VaultGuardIntegrity
        if (-not $Integrity.Success) {
            return @{ Success = $false; Message = "Imported baseline failed authentication: $($Integrity.Message)" }
        }
        return @{ Success = $true; Message = "Baseline vault imported and authenticated successfully." }
    } catch {
        return @{ Success = $false; Message = "Vault import failed: $($_.Exception.Message)" }
    }
}

Export-ModuleMember -Function Initialize-VaultGuardProtection, Get-VaultPaths, Protect-FileToQuarantine, Get-QuarantineVaultItems, Restore-QuarantinedItem, Remove-QuarantinedItem, New-VaultGuardBaseline, Test-VaultGuardIntegrity, Restore-FileFromVault, Export-VaultGuardBaseline, Import-VaultGuardBaseline
