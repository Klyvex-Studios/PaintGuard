# ==============================================================================
# VaultGuard.Vault.psm1
# Protected clean baseline, quarantine and recovery storage
# ==============================================================================

$script:VaultRoot = "C:\ProgramData\VaultGuard"
try {
    if (-not (Test-Path -LiteralPath $script:VaultRoot)) {
        New-Item -ItemType Directory -Path $script:VaultRoot -Force -ErrorAction Stop | Out-Null
    }
} catch {
    $script:VaultRoot = Join-Path $env:LOCALAPPDATA "VaultGuard"
    New-Item -ItemType Directory -Path $script:VaultRoot -Force | Out-Null
}

$script:BaselinePath   = Join-Path $script:VaultRoot "Baseline"
$script:QuarantinePath = Join-Path $script:VaultRoot "Quarantine"
$script:GoldenPath     = Join-Path $script:VaultRoot "GoldenVault"

function Initialize-VaultGuardProtection {
    [CmdletBinding()]
    param()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    foreach ($dir in @($script:VaultRoot, $script:BaselinePath, $script:QuarantinePath, $script:GoldenPath)) {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        try {
            $acl = Get-Acl -LiteralPath $dir
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($existing in @($acl.Access)) {
                [void]$acl.RemoveAccessRuleAll($existing)
            }

            $inherit = "ContainerInherit,ObjectInherit"
            $system = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", $inherit, "None", "Allow")
            $admins = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", $inherit, "None", "Allow")
            $user = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, "Modify", $inherit, "None", "Allow")
            $acl.AddAccessRule($system)
            $acl.AddAccessRule($admins)
            $acl.AddAccessRule($user)
            Set-Acl -LiteralPath $dir -AclObject $acl -ErrorAction Stop
        } catch {
            Write-Verbose "Vault ACL hardening warning for $dir: $($_.Exception.Message)"
        }
    }
}

function Get-VaultPaths {
    @{
        Root       = $script:VaultRoot
        Baseline   = $script:BaselinePath
        Quarantine = $script:QuarantinePath
        Golden     = $script:GoldenPath
    }
}

function Get-VaultGuardSigningKey {
    $keyFile = Join-Path $script:BaselinePath "vault.key"
    if (Test-Path -LiteralPath $keyFile) {
        $protected = [Convert]::FromBase64String((Get-Content -LiteralPath $keyFile -Raw).Trim())
        return [System.Security.Cryptography.ProtectedData]::Unprotect($protected, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    }

    $key = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($key) } finally { $rng.Dispose() }

    $protectedKey = [System.Security.Cryptography.ProtectedData]::Protect($key, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [Convert]::ToBase64String($protectedKey) | Out-File -LiteralPath $keyFile -Encoding ascii -Force
    return $key
}

function Get-VaultGuardManifestSignature {
    param([Parameter(Mandatory=$true)][string]$ManifestFile)

    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = Get-VaultGuardSigningKey
    try {
        $bytes = [System.IO.File]::ReadAllBytes($ManifestFile)
        return [Convert]::ToHexString($hmac.ComputeHash($bytes))
    } finally {
        $hmac.Dispose()
    }
}

function Test-VaultGuardManifestAuthentication {
    $manifest = Join-Path $script:BaselinePath "manifest.json"
    $signature = Join-Path $script:BaselinePath "vault.sig"
    if (-not (Test-Path -LiteralPath $manifest) -or -not (Test-Path -LiteralPath $signature)) { return $false }

    try {
        $actual = Get-VaultGuardManifestSignature -ManifestFile $manifest
        $expected = (Get-Content -LiteralPath $signature -Raw).Trim()
        return $actual -eq $expected
    } catch {
        return $false
    }
}

Initialize-VaultGuardProtection

# ------------------------------------------------------------------------------
# Quarantine
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

    $id = [Guid]::NewGuid().ToString()
    $binPath = Join-Path $script:QuarantinePath "$id.bin"
    $jsonPath = Join-Path $script:QuarantinePath "$id.json"
    $item = Get-Item -LiteralPath $FilePath -Force
    $hash = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash

    if ($DryRun -or $WhatIfPreference) {
        return @{ Success = $true; QuarantineId = $id; OriginalPath = $FilePath; Message = "DryRun: Would quarantine file." }
    }

    if (-not $PSCmdlet.ShouldProcess($FilePath, "Move to quarantine")) {
        return @{ Success = $true; QuarantineId = $id; Message = "WhatIf: Skipped." }
    }

    $metadata = [PSCustomObject]@{
        Id            = $id
        OriginalPath  = $item.FullName
        OriginalName  = $item.Name
        QuarantinedAt = (Get-Date).ToString("o")
        SHA256        = $hash
        FileSize      = $item.Length
        Attributes    = $item.Attributes.ToString()
        Reason        = $Reason
    }

    try {
        Move-Item -LiteralPath $FilePath -Destination $binPath -Force -ErrorAction Stop
        $metadata | ConvertTo-Json -Depth 3 | Out-File -LiteralPath $jsonPath -Encoding utf8 -Force
        return @{ Success = $true; QuarantineId = $id; OriginalPath = $FilePath }
    } catch {
        if ((Test-Path -LiteralPath $binPath) -and -not (Test-Path -LiteralPath $FilePath)) {
            Move-Item -LiteralPath $binPath -Destination $FilePath -Force -ErrorAction SilentlyContinue
        }
        return @{ Success = $false; Message = "Quarantine failed: $($_.Exception.Message)" }
    }
}

function Get-QuarantineVaultItems {
    [CmdletBinding()]
    param()

    $items = @()
    foreach ($json in Get-ChildItem -LiteralPath $script:QuarantinePath -Filter "*.json" -File -ErrorAction SilentlyContinue) {
        try {
            $record = Get-Content -LiteralPath $json.FullName -Raw | ConvertFrom-Json
            $payload = Join-Path $script:QuarantinePath "$($record.Id).bin"
            $record | Add-Member -NotePropertyName PayloadExists -NotePropertyValue (Test-Path -LiteralPath $payload) -Force
            $items += $record
        } catch {}
    }
    return ,$items
}

function Restore-QuarantinedItem {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)][string]$QuarantineId,
        [switch]$DryRun
    )

    if ($QuarantineId -notmatch '^[0-9a-fA-F-]{36}$') { return @{ Success = $false; Message = "Invalid quarantine identifier." } }

    $binPath = Join-Path $script:QuarantinePath "$QuarantineId.bin"
    $jsonPath = Join-Path $script:QuarantinePath "$QuarantineId.json"
    if (-not (Test-Path -LiteralPath $binPath) -or -not (Test-Path -LiteralPath $jsonPath)) {
        return @{ Success = $false; Message = "Quarantine payload or metadata is missing." }
    }

    $meta = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
    $currentHash = (Get-FileHash -LiteralPath $binPath -Algorithm SHA256).Hash
    if ($meta.SHA256 -and $currentHash -ne $meta.SHA256) {
        return @{ Success = $false; Message = "Quarantine integrity verification failed. Restore blocked." }
    }

    if ($DryRun -or $WhatIfPreference) { return @{ Success = $true; RestoredPath = $meta.OriginalPath; Message = "DryRun: Would restore item." } }
    if (-not $PSCmdlet.ShouldProcess($meta.OriginalPath, "Restore quarantined file")) { return @{ Success = $true; Message = "WhatIf: Skipped." } }
    if (Test-Path -LiteralPath $meta.OriginalPath) { return @{ Success = $false; Message = "A file already exists at the original path. Restore blocked." } }

    try {
        $targetFolder = Split-Path -Path $meta.OriginalPath -Parent
        if (-not (Test-Path -LiteralPath $targetFolder)) { New-Item -ItemType Directory -Path $targetFolder -Force | Out-Null }
        Move-Item -LiteralPath $binPath -Destination $meta.OriginalPath -Force -ErrorAction Stop
        Remove-Item -LiteralPath $jsonPath -Force -ErrorAction SilentlyContinue
        return @{ Success = $true; RestoredPath = $meta.OriginalPath }
    } catch {
        return @{ Success = $false; Message = "Restore failed: $($_.Exception.Message)" }
    }
}

function Remove-QuarantinedItem {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)][string]$QuarantineId,
        [switch]$DryRun
    )

    if ($QuarantineId -notmatch '^[0-9a-fA-F-]{36}$') { return @{ Success = $false; Message = "Invalid quarantine identifier." } }
    $binPath = Join-Path $script:QuarantinePath "$QuarantineId.bin"
    $jsonPath = Join-Path $script:QuarantinePath "$QuarantineId.json"

    if ($DryRun -or $WhatIfPreference) { return @{ Success = $true; Id = $QuarantineId; Message = "DryRun: Would purge item." } }
    if (-not $PSCmdlet.ShouldProcess($QuarantineId, "Permanently purge quarantine item")) { return @{ Success = $true; Message = "WhatIf: Skipped." } }

    try {
        if (Test-Path -LiteralPath $binPath) { Remove-Item -LiteralPath $binPath -Force -ErrorAction Stop }
        if (Test-Path -LiteralPath $jsonPath) { Remove-Item -LiteralPath $jsonPath -Force -ErrorAction Stop }
        return @{ Success = $true; Id = $QuarantineId }
    } catch {
        return @{ Success = $false; Message = "Purge failed: $($_.Exception.Message)" }
    }
}

# ------------------------------------------------------------------------------
# Baseline and recovery
# ------------------------------------------------------------------------------

function New-VaultGuardBaseline {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [string[]]$TargetPaths = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "C:\Program Files"),
        [switch]$HardlinkMode,
        [switch]$DryRun
    )

    if ($HardlinkMode) { Write-Warning "HardlinkMode is disabled. Recovery copies must be independent." }

    $blobs = Join-Path $script:BaselinePath "blobs"
    New-Item -ItemType Directory -Path $blobs -Force | Out-Null
    $entries = @()
    $captured = 0
    $skipped = 0

    foreach ($target in $TargetPaths) {
        if (-not (Test-Path -LiteralPath $target)) { continue }
        foreach ($exe in Get-ChildItem -LiteralPath $target -Filter "*.exe" -Recurse -File -ErrorAction SilentlyContinue) {
            if ($exe.Length -eq 844288 -or $exe.Name -match '^(v|gvg|vvg).+\.exe$') { $skipped++; continue }

            try {
                $hash = (Get-FileHash -LiteralPath $exe.FullName -Algorithm SHA256).Hash
                $blob = Join-Path $blobs "$hash.exe"
                if (-not ($DryRun -or $WhatIfPreference) -and -not (Test-Path -LiteralPath $blob)) {
                    Copy-Item -LiteralPath $exe.FullName -Destination $blob -Force -ErrorAction Stop
                    if ((Get-FileHash -LiteralPath $blob -Algorithm SHA256).Hash -ne $hash) {
                        Remove-Item -LiteralPath $blob -Force -ErrorAction SilentlyContinue
                        throw "Baseline copy hash mismatch."
                    }
                }

                $entries += [PSCustomObject]@{
                    OriginalPath = $exe.FullName
                    FileName     = $exe.Name
                    SHA256       = $hash
                    FileSize     = $exe.Length
                    LastWrite    = $exe.LastWriteTime.ToString("o")
                    Attributes   = $exe.Attributes.ToString()
                }
                $captured++
            } catch { $skipped++ }
        }
    }

    if (-not ($DryRun -or $WhatIfPreference)) {
        $manifest = Join-Path $script:BaselinePath "manifest.json"
        $sig = Join-Path $script:BaselinePath "vault.sig"
        $entries | ConvertTo-Json -Depth 4 | Out-File -LiteralPath $manifest -Encoding utf8 -Force
        (Get-VaultGuardManifestSignature -ManifestFile $manifest) | Out-File -LiteralPath $sig -Encoding ascii -Force
    }

    return @{ Success = $true; TotalCaptured = $captured; TotalSkipped = $skipped; VaultPath = $script:BaselinePath }
}

function Test-VaultGuardIntegrity {
    [CmdletBinding()]
    param()

    if (-not (Test-VaultGuardManifestAuthentication)) {
        return @{ Success = $false; Message = "Baseline authentication failed or baseline has not been created." }
    }

    $manifest = Join-Path $script:BaselinePath "manifest.json"
    $entries = @(Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json)
    $triage = @()
    $compromised = 0

    foreach ($entry in $entries) {
        $status = "CLEAN"
        $currentHash = "MISSING"
        if (Test-Path -LiteralPath $entry.OriginalPath) {
            try {
                $currentHash = (Get-FileHash -LiteralPath $entry.OriginalPath -Algorithm SHA256).Hash
                if ($currentHash -ne $entry.SHA256) { $status = "MODIFIED"; $compromised++ }
            } catch { $status = "UNREADABLE"; $compromised++ }
        } else { $status = "DELETED_OR_RENAMED"; $compromised++ }

        $triage += [PSCustomObject]@{
            OriginalPath = $entry.OriginalPath
            BaselineHash = $entry.SHA256
            CurrentHash  = $currentHash
            Status       = $status
        }
    }

    return @{ Success = $true; TotalMonitored = $entries.Count; CompromisedCount = $compromised; Triage = $triage }
}

function Restore-FileFromVault {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)][string]$OriginalPath,
        [switch]$DryRun
    )

    if (-not (Test-VaultGuardManifestAuthentication)) {
        return @{ Success = $false; Level = "Blocked"; Message = "Baseline authentication failed. Restore blocked." }
    }

    $manifest = Join-Path $script:BaselinePath "manifest.json"
    $entry = @(Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json) | Where-Object { $_.OriginalPath -eq $OriginalPath } | Select-Object -First 1
    if (-not $entry) { return @{ Success = $false; Level = "Unrecoverable"; Message = "File not present in clean baseline." } }

    $blob = Join-Path $script:BaselinePath "blobs\$($entry.SHA256).exe"
    if (-not (Test-Path -LiteralPath $blob)) { return @{ Success = $false; Level = "Unrecoverable"; Message = "Verified clean recovery blob is missing." } }
    if ((Get-FileHash -LiteralPath $blob -Algorithm SHA256).Hash -ne $entry.SHA256) { return @{ Success = $false; Level = "Blocked"; Message = "Recovery blob integrity failed." } }

    if ($DryRun -or $WhatIfPreference) { return @{ Success = $true; Level = "Level-2-Vault-Blob"; RestoredPath = $OriginalPath; Message = "DryRun: Would restore verified blob." } }
    if (-not $PSCmdlet.ShouldProcess($OriginalPath, "Restore verified clean baseline")) { return @{ Success = $true; Message = "WhatIf: Skipped." } }

    try {
        if (Test-Path -LiteralPath $OriginalPath) {
            $q = Protect-FileToQuarantine -FilePath $OriginalPath -Reason "Replaced during clean baseline restoration"
            if (-not $q.Success) { throw $q.Message }
        }
        Copy-Item -LiteralPath $blob -Destination $OriginalPath -Force -ErrorAction Stop
        if ((Get-FileHash -LiteralPath $OriginalPath -Algorithm SHA256).Hash -ne $entry.SHA256) { throw "Restored file hash mismatch." }
        return @{ Success = $true; Level = "Level-2-Vault-Blob"; RestoredPath = $OriginalPath }
    } catch {
        return @{ Success = $false; Level = "Failed"; Message = "Restore failed: $($_.Exception.Message)" }
    }
}

function Export-VaultGuardBaseline {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([Parameter(Mandatory=$true)][string]$DestinationPath, [switch]$DryRun)

    if ($DryRun -or $WhatIfPreference) { return @{ Success = $true; ExportLocation = $DestinationPath; Message = "DryRun: Would export baseline." } }
    try {
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
        Copy-Item -Path "$script:BaselinePath\*" -Destination $DestinationPath -Recurse -Force -ErrorAction Stop
        return @{ Success = $true; ExportLocation = $DestinationPath }
    } catch { return @{ Success = $false; Message = "Vault export failed: $($_.Exception.Message)" } }
}

function Import-VaultGuardBaseline {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([Parameter(Mandatory=$true)][string]$SourceVaultPath, [switch]$DryRun)

    if (-not (Test-Path -LiteralPath $SourceVaultPath)) { return @{ Success = $false; Message = "Source vault path not found." } }
    if ($DryRun -or $WhatIfPreference) { return @{ Success = $true; Message = "DryRun: Would import baseline." } }

    try {
        Copy-Item -Path "$SourceVaultPath\*" -Destination $script:BaselinePath -Recurse -Force -ErrorAction Stop
        if (-not (Test-VaultGuardManifestAuthentication)) { return @{ Success = $false; Message = "Imported baseline failed authentication." } }
        return @{ Success = $true; Message = "Baseline imported and authenticated." }
    } catch { return @{ Success = $false; Message = "Vault import failed: $($_.Exception.Message)" } }
}

Export-ModuleMember -Function Initialize-VaultGuardProtection, Get-VaultPaths, Protect-FileToQuarantine, Get-QuarantineVaultItems, Restore-QuarantinedItem, Remove-QuarantinedItem, New-VaultGuardBaseline, Test-VaultGuardIntegrity, Restore-FileFromVault, Export-VaultGuardBaseline, Import-VaultGuardBaseline
