# ==============================================================================
# Module: VaultGuard.Expiro.psm1
# Purpose: Conservative Expiro PE detector and recovery remediation
# ==============================================================================

Import-Module (Join-Path $PSScriptRoot "VaultGuard.Vault.psm1") -ErrorAction SilentlyContinue

function Get-PEHeaderInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$FilePath)

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return $null }

    $stream = $null
    $reader = $null
    try {
        $stream = [System.IO.File]::OpenRead($FilePath)
        $reader = New-Object System.IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { return $null }

        $stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
        $eLfanew = $reader.ReadInt32()
        if ($eLfanew -lt 0x40 -or $eLfanew -gt ($stream.Length - 256)) { return $null }

        $stream.Seek($eLfanew, [System.IO.SeekOrigin]::Begin) | Out-Null
        if ($reader.ReadUInt32() -ne 0x00004550) { return $null }

        $machine = $reader.ReadUInt16()
        $numberOfSections = $reader.ReadUInt16()
        [void]$reader.ReadUInt32()
        [void]$reader.ReadUInt32()
        [void]$reader.ReadUInt32()
        $sizeOfOptionalHeader = $reader.ReadUInt16()
        $characteristics = $reader.ReadUInt16()

        if ($numberOfSections -lt 1 -or $numberOfSections -gt 96 -or $sizeOfOptionalHeader -lt 64) { return $null }

        $optionalOffset = $stream.Position
        $magic = $reader.ReadUInt16()
        if ($magic -ne 0x010B -and $magic -ne 0x020B) { return $null }

        $stream.Seek($optionalOffset + 16, [System.IO.SeekOrigin]::Begin) | Out-Null
        $entryPoint = $reader.ReadUInt32()

        $sectionOffset = $optionalOffset + $sizeOfOptionalHeader
        if ($sectionOffset + ($numberOfSections * 40) -gt $stream.Length) { return $null }
        $stream.Seek($sectionOffset, [System.IO.SeekOrigin]::Begin) | Out-Null

        $sections = @()
        for ($i = 0; $i -lt $numberOfSections; $i++) {
            $name = ([System.Text.Encoding]::ASCII.GetString($reader.ReadBytes(8))).TrimEnd("`0")
            $virtualSize = $reader.ReadUInt32()
            $virtualAddress = $reader.ReadUInt32()
            $rawSize = $reader.ReadUInt32()
            $rawPointer = $reader.ReadUInt32()
            [void]$reader.ReadUInt32()
            [void]$reader.ReadUInt32()
            [void]$reader.ReadUInt16()
            [void]$reader.ReadUInt16()
            $sectionCharacteristics = $reader.ReadUInt32()

            $sections += [PSCustomObject]@{
                Index            = $i
                Name             = $name
                VirtualSize      = [uint32]$virtualSize
                VirtualAddress   = [uint32]$virtualAddress
                SizeOfRawData    = [uint32]$rawSize
                PointerToRawData = [uint32]$rawPointer
                Characteristics  = [uint32]$sectionCharacteristics
            }
        }

        return [PSCustomObject]@{
            Machine             = $machine
            NumberOfSections    = [int]$numberOfSections
            AddressOfEntryPoint = [uint32]$entryPoint
            Characteristics     = $characteristics
            FileSize            = $stream.Length
            Sections            = $sections
        }
    } catch {
        return $null
    } finally {
        if ($reader) { $reader.Dispose() }
        elseif ($stream) { $stream.Dispose() }
    }
}

function Get-ExpiroSignature {
    return @{
        Family      = "Expiro PE Infector"
        Aliases     = @("Win32/Expiro", "W32.Expiro", "PE Appender")
        Description = "PE-infector indicators requiring multiple corroborating structural anomalies before automatic remediation."
        Severity    = "CRITICAL"
    }
}

function Test-ExpiroThreat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [switch]$DeepPass
    )

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        return @{ Verdict = "Clean"; ConfidenceScore = 0; Indicators = @() }
    }

    $pe = Get-PEHeaderInfo -FilePath $FilePath
    if (-not $pe) {
        return @{ Verdict = "Clean"; ConfidenceScore = 0; Indicators = @() }
    }

    $indicators = @()
    $confidence = 0
    $knownSection = @($pe.Sections | Where-Object { $_.Name -match '^(\.vmp0|\.svp)$' })
    $lastSection = $pe.Sections[-1]

    if ($knownSection.Count -gt 0) {
        $indicators += "Known Expiro-associated section name present: $($knownSection[0].Name)"
        $confidence += 55
    }

    $sectionStart = [uint64]$lastSection.VirtualAddress
    $sectionEnd = $sectionStart + [Math]::Max([uint64]$lastSection.VirtualSize, [uint64]$lastSection.SizeOfRawData)
    $entryInLastSection = ([uint64]$pe.AddressOfEntryPoint -ge $sectionStart -and [uint64]$pe.AddressOfEntryPoint -lt $sectionEnd)
    if ($entryInLastSection) {
        $indicators += "Entry point resides in the final PE section"
        $confidence += if ($knownSection.Count -gt 0) { 30 } else { 15 }
    }

    $largeTrailingSection = ($lastSection.SizeOfRawData -ge 400000 -and $lastSection.SizeOfRawData -le 900000)
    if ($largeTrailingSection) {
        $indicators += "Large appended-looking final section ($($lastSection.SizeOfRawData) bytes)"
        $confidence += if ($knownSection.Count -gt 0) { 20 } else { 10 }
    }

    # Executable + writable final sections are a stronger anomaly than size alone.
    $IMAGE_SCN_MEM_EXECUTE = 0x20000000
    $IMAGE_SCN_MEM_WRITE = 0x80000000
    $execWritable = (($lastSection.Characteristics -band $IMAGE_SCN_MEM_EXECUTE) -ne 0 -and ($lastSection.Characteristics -band $IMAGE_SCN_MEM_WRITE) -ne 0)
    if ($execWritable) {
        $indicators += "Final PE section is both executable and writable"
        $confidence += 15
    }

    # Never auto-convict on common layout characteristics alone. Automatic infected
    # verdict requires either the known section marker plus corroboration, or a very
    # strong combination of structural anomalies.
    $verdict = "Clean"
    if ($knownSection.Count -gt 0 -and $confidence -ge 80) {
        $verdict = "Infected"
    } elseif ($knownSection.Count -eq 0 -and $entryInLastSection -and $largeTrailingSection -and $execWritable) {
        $verdict = "Suspicious"
        $confidence = [Math]::Min($confidence, 65)
    } elseif ($confidence -ge 40) {
        $verdict = "Suspicious"
    }

    return @{
        Family          = "Expiro PE Infector"
        Verdict         = $verdict
        ConfidenceScore = $confidence
        Indicators      = $indicators
        FilePath        = $FilePath
        PEHeader        = $pe
    }
}

function Invoke-ExpiroRemediation {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)][object]$Threat,
        [switch]$DryRun
    )

    if ($Threat.Verdict -ne "Infected") {
        return @{ Success = $false; Family = "Expiro PE Infector"; Message = "Automatic remediation blocked for non-infected Expiro verdict."; Actions = @() }
    }

    $targetFile = $Threat.FilePath
    $actions = @()
    if ($DryRun -or $WhatIfPreference) {
        return @{
            Success = $true
            Message = "DryRun: Would execute verified Expiro recovery pipeline on $targetFile"
            Actions = @("Would stop matching process", "Would restore authenticated baseline", "Would delegate Windows system file repair when appropriate")
        }
    }

    # Stop only processes whose executable path is the exact detected file.
    try {
        foreach ($proc in Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -eq $targetFile }) {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
            $actions += "Terminated matching process PID $($proc.ProcessId)"
        }
    } catch {}

    $vaultResult = Restore-FileFromVault -OriginalPath $targetFile
    if ($vaultResult.Success) {
        $actions += "Restored authenticated clean baseline ($($vaultResult.Level))"
        return @{ Success = $true; Family = "Expiro PE Infector"; Level = $vaultResult.Level; Actions = $actions }
    }

    if ($targetFile -match '(?i)^C:\\Windows\\(System32|SysWOW64)\\') {
        $quarantine = Protect-FileToQuarantine -FilePath $targetFile -Reason "Confirmed Expiro-infected Windows system file"
        if (-not $quarantine.Success) {
            return @{ Success = $false; Family = "Expiro PE Infector"; Level = "Blocked"; Actions = $actions; Message = $quarantine.Message }
        }

        try {
            Start-Process -FilePath "sfc.exe" -ArgumentList "/scanfile=`"$targetFile`"" -WindowStyle Hidden -Wait -ErrorAction Stop
            $actions += "Delegated system-file recovery to SFC"
            return @{ Success = $true; Family = "Expiro PE Infector"; Level = "Rung-3-SFC-Delegation"; Actions = $actions; SFCRecommended = $true }
        } catch {
            return @{ Success = $false; Family = "Expiro PE Infector"; Level = "Rung-3-SFC-Failed"; Actions = $actions; Message = $_.Exception.Message }
        }
    }

    $q = Protect-FileToQuarantine -FilePath $targetFile -Reason "Confirmed Expiro infection without clean baseline"
    if ($q.Success) {
        $actions += "Quarantined infected non-baseline executable; clean reinstall required"
        return @{ Success = $true; Family = "Expiro PE Infector"; Level = "Rung-4-Unrecoverable"; Actions = $actions; ReinstallRequired = $true }
    }

    return @{ Success = $false; Family = "Expiro PE Infector"; Level = "Blocked"; Actions = $actions; Message = $q.Message }
}

Export-ModuleMember -Function Get-PEHeaderInfo, Get-ExpiroSignature, Test-ExpiroThreat, Invoke-ExpiroRemediation
