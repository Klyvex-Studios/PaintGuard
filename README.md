# VaultGuard 360

**VaultGuard 360** is a Windows malware-defense and recovery project by **Klyvex Studios**. It combines a native .NET 8 WPF desktop application with PowerShell detection and remediation modules focused on removable-media malware, shortcut worms, Paint/Geacata-style replacement infections, Expiro-style PE infection indicators, persistence auditing, quarantine, clean-file baselines, and recovery.

> VaultGuard is an actively developed security product. Its current detection engine is intentionally family-specific and conservative; it should not yet be described as a complete replacement for a mature general-purpose antivirus product.

## Current architecture

```text
VaultGuard360.exe (WPF)
        |
        v
EngineService (.NET)
        |
        +-- in-process PowerShell runspace
        |
        +-- VaultGuard.Detection.psm1
        +-- VaultGuard.PaintGeacata.psm1
        +-- VaultGuard.ShortcutWorm.psm1
        +-- VaultGuard.Expiro.psm1
        +-- VaultGuard.Persistence.psm1
        +-- VaultGuard.Vaccine.psm1
        +-- VaultGuard.Vault.psm1
        +-- VaultGuard.Audit.psm1
```

The desktop application now invokes the protection modules directly through an in-process PowerShell runspace. The optional `PaintGuardEngine.ps1` loopback REST host remains available for separate tooling, but the normal desktop scan/quarantine/recovery flow no longer depends on a separately started localhost process.

## Desktop application

The WPF application contains four primary work areas:

- **Home** — live engine state, last scan data, quarantine count and remediation access.
- **Scan Center** — target selection, safe/dry-run mode, live verdict counts and engine logs.
- **Vault & Quarantine** — real baseline records and quarantine records with restore/delete actions.
- **Settings** — removable-media protection, engine runtime details and support workflow.

The UI uses a light neutral workspace with a dark navigation rail and restrained forest-green, amber and red security/status accents.

## Detection scope

### Paint / Geacata family

Uses corroborating indicators such as known payload size profiles and hidden twin-file behavior. Size alone is not enough for automatic remediation.

### Shortcut-worm family

Inspects shortcut targets and arguments for script-interpreter execution patterns, hidden-directory behavior and icon-hijack evidence. Remediation now quarantines only the shortcuts that were actually identified as malicious rather than every `.lnk` file in the directory.

### Expiro-style PE infection indicators

Parses PE headers and section tables. Automatic remediation requires strong corroborating structural evidence; common PE layouts by themselves remain suspicious/review-only rather than being automatically treated as infected.

## Protected storage

VaultGuard uses storage beneath `C:\ProgramData\VaultGuard` when available, with a per-user fallback when necessary.

### Baseline

- Stores independent clean executable copies under content hashes.
- Hard-link recovery mode is disabled because a hard link is not an independent clean copy.
- Copy hashes are verified after baseline capture.
- The baseline manifest is authenticated with HMAC-SHA256.
- The HMAC key is protected with Windows DPAPI for the current Windows identity.

### Quarantine

- Stores quarantined payloads as GUID-based `.bin` files with JSON metadata.
- Records original path, SHA-256, file size, time and detection reason.
- Verifies the quarantined payload hash before restore.
- Refuses to overwrite an existing file at the original path during restore.

### ACL model

VaultGuard no longer creates an `Everyone: Deny FullControl` rule. Protected storage removes inherited rules and explicitly grants required access to SYSTEM, Administrators and the active VaultGuard Windows identity. This prevents the application from accidentally denying itself access to its own recovery data.

## Remediation flow

```text
Detect
  -> classify
  -> quarantine confirmed malicious payload
  -> restore authenticated clean baseline when available
  -> repair family-specific persistence
  -> harden removable media / AutoRun policy
```

Safe scan mode is enabled by default in the Scan Center. When safe mode is enabled, detections are reported without changing files.

## Build

Requirements:

- Windows 10/11
- .NET 8 SDK
- PowerShell 7 supported by the embedded `System.Management.Automation` package

Build the desktop application:

```powershell
dotnet restore .\VaultGuard360.csproj
dotnet build .\VaultGuard360.csproj -c Release
```

Build the custom installer:

```powershell
.\Build-Installer.ps1
```

## CI and releases

`.github/workflows/ci.yml` validates pushes and pull requests by:

1. restoring and building the WPF application;
2. parsing all core PowerShell modules for syntax errors;
3. running security/architecture regression checks.

The release workflow no longer publishes a release on every push to `main`. GitHub Releases are produced from version tags (`v*.*.*`) or an explicit manual release workflow run.

## Security regression checks

The hardening suite specifically checks that:

- the desktop app creates a real PowerShell runspace;
- scans invoke `Invoke-VaultGuardScan`;
- fake scan delays/counters do not return;
- simulated USB insertion is not used by the main shell;
- the vault does not reintroduce `Everyone: Deny FullControl`;
- baseline hard links are not created;
- baseline authentication and DPAPI key protection remain present;
- quarantine restore retains integrity verification.

Run locally with:

```powershell
.\Tests\Hardening-Tests.ps1
```

## Optional REST host

`PaintGuardEngine.ps1` remains available for local integrations. It binds to `127.0.0.1` and protects `/api/` routes with bearer authentication. The WPF application does not require this host for normal operation.

## Project status

VaultGuard 360 is currently best described as a **specialized Windows malware-defense, incident-response and recovery platform under active development**. The project now has real desktop-to-engine integration and safer recovery behavior, but expanding coverage toward a mature general antivirus still requires broader file-type scanning, signed reputation/intelligence, safer behavioral monitoring, definition/update infrastructure, extensive false-positive corpora, adversarial testing and code signing.

## License

Created by **Klyvex Studios**. See [LICENSE](LICENSE), [SECURITY.md](SECURITY.md), and [CONTRIBUTING.md](CONTRIBUTING.md).
