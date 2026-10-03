using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace VaultGuard360.Services
{
    public sealed class ScanResult
    {
        public int TotalScanned { get; init; }
        public int ThreatsFound { get; init; }
        public int SuspiciousCount { get; init; }
        public IReadOnlyList<string> ThreatSummaries { get; init; } = Array.Empty<string>();
    }

    public sealed class RemediationResult
    {
        public bool Success { get; init; }
        public int ThreatsRemediated { get; init; }
        public int FilesRestored { get; init; }
        public int PersistenceFixed { get; init; }
        public string Message { get; init; } = string.Empty;
    }

    public sealed class QuarantineRecord
    {
        public string Id { get; init; } = string.Empty;
        public string OriginalName { get; init; } = string.Empty;
        public string OriginalPath { get; init; } = string.Empty;
        public string Sha256 { get; init; } = string.Empty;
        public string Reason { get; init; } = string.Empty;
        public string QuarantinedAt { get; init; } = string.Empty;
    }

    public sealed class BaselineRecord
    {
        public string FileName { get; init; } = string.Empty;
        public string OriginalPath { get; init; } = string.Empty;
        public string Sha256 { get; init; } = string.Empty;
        public long FileSize { get; init; }
    }

    public sealed class EngineService : IDisposable
    {
        private static EngineService? _instance;
        public static EngineService Instance => _instance ??= new EngineService();

        private readonly SemaphoreSlim _engineLock = new(1, 1);
        private Runspace? _runspace;
        private string _runtimeDirectory = string.Empty;

        public bool IsEngineInitialized { get; private set; }
        public string EngineState { get; private set; } = "Offline";
        public string LastError { get; private set; } = string.Empty;

        // Kept for backwards-compatible diagnostics. The desktop app now talks to the
        // engine in-process instead of trusting a separate localhost REST process.
        public string BearerToken { get; } = Guid.NewGuid().ToString("N");
        public int ApiPort { get; } = 18443;

        public event Action<string, bool>? OnLogReceived;
        public event Action<bool, string>? OnEngineStateChanged;

        private EngineService() { }

        public void InitializeEmbeddedEngine()
        {
            if (IsEngineInitialized) return;

            try
            {
                EngineState = "Starting";
                Log("Starting VaultGuard security engine...", false);

                _runtimeDirectory = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Klyvex Studios",
                    "VaultGuard 360",
                    "Runtime");
                Directory.CreateDirectory(_runtimeDirectory);

                string modulesDirectory = Path.Combine(_runtimeDirectory, "Modules");
                Directory.CreateDirectory(modulesDirectory);

                string[] moduleFiles =
                {
                    "VaultGuard.Vault.psm1",
                    "VaultGuard.PaintGeacata.psm1",
                    "VaultGuard.ShortcutWorm.psm1",
                    "VaultGuard.Expiro.psm1",
                    "VaultGuard.Detection.psm1",
                    "VaultGuard.Persistence.psm1",
                    "VaultGuard.Vaccine.psm1",
                    "VaultGuard.Audit.psm1"
                };

                foreach (string moduleFile in moduleFiles)
                {
                    string destination = Path.Combine(modulesDirectory, moduleFile);
                    ExtractEmbeddedResourceBySuffix($"Modules.{moduleFile}", destination);
                }

                _runspace = RunspaceFactory.CreateRunspace();
                _runspace.Open();

                using PowerShell ps = PowerShell.Create();
                ps.Runspace = _runspace;

                foreach (string moduleFile in moduleFiles)
                {
                    ps.Commands.Clear();
                    ps.Streams.Error.Clear();
                    ps.AddCommand("Import-Module")
                      .AddParameter("Name", Path.Combine(modulesDirectory, moduleFile))
                      .AddParameter("Force");
                    ps.Invoke();
                    ThrowIfPowerShellFailed(ps, $"Importing {moduleFile}");
                }

                ps.Commands.Clear();
                ps.Streams.Error.Clear();
                ps.AddCommand("Get-Command").AddParameter("Name", "Invoke-VaultGuardScan");
                var commandResult = ps.Invoke();
                ThrowIfPowerShellFailed(ps, "Validating scanner entry point");
                if (commandResult.Count == 0)
                    throw new InvalidOperationException("VaultGuard scanner command was not loaded.");

                IsEngineInitialized = true;
                EngineState = "Protected";
                LastError = string.Empty;
                Log("VaultGuard engine initialized. Real detection modules are online.", false);
                OnEngineStateChanged?.Invoke(true, EngineState);
            }
            catch (Exception ex)
            {
                IsEngineInitialized = false;
                EngineState = "Offline";
                LastError = ex.Message;
                Log($"Engine initialization failed: {ex.Message}", true);
                OnEngineStateChanged?.Invoke(false, EngineState);
            }
        }

        public async Task<ScanResult> ScanAsync(IEnumerable<string> paths, bool dryRun = true)
        {
            EnsureReady();
            string[] safePaths = paths.Where(p => !string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (safePaths.Length == 0) safePaths = new[] { @"C:\" };

            return await ExecuteLockedAsync(() =>
            {
                using PowerShell ps = CreatePowerShell();
                ps.AddCommand("Invoke-VaultGuardScan")
                  .AddParameter("Paths", safePaths);
                if (dryRun) ps.AddParameter("DryRun");

                Log($"Scanning {string.Join(", ", safePaths)} using live VaultGuard detectors...", false);
                var output = ps.Invoke();
                ThrowIfPowerShellFailed(ps, "Threat scan");

                PSObject? root = output.LastOrDefault();
                int total = ToInt(GetValue(root, "TotalScanned"));
                int infected = ToInt(GetValue(root, "ThreatsFound"));
                var review = AsEnumerable(GetValue(root, "ReviewQueue")).ToList();
                var threats = AsEnumerable(GetValue(root, "Threats")).ToList();

                var summaries = threats.Select(DescribeThreat).Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
                foreach (string summary in summaries) Log($"THREAT: {summary}", true);
                foreach (object item in review)
                {
                    string text = DescribeThreat(item);
                    if (!string.IsNullOrWhiteSpace(text)) Log($"REVIEW: {text}", false);
                }

                return new ScanResult
                {
                    TotalScanned = total,
                    ThreatsFound = infected,
                    SuspiciousCount = review.Count,
                    ThreatSummaries = summaries
                };
            });
        }

        public async Task<RemediationResult> RemediateAsync(IEnumerable<string> paths, bool dryRun)
        {
            EnsureReady();
            string[] safePaths = paths.Where(p => !string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (safePaths.Length == 0) safePaths = new[] { @"C:\" };

            return await ExecuteLockedAsync(() =>
            {
                _runspace!.SessionStateProxy.SetVariable("__vgPaths", safePaths);
                _runspace.SessionStateProxy.SetVariable("__vgDryRun", dryRun);

                const string script = @"
$scan = Invoke-VaultGuardScan -Paths $__vgPaths -DryRun:$__vgDryRun
$remediated = 0
$restored = 0
foreach ($threat in @($scan.Threats)) {
    if ($threat.Family -eq 'Paint / Geacata') {
        $r = Invoke-PaintGeacataRemediation -Threat $threat -DryRun:$__vgDryRun
        if ($r.Success) { $remediated++; $restored++ }
    }
    elseif ($threat.Family -eq 'Shortcut Worm') {
        $r = Invoke-ShortcutWormRemediation -Threat $threat -DryRun:$__vgDryRun
        if ($r.Success) { $remediated++ }
    }
    elseif ($threat.Family -eq 'Expiro PE Infector') {
        $r = Invoke-ExpiroRemediation -Threat $threat -DryRun:$__vgDryRun
        if ($r.Success) { $remediated++; if ($r.Level -like 'Level-1*' -or $r.Level -like 'Level-2*' -or $r.Level -like 'Rung-2*' -or $r.Level -like 'Rung-3*') { $restored++ } }
    }
}
$persistence = Repair-VaultGuardPersistence -DryRun:$__vgDryRun
if (-not $__vgDryRun) { Set-VaultGuardVaccine -HardenAutoRunPolicy -VaccinateConnectedUSB | Out-Null }
@{
    Success = $true
    ThreatsRemediated = $remediated
    FilesRestored = $restored
    PersistenceFixed = [int]$persistence.RemediatedCount
    Message = if ($__vgDryRun) { 'Dry run completed. No files were changed.' } else { 'Remediation completed.' }
}
";

                using PowerShell ps = CreatePowerShell();
                ps.AddScript(script);
                var output = ps.Invoke();
                ThrowIfPowerShellFailed(ps, "Remediation pipeline");
                PSObject? root = output.LastOrDefault();

                var result = new RemediationResult
                {
                    Success = ToBool(GetValue(root, "Success")),
                    ThreatsRemediated = ToInt(GetValue(root, "ThreatsRemediated")),
                    FilesRestored = ToInt(GetValue(root, "FilesRestored")),
                    PersistenceFixed = ToInt(GetValue(root, "PersistenceFixed")),
                    Message = Convert.ToString(GetValue(root, "Message")) ?? string.Empty
                };
                Log($"Remediation result: {result.Message} Threats={result.ThreatsRemediated}, Restored={result.FilesRestored}, Persistence={result.PersistenceFixed}", false);
                return result;
            });
        }

        public async Task<(bool Success, int Captured, int Skipped, string Message)> CaptureBaselineAsync(IEnumerable<string> paths)
        {
            EnsureReady();
            string[] safePaths = paths.Where(p => !string.IsNullOrWhiteSpace(p)).ToArray();
            return await ExecuteLockedAsync(() =>
            {
                using PowerShell ps = CreatePowerShell();
                ps.AddCommand("New-VaultGuardBaseline").AddParameter("TargetPaths", safePaths);
                var output = ps.Invoke();
                ThrowIfPowerShellFailed(ps, "Baseline capture");
                PSObject? root = output.LastOrDefault();
                bool ok = ToBool(GetValue(root, "Success"));
                int captured = ToInt(GetValue(root, "TotalCaptured"));
                int skipped = ToInt(GetValue(root, "TotalSkipped"));
                string message = ok ? $"Captured {captured} clean executable baselines ({skipped} skipped)." : "Baseline capture failed.";
                Log(message, !ok);
                return (ok, captured, skipped, message);
            });
        }

        public async Task<IReadOnlyList<QuarantineRecord>> GetQuarantineAsync()
        {
            EnsureReady();
            return await ExecuteLockedAsync(() =>
            {
                using PowerShell ps = CreatePowerShell();
                ps.AddCommand("Get-QuarantineVaultItems");
                var output = ps.Invoke();
                ThrowIfPowerShellFailed(ps, "Reading quarantine vault");
                return (IReadOnlyList<QuarantineRecord>)output.Select(item => new QuarantineRecord
                {
                    Id = Convert.ToString(GetValue(item, "Id")) ?? string.Empty,
                    OriginalName = Convert.ToString(GetValue(item, "OriginalName")) ?? string.Empty,
                    OriginalPath = Convert.ToString(GetValue(item, "OriginalPath")) ?? string.Empty,
                    Sha256 = Convert.ToString(GetValue(item, "SHA256")) ?? string.Empty,
                    Reason = Convert.ToString(GetValue(item, "Reason")) ?? string.Empty,
                    QuarantinedAt = Convert.ToString(GetValue(item, "QuarantinedAt")) ?? string.Empty
                }).ToList();
            });
        }

        public async Task<IReadOnlyList<BaselineRecord>> GetBaselineAsync(int limit = 200)
        {
            EnsureReady();
            return await ExecuteLockedAsync(() =>
            {
                _runspace!.SessionStateProxy.SetVariable("__vgLimit", Math.Max(1, limit));
                const string script = @"
$paths = Get-VaultPaths
$manifest = Join-Path $paths.Baseline 'manifest.json'
if (Test-Path $manifest) {
    @(Get-Content $manifest -Raw | ConvertFrom-Json) | Select-Object -First $__vgLimit
}
";
                using PowerShell ps = CreatePowerShell();
                ps.AddScript(script);
                var output = ps.Invoke();
                ThrowIfPowerShellFailed(ps, "Reading baseline vault");
                return (IReadOnlyList<BaselineRecord>)output.Select(item => new BaselineRecord
                {
                    FileName = Convert.ToString(GetValue(item, "FileName")) ?? string.Empty,
                    OriginalPath = Convert.ToString(GetValue(item, "OriginalPath")) ?? string.Empty,
                    Sha256 = Convert.ToString(GetValue(item, "SHA256")) ?? string.Empty,
                    FileSize = ToLong(GetValue(item, "FileSize"))
                }).ToList();
            });
        }

        public Task<bool> RestoreQuarantineAsync(string id) => InvokeBooleanCommandAsync("Restore-QuarantinedItem", "QuarantineId", id);
        public Task<bool> DeleteQuarantineAsync(string id) => InvokeBooleanCommandAsync("Remove-QuarantinedItem", "QuarantineId", id);

        public async Task<bool> SetUsbProtectionAsync(bool enabled)
        {
            EnsureReady();
            return await ExecuteLockedAsync(() =>
            {
                using PowerShell ps = CreatePowerShell();
                if (enabled)
                    ps.AddCommand("Set-VaultGuardVaccine").AddParameter("HardenAutoRunPolicy").AddParameter("VaccinateConnectedUSB");
                else
                    ps.AddCommand("Remove-VaultGuardVaccine");
                ps.Invoke();
                ThrowIfPowerShellFailed(ps, enabled ? "Enabling USB protection" : "Disabling USB protection");
                return true;
            });
        }

        private async Task<bool> InvokeBooleanCommandAsync(string command, string parameterName, string value)
        {
            EnsureReady();
            return await ExecuteLockedAsync(() =>
            {
                using PowerShell ps = CreatePowerShell();
                ps.AddCommand(command).AddParameter(parameterName, value);
                var output = ps.Invoke();
                ThrowIfPowerShellFailed(ps, command);
                return ToBool(GetValue(output.LastOrDefault(), "Success"));
            });
        }

        private PowerShell CreatePowerShell()
        {
            var ps = PowerShell.Create();
            ps.Runspace = _runspace ?? throw new InvalidOperationException("VaultGuard runspace is not initialized.");
            return ps;
        }

        private async Task<T> ExecuteLockedAsync<T>(Func<T> action)
        {
            await _engineLock.WaitAsync();
            try
            {
                return await Task.Run(action);
            }
            finally
            {
                _engineLock.Release();
            }
        }

        private void ExtractEmbeddedResourceBySuffix(string suffix, string destination)
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            string? resourceName = assembly.GetManifestResourceNames()
                .FirstOrDefault(name => name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase));
            if (resourceName == null)
                throw new FileNotFoundException($"Embedded engine resource not found: {suffix}");

            using Stream source = assembly.GetManifestResourceStream(resourceName)
                ?? throw new FileNotFoundException($"Unable to read embedded resource: {resourceName}");
            using FileStream target = File.Create(destination);
            source.CopyTo(target);
        }

        private static object? GetValue(object? item, string name)
        {
            if (item == null) return null;
            if (item is PSObject psObject)
            {
                if (psObject.BaseObject is IDictionary dictionary && dictionary.Contains(name))
                    return dictionary[name];
                return psObject.Properties[name]?.Value;
            }
            if (item is IDictionary dict && dict.Contains(name)) return dict[name];
            return item.GetType().GetProperty(name)?.GetValue(item);
        }

        private static IEnumerable<object> AsEnumerable(object? value)
        {
            if (value == null) yield break;
            if (value is string) { yield return value; yield break; }
            if (value is IEnumerable enumerable)
            {
                foreach (object? item in enumerable)
                    if (item != null) yield return item;
                yield break;
            }
            yield return value;
        }

        private static string DescribeThreat(object item)
        {
            string family = Convert.ToString(GetValue(item, "Family")) ?? "Threat";
            string path = Convert.ToString(GetValue(item, "CandidatePath"))
                       ?? Convert.ToString(GetValue(item, "FilePath"))
                       ?? Convert.ToString(GetValue(item, "TargetDir"))
                       ?? string.Empty;
            int confidence = ToInt(GetValue(item, "ConfidenceScore"));
            return $"{family} ({confidence}% confidence){(string.IsNullOrWhiteSpace(path) ? string.Empty : $" — {path}")}";
        }

        private static int ToInt(object? value) => value == null ? 0 : Convert.ToInt32(value);
        private static long ToLong(object? value) => value == null ? 0L : Convert.ToInt64(value);
        private static bool ToBool(object? value) => value != null && Convert.ToBoolean(value);

        private static void ThrowIfPowerShellFailed(PowerShell ps, string operation)
        {
            if (!ps.HadErrors) return;
            string errors = string.Join(" | ", ps.Streams.Error.Select(e => e.ToString()));
            throw new InvalidOperationException($"{operation} failed: {errors}");
        }

        private void EnsureReady()
        {
            if (!IsEngineInitialized || _runspace == null)
                throw new InvalidOperationException(string.IsNullOrWhiteSpace(LastError) ? "VaultGuard engine is offline." : LastError);
        }

        public void Log(string message, bool isError = false)
        {
            OnLogReceived?.Invoke($"[{DateTime.Now:HH:mm:ss}] {message}", isError);
        }

        public void Dispose()
        {
            try { _runspace?.Close(); } catch { }
            try { _runspace?.Dispose(); } catch { }
            _engineLock.Dispose();
        }
    }
}
