using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using VaultGuard360.Services;

namespace VaultGuard360.ViewModels
{
    public class VaultItem
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Path { get; set; } = string.Empty;
        public string Hash { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string DateAdded { get; set; } = string.Empty;
        public bool IsQuarantined { get; set; }
    }

    public class VaultViewModel : INotifyPropertyChanged
    {
        public ObservableCollection<VaultItem> BaselineAssets { get; } = new();
        public ObservableCollection<VaultItem> QuarantinedAssets { get; } = new();
        public ObservableCollection<VaultItem> GoldenVaultAssets { get; } = new();

        private string _statusMessage = "Loading protected storage...";
        private bool _isBusy;

        public string StatusMessage { get => _statusMessage; set { _statusMessage = value; OnPropertyChanged(); } }
        public bool IsBusy { get => _isBusy; set { _isBusy = value; OnPropertyChanged(); } }

        public VaultViewModel()
        {
            _ = RefreshAsync();
        }

        public async Task RefreshAsync()
        {
            if (!EngineService.Instance.IsEngineInitialized)
            {
                StatusMessage = "Protection engine is offline. Vault data is unavailable.";
                return;
            }

            IsBusy = true;
            try
            {
                var baseline = await EngineService.Instance.GetBaselineAsync(200);
                var quarantine = await EngineService.Instance.GetQuarantineAsync();

                BaselineAssets.Clear();
                foreach (var item in baseline)
                {
                    BaselineAssets.Add(new VaultItem
                    {
                        Name = item.FileName,
                        Path = item.OriginalPath,
                        Hash = ShortHash(item.Sha256),
                        Status = "VERIFIED"
                    });
                }

                QuarantinedAssets.Clear();
                foreach (var item in quarantine)
                {
                    QuarantinedAssets.Add(new VaultItem
                    {
                        Id = item.Id,
                        Name = item.OriginalName,
                        Path = item.OriginalPath,
                        Hash = ShortHash(item.Sha256),
                        Status = string.IsNullOrWhiteSpace(item.Reason) ? "ISOLATED" : item.Reason,
                        DateAdded = item.QuarantinedAt,
                        IsQuarantined = true
                    });
                }

                GoldenVaultAssets.Clear();
                GoldenVaultAssets.Add(new VaultItem
                {
                    Name = "Protected recovery store",
                    Path = @"C:\ProgramData\VaultGuard\GoldenVault",
                    Hash = "Engine-managed",
                    Status = "READY"
                });

                StatusMessage = $"{BaselineAssets.Count} baseline item(s) loaded; {QuarantinedAssets.Count} quarantined item(s).";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Vault refresh failed: {ex.Message}";
            }
            finally
            {
                IsBusy = false;
            }
        }

        public async Task CreateSystemBaselineSnapshotAsync()
        {
            if (IsBusy) return;
            IsBusy = true;
            StatusMessage = "Capturing independent clean-file baseline copies...";
            try
            {
                var result = await EngineService.Instance.CaptureBaselineAsync(new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\Downloads",
                    @"C:\Program Files"
                });
                StatusMessage = result.Message;
                NotificationService.Instance.AddNotification("Baseline capture", result.Message, !result.Success);
                await RefreshAsync();
            }
            catch (Exception ex)
            {
                StatusMessage = $"Baseline capture failed: {ex.Message}";
                NotificationService.Instance.AddNotification("Baseline capture failed", ex.Message, true);
            }
            finally
            {
                IsBusy = false;
            }
        }

        public async Task RunRemediationAsync()
        {
            if (IsBusy) return;
            IsBusy = true;
            StatusMessage = "Running live detection and remediation against C:\\...";
            try
            {
                var result = await EngineService.Instance.RemediateAsync(new[] { @"C:\" }, false);
                StatusMessage = $"{result.Message} {result.ThreatsRemediated} remediated; {result.FilesRestored} restored.";
                NotificationService.Instance.AddNotification("Remediation", StatusMessage, !result.Success);
                await RefreshAsync();
            }
            catch (Exception ex)
            {
                StatusMessage = $"Remediation failed: {ex.Message}";
                NotificationService.Instance.AddNotification("Remediation failed", ex.Message, true);
            }
            finally
            {
                IsBusy = false;
            }
        }

        public async Task RestoreQuarantinedItemAsync(VaultItem? item)
        {
            if (item == null || string.IsNullOrWhiteSpace(item.Id)) return;
            try
            {
                bool ok = await EngineService.Instance.RestoreQuarantineAsync(item.Id);
                NotificationService.Instance.AddNotification("Quarantine restore", ok ? $"Restored {item.Name}." : $"Could not restore {item.Name}.", !ok);
                await RefreshAsync();
            }
            catch (Exception ex)
            {
                NotificationService.Instance.AddNotification("Quarantine restore failed", ex.Message, true);
            }
        }

        public async Task DeleteQuarantinedItemAsync(VaultItem? item)
        {
            if (item == null || string.IsNullOrWhiteSpace(item.Id)) return;
            try
            {
                bool ok = await EngineService.Instance.DeleteQuarantineAsync(item.Id);
                NotificationService.Instance.AddNotification("Quarantine purge", ok ? $"Permanently deleted {item.Name}." : $"Could not delete {item.Name}.", !ok);
                await RefreshAsync();
            }
            catch (Exception ex)
            {
                NotificationService.Instance.AddNotification("Quarantine purge failed", ex.Message, true);
            }
        }

        public void SyncVaults() => _ = RefreshAsync();

        private static string ShortHash(string hash)
            => string.IsNullOrWhiteSpace(hash) ? "No hash" : $"SHA256: {(hash.Length > 16 ? hash[..16] + "..." : hash)}";

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
