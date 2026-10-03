using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using VaultGuard360.Services;

namespace VaultGuard360.ViewModels
{
    public class DashboardViewModel : INotifyPropertyChanged
    {
        private string _systemStatus = EngineService.Instance.IsEngineInitialized ? "Engine ready" : "Engine offline";
        private string _statusDetail = EngineService.Instance.IsEngineInitialized ? "On-demand detection and recovery modules are online" : "Security engine is not running";
        private string _targetDrive = @"C:\";
        private int _quarantineCount;
        private int _lastScanFiles;
        private int _lastThreats;
        private bool _isBusy;

        public string SystemStatus { get => _systemStatus; set { _systemStatus = value; OnPropertyChanged(); } }
        public string StatusDetail { get => _statusDetail; set { _statusDetail = value; OnPropertyChanged(); } }
        public string TargetDrive { get => _targetDrive; set { _targetDrive = value; OnPropertyChanged(); } }
        public int QuarantineCount { get => _quarantineCount; set { _quarantineCount = value; OnPropertyChanged(); } }
        public int LastScanFiles { get => _lastScanFiles; set { _lastScanFiles = value; OnPropertyChanged(); } }
        public int LastThreats { get => _lastThreats; set { _lastThreats = value; OnPropertyChanged(); } }
        public bool IsBusy { get => _isBusy; set { _isBusy = value; OnPropertyChanged(); } }

        public DashboardViewModel()
        {
            EngineService.Instance.OnEngineStateChanged += (online, state) =>
            {
                App.Current?.Dispatcher.Invoke(() =>
                {
                    SystemStatus = online ? "Engine ready" : "Engine offline";
                    StatusDetail = online ? "On-demand detection and recovery modules are online" : "Security engine needs attention";
                });
            };
            _ = RefreshQuarantineCountAsync();
        }

        public async Task ExecuteQuickScanAsync()
        {
            if (IsBusy) return;
            IsBusy = true;
            StatusDetail = "Quick scan in progress";
            NotificationService.Instance.AddNotification("Quick scan started", "Scanning Program Files with live detectors.", false);

            try
            {
                var scan = await EngineService.Instance.ScanAsync(new[] { @"C:\Program Files" }, true);
                LastScanFiles = scan.TotalScanned;
                LastThreats = scan.ThreatsFound;
                StatusDetail = scan.ThreatsFound == 0 ? "No active threat detected in quick-scan scope" : $"{scan.ThreatsFound} threat(s) require review";
                NotificationService.Instance.AddNotification(
                    "Quick scan complete",
                    $"Scanned {scan.TotalScanned:N0} files; {scan.ThreatsFound} infected and {scan.SuspiciousCount} suspicious.",
                    scan.ThreatsFound > 0);
            }
            catch (Exception ex)
            {
                StatusDetail = "Quick scan failed";
                NotificationService.Instance.AddNotification("Quick scan failed", ex.Message, true);
            }
            finally
            {
                IsBusy = false;
                await RefreshQuarantineCountAsync();
            }
        }

        public async Task ExecuteRemediationAsync()
        {
            if (IsBusy) return;
            IsBusy = true;
            StatusDetail = "Remediation in progress";
            try
            {
                var result = await EngineService.Instance.RemediateAsync(new[] { TargetDrive }, false);
                StatusDetail = result.Message;
                NotificationService.Instance.AddNotification(
                    "Remediation complete",
                    $"{result.ThreatsRemediated} threat(s) remediated, {result.FilesRestored} file(s) restored, {result.PersistenceFixed} persistence item(s) repaired.",
                    !result.Success);
            }
            catch (Exception ex)
            {
                StatusDetail = "Remediation failed";
                NotificationService.Instance.AddNotification("Remediation failed", ex.Message, true);
            }
            finally
            {
                IsBusy = false;
                await RefreshQuarantineCountAsync();
            }
        }

        public async Task RefreshQuarantineCountAsync()
        {
            try
            {
                if (!EngineService.Instance.IsEngineInitialized) return;
                var records = await EngineService.Instance.GetQuarantineAsync();
                QuarantineCount = records.Count;
            }
            catch { }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
