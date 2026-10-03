using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using VaultGuard360.Services;

namespace VaultGuard360.ViewModels
{
    public class ScanViewModel : INotifyPropertyChanged
    {
        private string _scanPath = @"C:\";
        private int _cleanCount;
        private int _suspiciousCount;
        private int _infectedCount;
        private bool _isDryRun = true;
        private bool _isScanning;
        private string _logOutput = "VaultGuard engine ready. Select a target and start a scan.\n";
        private string _scanStatus = "Ready";

        public string ScanPath { get => _scanPath; set { _scanPath = value; OnPropertyChanged(); } }
        public int CleanCount { get => _cleanCount; set { _cleanCount = value; OnPropertyChanged(); } }
        public int SuspiciousCount { get => _suspiciousCount; set { _suspiciousCount = value; OnPropertyChanged(); } }
        public int InfectedCount { get => _infectedCount; set { _infectedCount = value; OnPropertyChanged(); } }
        public bool IsDryRun { get => _isDryRun; set { _isDryRun = value; OnPropertyChanged(); } }
        public bool IsScanning { get => _isScanning; set { _isScanning = value; OnPropertyChanged(); } }
        public string LogOutput { get => _logOutput; set { _logOutput = value; OnPropertyChanged(); } }
        public string ScanStatus { get => _scanStatus; set { _scanStatus = value; OnPropertyChanged(); } }

        public ScanViewModel()
        {
            EngineService.Instance.OnLogReceived += (message, isError) =>
            {
                App.Current?.Dispatcher.Invoke(() => LogOutput += message + Environment.NewLine);
            };
        }

        public async Task ExecuteUnifiedLifecycleScanAsync()
        {
            if (IsScanning) return;
            IsScanning = true;
            ScanStatus = IsDryRun ? "Scanning" : "Scanning and remediating";
            LogOutput += $"\n[{DateTime.Now:HH:mm:ss}] Target: {ScanPath}\n";

            try
            {
                var scan = await EngineService.Instance.ScanAsync(new[] { ScanPath }, true);
                InfectedCount = scan.ThreatsFound;
                SuspiciousCount = scan.SuspiciousCount;
                CleanCount = Math.Max(0, scan.TotalScanned - scan.ThreatsFound - scan.SuspiciousCount);

                if (!IsDryRun && scan.ThreatsFound > 0)
                {
                    ScanStatus = "Remediating detected threats";
                    var remediation = await EngineService.Instance.RemediateAsync(new[] { ScanPath }, false);
                    NotificationService.Instance.AddNotification(
                        "Remediation complete",
                        $"{remediation.ThreatsRemediated} threat(s) remediated; {remediation.FilesRestored} file(s) restored.",
                        false);
                }

                ScanStatus = scan.ThreatsFound == 0 ? "No active threat detected" : $"{scan.ThreatsFound} threat(s) detected";
                NotificationService.Instance.AddNotification(
                    "Scan complete",
                    $"Scanned {scan.TotalScanned:N0} executable files. {scan.ThreatsFound} infected, {scan.SuspiciousCount} suspicious.",
                    scan.ThreatsFound > 0);
            }
            catch (Exception ex)
            {
                ScanStatus = "Scan failed";
                LogOutput += $"[{DateTime.Now:HH:mm:ss}] ERROR: {ex.Message}\n";
                NotificationService.Instance.AddNotification("Scan failed", ex.Message, true);
            }
            finally
            {
                IsScanning = false;
            }
        }

        public Task StartHeuristicScan() => ExecuteUnifiedLifecycleScanAsync();

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
