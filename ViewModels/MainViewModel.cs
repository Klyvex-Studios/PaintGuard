using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using VaultGuard360.Services;

namespace VaultGuard360.ViewModels
{
    public class MainViewModel : INotifyPropertyChanged
    {
        private object _currentView;
        private string _activeTab = "Dashboard";
        private bool _isNotificationFlyoutOpen;
        private bool _isUsbFlyoutOpen;
        private bool _isShieldFlyoutOpen;
        private bool _isHeuristicFlyoutOpen;
        private bool _isRealTimeProtected = EngineService.Instance.IsUsbWatcherRunning;

        public DashboardViewModel DashboardVM { get; } = new();
        public ScanViewModel ScanVM { get; } = new();
        public VaultViewModel VaultVM { get; } = new();
        public SettingsViewModel SettingsVM { get; } = new();
        public NotificationService NotificationService => NotificationService.Instance;
        public EngineService Engine => EngineService.Instance;

        public object CurrentView { get => _currentView; set { _currentView = value; OnPropertyChanged(); } }
        public string ActiveTab { get => _activeTab; set { _activeTab = value; OnPropertyChanged(); } }
        public bool IsNotificationFlyoutOpen { get => _isNotificationFlyoutOpen; set { _isNotificationFlyoutOpen = value; OnPropertyChanged(); } }
        public bool IsUsbFlyoutOpen { get => _isUsbFlyoutOpen; set { _isUsbFlyoutOpen = value; OnPropertyChanged(); } }
        public bool IsShieldFlyoutOpen { get => _isShieldFlyoutOpen; set { _isShieldFlyoutOpen = value; OnPropertyChanged(); } }
        public bool IsHeuristicFlyoutOpen { get => _isHeuristicFlyoutOpen; set { _isHeuristicFlyoutOpen = value; OnPropertyChanged(); } }
        public bool IsRealTimeProtected { get => _isRealTimeProtected; set { _isRealTimeProtected = value; OnPropertyChanged(); } }

        public MainViewModel()
        {
            _currentView = DashboardVM;
        }

        public void Navigate(string tabName)
        {
            ActiveTab = tabName;
            CloseFlyouts();
            CurrentView = tabName switch
            {
                "ScanCenter" => ScanVM,
                "VaultManager" => VaultVM,
                "Settings" => SettingsVM,
                _ => DashboardVM
            };
            if (tabName == "VaultManager") _ = VaultVM.RefreshAsync();
        }

        public void ToggleNotifications() => ToggleFlyout(nameof(IsNotificationFlyoutOpen));
        public void ToggleUsbStatus() => ToggleFlyout(nameof(IsUsbFlyoutOpen));
        public void ToggleShieldStatus() => ToggleFlyout(nameof(IsShieldFlyoutOpen));
        public void ToggleHeuristicStatus() => ToggleFlyout(nameof(IsHeuristicFlyoutOpen));

        public async Task ToggleRealTimeProtectionAsync()
        {
            if (!EngineService.Instance.IsEngineInitialized)
            {
                NotificationService.Instance.AddNotification("Protection engine offline", EngineService.Instance.LastError, true);
                return;
            }

            bool target = !IsRealTimeProtected;
            try
            {
                bool ok = await EngineService.Instance.SetUsbWatcherAsync(target);
                if (ok)
                {
                    IsRealTimeProtected = target;
                    NotificationService.Instance.AddNotification(
                        "USB live monitoring",
                        target ? "USB arrival monitoring enabled." : "USB arrival monitoring paused.",
                        false);
                }
            }
            catch (System.Exception ex)
            {
                NotificationService.Instance.AddNotification("Protection change failed", ex.Message, true);
            }
        }

        private void ToggleFlyout(string property)
        {
            bool next = property switch
            {
                nameof(IsNotificationFlyoutOpen) => !IsNotificationFlyoutOpen,
                nameof(IsUsbFlyoutOpen) => !IsUsbFlyoutOpen,
                nameof(IsShieldFlyoutOpen) => !IsShieldFlyoutOpen,
                nameof(IsHeuristicFlyoutOpen) => !IsHeuristicFlyoutOpen,
                _ => false
            };
            CloseFlyouts();
            switch (property)
            {
                case nameof(IsNotificationFlyoutOpen): IsNotificationFlyoutOpen = next; break;
                case nameof(IsUsbFlyoutOpen): IsUsbFlyoutOpen = next; break;
                case nameof(IsShieldFlyoutOpen): IsShieldFlyoutOpen = next; break;
                case nameof(IsHeuristicFlyoutOpen): IsHeuristicFlyoutOpen = next; break;
            }
        }

        public void CloseFlyouts()
        {
            IsNotificationFlyoutOpen = false;
            IsUsbFlyoutOpen = false;
            IsShieldFlyoutOpen = false;
            IsHeuristicFlyoutOpen = false;
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
