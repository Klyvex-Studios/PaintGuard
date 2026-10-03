using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using VaultGuard360.Services;

namespace VaultGuard360.ViewModels
{
    public class SettingsViewModel : INotifyPropertyChanged
    {
        private bool _isRemovableMediaProtectionEnabled;
        private bool _isApplyingProtection;

        public SettingsViewModel()
        {
            string policyState = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Klyvex Studios",
                "VaultGuard 360",
                "autorun-policy-state.json");
            _isRemovableMediaProtectionEnabled = File.Exists(policyState);
        }

        public bool IsRemovableMediaProtectionEnabled
        {
            get => _isRemovableMediaProtectionEnabled;
            set
            {
                if (_isRemovableMediaProtectionEnabled == value) return;
                _isRemovableMediaProtectionEnabled = value;
                OnPropertyChanged();
                _ = ApplyRemovableMediaProtectionAsync();
            }
        }

        public bool IsApplyingProtection { get => _isApplyingProtection; set { _isApplyingProtection = value; OnPropertyChanged(); } }
        public string EngineState => EngineService.Instance.EngineState;
        public string RuntimeMode => "In-process protected runspace";

        private string _contactName = string.Empty;
        private string _contactEmail = string.Empty;
        private string _contactSubject = "VaultGuard 360 Support Inquiry";
        private string _contactMessage = string.Empty;
        private string _supportStatus = string.Empty;
        private bool _isSending;

        public string ContactName { get => _contactName; set { _contactName = value; OnPropertyChanged(); } }
        public string ContactEmail { get => _contactEmail; set { _contactEmail = value; OnPropertyChanged(); } }
        public string ContactSubject { get => _contactSubject; set { _contactSubject = value; OnPropertyChanged(); } }
        public string ContactMessage { get => _contactMessage; set { _contactMessage = value; OnPropertyChanged(); } }
        public string SupportStatus { get => _supportStatus; set { _supportStatus = value; OnPropertyChanged(); } }
        public bool IsSending { get => _isSending; set { _isSending = value; OnPropertyChanged(); } }

        private async Task ApplyRemovableMediaProtectionAsync()
        {
            if (IsApplyingProtection || !EngineService.Instance.IsEngineInitialized) return;
            IsApplyingProtection = true;
            try
            {
                bool success = await EngineService.Instance.SetUsbProtectionAsync(IsRemovableMediaProtectionEnabled);
                SupportStatus = success
                    ? (IsRemovableMediaProtectionEnabled
                        ? "Removable-media vaccine and AutoRun hardening enabled."
                        : "VaultGuard removable-media protections reverted where VaultGuard owns the setting.")
                    : "The protection setting could not be fully applied.";
            }
            catch (Exception ex)
            {
                SupportStatus = $"Protection setting failed: {ex.Message}";
            }
            finally
            {
                IsApplyingProtection = false;
            }
        }

        public async Task SendSupportMessageAsync()
        {
            if (string.IsNullOrWhiteSpace(ContactEmail) || string.IsNullOrWhiteSpace(ContactMessage))
            {
                SupportStatus = "Please provide your email address and message.";
                return;
            }

            IsSending = true;
            SupportStatus = "Preparing your support message...";
            try
            {
                OpenMailClientFallback();
                await Task.CompletedTask;
            }
            finally
            {
                IsSending = false;
            }
        }

        private void OpenMailClientFallback()
        {
            try
            {
                const string supportAddress = "admin@highqsolidacademy.com";
                string body = $"VaultGuard 360 / Klyvex Studios\n\nFrom: {ContactName} ({ContactEmail})\n\n{ContactMessage}";
                string mailtoUri = $"mailto:{supportAddress}?subject={Uri.EscapeDataString(ContactSubject)}&body={Uri.EscapeDataString(body)}";
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(mailtoUri) { UseShellExecute = true });
                SupportStatus = "Opened your default mail client. A dedicated Klyvex support address can replace this fallback later.";
            }
            catch (Exception ex)
            {
                SupportStatus = $"Could not open the mail client: {ex.Message}";
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
