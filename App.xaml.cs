using System.Windows;
using VaultGuard360.Services;

namespace VaultGuard360
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            // Load the on-demand detection/remediation engine. The USB arrival watcher
            // remains a separate, explicit control and is not treated as a full
            // filesystem real-time antivirus service.
            EngineService.Instance.InitializeEmbeddedEngine();
        }

        protected override void OnExit(ExitEventArgs e)
        {
            try
            {
                if (EngineService.Instance.IsEngineInitialized && EngineService.Instance.IsUsbWatcherRunning)
                    EngineService.Instance.SetUsbWatcherAsync(false).GetAwaiter().GetResult();
            }
            catch { }
            EngineService.Instance.Dispose();
            base.OnExit(e);
        }
    }
}
