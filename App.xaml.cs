using System.Windows;
using VaultGuard360.Services;

namespace VaultGuard360
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            EngineService.Instance.InitializeEmbeddedEngine();
            if (EngineService.Instance.IsEngineInitialized)
                _ = EngineService.Instance.SetUsbWatcherAsync(true);
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
