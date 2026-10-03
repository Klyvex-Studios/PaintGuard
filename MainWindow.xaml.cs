using System.Windows;
using System.Windows.Input;
using VaultGuard360.ViewModels;

namespace VaultGuard360
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            MaxHeight = SystemParameters.WorkArea.Height;
            MaxWidth = SystemParameters.WorkArea.Width;
        }

        private MainViewModel? VM => DataContext as MainViewModel;

        private void NavDashboard_Click(object sender, RoutedEventArgs e) => VM?.Navigate("Dashboard");
        private void NavScanCenter_Click(object sender, RoutedEventArgs e) => VM?.Navigate("ScanCenter");
        private void NavVaultManager_Click(object sender, RoutedEventArgs e) => VM?.Navigate("VaultManager");
        private void NavSettings_Click(object sender, RoutedEventArgs e) => VM?.Navigate("Settings");

        private void ToggleNotifications_Click(object sender, RoutedEventArgs e) => VM?.ToggleNotifications();
        private void ToggleUsb_Click(object sender, RoutedEventArgs e) => VM?.ToggleUsbStatus();
        private void ToggleShield_Click(object sender, RoutedEventArgs e) => VM?.ToggleShieldStatus();
        private void ToggleHeuristic_Click(object sender, RoutedEventArgs e) => VM?.ToggleHeuristicStatus();

        private async void ToggleProtection_Click(object sender, RoutedEventArgs e)
        {
            if (VM != null) await VM.ToggleRealTimeProtectionAsync();
        }

        private async void QuickScanTop_Click(object sender, RoutedEventArgs e)
        {
            if (VM == null) return;
            VM.Navigate("Dashboard");
            await VM.DashboardVM.ExecuteQuickScanAsync();
        }

        private void Header_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2)
            {
                ToggleMaximize();
                return;
            }
            if (e.LeftButton == MouseButtonState.Pressed && WindowState != WindowState.Maximized)
                DragMove();
        }

        private void MinimizeWindow_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
        private void MaximizeWindow_Click(object sender, RoutedEventArgs e) => ToggleMaximize();
        private void CloseWindow_Click(object sender, RoutedEventArgs e) => Close();

        private void ToggleMaximize()
        {
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        }
    }
}
