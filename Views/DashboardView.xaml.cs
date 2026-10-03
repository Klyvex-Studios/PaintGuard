using System.Windows;
using System.Windows.Controls;
using VaultGuard360.ViewModels;

namespace VaultGuard360.Views
{
    public partial class DashboardView : UserControl
    {
        public DashboardView()
        {
            InitializeComponent();
        }

        private async void QuickScan_Click(object sender, RoutedEventArgs e)
        {
            if (DataContext is DashboardViewModel vm)
                await vm.ExecuteQuickScanAsync();
        }

        private async void Remediate_Click(object sender, RoutedEventArgs e)
        {
            if (DataContext is DashboardViewModel vm)
                await vm.ExecuteRemediationAsync();
        }
    }
}
