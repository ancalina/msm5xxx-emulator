using Microsoft.UI.Xaml;
using Msm5xxx.Desktop.Core;

namespace Msm5xxx.Desktop;

public partial class App : Application
{
    public static App Instance => (App)Current;
    public BackendOptions Options { get; } = BackendOptions.Discover();
    private readonly Dictionary<string, EmulatorWindow> sessions = new(StringComparer.OrdinalIgnoreCase);
    private LauncherWindow? launcher;

    public App()
    {
        UnhandledException += (_, args) =>
        {
            try
            {
                var directory = Environment.GetEnvironmentVariable("MSM5XXX_STATE_DIR") ?? AppContext.BaseDirectory;
                Directory.CreateDirectory(directory);
                File.AppendAllText(Path.Combine(directory, "desktop.log"), DateTimeOffset.Now + "\n" + args.Exception + "\n");
            }
            catch (Exception) { }
        };
        InitializeComponent();
    }

    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        launcher = new LauncherWindow();
        launcher.Activate();
        foreach (var path in Environment.GetCommandLineArgs().Skip(1))
            await launcher.ImportFromCommandLineAsync(path);
    }

    public void Open(FirmwareEntry firmware)
    {
        var path = Path.GetFullPath(firmware.Path);
        if (sessions.TryGetValue(path, out var existing)) { existing.Activate(); return; }
        var window = new EmulatorWindow(firmware);
        sessions.Add(path, window);
        window.Closed += (_, _) => { sessions.Remove(path); launcher?.RefreshAfterSession(); };
        window.Activate();
    }

    public async Task<bool> CloseSessionsAsync()
    {
        foreach (var window in sessions.Values.ToArray())
            if (!await window.ShutdownAndCloseAsync()) return false;
        return true;
    }

    internal async Task RefreshLanguagesAsync()
    {
        var windows = sessions.Values.ToArray();
        if (launcher is not null) { await launcher.RefreshLanguageAsync(); await launcher.RefreshSettingsLanguageAsync(); }
        foreach (var window in windows) { await window.RefreshLanguageAsync(); await window.RefreshSettingsLanguageAsync(); }
    }
}
