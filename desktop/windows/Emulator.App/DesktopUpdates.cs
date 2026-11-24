using Velopack;
using Velopack.Sources;

namespace Msm5xxx.Desktop;

internal sealed class DesktopUpdates
{
    internal static DesktopUpdates Instance { get; } = new();
    private readonly SemaphoreSlim checking = new(1, 1);
    private UpdateManager? manager;
    private UpdateManager Manager => manager ??= Environment.GetEnvironmentVariable("MSM5XXX_UPDATE_FEED") is { Length: > 0 } feed
        ? new UpdateManager(feed)
        : new UpdateManager(new GithubSource("https://github.com/ancalina/msm5xxx-emulator", null, false));
    internal bool Installed => Manager.IsInstalled;
    internal bool Ready => Manager.UpdatePendingRestart is not null;
    internal event Action? Changed;

    internal async Task<bool> CheckAsync()
    {
        await checking.WaitAsync();
        try
        {
            if (!Installed) throw new InvalidOperationException("Install the app with Setup before checking for updates.");
            var update = await Manager.CheckForUpdatesAsync();
            if (update is not null) await Manager.DownloadUpdatesAsync(update);
            Changed?.Invoke();
            return Ready;
        }
        finally { checking.Release(); }
    }

    internal async Task RestartAsync()
    {
        var update = Manager.UpdatePendingRestart;
        if (update is null) return;
        await App.Instance.CloseSessionsAsync();
        Manager.ApplyUpdatesAndRestart(update);
    }
}
