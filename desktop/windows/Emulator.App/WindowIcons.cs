using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Msm5xxx.Desktop;

internal static class WindowIcons
{
    private static readonly List<(WeakReference<Window> Window, WeakReference<TitleBar> Bar)> windows = [];
    private static readonly string settingsPath = Path.Combine(
        Environment.GetEnvironmentVariable("MSM5XXX_STATE_DIR") ??
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MSM5xxx"), "desktop-settings.json");
    public static bool Simple { get; private set; } = Read();
    private static bool Read()
    {
        try { return JsonSerializer.Deserialize<Dictionary<string, bool>>(File.ReadAllText(settingsPath))?.GetValueOrDefault("simple_icon") == true; }
        catch (Exception) { return false; }
    }
    public static void Register(Window window, TitleBar bar)
    {
        var reference = (new WeakReference<Window>(window), new WeakReference<TitleBar>(bar));
        windows.Add(reference);
        window.Closed += (_, _) => windows.Remove(reference);
        Apply(window, bar);
    }
    private static void Apply(Window window, TitleBar bar)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Branding", Simple ? "simple.ico" : "full.ico");
        window.AppWindow.SetIcon(path);
        bar.IconSource = null;
    }
    public static void SetSimple(bool simple)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(settingsPath)!);
        File.WriteAllText(settingsPath, JsonSerializer.Serialize(new Dictionary<string, bool> { ["simple_icon"] = simple }));
        Simple = simple;
        windows.RemoveAll(reference => !reference.Window.TryGetTarget(out _));
        foreach (var reference in windows) if (reference.Window.TryGetTarget(out var window) && reference.Bar.TryGetTarget(out var bar)) Apply(window, bar);
    }
}
