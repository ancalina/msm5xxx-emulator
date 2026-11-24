using System.Runtime.InteropServices;
using System.Text.Json;

namespace Msm5xxx.Desktop;

internal sealed record InstallPreferences(bool Completed = false, bool Automatic = true)
{
    internal static string StateDirectory => Environment.GetEnvironmentVariable("MSM5XXX_STATE_DIR") ??
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MSM5xxx");
    private static string FileName => Path.Combine(StateDirectory, "updates.json");

    internal static InstallPreferences Load()
    {
        try { return JsonSerializer.Deserialize<InstallPreferences>(File.ReadAllText(FileName)) ?? new(); }
        catch (FileNotFoundException) { return new(); }
        catch (DirectoryNotFoundException) { return new(); }
    }

    internal void Save()
    {
        Directory.CreateDirectory(StateDirectory);
        File.WriteAllText(FileName + ".tmp", JsonSerializer.Serialize(this));
        File.Move(FileName + ".tmp", FileName, overwrite: true);
    }

    internal static void CreateDesktopShortcut()
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "MSM5xxx Emulator.lnk");
        if (File.Exists(path)) throw new IOException("A desktop shortcut with this name already exists.");
        var shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!);
        try
        {
            dynamic shortcut = shell!.GetType().InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod,
                null, shell, [path])!;
            // Velopack keeps the current directory stable across updates.
            shortcut.TargetPath = Path.Combine(AppContext.BaseDirectory, "MSM5xxx.Desktop.exe");
            shortcut.Save();
            Marshal.FinalReleaseComObject(shortcut);
        }
        finally { if (shell is not null) Marshal.FinalReleaseComObject(shell); }
    }

    internal static void BeforeUninstall()
    {
        var shortcut = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "MSM5xxx Emulator.lnk");
        if (File.Exists(shortcut))
        {
            var shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!);
            try
            {
                dynamic link = shell!.GetType().InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod, null, shell, [shortcut])!;
                var target = Path.Combine(AppContext.BaseDirectory, "MSM5xxx.Desktop.exe");
                if (string.Equals((string)link.TargetPath, target, StringComparison.OrdinalIgnoreCase)) File.Delete(shortcut);
                Marshal.FinalReleaseComObject(link);
            }
            finally { if (shell is not null) Marshal.FinalReleaseComObject(shell); }
        }
        if (!Directory.Exists(StateDirectory)) return;
        // shortcut: Velopack limits this hook to 30 seconds; use a separate native helper if a longer decision window is needed.
        // A timeout or a closed prompt preserves data; only an explicit Yes removes it.
        if (MessageBox(0, "Delete your MSM5xxx library, settings and saved states? Firmware source files are kept.",
            "Uninstall MSM5xxx Emulator", 0x00000004 | 0x00000100 | 0x00000020) == 6)
            Directory.Delete(StateDirectory, recursive: true);
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "MessageBoxW")]
    private static extern int MessageBox(nint window, string text, string caption, uint type);
}
