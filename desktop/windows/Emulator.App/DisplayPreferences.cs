using System.Text.Json;
using Msm5xxx.Desktop.Core;

namespace Msm5xxx.Desktop;

internal static class DisplayPreferences
{
    private static string PathName => Path.Combine(Environment.GetEnvironmentVariable("MSM5XXX_STATE_DIR") ??
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MSM5xxx"), "display-docking.json");
    private static Dictionary<string, DockSide> Read()
    {
        try { return JsonSerializer.Deserialize<Dictionary<string, DockSide>>(File.ReadAllText(PathName)) ?? []; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException) { return []; }
    }
    public static DockSide Get(string firmware)
    {
        var side = Read().GetValueOrDefault(firmware);
        return Enum.IsDefined(side) ? side : DockSide.None;
    }
    public static void Set(string firmware, DockSide side)
    {
        try
        {
            var values = Read(); values[firmware] = side;
            Directory.CreateDirectory(Path.GetDirectoryName(PathName)!);
            var temporary = PathName + ".tmp";
            File.WriteAllText(temporary, JsonSerializer.Serialize(values));
            File.Move(temporary, PathName, overwrite: true);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { System.Diagnostics.Debug.WriteLine(error); }
    }
}
