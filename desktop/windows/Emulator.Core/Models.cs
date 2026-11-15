using System.Globalization;
using System.Text.Json;

namespace Msm5xxx.Desktop.Core;

public static class ProtocolJson
{
    public static readonly JsonSerializerOptions Options = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
    public static T As<T>(this JsonElement value) => value.Deserialize<T>(Options) ?? throw new InvalidDataException("Missing backend result.");
}

public sealed record FirmwareEntry(string Path, string Name, string? Model, string? Chipset, long? Size,
    bool Available, double? LastBooted, string? Thumbnail, string? Sha256);
public sealed record LibrarySnapshot(string[] Folders, FirmwareEntry[] Entries);
public sealed record KeyDefinition(string Label, int Bit, int Row, int Column, string Text, string AccessibleName);
public sealed record MetricDefinition(string Key, string Title, string Description);
public sealed record KeypadLayout(string Language, KeyDefinition[] Keys, MetricDefinition[] Metrics,
    Dictionary<string, int> Keyboard, int KeyHoldMs);
public sealed record SessionStarted(string Title, string Model, string Chipset, int Width, int Height, int[] Keys, int[]? NativeKeys = null);
public sealed record HardwareField(string Name, string Label, string Value, string[]? Choices);
public sealed record HardwareSection(string Title, HardwareField[] Fields);
public sealed record HardwareSettings(HardwareSection[] Sections);

public static class SettingsValidation
{
    public static bool NetworkTime(string value) => value.Length == 0 ||
        DateTime.TryParseExact(value, "yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out _);
}
