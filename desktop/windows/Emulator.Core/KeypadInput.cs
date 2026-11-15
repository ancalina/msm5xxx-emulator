using System.Diagnostics;

namespace Msm5xxx.Desktop.Core;

public static class KeypadMapping
{
    public static int? Resolve(IReadOnlyDictionary<string, int> keyboard, int virtualKey, bool shift = false,
        bool control = false, bool alt = false, bool windows = false)
    {
        if (control || alt || windows) return null;
        var symbol = virtualKey switch
        {
            0x26 => "Up", 0x28 => "Down", 0x25 => "Left", 0x27 => "Right", 0x0D => "Return", 0x1B => "Escape",
            0x6B => "KP_Add", 0x6D => "KP_Subtract", 0xBB when shift => "plus", 0xBD when !shift => "minus",
            >= 0x30 and <= 0x39 when !shift => ((char)virtualKey).ToString(),
            >= 0x60 and <= 0x69 => (virtualKey - 0x60).ToString(),
            _ => ""
        };
        return keyboard.TryGetValue(symbol, out var bit) ? bit : null;
    }

    public static bool IsAvailable(int bit, IReadOnlySet<int> firmwareKeys, IReadOnlyDictionary<int, int?> mappings) =>
        firmwareKeys.Contains(bit) || (mappings.TryGetValue(bit, out var code) && code.HasValue);
}

/// <summary>Combines pointer and keyboard ownership, debounces repeats, and preserves minimum hold time.</summary>
public sealed class KeypadInput(Func<int, bool, Task> send, int holdMilliseconds)
{
    private sealed class Held
    {
        public HashSet<string> Sources { get; } = [];
        public long Started { get; set; }
    }
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly Dictionary<int, Held> held = [];

    public async Task PressAsync(int bit, string source)
    {
        await gate.WaitAsync();
        try
        {
            if (held.TryGetValue(bit, out var existing)) { existing.Sources.Add(source); return; }
            await send(bit, true);
            var key = new Held { Started = Stopwatch.GetTimestamp() };
            key.Sources.Add(source);
            held.Add(bit, key);
        }
        finally { gate.Release(); }
    }

    public async Task ReleaseAsync(int bit, string source)
    {
        Held? key;
        await gate.WaitAsync();
        try
        {
            if (!held.TryGetValue(bit, out key) || !key.Sources.Remove(source) || key.Sources.Count != 0) return;
        }
        finally { gate.Release(); }
        await FinishReleaseAsync(bit, key);
    }

    private async Task FinishReleaseAsync(int bit, Held key)
    {
        var remaining = holdMilliseconds - Stopwatch.GetElapsedTime(key.Started).TotalMilliseconds;
        while (remaining > 0)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(Math.Ceiling(remaining)));
            remaining = holdMilliseconds - Stopwatch.GetElapsedTime(key.Started).TotalMilliseconds;
        }
        await gate.WaitAsync();
        try
        {
            if (!held.TryGetValue(bit, out var current) || current != key || current.Sources.Count != 0) return;
            try { await send(bit, false); }
            finally { held.Remove(bit); }
        }
        finally { gate.Release(); }
    }

    public async Task ReleaseAllAsync()
    {
        KeyValuePair<int, Held>[] keys;
        await gate.WaitAsync();
        try
        {
            keys = held.ToArray();
            foreach (var key in keys) key.Value.Sources.Clear();
        }
        finally { gate.Release(); }
        await Task.WhenAll(keys.Select(key => FinishReleaseAsync(key.Key, key.Value)));
    }
}
