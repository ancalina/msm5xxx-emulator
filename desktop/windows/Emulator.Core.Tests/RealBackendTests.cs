using Msm5xxx.Desktop.Core;
using Xunit;

namespace Msm5xxx.Desktop.Tests;

public sealed class FirmwareFactAttribute : FactAttribute
{
    public FirmwareFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("MSM5XXX_TEST_FIRMWARE") is null)
            Skip = "Set MSM5XXX_TEST_FIRMWARE, MSM5XXX_BUNDLE, MSM5XXX_QEMU and MSM5XXX_PYTHON to run a real session.";
    }
}

public class RealBackendTests
{
    [FirmwareFact]
    [Trait("Category", "RealBackend")]
    public async Task BootsFirmwarePollsFramesAcceptsInputAndStops()
    {
        var options = BackendOptions.Discover();
        Assert.NotNull(options.StateDirectory);
        await using var client = await BackendClient.StartAsync(options);
        var layout = (await client.CallAsync("ui.layout")).As<KeypadLayout>();
        Assert.NotEmpty(layout.Keys);
        var firmware = Environment.GetEnvironmentVariable("MSM5XXX_TEST_FIRMWARE")!;
        await client.CallAsync("library.add_file", new { path = firmware });
        var library = (await client.CallAsync("library.scan")).As<LibrarySnapshot>();
        Assert.Contains(library.Entries, entry => entry.Path == firmware && entry.Available && entry.Size > 0);
        await client.CallAsync("session.open", new { firmware });
        var start = (await client.CallAsync("session.start")).As<SessionStarted>();
        Assert.NotEmpty(start.Title);
        Assert.NotNull(start.NativeKeys);
        Assert.All(start.NativeKeys, bit => Assert.Contains(bit, start.Keys));
        RgbFrame? image = null;
        for (var n = 0; n < 300; n++)
        {
            var frame = await client.CallAsync("session.frame", new { since = -1, secondary_since = -1 });
            Assert.True(frame.GetProperty("running").GetBoolean());
            if (frame.TryGetProperty("rgb", out var rgb) && frame.GetProperty("seq").GetInt64() > 0)
                image = new(frame.GetProperty("width").GetInt32(), frame.GetProperty("height").GetInt32(), rgb.GetBytesFromBase64());
            if (image is not null && n > 20) break;
            await Task.Delay(100);
        }
        Assert.NotNull(image);
        Assert.Equal(image.Width * image.Height * 3, image.Rgb.Length);
        Assert.Equal(image.Width * image.Height * 4, image.Render(image.Width, image.Height).Length);
        var state = await client.CallAsync("session.state");
        Assert.True(state.GetProperty("running").GetBoolean());
        Assert.True(state.TryGetProperty("metrics", out _));
        Assert.NotEmpty((await client.CallAsync("session.settings")).As<HardwareSettings>().Sections);
        if (start.Keys.Length > 0)
        {
            var input = new KeypadInput(async (bit, pressed) => { await client.CallAsync("session.key", new { bit, pressed }); }, layout.KeyHoldMs);
            await input.PressAsync(start.Keys[0], "test");
            await input.ReleaseAllAsync();
        }
        await client.CallAsync("session.stop");
        Assert.False((await client.CallAsync("session.state")).GetProperty("running").GetBoolean());
        library = (await client.CallAsync("library.scan")).As<LibrarySnapshot>();
        Assert.Contains(library.Entries, entry => entry.Path == firmware && entry.LastBooted > 0 && File.Exists(entry.Thumbnail));
    }
}
