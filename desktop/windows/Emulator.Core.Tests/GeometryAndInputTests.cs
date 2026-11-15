using Msm5xxx.Desktop.Core;
using Xunit;

namespace Msm5xxx.Desktop.Tests;

public class GeometryAndInputTests
{
    [Fact]
    public void MissingFirmwareMetadataStillLoadsAsAnUnavailableRow()
    {
        using var json = System.Text.Json.JsonDocument.Parse("{\"folders\":[],\"entries\":[{\"path\":\"missing.bin\",\"name\":\"missing.bin\",\"model\":null,\"chipset\":null,\"size\":null,\"available\":false,\"last_booted\":null,\"thumbnail\":null,\"sha256\":null}]}");
        var entry = Assert.Single(json.RootElement.As<LibrarySnapshot>().Entries);
        Assert.False(entry.Available);
        Assert.Null(entry.Size);
    }

    [Theory]
    [InlineData(128, 128, 300, 384, 764)]
    [InlineData(176, 220, 320, 352, 820)]
    [InlineData(320, 240, 300, 320, 620)]
    public void OpensAtSmallestWholeScale(int w, int h, int minimum, double expectedWidth, double expectedHeight)
    {
        Assert.Equal(new ContentSize(expectedWidth, expectedHeight), DisplayGeometry.Initial(w, h, minimum, 320, 60));
    }

    [Fact]
    public void WorkAreaKeepsTheNaturalScaleWhenItFits()
    {
        Assert.Equal(new ContentSize(384, 764), DisplayGeometry.Initial(128, 128, 300, 320, 60, new(500, 800)));
    }

    [Fact]
    public void WorkAreaCapsX350ToTheLargestWholeScaleThatFits()
    {
        // Available content area = 1920×1040 work area minus 16×9 native frame pixels.
        Assert.Equal(new ContentSize(640, 1016), DisplayGeometry.Initial(128, 128, 600, 328, 48, new(1904, 1031)));
    }

    [Fact]
    public void ExactFitUsesTheLargestWholeScaleWithinBothDimensions()
    {
        Assert.Equal(new ContentSize(600, 1020), DisplayGeometry.Initial(128, 160, 600, 320, 60, new(512, 1020)));
    }

    [Fact]
    public void A640ChoosesFourTimesWhenFiveTimesExceedsWorkAreaHeight()
    {
        Assert.Equal(new ContentSize(640, 1020), DisplayGeometry.Initial(128, 160, 640, 320, 60, new(1904, 1031)));
    }

    [Fact]
    public void WidthCanBeTheLimitingWorkAreaDimension()
    {
        Assert.Equal(new ContentSize(600, 764), DisplayGeometry.Initial(128, 128, 600, 320, 60, new(384, 1000)));
    }

    [Fact]
    public void UsesFractionalLcdScaleWhenOneWholeScaleCannotFit()
    {
        Assert.Equal(new ContentSize(640, 400), DisplayGeometry.Initial(128, 160, 640, 320, 60, new(100, 400)));
    }

    [Fact]
    public void KeepsFixedControlsAndAtLeastOneLcdPixelWhenTheyExceedTheWorkArea()
    {
        Assert.Equal(new ContentSize(640, 381.25), DisplayGeometry.Initial(128, 160, 640, 320, 60, new(100, 200)));
    }

    [Fact]
    public void WidthResizePreservesAspectAndExtraHeightMakesSideBars()
    {
        Assert.Equal(1020, DisplayGeometry.HeightForWidth(512, 128, 160, 320, 60));
        Assert.Equal(new DisplayRect(0, 140, 256, 320), DisplayGeometry.Fit(128, 160, 256, 600));
        Assert.Equal(new DisplayRect(96, 0, 128, 160), DisplayGeometry.Fit(128, 160, 320, 160));
    }

    [Fact]
    public void PixelScalingUsesNearestNeighborAndBgra()
    {
        var image = new RgbFrame(2, 1, [255, 0, 0, 0, 255, 0]);
        Assert.Equal(new byte[] { 0, 0, 255, 255, 0, 0, 255, 255, 0, 255, 0, 255, 0, 255, 0, 255 }, image.Render(4, 2)[..16]);
        Assert.Throws<InvalidDataException>(() => new RgbFrame(2, 1, [0]).Render(4, 2));
    }

    [Theory]
    [InlineData(0x31, false, 11)]
    [InlineData(0x61, false, 11)]
    [InlineData(0x26, false, 1)]
    [InlineData(0xBB, true, 10)]
    [InlineData(0x31, true, null)]
    public void MapsProtocolSymbolsAndNumberPad(int key, bool shift, int? expected)
    {
        Dictionary<string, int> map = new() { ["1"] = 11, ["Up"] = 1, ["plus"] = 10 };
        Assert.Equal(expected, KeypadMapping.Resolve(map, key, shift));
        Assert.Null(KeypadMapping.Resolve(map, key, shift, control: true));
        Assert.Null(KeypadMapping.Resolve(map, key, shift, alt: true));
        Assert.Null(KeypadMapping.Resolve(map, key, shift, windows: true));
    }

    [Fact]
    public void AManualMappingEnablesAnAbsentFirmwareKey()
    {
        Assert.True(KeypadMapping.IsAvailable(2, new HashSet<int> { 1 }, new Dictionary<int, int?> { [2] = 0 }));
        Assert.False(KeypadMapping.IsAvailable(2, new HashSet<int> { 1 }, new Dictionary<int, int?> { [2] = null }));
    }

    [Fact]
    public async Task TapAndFocusLossRespectHoldAndCombineSources()
    {
        var events = new List<(int Bit, bool Pressed, long At)>();
        var input = new KeypadInput((bit, pressed) => { events.Add((bit, pressed, System.Diagnostics.Stopwatch.GetTimestamp())); return Task.CompletedTask; }, 80);
        await input.PressAsync(5, "keyboard");
        await input.PressAsync(5, "keyboard");
        await input.PressAsync(5, "pointer");
        await input.ReleaseAsync(5, "pointer");
        Assert.Single(events);
        await input.ReleaseAllAsync();
        Assert.Equal(2, events.Count);
        Assert.False(events[1].Pressed);
        Assert.True(System.Diagnostics.Stopwatch.GetElapsedTime(events[0].At, events[1].At).TotalMilliseconds >= 80);
        await input.ReleaseAsync(5, "keyboard");
        Assert.Equal(2, events.Count);
    }

    [Fact]
    public async Task RepressDuringDelayedReleaseDoesNotReleaseTheNewHold()
    {
        var events = new List<bool>();
        var input = new KeypadInput((_, pressed) => { events.Add(pressed); return Task.CompletedTask; }, 80);
        await input.PressAsync(1, "keyboard");
        var release = input.ReleaseAsync(1, "keyboard");
        await input.PressAsync(1, "pointer");
        await release;
        Assert.Equal(new[] { true }, events);
        await input.ReleaseAsync(1, "pointer");
        Assert.Equal(new[] { true, false }, events);
    }

    [Theory]
    [InlineData("", true)]
    [InlineData("2024-02-29 13:45", true)]
    [InlineData("2025-02-29 13:45", false)]
    [InlineData("2026-11-14 24:00", false)]
    [InlineData("2026-1-1 1:00", false)]
    public void ValidatesNetworkTime(string value, bool valid) => Assert.Equal(valid, SettingsValidation.NetworkTime(value));
}
