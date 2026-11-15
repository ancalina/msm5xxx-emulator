using Msm5xxx.Desktop.Core;
using Xunit;

namespace Msm5xxx.Desktop.Core.Tests;

public class KeypadSizingTests
{
    [Fact]
    public void NaturalColumnsKeepsFirstIndependentAndEqualizesRemainingColumns()
    {
        Assert.Equal(new[] { 62d, 52d, 52d, 52d }, KeypadSizing.NaturalColumns([62, 44, 52, 38]));
        Assert.Equal(new[] { 40d, 62d, 62d, 62d }, KeypadSizing.NaturalColumns([40, 62, 52, 44]));
    }

    [Theory]
    [InlineData(0, 50, 11)]
    [InlineData(50, 50, 11)]
    [InlineData(100, 50, 8)] // The proportional size (5.5) is clamped to the readable floor.
    [InlineData(70, 35, 8)]
    public void FitCounterFontFitsOrHonorsTheFloor(double measured, double available, double expected)
    {
        Assert.Equal(expected, KeypadSizing.FitCounterFont(measured, available), 6);
    }

    [Fact]
    public void FitCounterFontShrinksProportionallyAndReturnsToNaturalSize()
    {
        Assert.Equal(9.9, KeypadSizing.FitCounterFont(110, 99), 6);
        Assert.Equal(11, KeypadSizing.FitCounterFont(110, 120));
        Assert.Equal(14, KeypadSizing.FitCounterFont(100, 100, naturalFontSize: 14, minimumFontSize: 10));
        Assert.Equal(10, KeypadSizing.FitCounterFont(200, 100, naturalFontSize: 14, minimumFontSize: 10));
    }

    [Fact]
    public void NaturalColumnsRejectsMissingOrInvalidWidths()
    {
        Assert.Throws<ArgumentNullException>(() => KeypadSizing.NaturalColumns(null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => KeypadSizing.NaturalColumns([10]));
        Assert.Throws<ArgumentOutOfRangeException>(() => KeypadSizing.NaturalColumns([10, -1]));
        Assert.Throws<ArgumentOutOfRangeException>(() => KeypadSizing.NaturalColumns([10, double.NaN]));
        Assert.Throws<ArgumentOutOfRangeException>(() => KeypadSizing.NaturalColumns([10, double.PositiveInfinity]));
    }

    [Fact]
    public void AllocateColumnsSharesPhysicalPixelsAndLeavesRemainderInFirstColumn()
    {
        Assert.Equal(new[] { 59d, 99d, 99d, 99d }, KeypadSizing.AllocateColumns([59, 65, 42, 51], 356));
        Assert.Equal(new[] { 61d, 157d, 157d, 157d }, KeypadSizing.AllocateColumns([59, 65, 42, 51], 532));
        Assert.Equal(new[] { 62d, 98d, 98d, 98d }, KeypadSizing.AllocateColumns([62, 44, 52, 38], 356));
    }

    [Fact]
    public void AllocateColumnsKeepsEqualPhysicalWidthsAtFractionalScale()
    {
        var widths = KeypadSizing.AllocateColumns([39.25, 42.5, 37, 40], 240.1, 1.25);
        Assert.Equal(widths[1] * 1.25, widths[2] * 1.25, 10);
        Assert.Equal(widths[2] * 1.25, widths[3] * 1.25, 10);
        Assert.Equal(300, Math.Round(widths.Sum() * 1.25));
    }

    [Fact]
    public void AllocateColumnsPreservesNaturalMinimumsWhenAvailableSpaceIsTooSmall()
    {
        Assert.Equal(new[] { 62d, 52d, 52d, 52d }, KeypadSizing.AllocateColumns([62, 44, 52, 38], 100));
    }

    [Fact]
    public void AllocateColumnsRejectsInvalidWidthAndScale()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => KeypadSizing.AllocateColumns([10, 20], -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => KeypadSizing.AllocateColumns([10, 20], double.PositiveInfinity));
        Assert.Throws<ArgumentOutOfRangeException>(() => KeypadSizing.AllocateColumns([10, 20], 40, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => KeypadSizing.AllocateColumns([10, 20], 40, double.NaN));
    }

    [Fact]
    public void FitCounterFontRejectsInvalidDimensionsAndLimits()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => KeypadSizing.FitCounterFont(-1, 10));
        Assert.Throws<ArgumentOutOfRangeException>(() => KeypadSizing.FitCounterFont(10, double.NaN));
        Assert.Throws<ArgumentOutOfRangeException>(() => KeypadSizing.FitCounterFont(10, 10, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => KeypadSizing.FitCounterFont(10, 10, 8, 9));
    }
}
