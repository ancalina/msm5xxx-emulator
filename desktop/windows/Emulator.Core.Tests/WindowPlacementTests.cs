using Msm5xxx.Desktop.Core;
using Xunit;

namespace Msm5xxx.Desktop.Tests;

public sealed class WindowPlacementTests
{
    private static readonly DisplayRect Main = new(100, 200, 500, 400);

    [Fact]
    public void EnforceMinimumClampsBothDimensionsForProgrammaticPlacement()
    {
        Assert.Equal(new DisplayRect(20, 30, 400, 769),
            WindowPlacement.EnforceMinimum(new(20, 30, 200, 300), new(400, 769)));
    }

    [Fact]
    public void EnforceMinimumClampsWidthAndHeightIndependently()
    {
        Assert.Equal(new DisplayRect(20, 30, 400, 800),
            WindowPlacement.EnforceMinimum(new(20, 30, 200, 800), new(400, 769)));
        Assert.Equal(new DisplayRect(20, 30, 500, 769),
            WindowPlacement.EnforceMinimum(new(20, 30, 500, 300), new(400, 769)));
    }

    [Theory]
    [InlineData(1, -100, 200)]
    [InlineData(3, 100, -269)]
    [InlineData(4, -100, -269)]
    [InlineData(7, -100, 200)]
    public void EnforceMinimumPreservesOppositeEdgesForSizing(int edge, int expectedX, int expectedY)
    {
        Assert.Equal(new DisplayRect(expectedX, expectedY, 400, 769),
            WindowPlacement.EnforceMinimum(new(100, 200, 200, 300), new(400, 769), edge));
    }

    [Fact]
    public void EnforceMinimumRoundsFractionalMinimumUpAndLeavesLargerSizeAlone()
    {
        Assert.Equal(new DisplayRect(20, 30, 11, 21),
            WindowPlacement.EnforceMinimum(new(20, 30, 4, 5), new(10.2, 20.1)));
        Assert.Equal(new DisplayRect(20, 30, 500, 800),
            WindowPlacement.EnforceMinimum(new(20, 30, 500, 800), new(400, 769)));
    }

    [Fact]
    public void EnforceMinimumRejectsInvalidMinimumAndSizingEdge()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => WindowPlacement.EnforceMinimum(new(0, 0, 1, 1), new(0, 2)));
        Assert.Throws<ArgumentOutOfRangeException>(() => WindowPlacement.EnforceMinimum(new(0, 0, 1, 1), new(2, double.NaN)));
        Assert.Throws<ArgumentOutOfRangeException>(() => WindowPlacement.EnforceMinimum(new(0, 0, 1, 1), new(2, 2), -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => WindowPlacement.EnforceMinimum(new(0, 0, 1, 1), new(2, 2), 9));
    }

    [Theory]
    [InlineData(70, 220, 20, 100, DockSide.Left)]
    [InlineData(606, 220, 20, 100, DockSide.Right)]
    [InlineData(68, 220, 16, 100, DockSide.Left)]
    [InlineData(616, 220, 16, 100, DockSide.Right)]
    public void SnapSideAcceptsEitherSideWithinDistance(int x, int y, int distance, int height, DockSide expected)
    {
        Assert.Equal(expected, WindowPlacement.SnapSide(Main, new(x, y, 30, height), distance));
    }

    [Fact]
    public void SnapSideRejectsDistantOrVerticallyDisjointWindows()
    {
        Assert.Equal(DockSide.None, WindowPlacement.SnapSide(Main, new(50, 220, 30, 100)));
        Assert.Equal(DockSide.None, WindowPlacement.SnapSide(Main, new(606, 700, 30, 40)));
        Assert.Equal(DockSide.None, WindowPlacement.SnapSide(Main, new(606, 190, 30, 10), mainContentTopInset: 20));
    }

    [Theory]
    [InlineData(DockSide.Left, 10)]
    [InlineData(DockSide.Right, 600)]
    public void DockedPlacesAtSideAndAlignsToMainContent(DockSide side, int expectedX)
    {
        Assert.Equal(new DisplayRect(expectedX, 237, 90, 60),
            WindowPlacement.Docked(Main, new ContentSize(90, 60), side, mainContentTopInset: 37));
    }

    [Fact]
    public void DockedTracksMainWindowMovement()
    {
        var movedMain = new DisplayRect(300, 450, 500, 400);
        Assert.Equal(new DisplayRect(800, 462, 90, 60),
            WindowPlacement.Docked(movedMain, new ContentSize(90, 60), DockSide.Right, 12));
    }

    [Fact]
    public void PlacesToRightWhenTheSecondaryFitsThere()
    {
        var result = WindowPlacement.BesideWithinWorkArea(
            new(0, 0, 656, 1025), new(304, 249), new(0, 0, 1920, 1040), mainContentTopInset: 49);

        Assert.Equal(new DisplayRect(656, 49, 304, 249), result);
    }

    [Fact]
    public void UsesLeftSideWhenSecondaryDoesNotFitToTheRight()
    {
        var result = WindowPlacement.BesideWithinWorkArea(
            new(1400, 100, 500, 600), new(300, 249), new(0, 0, 1920, 1040), mainContentTopInset: 49);

        Assert.Equal(new DisplayRect(1100, 149, 300, 249), result);
    }

    [Fact]
    public void UsesRightSideWhenTheRememberedLeftPositionIsOffscreen()
    {
        // No saved side is passed in: on this display a right placement fits, while a left placement would not.
        var result = WindowPlacement.BesideWithinWorkArea(
            new(0, 0, 656, 1025), new(304, 249), new(0, 0, 1920, 1040), mainContentTopInset: 49);

        Assert.Equal(656, result.X);
        Assert.True(result.X >= 0 && result.X + result.Width <= 1920);
    }

    [Fact]
    public void OverlapsAtTheRightWhenNeitherSideFits()
    {
        var result = WindowPlacement.BesideWithinWorkArea(
            new(100, 20, 300, 300), new(400, 120), new(0, 0, 500, 400), mainContentTopInset: 5);

        Assert.Equal(new DisplayRect(100, 25, 400, 120), result);
    }

    [Fact]
    public void ClampsVerticalPlacementAndPreservesNegativeDisplayOrigins()
    {
        var bottomClamped = WindowPlacement.BesideWithinWorkArea(
            new(0, 950, 500, 80), new(300, 249), new(0, 0, 1920, 1040), mainContentTopInset: 49);
        var negativeOrigin = WindowPlacement.BesideWithinWorkArea(
            new(-1920, -900, 656, 800), new(304, 249), new(-1920, -1000, 1920, 1040), mainContentTopInset: 49);

        Assert.Equal(791, bottomClamped.Y);
        Assert.Equal(new DisplayRect(-1264, -851, 304, 249), negativeOrigin);
    }

    [Fact]
    public void KeepsAnOversizedSecondaryAtTheNearestWorkAreaOrigin()
    {
        var result = WindowPlacement.BesideWithinWorkArea(
            new(100, 20, 300, 100), new(700, 800), new(0, 0, 500, 400), mainContentTopInset: 5);

        Assert.Equal(new DisplayRect(0, 0, 700, 800), result);
    }

    [Fact]
    public void RejectsInvalidWorkAreaAndInset()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => WindowPlacement.BesideWithinWorkArea(Main, new(90, 60), new(0, 0, 0, 200)));
        Assert.Throws<ArgumentOutOfRangeException>(() => WindowPlacement.BesideWithinWorkArea(Main, new(90, 60), new(0, 0, 500, 500), -1));
    }

    [Fact]
    public void HorizontalSizingPreservesFixedLeftAndTop()
    {
        var result = WindowPlacement.KeepAspect(new(40, 50, 336, 219), 4, 3, 16, 39, edge: 2);
        Assert.Equal(new DisplayRect(40, 50, 336, 279), result);
    }

    [Fact]
    public void VerticalSizingPreservesBottomAndLeft()
    {
        var result = WindowPlacement.KeepAspect(new(40, 50, 216, 179), 4, 3, 16, 39, edge: 3);
        Assert.Equal(40, result.X);
        Assert.Equal(229, result.Y + result.Height);
        Assert.Equal(203, result.Width);
        Assert.Equal(179, result.Height);
    }

    [Fact]
    public void CornerSizingChoosesNearestAspectProjectionAndKeepsOppositeCorner()
    {
        // Proposed content 310x230 is closer to the width-driven 310x233 result.
        var result = WindowPlacement.KeepAspect(new(40, 50, 326, 269), 4, 3, 16, 39, edge: 4);
        Assert.Equal(new DisplayRect(40, 47, 326, 272), result);
        Assert.Equal(366, result.X + result.Width);
        Assert.Equal(319, result.Y + result.Height);
    }

    [Fact]
    public void SizingEnforcesOneLcdPixelMinimum()
    {
        var result = WindowPlacement.KeepAspect(new(80, 90, 3, 3), 128, 64, 16, 30, edge: 6);
        Assert.Equal(144, result.Width);
        Assert.Equal(94, result.Height);
        Assert.Equal(90, result.Y);
    }
}
