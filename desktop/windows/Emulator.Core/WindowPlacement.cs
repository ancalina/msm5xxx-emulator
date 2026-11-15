namespace Msm5xxx.Desktop.Core;

public enum DockSide { None, Left, Right }

/// <summary>Portable placement rules for the secondary display window.</summary>
public static class WindowPlacement
{
    /// <summary>Clamps a proposed outer rectangle to a minimum size while preserving the opposite edge while sizing.</summary>
    public static DisplayRect EnforceMinimum(DisplayRect proposed, ContentSize minimum, int edge = 0)
    {
        ValidateSize(minimum);
        if (edge is < 0 or > 8) throw new ArgumentOutOfRangeException(nameof(edge));

        var minimumWidth = checked((int)Math.Ceiling(minimum.Width));
        var minimumHeight = checked((int)Math.Ceiling(minimum.Height));
        var width = Math.Max(proposed.Width, minimumWidth);
        var height = Math.Max(proposed.Height, minimumHeight);
        var x = proposed.X;
        var y = proposed.Y;

        // WM_SIZING preserves the opposite edge for left and top drags. Edge zero is
        // the programmatic placement path and keeps the requested top-left corner.
        if (edge is 1 or 4 or 7) x = checked(proposed.X + proposed.Width - width);
        if (edge is 3 or 4 or 5) y = checked(proposed.Y + proposed.Height - height);
        return new(x, y, width, height);
    }

    /// <summary>Places the secondary window beside the main window when possible, within a display work area.</summary>
    public static DisplayRect BesideWithinWorkArea(
        DisplayRect main,
        ContentSize secondaryOuter,
        DisplayRect workArea,
        int mainContentTopInset = 0)
    {
        var width = ToDimension(secondaryOuter.Width);
        var height = ToDimension(secondaryOuter.Height);
        if (workArea.Width <= 0 || workArea.Height <= 0)
            throw new ArgumentOutOfRangeException(nameof(workArea));
        if (mainContentTopInset < 0)
            throw new ArgumentOutOfRangeException(nameof(mainContentTopInset));

        var workRight = (long)workArea.X + workArea.Width;
        var workBottom = (long)workArea.Y + workArea.Height;
        var y = ClampOrigin((long)main.Y + mainContentTopInset, workArea.Y, workBottom, height);
        var right = (long)main.X + main.Width;
        if (FitsWorkArea(right, y, width, height, workArea.X, workArea.Y, workRight, workBottom))
            return new(checked((int)right), y, width, height);

        var left = (long)main.X - width;
        if (FitsWorkArea(left, y, width, height, workArea.X, workArea.Y, workRight, workBottom))
            return new(checked((int)left), y, width, height);

        // If neither side fits, overlap on the right and keep as much of the window in the work area as possible.
        var overlapX = ClampOrigin(right, workArea.X, workRight, width);
        return new(overlapX, y, width, height);
    }

    /// <summary>Returns the secondary window rectangle flush beside the main window.</summary>
    public static DisplayRect Docked(DisplayRect main, ContentSize secondaryOuter, DockSide side, int mainContentTopInset = 0)
    {
        ValidateSize(secondaryOuter);
        if (mainContentTopInset < 0) throw new ArgumentOutOfRangeException(nameof(mainContentTopInset));
        var width = ToDimension(secondaryOuter.Width);
        var height = ToDimension(secondaryOuter.Height);
        return side switch
        {
            DockSide.Left => new(checked(main.X - width), checked(main.Y + mainContentTopInset), width, height),
            DockSide.Right => new(checked(main.X + main.Width), checked(main.Y + mainContentTopInset), width, height),
            _ => throw new ArgumentOutOfRangeException(nameof(side), "A docked window must have a left or right side.")
        };
    }

    /// <summary>Finds a nearby side when the windows overlap vertically; otherwise returns None.</summary>
    public static DockSide SnapSide(DisplayRect main, DisplayRect secondary, int distance = 16, int mainContentTopInset = 0)
    {
        if (distance < 0) throw new ArgumentOutOfRangeException(nameof(distance));
        if (mainContentTopInset < 0) throw new ArgumentOutOfRangeException(nameof(mainContentTopInset));
        if (main.Width <= 0 || main.Height <= 0 || secondary.Width <= 0 || secondary.Height <= 0) return DockSide.None;

        var contentTop = (long)main.Y + mainContentTopInset;
        var contentBottom = (long)main.Y + main.Height;
        var secondaryBottom = (long)secondary.Y + secondary.Height;
        if (Math.Min(contentBottom, secondaryBottom) <= Math.Max(contentTop, secondary.Y)) return DockSide.None;

        var leftGap = Math.Abs((long)secondary.X + secondary.Width - main.X);
        var rightGap = Math.Abs((long)secondary.X - ((long)main.X + main.Width));
        var leftNear = leftGap <= distance;
        var rightNear = rightGap <= distance;
        if (!leftNear && !rightNear) return DockSide.None;
        return leftNear && (!rightNear || leftGap <= rightGap) ? DockSide.Left : DockSide.Right;
    }

    /// <summary>Adjusts a proposed outer rectangle to the LCD aspect ratio for a Win32 WM_SIZING edge (1..8).</summary>
    public static DisplayRect KeepAspect(DisplayRect proposed, int lcdW, int lcdH, int borderWidth, int borderHeight, int edge)
    {
        if (lcdW <= 0) throw new ArgumentOutOfRangeException(nameof(lcdW));
        if (lcdH <= 0) throw new ArgumentOutOfRangeException(nameof(lcdH));
        if (borderWidth < 0) throw new ArgumentOutOfRangeException(nameof(borderWidth));
        if (borderHeight < 0) throw new ArgumentOutOfRangeException(nameof(borderHeight));
        if (edge is < 1 or > 8) throw new ArgumentOutOfRangeException(nameof(edge));

        var proposedContentWidth = Math.Max(lcdW, proposed.Width - borderWidth);
        var proposedContentHeight = Math.Max(lcdH, proposed.Height - borderHeight);
        var horizontal = edge is 1 or 2;
        var vertical = edge is 3 or 6;
        int contentWidth;
        int contentHeight;

        if (horizontal)
        {
            contentWidth = proposedContentWidth;
            contentHeight = ScaleRound(contentWidth, lcdH, lcdW);
        }
        else if (vertical)
        {
            contentHeight = proposedContentHeight;
            contentWidth = ScaleRound(contentHeight, lcdW, lcdH);
        }
        else
        {
            var byWidthHeight = ScaleRound(proposedContentWidth, lcdH, lcdW);
            var byHeightWidth = ScaleRound(proposedContentHeight, lcdW, lcdH);
            var widthError = Math.Abs((double)byWidthHeight - proposedContentHeight);
            var heightError = Math.Abs((double)byHeightWidth - proposedContentWidth);
            if (widthError <= heightError)
            {
                contentWidth = proposedContentWidth;
                contentHeight = byWidthHeight;
            }
            else
            {
                contentWidth = byHeightWidth;
                contentHeight = proposedContentHeight;
            }
        }

        var width = checked(contentWidth + borderWidth);
        var height = checked(contentHeight + borderHeight);
        var x = proposed.X;
        var y = proposed.Y;
        // Left and top sizing preserve the opposite edge. For top-left, both far edges stay fixed.
        if (edge is 1 or 4 or 7) x = checked(proposed.X + proposed.Width - width);
        if (edge is 3 or 4 or 5) y = checked(proposed.Y + proposed.Height - height);
        return new(x, y, width, height);
    }

    private static int ScaleRound(int value, int numerator, int denominator) =>
        Math.Max(1, checked((int)Math.Round((double)value * numerator / denominator, MidpointRounding.AwayFromZero)));

    private static int ToDimension(double value)
    {
        if (!double.IsFinite(value) || value <= 0 || value > int.MaxValue) throw new ArgumentOutOfRangeException(nameof(value));
        return Math.Max(1, checked((int)Math.Round(value, MidpointRounding.AwayFromZero)));
    }

    private static int ClampOrigin(long desired, int workStart, long workEnd, int size)
    {
        var maximum = Math.Max((long)workStart, workEnd - size);
        return checked((int)Math.Clamp(desired, (long)workStart, maximum));
    }

    private static bool FitsWorkArea(long x, int y, int width, int height, int workLeft, int workTop, long workRight, long workBottom) =>
        x >= workLeft && x + width <= workRight && y >= workTop && (long)y + height <= workBottom;

    private static void ValidateSize(ContentSize size)
    {
        _ = ToDimension(size.Width);
        _ = ToDimension(size.Height);
    }
}
