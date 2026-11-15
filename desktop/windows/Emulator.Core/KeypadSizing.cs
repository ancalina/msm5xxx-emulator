namespace Msm5xxx.Desktop.Core;

/// <summary>Calculations shared by the emulator keypad layout and its live counters.</summary>
public static class KeypadSizing
{
    /// <summary>
    /// Keeps column zero at its own natural width and makes every later keypad column
    /// as wide as the widest of those columns.
    /// </summary>
    public static double[] NaturalColumns(IReadOnlyList<double> naturalWidths)
    {
        ArgumentNullException.ThrowIfNull(naturalWidths);
        if (naturalWidths.Count < 2)
            throw new ArgumentOutOfRangeException(nameof(naturalWidths), "At least two keypad columns are required.");

        var maximum = 0d;
        for (var i = 0; i < naturalWidths.Count; i++)
        {
            var width = naturalWidths[i];
            if (!double.IsFinite(width) || width < 0)
                throw new ArgumentOutOfRangeException(nameof(naturalWidths), "Column widths must be finite and nonnegative.");
            if (i > 0) maximum = Math.Max(maximum, width);
        }

        var result = new double[naturalWidths.Count];
        result[0] = naturalWidths[0];
        Array.Fill(result, maximum, 1, result.Length - 1);
        return result;
    }

    /// <summary>
    /// Allocates the available width in physical pixels while keeping columns 1 onward
    /// exactly equal. Any indivisible remainder is assigned to column zero.
    /// </summary>
    public static double[] AllocateColumns(IReadOnlyList<double> naturalWidths, double availableWidth, double scale = 1)
    {
        var normalized = NaturalColumns(naturalWidths);
        if (!double.IsFinite(availableWidth) || availableWidth < 0)
            throw new ArgumentOutOfRangeException(nameof(availableWidth));
        if (!double.IsFinite(scale) || scale <= 0)
            throw new ArgumentOutOfRangeException(nameof(scale));

        var firstMinimum = (int)Math.Ceiling(normalized[0] * scale);
        var commonMinimum = (int)Math.Ceiling(normalized[1] * scale);
        var physicalWidth = Math.Max((int)Math.Floor(availableWidth * scale),
            firstMinimum + commonMinimum * (normalized.Length - 1));
        var sharedWidth = Math.Max(commonMinimum,
            (int)Math.Floor((physicalWidth - firstMinimum) / (double)(normalized.Length - 1)));
        var firstWidth = physicalWidth - sharedWidth * (normalized.Length - 1);

        var result = new double[normalized.Length];
        result[0] = firstWidth / scale;
        Array.Fill(result, sharedWidth / scale, 1, result.Length - 1);
        return result;
    }

    /// <summary>Shrinks a live counter's font to fit its column, down to a readable floor.</summary>
    public static double FitCounterFont(double measuredWidth, double availableWidth,
        double naturalFontSize = 11, double minimumFontSize = 8)
    {
        if (!double.IsFinite(measuredWidth) || measuredWidth < 0)
            throw new ArgumentOutOfRangeException(nameof(measuredWidth));
        if (!double.IsFinite(availableWidth) || availableWidth < 0)
            throw new ArgumentOutOfRangeException(nameof(availableWidth));
        if (!double.IsFinite(naturalFontSize) || naturalFontSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(naturalFontSize));
        if (!double.IsFinite(minimumFontSize) || minimumFontSize <= 0 || minimumFontSize > naturalFontSize)
            throw new ArgumentOutOfRangeException(nameof(minimumFontSize));

        if (measuredWidth <= availableWidth || measuredWidth == 0) return naturalFontSize;
        if (availableWidth == 0) return minimumFontSize;
        return Math.Max(minimumFontSize, naturalFontSize * availableWidth / measuredWidth);
    }
}
