namespace Msm5xxx.Desktop.Core;

public readonly record struct ContentSize(double Width, double Height);
public readonly record struct DisplayRect(int X, int Y, int Width, int Height);

public static class DisplayGeometry
{
    public static ContentSize Initial(int lcdWidth, int lcdHeight, double keypadWidth, double keypadHeight, double toolbarHeight, ContentSize? available = null)
    {
        Validate(lcdWidth, lcdHeight);
        ValidateNonnegative(keypadWidth, nameof(keypadWidth));
        ValidateNonnegative(keypadHeight, nameof(keypadHeight));
        ValidateNonnegative(toolbarHeight, nameof(toolbarHeight));
        if (available is { } bounds)
        {
            ValidateNonnegative(bounds.Width, nameof(available));
            ValidateNonnegative(bounds.Height, nameof(available));
        }

        var scale = Math.Max(1, Math.Ceiling(keypadWidth / lcdWidth));
        if (available is { } area)
        {
            var controlsHeight = keypadHeight + toolbarHeight;
            var heightScale = (area.Height - controlsHeight) / lcdHeight;
            var widthScale = area.Width / lcdWidth;
            if (lcdWidth * scale > area.Width || lcdHeight * scale + controlsHeight > area.Height)
            {
                var fittingScale = Math.Min(scale, Math.Min(widthScale, heightScale));
                if (fittingScale >= 1)
                    scale = Math.Floor(fittingScale);
                else
                {
                    // shortcut: physical work area smaller than natural controls, needs larger display
                    scale = Math.Max(1d / Math.Min(lcdWidth, lcdHeight), fittingScale);
                }
            }
        }
        var result = new ContentSize(Math.Max(keypadWidth, lcdWidth * scale), lcdHeight * scale + keypadHeight + toolbarHeight);
        if (!double.IsFinite(result.Width) || !double.IsFinite(result.Height))
            throw new ArgumentOutOfRangeException(nameof(keypadWidth), "Display geometry exceeds the supported range.");
        return result;
    }

    public static double HeightForWidth(double width, int lcdWidth, int lcdHeight, double keypadHeight, double toolbarHeight)
    {
        Validate(lcdWidth, lcdHeight);
        return width * lcdHeight / lcdWidth + keypadHeight + toolbarHeight;
    }

    public static DisplayRect Fit(int lcdWidth, int lcdHeight, int areaWidth, int areaHeight)
    {
        Validate(lcdWidth, lcdHeight);
        if (areaWidth <= 0 || areaHeight <= 0) return default;
        var scale = Math.Min((double)areaWidth / lcdWidth, (double)areaHeight / lcdHeight);
        var w = Math.Max(1, (int)Math.Round(lcdWidth * scale));
        var h = Math.Max(1, (int)Math.Round(lcdHeight * scale));
        return new((areaWidth - w) / 2, (areaHeight - h) / 2, w, h);
    }

    private static void Validate(int width, int height)
    {
        if (width <= 0 || height <= 0) throw new ArgumentOutOfRangeException(nameof(width));
    }

    private static void ValidateNonnegative(double value, string parameterName)
    {
        if (!double.IsFinite(value) || value < 0) throw new ArgumentOutOfRangeException(parameterName);
    }
}

public sealed record RgbFrame(int Width, int Height, byte[] Rgb)
{
    public byte[] Render(int width, int height)
    {
        if (width <= 0 || height <= 0 || (long)width * height > 16_777_216) throw new ArgumentOutOfRangeException(nameof(width));
        if (Width <= 0 || Height <= 0 || (long)Width * Height * 3 != Rgb.Length) throw new InvalidDataException("Invalid LCD frame.");
        var output = new byte[checked(width * height * 4)];
        for (var a = 3; a < output.Length; a += 4) output[a] = 255;
        var rect = DisplayGeometry.Fit(Width, Height, width, height);
        for (var y = 0; y < rect.Height; y++)
            for (var x = 0; x < rect.Width; x++)
            {
                var source = ((y * Height / rect.Height) * Width + x * Width / rect.Width) * 3;
                var target = ((y + rect.Y) * width + x + rect.X) * 4;
                output[target] = Rgb[source + 2]; output[target + 1] = Rgb[source + 1]; output[target + 2] = Rgb[source];
            }
        return output;
    }
}
