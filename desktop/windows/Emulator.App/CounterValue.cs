using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Msm5xxx.Desktop.Core;

namespace Msm5xxx.Desktop;

/// <summary>A single-line counter that fits inside its allocated keypad column.</summary>
internal sealed class CounterValue
{
    private const double NaturalFontSize = 11;
    private readonly string title;
    private readonly string description;
    private readonly TextBlock measure = new() { FontSize = NaturalFontSize, FontFamily = new FontFamily("Consolas") };
    private double naturalWidth;

    public Grid Host { get; } = new() { Height = 15 };

    public TextBlock View { get; } = new()
    {
        FontSize = NaturalFontSize, FontFamily = new FontFamily("Consolas"),
        Height = 15, TextWrapping = Microsoft.UI.Xaml.TextWrapping.NoWrap,
        TextTrimming = Microsoft.UI.Xaml.TextTrimming.CharacterEllipsis
    };

    public CounterValue(string title, string description)
    {
        this.title = title;
        this.description = description;
        Host.Children.Add(View);
        AutomationProperties.SetHelpText(View, description);
        Host.SizeChanged += (_, _) => Fit();
        SetValue("—");
    }

    public void SetValue(string value)
    {
        if (View.Text == value) return;
        View.Text = value;
        measure.Text = value;
        measure.Measure(new(double.PositiveInfinity, double.PositiveInfinity));
        naturalWidth = measure.DesiredSize.Width;
        AutomationProperties.SetName(View, title + ": " + value);
        ToolTipService.SetToolTip(View, description + "\n" + value);
        Fit();
    }

    private void Fit()
    {
        if (Host.ActualWidth <= 0) return;
        // TextBlock.ActualWidth can be the ink width rather than the allocated cell.
        // Use the containing grid so a short value cannot cause another shrink.
        View.Width = Host.ActualWidth;
        View.FontSize = KeypadSizing.FitCounterFont(naturalWidth, Host.ActualWidth, NaturalFontSize);
    }
}
