using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;

namespace Msm5xxx.Desktop;

/// <summary>Keeps title text within the space left by commands and system caption buttons.</summary>
internal sealed class TitleBarLayout
{
    private Grid? layout;
    private TextBlock? title;
    private TextBlock? subtitle;
    private string? measuredTitle;
    private double measuredFontSize, measuredHeight, naturalTitleWidth;
    private (Rect Left, Rect Right, double Width, double Height, double Scale)? hitBounds;

    public static void Attach(TitleBar bar) => new TitleBarLayout().Watch(bar);

    private void Watch(TitleBar bar)
    {
        bar.Resources["TitleBarMinDragRegionWidth"] = 16.0;
        bar.Resources["TitleBarSubtitleMargin"] = new Thickness(0, 0, 8, 0);
        bar.Loaded += (_, _) => Constrain(bar);
        bar.SizeChanged += (_, _) => Constrain(bar);
        bar.RegisterPropertyChangedCallback(TitleBar.TitleProperty, (_, _) => Queue(bar));
        bar.RegisterPropertyChangedCallback(TitleBar.SubtitleProperty, (_, _) => Queue(bar));
        bar.LayoutUpdated += (_, _) => Constrain(bar);
    }

    private void Queue(TitleBar bar) => bar.DispatcherQueue.TryEnqueue(() => Constrain(bar));

    public static double NaturalWidth(TitleBar bar)
    {
        var layout = Find<Grid>(bar, "PART_LayoutRoot");
        if (layout is null) return 0;
        double TextWidth(string name, string value)
        {
            if (string.IsNullOrEmpty(value) || Find<TextBlock>(bar, name) is not { } source) return 0;
            var probe = new TextBlock { Text = value, FontFamily = source.FontFamily, FontSize = source.FontSize, FontWeight = source.FontWeight };
            probe.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            return probe.DesiredSize.Width + source.Margin.Left + source.Margin.Right;
        }
        return layout.ColumnDefinitions.Select((column, index) => index is 6 or 7 or 8 ? 0 : column.ActualWidth).Sum()
            + TextWidth("PART_TitleText", bar.Title);
    }

    private static T? Find<T>(DependencyObject parent, string name) where T : FrameworkElement
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T element && element.Name == name) return element;
            if (Find<T>(child, name) is { } descendant) return descendant;
        }
        return null;
    }

    private void Constrain(TitleBar bar)
    {
        if (bar.XamlRoot is null || bar.ActualWidth < 1) return;
        layout ??= Find<Grid>(bar, "PART_LayoutRoot");
        if (layout is null) return;
        title ??= Find<TextBlock>(bar, "PART_TitleText");
        subtitle ??= Find<TextBlock>(bar, "PART_SubtitleText");
        if (title is null) return;
        // These named parts and columns belong to the pinned WinUI TitleBar template.
        var fixedWidth = layout.ColumnDefinitions.Select((column, index) => index is 6 or 7 or 8 ? 0 : column.ActualWidth).Sum();
        var budget = Math.Max(0, bar.ActualWidth - fixedWidth - title.Margin.Left - title.Margin.Right -
            (subtitle is null ? 0 : subtitle.Margin.Left + subtitle.Margin.Right));
        if (measuredTitle != bar.Title || measuredFontSize != title.FontSize || measuredHeight != title.DesiredSize.Height)
        {
            var measure = new TextBlock { Text = bar.Title, FontFamily = title.FontFamily, FontSize = title.FontSize, FontWeight = title.FontWeight };
            measure.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            naturalTitleWidth = measure.DesiredSize.Width;
            measuredTitle = bar.Title; measuredFontSize = title.FontSize; measuredHeight = title.DesiredSize.Height;
        }
        var titleWidth = Math.Min(budget, naturalTitleWidth);
        if (Math.Abs(title.MaxWidth - titleWidth) > 0.1) title.MaxWidth = titleWidth;
        if (subtitle is not null)
        {
            var width = Math.Max(0, budget - titleWidth);
            if (Math.Abs(subtitle.MaxWidth - width) > 0.1) subtitle.MaxWidth = width;
        }
        Rect Bounds(object header)
        {
            if (header is not FrameworkElement element || element.ActualWidth == 0) return default;
            return new Rect(element.TransformToVisual(bar).TransformPoint(new Point(0, 0)), new Size(element.ActualWidth, element.ActualHeight));
        }
        var current = (Bounds(bar.LeftHeader), Bounds(bar.RightHeader), bar.ActualWidth, bar.ActualHeight, bar.XamlRoot?.RasterizationScale ?? 1);
        if (hitBounds != current)
        {
            hitBounds = current;
            bar.RecomputeDragRegions();
        }
    }
}
