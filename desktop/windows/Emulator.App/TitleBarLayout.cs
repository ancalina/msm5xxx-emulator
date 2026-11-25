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
    private GridLength? headerPadding, dragWidth;
    private Thickness? titleMargin;
    private (Rect Left, Rect Right, double Width, double Height, double Scale)? hitBounds;

    private Microsoft.UI.Windowing.AppWindowTitleBar nativeTitleBar = null!;
    public double MinimumWidth { get; private set; }
    public event Action? MinimumWidthChanged;

    public static TitleBarLayout Attach(TitleBar bar, Microsoft.UI.Windowing.AppWindowTitleBar nativeTitleBar)
    {
        var result = new TitleBarLayout { nativeTitleBar = nativeTitleBar };
        result.Watch(bar);
        return result;
    }

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
        // shortcut: pinned WinUI TitleBar template columns; review when upgrading Windows App SDK.
        headerPadding ??= layout.ColumnDefinitions[4].Width;
        dragWidth ??= layout.ColumnDefinitions[10].Width;
        titleMargin ??= title.Margin;
        if (measuredTitle != bar.Title || measuredFontSize != title.FontSize || measuredHeight != title.DesiredSize.Height)
        {
            var measure = new TextBlock { Text = bar.Title, FontFamily = title.FontFamily, FontSize = title.FontSize, FontWeight = title.FontWeight };
            measure.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            naturalTitleWidth = measure.DesiredSize.Width;
            measuredTitle = bar.Title; measuredFontSize = title.FontSize; measuredHeight = title.DesiredSize.Height;
        }
        var scale = bar.XamlRoot.RasterizationScale;
        // Native caption insets are physical pixels; template column widths are DIPs.
        var captionPadding = new GridLength(nativeTitleBar.RightInset / scale);
        if (!layout.ColumnDefinitions[11].Width.Equals(captionPadding)) layout.ColumnDefinitions[11].Width = captionPadding;
        var viewport = Math.Min(bar.ActualWidth, bar.XamlRoot.Size.Width);
        var fullFixedWidth = layout.ColumnDefinitions.Select((column, index) => index is 6 or 7 or 8 ? 0 :
            index == 4 ? headerPadding.Value.Value : index == 10 ? dragWidth.Value.Value : index == 11 ? captionPadding.Value : column.ActualWidth).Sum();
        var minimum = fullFixedWidth + titleMargin.Value.Left + titleMargin.Value.Right + naturalTitleWidth
            + Math.Max(0, nativeTitleBar.LeftInset / scale - layout.ColumnDefinitions[0].ActualWidth);
        if (Math.Abs(MinimumWidth - minimum) > 0.1)
        {
            MinimumWidth = minimum;
            MinimumWidthChanged?.Invoke();
        }
        var narrow = viewport < fullFixedWidth + titleMargin.Value.Left + titleMargin.Value.Right + naturalTitleWidth;
        var padding = narrow ? new GridLength(0) : headerPadding.Value;
        var drag = narrow ? new GridLength(0) : dragWidth.Value;
        var margin = narrow ? new Thickness(0) : titleMargin.Value;
        if (!layout.ColumnDefinitions[4].Width.Equals(padding)) layout.ColumnDefinitions[4].Width = padding;
        if (!layout.ColumnDefinitions[10].Width.Equals(drag)) layout.ColumnDefinitions[10].Width = drag;
        if (!title.Margin.Equals(margin)) title.Margin = margin;
        var fixedWidth = layout.ColumnDefinitions.Select((column, index) => index is 6 or 7 or 8 ? 0 :
            index is 4 or 10 or 11 ? column.Width.Value : column.ActualWidth).Sum();
        var budget = Math.Max(0, viewport - fixedWidth - title.Margin.Left - title.Margin.Right -
            (subtitle is null || string.IsNullOrEmpty(bar.Subtitle) ? 0 : subtitle.Margin.Left + subtitle.Margin.Right));
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
