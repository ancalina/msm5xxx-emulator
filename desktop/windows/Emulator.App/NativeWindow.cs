using System.Runtime.InteropServices;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Msm5xxx.Desktop.Core;
using Windows.Graphics;

namespace Msm5xxx.Desktop;

internal static partial class NativeWindow
{
    [StructLayout(LayoutKind.Sequential)]
    private struct ClientRect { public int Left, Top, Right, Bottom; }
    [LibraryImport("user32.dll")] private static partial uint GetDpiForWindow(nint window);
    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetClientRect(nint window, out ClientRect rect);
    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetWindowRect(nint window, out ClientRect rect);
    public static DisplayRect OuterBounds(Window window)
    {
        if (!GetWindowRect(WinRT.Interop.WindowNative.GetWindowHandle(window), out var bounds)) throw new System.ComponentModel.Win32Exception();
        return new(bounds.Left, bounds.Top, bounds.Right - bounds.Left, bounds.Bottom - bounds.Top);
    }
    [LibraryImport("dwmapi.dll")]
    private static partial int DwmGetWindowAttribute(nint window, int attribute, out ClientRect rect, int size);
    [LibraryImport("dwmapi.dll", EntryPoint = "DwmGetWindowAttribute")]
    private static partial int GetFrameAttribute(nint window, int attribute, out uint value, int size);
    [LibraryImport("user32.dll")] private static partial int GetSystemMetricsForDpi(int index, uint dpi);

    private static int ContentTopInset(Window window)
    {
        if (!window.ExtendsContentIntoTitleBar || window.AppWindow.Presenter is OverlappedPresenter { State: OverlappedPresenterState.Maximized }) return 0;
        var handle = WinRT.Interop.WindowNative.GetWindowHandle(window);
        // Read the actual frame, rather than a temporarily stale XAML height during WM_SIZE.
        if (GetFrameAttribute(handle, 37, out var border, sizeof(uint)) == 0) return checked((int)border);
        return GetSystemMetricsForDpi(6, GetDpiForWindow(handle)); // SM_CYBORDER, Windows 10 fallback.
    }

    public static DisplayRect VisibleBounds(Window window)
    {
        if (DwmGetWindowAttribute(WinRT.Interop.WindowNative.GetWindowHandle(window), 9, out var bounds, Marshal.SizeOf<ClientRect>()) == 0 && bounds.Right > bounds.Left && bounds.Bottom > bounds.Top)
            return new(bounds.Left, bounds.Top, bounds.Right - bounds.Left, bounds.Bottom - bounds.Top);
        return OuterBounds(window);
    }
    public static double Scale(Window window) => GetDpiForWindow(WinRT.Interop.WindowNative.GetWindowHandle(window)) / 96.0;

    public static DisplayRect WorkArea(Window window)
    {
        var display = DisplayArea.GetFromWindowId(window.AppWindow.Id, DisplayAreaFallback.Nearest)
            ?? throw new InvalidOperationException("The window has no display.");
        var work = display.WorkArea;
        return new(work.X, work.Y, work.Width, work.Height);
    }

    public static ContentSize AvailableClientSize(Window window)
    {
        var work = WorkArea(window);
        var border = MinimumOuterSize(window, 0, 0);
        var scale = Scale(window);
        return new(Math.Max(1, (work.Width - border.Width) / scale), Math.Max(1, (work.Height - border.Height) / scale));
    }

    public static void ResizeClient(Window window, double width, double height, bool fitToWorkArea = false, bool constrainSize = true)
    {
        var scale = Scale(window);
        var pixels = new ContentSize(Math.Ceiling(width * scale), Math.Ceiling(height * scale));
        var handle = WinRT.Interop.WindowNative.GetWindowHandle(window);
        if (!GetClientRect(handle, out var client)) throw new System.ComponentModel.Win32Exception();
        // AppWindow.ClientSize excludes the legacy caption even when XAML extends into that area.
        var outer = OuterBounds(window);
        var borderWidth = outer.Width - (client.Right - client.Left);
        var borderHeight = outer.Height - (client.Bottom - client.Top);
        borderHeight += ContentTopInset(window);
        var area = fitToWorkArea ? DisplayArea.GetFromWindowId(window.AppWindow.Id, DisplayAreaFallback.Nearest) : null;
        if (area is not null)
        {
            if (constrainSize) pixels = DisplayGeometry.ConstrainToAvailableArea(pixels, new(area.WorkArea.Width - borderWidth, area.WorkArea.Height - borderHeight));
        }
        window.AppWindow.Resize(new SizeInt32(Math.Max(1, (int)pixels.Width + borderWidth), Math.Max(1, (int)pixels.Height + borderHeight)));
        if (area is not null)
        {
            var work = area.WorkArea;
            var resized = OuterBounds(window);
            var position = new PointInt32(resized.X, resized.Y);
            window.AppWindow.Move(new PointInt32(
                Math.Clamp(position.X, work.X, work.X + Math.Max(0, work.Width - resized.Width)),
                Math.Clamp(position.Y, work.Y, work.Y + Math.Max(0, work.Height - resized.Height))));
        }
    }

    public static void FollowTitleBarTheme(Window window, TitleBar bar)
    {
        var closed = false; window.Closed += (_, _) => closed = true;
        void Apply()
        {
            if (closed) return;
            if (bar.Foreground is not SolidColorBrush brush) return;
            var caption = window.AppWindow.TitleBar;
            var foreground = brush.Color;
            caption.ButtonForegroundColor = caption.ButtonHoverForegroundColor = caption.ButtonPressedForegroundColor = foreground;
            foreground.A = 128; caption.ButtonInactiveForegroundColor = foreground;
            caption.ButtonBackgroundColor = caption.ButtonInactiveBackgroundColor = Microsoft.UI.Colors.Transparent;
            foreground = brush.Color; foreground.A = bar.ActualTheme == ElementTheme.Dark ? (byte)24 : (byte)16;
            caption.ButtonHoverBackgroundColor = foreground;
            foreground.A = 12; caption.ButtonPressedBackgroundColor = foreground;
        }
        bar.Loaded += (_, _) => Apply();
        bar.ActualThemeChanged += (_, _) => bar.DispatcherQueue.TryEnqueue(Apply);
    }

    public static void SetMinimumClientSize(Window window, double width, double height)
    {
        if (window.AppWindow.Presenter is not OverlappedPresenter presenter || presenter.State != OverlappedPresenterState.Restored) return;
        if (!GetClientRect(WinRT.Interop.WindowNative.GetWindowHandle(window), out var client) || client.Right <= 0 || client.Bottom <= 0) return;
        var minimum = MinimumOuterSize(window, width, height);
        var minimumWidth = (int)minimum.Width; var minimumHeight = (int)minimum.Height;
        if (presenter.PreferredMinimumWidth != minimumWidth) presenter.PreferredMinimumWidth = minimumWidth;
        if (presenter.PreferredMinimumHeight != minimumHeight) presenter.PreferredMinimumHeight = minimumHeight;
    }

    public static ContentSize MinimumOuterSize(Window window, double width, double height)
    {
        if (!GetClientRect(WinRT.Interop.WindowNative.GetWindowHandle(window), out var client)) throw new System.ComponentModel.Win32Exception();
        var scale = Scale(window);
        var outer = OuterBounds(window);
        var minimumWidth = (int)Math.Ceiling(width * scale) + outer.Width - client.Right;
        var minimumHeight = (int)Math.Ceiling(height * scale) + outer.Height - client.Bottom;
        minimumHeight += ContentTopInset(window);
        return new(minimumWidth, minimumHeight);
    }

    public static bool IsNormal(Window window) => window.AppWindow.Presenter is OverlappedPresenter { State: OverlappedPresenterState.Restored };
}
