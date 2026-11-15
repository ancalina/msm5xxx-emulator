using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;
using Msm5xxx.Desktop.Core;

namespace Msm5xxx.Desktop;

/// <summary>Constrains an interactive width drag without changing Snap, maximize, or DPI-driven bounds.</summary>
internal sealed class WindowSizing : IDisposable
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Rect { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowPosition { public nint Hwnd, InsertAfter; public int X, Y, Width, Height; public uint Flags; }
    [DllImport("user32.dll")] private static extern int GetSystemMetricsForDpi(int index, uint dpi);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate nint SubclassProcedure(nint hwnd, uint message, nuint wParam, nint lParam, nuint id, nuint data);

    [DllImport("comctl32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowSubclass(nint hwnd, SubclassProcedure procedure, nuint id, nuint data);
    [DllImport("comctl32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RemoveWindowSubclass(nint hwnd, SubclassProcedure procedure, nuint id);
    [DllImport("comctl32.dll")]
    private static extern nint DefSubclassProc(nint hwnd, uint message, nuint wParam, nint lParam);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(nint hwnd, out Rect rect);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetClientRect(nint hwnd, out Rect rect);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(nint hwnd);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsZoomed(nint hwnd);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowPos(nint hwnd, nint after, int x, int y, int width, int height, uint flags);

    private readonly Window window;
    private readonly FrameworkElement root;
    private readonly nint handle;
    private readonly SubclassProcedure procedure;
    private readonly Func<double, double?> naturalHeight;
    private double extraHeight;
    private bool disposed, correctingSize;
    public Func<ContentSize>? MinimumTrackSize { get; set; }
    public Func<DisplayRect, int, DisplayRect>? ResizeBounds { get; set; }
    public Func<DisplayRect, DisplayRect>? MoveBounds { get; set; }
    public event Action? InteractionStarted;
    public event Action? InteractionEnded;

    public WindowSizing(Window window, FrameworkElement root, Func<double, double?> naturalHeight)
    {
        this.window = window; this.root = root; this.naturalHeight = naturalHeight;
        handle = WinRT.Interop.WindowNative.GetWindowHandle(window);
        procedure = HandleMessage;
        if (!SetWindowSubclass(handle, procedure, 1, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
        window.Closed += OnClosed;
    }

    private nint HandleMessage(nint hwnd, uint message, nuint wParam, nint lParam, nuint id, nuint data)
    {
        try
        {
            if (message == 0x0047 && MinimumTrackSize is not null) // Also covers SWP_NOSENDCHANGING and restore.
            {
                var result = DefSubclassProc(hwnd, message, wParam, lParam);
                if (!correctingSize && !IsIconic(hwnd) && !IsZoomed(hwnd) && GetWindowRect(hwnd, out var current))
                {
                    var bounds = new DisplayRect(current.Left, current.Top, current.Right - current.Left, current.Bottom - current.Top);
                    var constrained = WindowPlacement.EnforceMinimum(bounds, MinimumTrackSize());
                    if (constrained != bounds)
                    {
                        correctingSize = true;
                        try { SetWindowPos(hwnd, 0, 0, 0, constrained.Width, constrained.Height, 0x16); }
                        finally { correctingSize = false; }
                    }
                }
                return result;
            }
            if (message == 0x0046 && MinimumTrackSize is not null && !IsIconic(hwnd))
            {
                var position = Marshal.PtrToStructure<WindowPosition>(lParam);
                if ((position.Flags & 1) == 0 && !IsZoomed(hwnd))
                {
                    var constrained = WindowPlacement.EnforceMinimum(new(position.X, position.Y, position.Width, position.Height), MinimumTrackSize());
                    position.Width = constrained.Width; position.Height = constrained.Height;
                    Marshal.StructureToPtr(position, lParam, false);
                    // A secondary LCD can be narrower than the default system caption minimum.
                    if (position.Width < GetSystemMetricsForDpi(28, (uint)Math.Round(NativeWindow.Scale(window) * 96))) return 0;
                }
            }
            if (message == 0x0024 && MinimumTrackSize is not null)
            {
                var result = DefSubclassProc(hwnd, message, wParam, lParam);
                var minimum = MinimumTrackSize();
                Marshal.WriteInt32(lParam, 24, (int)Math.Ceiling(minimum.Width));
                Marshal.WriteInt32(lParam, 28, (int)Math.Ceiling(minimum.Height));
                // A natural whole-LCD opening may exceed the monitor's default tracking limit.
                Marshal.WriteInt32(lParam, 32, Math.Max(Marshal.ReadInt32(lParam, 32), (int)Math.Ceiling(minimum.Width)));
                Marshal.WriteInt32(lParam, 36, Math.Max(Marshal.ReadInt32(lParam, 36), (int)Math.Ceiling(minimum.Height)));
                if (root.ActualHeight > 0 && GetWindowRect(hwnd, out var bounds) && GetClientRect(hwnd, out var client) && client.Right > client.Left && client.Bottom > client.Top)
                {
                    var scale = NativeWindow.Scale(window);
                    var borderWidth = bounds.Right - bounds.Left - (client.Right - client.Left);
                    var borderHeight = bounds.Bottom - bounds.Top - (int)Math.Round(root.ActualHeight * scale);
                    var maxTrackWidth = Marshal.ReadInt32(lParam, 32);
                    var height = naturalHeight(Math.Max(1, maxTrackWidth - borderWidth) / scale);
                    if (height.HasValue)
                    {
                        var maxTrackHeight = checked((int)Math.Ceiling((height.Value + extraHeight) * scale) + borderHeight);
                        Marshal.WriteInt32(lParam, 36, Math.Max(Marshal.ReadInt32(lParam, 36), maxTrackHeight));
                    }
                }
                return result;
            }
            if (message == 0x0231) // WM_ENTERSIZEMOVE: preserve the user's extra display height throughout a drag.
            {
                InteractionStarted?.Invoke();
                var height = naturalHeight(root.ActualWidth);
                extraHeight = height.HasValue ? Math.Max(0, root.ActualHeight - height.Value) : 0;
            }
            else if (message == 0x0232) InteractionEnded?.Invoke();
            else if (message == 0x0216 && MoveBounds is not null)
            {
                var rect = Marshal.PtrToStructure<Rect>(lParam);
                var adjusted = MoveBounds(new(rect.Left, rect.Top, rect.Right - rect.Left, rect.Bottom - rect.Top));
                rect.Left = adjusted.X; rect.Top = adjusted.Y; rect.Right = adjusted.X + adjusted.Width; rect.Bottom = adjusted.Y + adjusted.Height;
                Marshal.StructureToPtr(rect, lParam, false);
                return 1;
            }
            else if (message == 0x0214)
            {
                var edge = (int)wParam;
                var rect = Marshal.PtrToStructure<Rect>(lParam);
                var adjusted = new DisplayRect(rect.Left, rect.Top, rect.Right - rect.Left, rect.Bottom - rect.Top);
                if (MinimumTrackSize is not null) adjusted = WindowPlacement.EnforceMinimum(adjusted, MinimumTrackSize(), edge);
                if (ResizeBounds is not null) adjusted = ResizeBounds(adjusted, edge);
                else if (edge is 1 or 2 or 4 or 5 or 7 or 8 && GetWindowRect(hwnd, out var bounds) && GetClientRect(hwnd, out var client))
                {
                    var borderWidth = bounds.Right - bounds.Left - (client.Right - client.Left);
                    var scale = NativeWindow.Scale(window);
                    var borderHeight = bounds.Bottom - bounds.Top - (int)Math.Round(root.ActualHeight * scale);
                    var height = naturalHeight(Math.Max(1, adjusted.Width - borderWidth) / scale);
                    if (height.HasValue)
                    {
                        var pixels = checked((int)Math.Ceiling((height.Value + extraHeight) * scale) + borderHeight);
                        if (edge is 4 or 5) adjusted = adjusted with { Y = adjusted.Y + adjusted.Height - pixels, Height = pixels };
                        else adjusted = adjusted with { Height = pixels };
                    }
                }
                if (MinimumTrackSize is not null) adjusted = WindowPlacement.EnforceMinimum(adjusted, MinimumTrackSize(), edge);
                rect.Left = adjusted.X; rect.Top = adjusted.Y; rect.Right = adjusted.X + adjusted.Width; rect.Bottom = adjusted.Y + adjusted.Height;
                Marshal.StructureToPtr(rect, lParam, false);
                return 1;
            }
            else if (message == 0x0082) Dispose(); // WM_NCDESTROY.
        }
        catch (Exception error) { System.Diagnostics.Debug.WriteLine(error); }
        return DefSubclassProc(hwnd, message, wParam, lParam);
    }

    private void OnClosed(object sender, WindowEventArgs args) => Dispose();

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        RemoveWindowSubclass(handle, procedure, 1);
        window.Closed -= OnClosed;
        GC.KeepAlive(procedure);
    }
}
