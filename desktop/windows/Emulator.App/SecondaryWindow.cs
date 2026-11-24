using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Automation;
using Msm5xxx.Desktop.Core;
using Windows.Graphics;

namespace Msm5xxx.Desktop;

public sealed class SecondaryWindow : Window
{
    private readonly ScreenView screen;
    private readonly Window owner;
    private readonly string firmware;
    private readonly Func<int> contentTop;
    private readonly Grid root;
    private readonly WindowSizing sizing;
    private DockSide side;
    private PointInt32? expectedPosition;
    private bool interacting, resizing, wantsVisible, ownerMinimized, placed;
    private readonly TitleBar titleBar = new() { Height = 48 };
    private Strings text;
    private bool? enabled;
    private bool preview;
    private bool disposing;
    private (int Width, int Height) size;

    public SecondaryWindow(Window owner, string firmware, Strings text, Func<int> contentTop)
    {
        this.text = text; this.owner = owner; this.firmware = firmware; this.contentTop = contentTop;
        side = DisplayPreferences.Get(firmware);
        WindowIcons.Register(this, titleBar);
        TitleBarLayout.Attach(titleBar);
        ExtendsContentIntoTitleBar = true; SetTitleBar(titleBar);
        AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
        SystemBackdrop = new MicaBackdrop();
        NativeWindow.FollowTitleBarTheme(this, titleBar);
        screen = new(text["additional_display"]);
        root = new Grid();
        root.RowDefinitions.Add(new() { Height = GridLength.Auto });
        root.RowDefinitions.Add(new() { Height = new(1, GridUnitType.Star) });
        root.Children.Add(titleBar); Grid.SetRow(screen, 1); root.Children.Add(screen); Content = root;
        root.Loaded += (_, _) =>
        {
            if (size.Width > 0) { NativeWindow.ResizeClient(this, size.Width * 3, size.Height * 3 + titleBar.Height); UpdateMinimum(); PlaceAtOpening(); }
        };
        if (AppWindow.Presenter is OverlappedPresenter presenter)
        { presenter.IsMinimizable = false; presenter.IsMaximizable = false; presenter.IsResizable = true; }
        root.SizeChanged += (_, _) => UpdateMinimum();
        sizing = new(this, root, width => size.Width > 0 ? width * size.Height / size.Width + titleBar.Height : null);
        sizing.MinimumTrackSize = () => NativeWindow.MinimumOuterSize(this, Math.Max(1, size.Width), Math.Max(1, size.Height) + titleBar.Height);
        sizing.ResizeBounds = (bounds, edge) =>
        {
            resizing = true;
            var scale = NativeWindow.Scale(this);
            return size.Width == 0 ? bounds : WindowPlacement.KeepAspect(bounds, size.Width, size.Height,
                Math.Max(0, NativeWindow.OuterBounds(this).Width - (int)Math.Round(screen.ActualWidth * scale)),
                Math.Max(0, NativeWindow.OuterBounds(this).Height - (int)Math.Round(screen.ActualHeight * scale)), edge);
        };
        sizing.MoveBounds = SnapMoving;
        sizing.InteractionStarted += () => { interacting = true; resizing = false; };
        sizing.InteractionEnded += () => { interacting = false; if (resizing && side != DockSide.None) Follow(); else EvaluatePosition(); };
        owner.AppWindow.Changed += OwnerChanged;
        AppWindow.Changed += SecondaryChanged;
        AppWindow.Closing += (_, args) =>
        {
            if (disposing) return;
            args.Cancel = true; Hide();
        };
    }

    public void Update(RgbFrame? frame, bool? enabled, bool preview)
    {
        this.enabled = enabled; this.preview = preview;
        if (frame is not null)
        {
            if (size != (frame.Width, frame.Height))
            {
                size = (frame.Width, frame.Height);
                NativeWindow.ResizeClient(this, size.Width * 3, size.Height * 3 + titleBar.Height);
                UpdateMinimum();
                if (root.IsLoaded) { if (placed) Follow(); else PlaceAtOpening(); }
            }
            screen.ShowFrame(frame);
        }
        var power = text[enabled is true ? "power_on" : enabled is false ? "power_off" : "power_unknown"];
        Title = titleBar.Title = owner.Title;
        titleBar.Subtitle = "";
        AutomationProperties.SetName(titleBar, owner.Title + " · " + text["additional_display"]);
        ToolTipService.SetToolTip(titleBar,
            $"{power} · {size.Width}×{size.Height} · {text[preview ? "secondary_preview" : "secondary_unknown"]}");
    }

    public new void Activate()
    {
        wantsVisible = true;
        if (!ownerMinimized) base.Activate();
        if (root.IsLoaded)
        {
            if (!placed || !Fits(NativeWindow.OuterBounds(this), NativeWindow.WorkArea(owner))) PlaceAtOpening();
            else Follow();
        }
    }
    public void Hide() { wantsVisible = false; AppWindow.Hide(); }
    private void UpdateMinimum()
    {
        if (size.Width > 0) NativeWindow.SetMinimumClientSize(this, size.Width, size.Height + titleBar.Height);
    }
    private void SetSide(DockSide value)
    {
        if (side == value) return;
        side = value; DisplayPreferences.Set(firmware, side);
    }
    private DisplayRect SnapMoving(DisplayRect proposed)
    {
        var visible = NativeWindow.VisibleBounds(this);
        var outer = NativeWindow.OuterBounds(this);
        var dx = visible.X - outer.X; var dy = visible.Y - outer.Y;
        var candidate = new DisplayRect(proposed.X + dx, proposed.Y + dy, visible.Width, visible.Height);
        SetSide(WindowPlacement.SnapSide(NativeWindow.VisibleBounds(owner), candidate, 16, contentTop()));
        if (side == DockSide.None) return proposed;
        var docked = WindowPlacement.Docked(NativeWindow.VisibleBounds(owner), new(visible.Width, visible.Height), side, contentTop());
        expectedPosition = new(docked.X - dx, docked.Y - dy);
        return proposed with { X = docked.X - dx, Y = docked.Y - dy };
    }
    private void EvaluatePosition()
    {
        if (disposing || ownerMinimized) return;
        SetSide(WindowPlacement.SnapSide(NativeWindow.VisibleBounds(owner), NativeWindow.VisibleBounds(this), 16, contentTop()));
        Follow();
    }
    private static bool Fits(DisplayRect bounds, DisplayRect area) => bounds.X >= area.X && bounds.Y >= area.Y &&
        (long)bounds.X + bounds.Width <= (long)area.X + area.Width && (long)bounds.Y + bounds.Height <= (long)area.Y + area.Height;

    private DisplayRect DockedOuter(DockSide dockSide)
    {
        var visible = NativeWindow.VisibleBounds(this);
        var outer = NativeWindow.OuterBounds(this);
        var docked = WindowPlacement.Docked(NativeWindow.VisibleBounds(owner), new(visible.Width, visible.Height), dockSide, contentTop());
        return outer with { X = docked.X - (visible.X - outer.X), Y = docked.Y - (visible.Y - outer.Y) };
    }

    private void MoveTo(DisplayRect bounds)
    {
        expectedPosition = new(bounds.X, bounds.Y);
        if (AppWindow.Position.X != bounds.X || AppWindow.Position.Y != bounds.Y) AppWindow.Move(expectedPosition.Value);
    }

    private void PlaceAtOpening()
    {
        if (disposing || ownerMinimized || size.Width == 0) return;
        var area = NativeWindow.WorkArea(owner);
        if (side != DockSide.None && Fits(DockedOuter(side), area))
        {
            placed = true; MoveTo(DockedOuter(side)); return;
        }
        var main = NativeWindow.OuterBounds(owner);
        var outer = NativeWindow.OuterBounds(this);
        var bounds = WindowPlacement.BesideWithinWorkArea(main, new(outer.Width, outer.Height), area, contentTop());
        var fallbackSide = bounds.X == main.X + main.Width ? DockSide.Right : bounds.X + bounds.Width == main.X ? DockSide.Left : DockSide.None;
        if (fallbackSide != DockSide.None)
        {
            var flush = DockedOuter(fallbackSide);
            flush = flush with { Y = bounds.Y };
            if (Fits(flush, area)) bounds = flush;
        }
        // Preserve a remembered attachment only where it can remain on this display.
        if (side != DockSide.None) SetSide(fallbackSide);
        placed = true; MoveTo(bounds);
    }

    private void Follow()
    {
        if (!placed || side == DockSide.None || disposing || ownerMinimized || size.Width == 0) return;
        var bounds = DockedOuter(side);
        if (Fits(bounds, NativeWindow.WorkArea(owner))) MoveTo(bounds);
        else PlaceAtOpening();
    }
    private void OwnerChanged(AppWindow sender, AppWindowChangedEventArgs args)
    {
        if (!placed || side == DockSide.None || disposing) return;
        var minimized = owner.AppWindow.Presenter is OverlappedPresenter { State: OverlappedPresenterState.Minimized };
        if (minimized) { ownerMinimized = true; AppWindow.Hide(); return; }
        if (ownerMinimized) { ownerMinimized = false; if (wantsVisible) AppWindow.Show(false); }
        if (!interacting) Follow();
    }
    private void SecondaryChanged(AppWindow sender, AppWindowChangedEventArgs args)
    {
        if (disposing || !placed) return;
        if (args.DidSizeChange) { UpdateMinimum(); if (!interacting) Follow(); }
        if (!args.DidPositionChange || interacting || ownerMinimized) return;
        if (expectedPosition is { } expected && AppWindow.Position.X == expected.X && AppWindow.Position.Y == expected.Y) return;
        expectedPosition = null; EvaluatePosition();
    }
    public void SetLanguage(Strings value)
    {
        text = value;
        screen.SetAccessibleName(text["additional_display"]);
        Update(null, enabled, preview);
    }
    public void DisposeWindow() { disposing = true; owner.AppWindow.Changed -= OwnerChanged; sizing.Dispose(); screen.Stop(); Close(); }
}
