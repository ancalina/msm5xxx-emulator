using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Windowing;
using Windows.Storage.Pickers;

namespace Msm5xxx.Desktop;

public abstract class DesktopWindow : Window
{
    protected Strings Text = new();
    protected readonly Grid Root = (Grid)XamlReader.Load("<Grid xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' />");
    protected readonly TitleBar Commands = new();
    protected readonly StackPanel TitleActions = new() { Orientation = Orientation.Horizontal, Spacing = 0, VerticalAlignment = VerticalAlignment.Center };
    protected readonly InfoBar Error = new() { Severity = InfoBarSeverity.Error, IsClosable = true };
    protected readonly Grid Body = new();
    private readonly SemaphoreSlim dialogs = new(1, 1);
    protected bool IsClosing { get; private set; }
    protected bool DialogOpen { get; private set; }
    private bool allowClose;
    private Task<bool>? shutdown;
    private SettingsWindow? settings;
    protected double MinimumClientWidth = 320, MinimumClientHeight = 180;

    protected DesktopWindow()
    {
        Root.RowDefinitions.Add(new() { Height = GridLength.Auto });
        Root.RowDefinitions.Add(new() { Height = GridLength.Auto });
        Root.RowDefinitions.Add(new() { Height = new(1, GridUnitType.Star) });
        Commands.RightHeader = TitleActions;
        TitleBar.SetIsDragRegion(TitleActions, false);
        TitleBarLayout.Attach(Commands);
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(Commands);
        AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;
        SystemBackdrop = new MicaBackdrop();
        NativeWindow.FollowTitleBarTheme(this, Commands);
        SizeChanged += (_, _) => NativeWindow.SetMinimumClientSize(this, MinimumClientWidth, MinimumClientHeight);
        Root.Loaded += (_, _) =>
        {
            NativeWindow.SetMinimumClientSize(this, MinimumClientWidth, MinimumClientHeight);
            Root.XamlRoot.Changed += (_, _) => NativeWindow.SetMinimumClientSize(this, MinimumClientWidth, MinimumClientHeight);
        };
        Root.Children.Add(Commands); Grid.SetRow(Error, 1); Root.Children.Add(Error);
        Grid.SetRow(Body, 2); Root.Children.Add(Body);
        Content = Root;
        WindowIcons.Register(this, Commands);
        AutomationProperties.SetLiveSetting(Error, Microsoft.UI.Xaml.Automation.Peers.AutomationLiveSetting.Polite);
        AppWindow.Closing += (sender, args) =>
        {
            if (allowClose) return;
            args.Cancel = true;
            _ = ShutdownAndCloseAsync();
        };
    }

    public new string Title
    {
        get => base.Title;
        set { base.Title = value; Commands.Title = value; }
    }

    protected void RefreshTitleBar() => DispatcherQueue.TryEnqueue(() => Commands.RecomputeDragRegions());

    public async Task<bool> ShutdownAndCloseAsync()
    {
        var attempt = shutdown ??= ShutdownCoreAsync();
        var closed = await attempt;
        if (!closed && ReferenceEquals(shutdown, attempt)) shutdown = null;
        return closed;
    }

    private async Task<bool> ShutdownCoreAsync()
    {
        try
        {
            if (settings is not null && !await settings.ShutdownAndCloseAsync()) return false;
            if (!await CanCloseAsync()) return false;
        }
        catch (Exception error) { ShowError(error); return false; }
        IsClosing = true;
        Commands.IsEnabled = false;
        Body.IsHitTestVisible = false;
        try { await ShutdownAsync(); }
        catch (Exception error) { System.Diagnostics.Debug.WriteLine(error); }
        finally { allowClose = true; Close(); }
        return true;
    }

    protected Task ShowSettingsAsync(Msm5xxx.Desktop.Core.BackendClient backend, Func<Task>? restart = null)
    {
        if (settings is null)
        {
            var window = new SettingsWindow(backend, Text, restart);
            settings = window;
            window.Closed += (_, _) => { if (ReferenceEquals(settings, window)) settings = null; };
        }
        settings.Activate();
        return Task.CompletedTask;
    }

    internal Task RefreshSettingsLanguageAsync() => settings?.RefreshLanguageAsync() ?? Task.CompletedTask;

    protected virtual Task<bool> CanCloseAsync() => Task.FromResult(true);
    protected virtual Task ShutdownAsync() => Task.CompletedTask;
    protected virtual Task BeforeDialogAsync() => Task.CompletedTask;
    protected virtual Task RetryAsync() => Task.CompletedTask;
    protected virtual bool CanRetry => true;

    protected async Task Guard(Func<Task> operation)
    {
        try { await operation(); }
        catch (OperationCanceledException) when (IsClosing) { }
        catch (Exception error) { ShowError(error); }
    }

    protected void ShowError(Exception error)
    {
        if (IsClosing) return;
        AutomationProperties.SetName(Error, Text["error_title"]);
        Error.Title = Text["error_title"]; Error.Message = error.Message; Error.IsOpen = true;
        Error.ActionButton = CanRetry ? Button(Text["retry"], () => Guard(RetryAsync)) : null;
    }

    public async Task<ContentDialogResult> ShowDialogAsync(ContentDialog dialog)
    {
        await dialogs.WaitAsync();
        var content = dialog.Content as FrameworkElement;
        var maximum = content?.MaxHeight ?? double.PositiveInfinity;
        void ConstrainContent()
        {
            if (content is not null) content.MaxHeight = Math.Min(maximum, Math.Max(80, Root.ActualHeight - 220));
        }
        SizeChangedEventHandler resized = (_, _) => ConstrainContent();
        try
        {
            if (IsClosing) return ContentDialogResult.None;
            DialogOpen = true;
            await BeforeDialogAsync();
            dialog.XamlRoot = Root.XamlRoot;
            dialog.RequestedTheme = Root.ActualTheme;
            ConstrainContent();
            Root.SizeChanged += resized;
            return await dialog.ShowAsync();
        }
        finally
        {
            Root.SizeChanged -= resized;
            if (content is not null) content.MaxHeight = maximum;
            DialogOpen = false; dialogs.Release();
        }
    }

    private static FontIcon TitleCommandIcon(Symbol symbol) => new()
    {
        Glyph = char.ConvertFromUtf32((int)symbol), FontSize = 16,
        FontFamily = new FontFamily(OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000) ? "Segoe Fluent Icons" : "Segoe MDL2 Assets")
    };

    protected Button Command(string label, Symbol symbol, Func<Task> action)
    {
        var button = new Button { Content = TitleCommandIcon(symbol), Style = (Style)Application.Current.Resources["SubtleButtonStyle"], Width = 48, Height = 48, Padding = new(0) };
        AutomationProperties.SetName(button, label);
        ToolTipService.SetToolTip(button, label);
        button.Click += async (_, _) => await Guard(action);
        TitleActions.Children.Add(button); RefreshTitleBar();
        return button;
    }

    protected MenuFlyout AddMenu()
    {
        var menu = new MenuFlyout();
        var button = new Button { Content = TitleCommandIcon(Symbol.More), Flyout = menu, Style = (Style)Application.Current.Resources["SubtleButtonStyle"], Width = 48, Height = 48, Padding = new(0) };
        AutomationProperties.SetName(button, Text["menu_access"]);
        ToolTipService.SetToolTip(button, Text["menu_access"]);
        TitleActions.Children.Add(button); RefreshTitleBar();
        return menu;
    }

    protected MenuFlyoutItem MenuItem(string label, Func<Task> action)
    {
        var item = new MenuFlyoutItem { Text = label };
        item.Click += async (_, _) => await Guard(action);
        return item;
    }

    internal static TextBlock Label(string text, double size = 14) => new()
    {
        Text = text, FontSize = size, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true
    };

    internal static Button Button(string label, Func<Task> action)
    {
        var button = new Button { Content = label };
        AutomationProperties.SetName(button, label);
        button.Click += async (_, _) => await action();
        return button;
    }

    protected async Task<string?> PickFileAsync()
    {
        var picker = new FileOpenPicker(); picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        return (await picker.PickSingleFileAsync())?.Path;
    }

    protected async Task<string?> PickFolderAsync()
    {
        var picker = new FolderPicker(); picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        return (await picker.PickSingleFolderAsync())?.Path;
    }
}
