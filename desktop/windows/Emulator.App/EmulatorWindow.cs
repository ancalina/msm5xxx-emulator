using System.Text.Json;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Msm5xxx.Desktop.Core;
using Windows.Storage.Pickers;
using Windows.System;
using Windows.UI.Core;

namespace Msm5xxx.Desktop;

public sealed class EmulatorWindow : DesktopWindow
{
    private readonly FirmwareEntry firmware;
    private BackendClient? backend;
    private readonly CancellationTokenSource backendLifetime = new();
    private KeypadLayout? layout;
    private KeypadInput? input;
    private readonly ScreenView screen;
    private readonly Grid keypad = new() { ColumnSpacing = 4, RowSpacing = 4, Padding = new(8, 4, 8, 4) };
    private readonly Dictionary<int, Button> buttons = [];
    private readonly Dictionary<string, CounterValue> metrics = [];
    private double[] naturalKeypadColumns = [];
    private readonly Dictionary<int, int?> mappings = [];
    private readonly Dictionary<VirtualKey, int> keyboardHeld = [];
    private HashSet<int> firmwareKeys = [];
    private readonly SemaphoreSlim mutation = new(1, 1);
    private readonly Task initialize;
    private CancellationTokenSource? polling;
    private Task framePoll = Task.CompletedTask, statePoll = Task.CompletedTask;
    private Button? power;
    private Button? done;
    private Button? fold;
    private ToggleMenuFlyoutItem? networkToggle, editToggle;
    private MenuFlyoutItem? secondaryItem;
    private SecondaryWindow? secondary;
    private bool secondarySeen;
    private bool running;
    private bool busy;
    private bool editing;
    private bool mappingOpening;
    private MenuFlyoutItem? captureItem;
    private (int Width, int Height) lcd = (128, 128);
    private bool hasFrameGeometry;
    private long frameSequence = -1, secondarySequence = -1;
    private readonly WindowSizing sizing;
    private ContentSize minimumTrackSize = new(336, 189);
    private ContentSize fittedAvailable;
    private DisplayRect fittedWorkArea;
    private double fittedScale;
    private string chipset = "";
    private JsonElement lastState;
    private string? lastInputError;

    public EmulatorWindow(FirmwareEntry firmware)
    {
        this.firmware = firmware;
        Title = firmware.Name;
        screen = new(Text["firmware_screen"]);
        AutomationProperties.SetHelpText(screen, Text["screen_unavailable"]);
        screen.RenderFailed += ShowError;
        Body.RowDefinitions.Add(new() { Height = new(1, GridUnitType.Star) });
        Body.RowDefinitions.Add(new() { Height = GridLength.Auto });
        Body.Children.Add(screen); Grid.SetRow(keypad, 1); Body.Children.Add(keypad);
        keypad.SizeChanged += (_, _) => ArrangeKeypadColumns();
        BuildChrome();
        MinimumClientWidth = 384; MinimumClientHeight = 760;
        Root.MinWidth = MinimumClientWidth; Root.MinHeight = MinimumClientHeight;
        NativeWindow.ResizeClient(this, 384, 760, fitToWorkArea: true);
        sizing = new(this, Root, width => !hasFrameGeometry ? null :
            DisplayGeometry.HeightForWidth(width, lcd.Width, lcd.Height, keypad.DesiredSize.Height,
                Commands.ActualHeight + (Error.IsOpen ? Error.ActualHeight : 0)));
        minimumTrackSize = NativeWindow.MinimumOuterSize(this, MinimumClientWidth, MinimumClientHeight);
        sizing.MinimumTrackSize = () => minimumTrackSize;
        Root.SizeChanged += (_, _) =>
        {
            if (NativeWindow.IsNormal(this)) minimumTrackSize = NativeWindow.MinimumOuterSize(this, MinimumClientWidth, MinimumClientHeight);
        };
        AppWindow.Changed += (_, _) =>
        {
            ArrangeKeypadColumns();
            if (hasFrameGeometry && NativeWindow.IsNormal(this) && (NativeWindow.WorkArea(this) != fittedWorkArea || NativeWindow.Scale(this) != fittedScale))
                DispatcherQueue.TryEnqueue(() => Fit(false));
        };
        Root.AddHandler(UIElement.PreviewKeyDownEvent, new KeyEventHandler(KeyDown), true);
        Root.AddHandler(UIElement.PreviewKeyUpEvent, new KeyEventHandler(KeyUp), true);
        Activated += (sender, args) =>
        {
            if (args.WindowActivationState == WindowActivationState.Deactivated) _ = Guard(ReleaseAllAsync);
        };
        initialize = Guard(InitializeAsync);
    }

    private void BuildChrome()
    {
        AutomationProperties.SetName(Commands, Text["commands"]);
        TitleActions.Children.Clear();
        power = Command(Text[running ? "stop_emulator" : "power_on_action"], Symbol.Play, TogglePowerAsync);
        power.Content = PowerIcon();
        Commands.LeftHeader = null;
        Commands.Subtitle = "";
        ToolTipService.SetToolTip(Commands, null);
        RefreshTitleBar();
        var menu = AddMenu();
        menu.Items.Add(MenuItem(Text["reboot_emulator"], RestartAsync));
        captureItem = MenuItem(Text["capture"], CaptureAsync);
        captureItem.IsEnabled = screen.Frame is not null; menu.Items.Add(captureItem);
        secondaryItem = MenuItem(Text["additional_display"], () => { secondary?.Activate(); return Task.CompletedTask; });
        secondaryItem.IsEnabled = secondarySeen && running; menu.Items.Add(secondaryItem);
        menu.Items.Add(MenuItem(Text["library_info"], InfoAsync));
        menu.Items.Add(new MenuFlyoutSeparator());
        networkToggle = new ToggleMenuFlyoutItem { Text = Text["virtual_network_menu"] };
        networkToggle.Click += async (_, _) => await Guard(async () =>
        {
            var requested = networkToggle.IsChecked;
            try { await backend!.CallAsync("settings.set", new { key = "virtual_network", value = requested }); }
            catch { networkToggle.IsChecked = !requested; throw; }
            if (running) await RestartAsync();
        });
        menu.Items.Add(networkToggle);
        var time = new MenuFlyoutSubItem { Text = Text["time"] };
        time.Items.Add(MenuItem(Text["network_host_time"], async () =>
        {
            await backend!.CallAsync("settings.set", new { key = "network_host_time", value = true });
            if (running) await backend.CallAsync("session.network_time");
        }));
        time.Items.Add(MenuItem(Text["set_time"], SetTimeAsync)); menu.Items.Add(time);
        menu.Items.Add(new MenuFlyoutSeparator());
        editToggle = new ToggleMenuFlyoutItem { Text = Text["edit_input"], IsChecked = editing };
        editToggle.Click += async (_, _) => await Guard(() => SetEditingAsync(editToggle.IsChecked)); menu.Items.Add(editToggle);
        menu.Items.Add(MenuItem(Text["settings"], SettingsAsync));
        Commands.IsEnabled = backend is not null && !busy;
    }

    private Task InitializeAsync() => WithTaskbarProgressAsync(InitializeCoreAsync);

    private async Task InitializeCoreAsync()
    {
        backend = await BackendClient.StartAsync(App.Instance.Options, backendLifetime.Token);
        if (IsClosing) { await backend.DisposeAsync(); return; }
        await backend.CallAsync("session.open", new { firmware = firmware.Path });
        await ReloadLayoutAsync();
        await BootAsync();
    }

    protected override bool CanRetry => !running && !busy;

    protected override async Task RetryAsync()
    {
        if (running || busy) return;
        if (backend is null || !backend.IsConnected)
        {
            if (backend is not null) await backend.DisposeAsync();
            backend = null;
            await InitializeAsync();
        }
        else await RestartAsync();
    }

    private async Task ReloadLayoutAsync()
    {
        await ReleaseAllAsync();
        layout = (await backend!.CallAsync("ui.layout")).As<KeypadLayout>();
        Text = new(layout.Language);
        input = new(async (bit, pressed) =>
        {
            var accepted = await backend.CallAsync("session.key", new { bit, pressed });
            if (pressed && !accepted.GetBoolean()) throw new IOException(Text["key_unavailable"]);
        }, layout.KeyHoldMs);
        BuildChrome(); BuildKeypad();
        screen.SetAccessibleName(Text["firmware_screen"]);
        secondary?.SetLanguage(Text);
        AutomationProperties.SetHelpText(screen, Text["screen_unavailable"]);
        var settings = await backend.CallAsync("settings.get");
        networkToggle!.IsChecked = settings.GetProperty("virtual_network").GetBoolean();
    }

    internal Task RefreshLanguageAsync() => Guard(async () =>
    {
        if (backend is null || IsClosing) return;
        await mutation.WaitAsync();
        busy = true; Commands.IsEnabled = false; UpdateKeys();
        try
        {
            if (IsClosing) return;
            var language = (await backend.CallAsync("hello")).GetProperty("language").GetString();
            if (language != Text.Language) await ReloadLayoutAsync();
        }
        finally
        {
            busy = false; Commands.IsEnabled = !IsClosing; UpdateKeys(); mutation.Release();
        }
    });

    private void BuildKeypad()
    {
        keypad.Children.Clear(); keypad.RowDefinitions.Clear(); keypad.ColumnDefinitions.Clear(); buttons.Clear(); metrics.Clear();
        naturalKeypadColumns = [];
        var columns = Math.Max(4, layout!.Keys.Max(key => key.Column) + 1);
        var rows = Math.Max(9, layout.Keys.Max(key => key.Row) + 1);
        for (var c = 0; c < columns; c++) keypad.ColumnDefinitions.Add(new() { Width = new(1, GridUnitType.Star), MinWidth = 0 });
        for (var r = 0; r < rows; r++) keypad.RowDefinitions.Add(new() { Height = new(32), MinHeight = 32 });
        foreach (var key in layout.Keys)
        {
            var button = new Button
            {
                Content = key.Text, MinHeight = 32, MinWidth = 0,
                CornerRadius = new(0), BorderThickness = new(0),
                HorizontalAlignment = HorizontalAlignment.Stretch, VerticalAlignment = VerticalAlignment.Stretch,
                IsEnabled = false, Tag = key.Bit
            };
            AutomationProperties.SetName(button, key.AccessibleName);
            AutomationProperties.SetHelpText(button, Text["key_help"]);
            var pointerActive = false;
            button.AddHandler(UIElement.PointerPressedEvent, new PointerEventHandler((sender, args) =>
            {
                if (!args.GetCurrentPoint(button).Properties.IsLeftButtonPressed) return;
                if (editing) return;
                if (!running || busy || DialogOpen) return;
                pointerActive = true;
                button.CapturePointer(args.Pointer);
                _ = Guard(() => input!.PressAsync(key.Bit, "pointer:" + args.Pointer.PointerId));
            }), true);
            PointerEventHandler release = (sender, args) =>
            {
                _ = Guard(async () => { if (input is not null) await input.ReleaseAsync(key.Bit, "pointer:" + args.Pointer.PointerId); });
                // Click runs synchronously after release; cancellation has no click.
                DispatcherQueue.TryEnqueue(() => pointerActive = false);
            };
            button.AddHandler(UIElement.PointerReleasedEvent, release, true);
            button.PointerCaptureLost += release;
            button.PointerCanceled += release;
            button.ContextRequested += async (_, args) => { args.Handled = true; await Guard(() => EditMappingAsync(key)); };
            button.Click += async (_, _) =>
            {
                // Pointer presses already have their own down/up lifetime. Click also supports UI Automation.
                if (pointerActive) { pointerActive = false; return; }
                if (editing) { await Guard(() => EditMappingAsync(key)); return; }
                if (running && !busy && !DialogOpen) await Guard(async () =>
                {
                    await input!.PressAsync(key.Bit, "invoke"); await input.ReleaseAsync(key.Bit, "invoke");
                });
            };
            Grid.SetRow(button, key.Row); Grid.SetColumn(button, key.Column); keypad.Children.Add(button); buttons[key.Bit] = button;
        }
        fold = Button(Text["fold_short_open"], () => Guard(async () => { if (running) await backend!.CallAsync("session.fold"); }));
        fold.CornerRadius = new(0); fold.BorderThickness = new(0);
        fold.IsEnabled = false; fold.MinWidth = 0; fold.HorizontalAlignment = HorizontalAlignment.Stretch; Grid.SetRow(fold, 3); keypad.Children.Add(fold);
        var numbers = new StackPanel { Spacing = 4, Margin = new(0, 6, 0, 0) };
        foreach (var metric in layout.Metrics)
        {
            var group = new StackPanel();
            group.Children.Add(Label(metric.Title, 11));
            var value = new CounterValue(metric.Title, metric.Description);
            group.Children.Add(value.Host); ToolTipService.SetToolTip(group, metric.Description);
            numbers.Children.Add(group); metrics[metric.Key] = value;
        }
        Grid.SetRow(numbers, 4); Grid.SetRowSpan(numbers, 4); keypad.Children.Add(numbers);
        done = Button(Text["done_short"], () => Guard(() => SetEditingAsync(false)));
        done.MinWidth = 0; done.MinHeight = 32; done.CornerRadius = new(0); done.BorderThickness = new(0);
        done.HorizontalAlignment = HorizontalAlignment.Stretch;
        done.Visibility = editing ? Visibility.Visible : Visibility.Collapsed;
        AutomationProperties.SetName(done, Text["done_editing"]);
        ToolTipService.SetToolTip(done, Text["done_editing"]);
        Grid.SetRow(done, 8); keypad.Children.Add(done);
        AutomationProperties.SetHelpText(keypad, Text["key_help"]);
        SetMetrics(); UpdateKeys();
        if (hasFrameGeometry) DispatcherQueue.TryEnqueue(() => Fit(false));
    }

    private static FontIcon PowerIcon() => new() { Glyph = "\uE7E8", FontFamily = new FontFamily(OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000) ? "Segoe Fluent Icons" : "Segoe MDL2 Assets"), FontSize = 16 };

    private void UpdateKeys()
    {
        if (power is not null)
        {
            var label = Text[running ? "stop_emulator" : "power_on_action"];
            power.Content = PowerIcon();
            AutomationProperties.SetName(power, label);
            ToolTipService.SetToolTip(power, label);
        }
        foreach (var (bit, button) in buttons)
        {
            var available = KeypadMapping.IsAvailable(bit, firmwareKeys, mappings);
            button.IsEnabled = !busy && (editing || (running && available));
            ToolTipService.SetToolTip(button, available ? Text["key_help"] : Text["key_unavailable"]);
            AutomationProperties.SetHelpText(button, available ? Text["key_help"] : Text["key_unavailable"]);
        }
    }

    private async Task MutateAsync(Func<Task> operation)
    {
        if (busy || IsClosing) return;
        await mutation.WaitAsync();
        busy = true; Commands.IsEnabled = false; UpdateKeys();
        try { await operation(); }
        catch
        {
            if (!running) { Title = firmware.Name; }
            throw;
        }
        finally { busy = false; Commands.IsEnabled = !IsClosing; UpdateKeys(); mutation.Release(); }
    }

    private Task BootAsync() => MutateAsync(StartSessionAsync);
    private Task TogglePowerAsync() => MutateAsync(async () => { if (running) await StopSessionAsync(); else await StartSessionAsync(); });
    private Task RestartAsync() => MutateAsync(async () =>
    {
        await StopSessionAsync(); await ReloadLayoutAsync(); await StartSessionAsync();
    });

    private Task StartSessionAsync() => WithTaskbarProgressAsync(StartSessionCoreAsync);

    private async Task StartSessionCoreAsync()
    {
        if (backend is null || IsClosing) return;
        await StopPollingAsync();
        await ReleaseAllAsync();
        await backend.CallAsync("session.stop");
        screen.Clear(); captureItem!.IsEnabled = false;
        Error.IsOpen = false;
        Title = firmware.Name;
        var result = (await backend.CallAsync("session.start")).As<SessionStarted>();
        if (IsClosing) return;
        chipset = result.Chipset; firmwareKeys = (result.NativeKeys ?? []).ToHashSet();
        mappings.Clear();
        foreach (var key in layout!.Keys)
        {
            var mapping = await backend.CallAsync("session.key_mapping", new { bit = key.Bit });
            mappings[key.Bit] = mapping.ValueKind == JsonValueKind.Null ? null : mapping.GetInt32();
        }
        Title = result.Title;
        lastState = await backend.CallAsync("session.state");
        running = true; frameSequence = secondarySequence = -1; secondarySeen = false; lastInputError = null;
        AutomationProperties.SetName(power!, Text["stop_emulator"]);
        UpdateKeys();
        polling = new();
        framePoll = Task.Run(() => PollFramesAsync(polling.Token));
        statePoll = Task.Run(() => PollStateAsync(polling.Token));
    }

    private async Task StopSessionAsync()
    {
        await StopPollingAsync();
        await ReleaseAllAsync();
        running = false;
        lastState = default;
        if (backend is not null) await backend.CallAsync("session.stop");
        screen.Clear(); captureItem!.IsEnabled = false;
        SetMetrics();
        if (fold is not null) fold.IsEnabled = false;
        secondary?.Hide(); secondaryItem!.IsEnabled = false;
        AutomationProperties.SetName(power!, Text["power_on_action"]);
        UpdateKeys();
    }

    private async Task StopPollingAsync()
    {
        if (polling is null) return;
        polling.Cancel();
        await Task.WhenAll(framePoll, statePoll);
        polling.Dispose(); polling = null;
    }

    private async Task PollFramesAsync(CancellationToken token)
    {
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1.0 / 30));
            while (await timer.WaitForNextTickAsync(token))
            {
                var frame = await backend!.CallAsync("session.frame", new { since = frameSequence, secondary_since = secondarySequence }, token);
                var primary = DecodeFrame(frame);
                RgbFrame? extra = null; JsonElement secondaryState = default;
                if (frame.TryGetProperty("secondary", out var s)) { secondaryState = s; extra = DecodeFrame(s); }
                await OnUiAsync(() =>
                {
                    if (token.IsCancellationRequested || IsClosing) return;
                    if (!frame.GetProperty("running").GetBoolean()) { SetStoppedState(); return; }
                    // Sequence zero is the decoder's profile-sized blank buffer, before LCD output.
                    if (primary is not null && frame.GetProperty("seq").GetInt64() > 0)
                    {
                        screen.ShowFrame(primary);
                        captureItem!.IsEnabled = true;
                        if (!hasFrameGeometry || lcd != (primary.Width, primary.Height))
                        { lcd = (primary.Width, primary.Height); hasFrameGeometry = true; Fit(); }
                    }
                    if (frame.TryGetProperty("seq", out var sequence)) frameSequence = sequence.GetInt64();
                    if (secondaryState.ValueKind == JsonValueKind.Object)
                    {
                        if (secondary is null && extra is not null) secondary = new(this, firmware.Sha256 ?? firmware.Path, Text, () => (int)Math.Round(Commands.ActualHeight * NativeWindow.Scale(this)) + 1);
                        if (secondary is not null)
                        {
                            var enabledValue = secondaryState.GetProperty("enabled");
                            bool? enabled = enabledValue.ValueKind is JsonValueKind.True or JsonValueKind.False ? enabledValue.GetBoolean() : null;
                            secondary.Update(extra, enabled, secondaryState.GetProperty("preview").GetBoolean());
                            if (!secondarySeen && extra is not null) { secondarySeen = true; secondary.Activate(); secondaryItem!.IsEnabled = true; }
                        }
                        secondarySequence = secondaryState.GetProperty("seq").GetInt64();
                    }
                });
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception error) { await OnUiAsync(() => { SetStoppedState(); ShowError(error); }); }
    }

    private async Task PollStateAsync(CancellationToken token)
    {
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(100));
            while (await timer.WaitForNextTickAsync(token))
            {
                var state = await backend!.CallAsync("session.state", cancellation: token);
                await OnUiAsync(() =>
                {
                    if (token.IsCancellationRequested || IsClosing) return;
                    lastState = state;
                    if (!state.GetProperty("running").GetBoolean()) { SetStoppedState(); return; }
                    var values = state.GetProperty("metrics");
                    SetMetrics(values);
                    var lid = state.GetProperty("fold");
                    fold!.IsEnabled = lid.ValueKind is JsonValueKind.True or JsonValueKind.False;
                    fold.Content = Text[lid.ValueKind == JsonValueKind.True ? "fold_short_close" : "fold_short_open"];
                    AutomationProperties.SetName(fold, Text[lid.ValueKind == JsonValueKind.Null ? "fold_unavailable" : lid.ValueKind == JsonValueKind.True ? "fold_access_close" : "fold_access_open"]);
                    AutomationProperties.SetHelpText(fold, lid.ValueKind == JsonValueKind.Null ? Text["fold_unavailable"] : "");
                    if (state.TryGetProperty("input_error", out var error) && error.ValueKind == JsonValueKind.String && error.GetString() != lastInputError)
                    { lastInputError = error.GetString(); ShowError(new IOException(lastInputError)); }
                });
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception error) { await OnUiAsync(() => { SetStoppedState(); ShowError(error); }); }
    }

    private void SetStoppedState()
    {
        running = false; lastState = default; polling?.Cancel(); secondary?.Hide();
        screen.Clear();
        if (captureItem is not null) captureItem.IsEnabled = false;
        SetMetrics();
        if (fold is not null) fold.IsEnabled = false;
        if (power is not null) AutomationProperties.SetName(power, Text["power_on_action"]);
        if (secondaryItem is not null) secondaryItem.IsEnabled = false;
        keyboardHeld.Clear();
        if (input is not null) _ = Guard(input.ReleaseAllAsync);
        UpdateKeys();
    }

    private void SetMetrics(JsonElement values = default)
    {
        foreach (var (key, label) in metrics)
        {
            label.SetValue(values.ValueKind == JsonValueKind.Object && values.TryGetProperty(key, out var value) ? value.ToString() : "—");
        }
    }

    private static RgbFrame? DecodeFrame(JsonElement value)
    {
        if (!value.TryGetProperty("rgb", out var rgb)) return null;
        var w = value.GetProperty("width").GetInt32(); var h = value.GetProperty("height").GetInt32();
        var bytes = rgb.GetBytesFromBase64();
        if (w <= 0 || h <= 0 || (long)w * h * 3 != bytes.Length) throw new InvalidDataException("Invalid LCD frame.");
        return new(w, h, bytes);
    }

    private Task OnUiAsync(Action action)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!DispatcherQueue.TryEnqueue(() => { try { action(); completion.SetResult(); } catch (Exception error) { completion.SetException(error); } })) completion.SetResult();
        return completion.Task;
    }

    private void Fit(bool force = true)
    {
        foreach (var column in keypad.ColumnDefinitions) column.MinWidth = 0;
        var naturalColumnWidths = new double[keypad.ColumnDefinitions.Count];
        foreach (var button in keypad.Children.OfType<Button>())
        {
            button.Measure(new(double.PositiveInfinity, double.PositiveInfinity));
            var column = Grid.GetColumn(button);
            naturalColumnWidths[column] = Math.Max(naturalColumnWidths[column], Math.Ceiling(button.DesiredSize.Width));
        }
        var minima = naturalKeypadColumns = KeypadSizing.NaturalColumns(naturalColumnWidths);
        for (var c = 0; c < minima.Length; c++)
        {
            var column = keypad.ColumnDefinitions[c];
            column.MinWidth = minima[c];
            column.Width = new(minima[c]);
        }
        var naturalKeypadWidth = keypad.ColumnDefinitions.Sum(column => column.MinWidth) +
            keypad.ColumnSpacing * (keypad.ColumnDefinitions.Count - 1) + keypad.Padding.Left + keypad.Padding.Right;
        keypad.Measure(new(naturalKeypadWidth, double.PositiveInfinity));
        ArrangeKeypadColumns();
        if (!NativeWindow.IsNormal(this)) return;
        fittedWorkArea = NativeWindow.WorkArea(this);
        fittedScale = NativeWindow.Scale(this);
        fittedAvailable = NativeWindow.AvailableClientSize(this);
        var size = DisplayGeometry.Initial(lcd.Width, lcd.Height, naturalKeypadWidth,
            keypad.DesiredSize.Height, Commands.ActualHeight + (Error.IsOpen ? Error.ActualHeight : 0), fittedAvailable);
        MinimumClientWidth = size.Width; MinimumClientHeight = size.Height;
        Root.MinWidth = size.Width; Root.MinHeight = size.Height;
        minimumTrackSize = NativeWindow.MinimumOuterSize(this, size.Width, size.Height);
        NativeWindow.SetMinimumClientSize(this, size.Width, size.Height);
        if (force || Root.ActualWidth < size.Width || Root.ActualHeight < size.Height || Root.ActualWidth > fittedAvailable.Width || Root.ActualHeight > fittedAvailable.Height)
            NativeWindow.ResizeClient(this, size.Width, size.Height, fitToWorkArea: true, constrainSize: false);
        NativeWindow.SetMinimumClientSize(this, size.Width, size.Height);
        ArrangeKeypadColumns();
    }

    private void ArrangeKeypadColumns()
    {
        if (naturalKeypadColumns.Length != keypad.ColumnDefinitions.Count || naturalKeypadColumns.Length < 2) return;
        var available = AppWindow.ClientSize.Width / NativeWindow.Scale(this) - keypad.Padding.Left - keypad.Padding.Right -
            keypad.ColumnSpacing * (naturalKeypadColumns.Length - 1);
        if (available <= 0) return;
        var widths = KeypadSizing.AllocateColumns(naturalKeypadColumns, available, NativeWindow.Scale(this));
        for (var c = 0; c < widths.Length; c++)
            if (keypad.ColumnDefinitions[c].Width.Value != widths[c])
                keypad.ColumnDefinitions[c].Width = new(widths[c]);
    }

    private static bool Down(VirtualKey key) => (InputKeyboardSource.GetKeyStateForCurrentThread(key) & CoreVirtualKeyStates.Down) != 0;

    private void KeyDown(object sender, KeyRoutedEventArgs args)
    {
        if (!running || busy || editing || DialogOpen || IsClosing || layout is null) return;
        if (args.OriginalSource is TextBox or PasswordBox or ComboBox) return;
        // Title-bar commands and their flyouts keep their native keyboard handling.
        for (var node = args.OriginalSource as DependencyObject; node is not null; node = VisualTreeHelper.GetParent(node))
            if (ReferenceEquals(node, Commands) || node is MenuFlyoutItemBase) return;
        var bit = KeypadMapping.Resolve(layout.Keyboard, (int)args.Key, Down(VirtualKey.Shift), Down(VirtualKey.Control), Down(VirtualKey.Menu), Down(VirtualKey.LeftWindows) || Down(VirtualKey.RightWindows));
        if (bit is null || !KeypadMapping.IsAvailable(bit.Value, firmwareKeys, mappings)) return;
        args.Handled = true;
        if (keyboardHeld.ContainsKey(args.Key)) return;
        keyboardHeld[args.Key] = bit.Value;
        _ = Guard(() => input!.PressAsync(bit.Value, "keyboard:" + (int)args.Key));
    }

    private void KeyUp(object sender, KeyRoutedEventArgs args)
    {
        if (!keyboardHeld.Remove(args.Key, out var bit)) return;
        args.Handled = true;
        _ = Guard(() => input!.ReleaseAsync(bit, "keyboard:" + (int)args.Key));
    }

    private async Task ReleaseAllAsync()
    {
        keyboardHeld.Clear();
        if (input is not null) await input.ReleaseAllAsync();
    }

    protected override Task BeforeDialogAsync() => ReleaseAllAsync();

    private async Task SetEditingAsync(bool value)
    {
        await ReleaseAllAsync(); editing = value;
        done!.Visibility = value ? Visibility.Visible : Visibility.Collapsed;
        RefreshTitleBar();
        editToggle!.IsChecked = value; UpdateKeys();
    }

    private async Task EditMappingAsync(KeyDefinition key)
    {
        if (mappingOpening || DialogOpen || busy || backend is null) return;
        mappingOpening = true;
        try { await EditMappingCoreAsync(key); }
        finally { mappingOpening = false; }
    }

    private async Task EditMappingCoreAsync(KeyDefinition key)
    {
        if (backend is null || busy || DialogOpen) return;
        var saved = await backend.CallAsync("session.key_mapping", new { bit = key.Bit });
        var entry = new TextBox { Header = Text["mapping_hint"], Text = saved.ValueKind == JsonValueKind.Null ? "" : $"0x{saved.GetInt32():X2}" };
        AutomationProperties.SetName(entry, key.AccessibleName + " · " + Text["edit_input"]);
        var content = new StackPanel { Spacing = 12 }; var error = new InfoBar { Severity = InfoBarSeverity.Error };
        content.Children.Add(entry); content.Children.Add(error);
        var dialog = new ContentDialog { Title = key.AccessibleName, Content = content, PrimaryButtonText = Text["save"], CloseButtonText = Text["cancel"], DefaultButton = ContentDialogButton.Primary };
        dialog.PrimaryButtonClick += async (_, args) =>
        {
            var deferral = args.GetDeferral();
            try
            {
                var result = await backend.CallAsync("session.set_key_mapping", new { bit = key.Bit, value = entry.Text });
                mappings[key.Bit] = result.ValueKind == JsonValueKind.Null ? null : result.GetInt32(); UpdateKeys();
            }
            catch (Exception failure) { args.Cancel = true; error.Message = failure.Message; error.IsOpen = true; }
            finally { deferral.Complete(); }
        };
        await ShowDialogAsync(dialog);
    }

    private async Task CaptureAsync()
    {
        var frame = screen.Frame; if (frame is null) return;
        await ReleaseAllAsync();
        var picker = new FileSavePicker { SuggestedFileName = Path.GetFileNameWithoutExtension(firmware.Path) + ".png" };
        picker.FileTypeChoices.Add("PNG", new List<string> { ".png" });
        WinRT.Interop.InitializeWithWindow.Initialize(picker, WinRT.Interop.WindowNative.GetWindowHandle(this));
        var file = await picker.PickSaveFileAsync();
        if (file is not null) await ScreenView.SavePngAsync(frame, file.Path);
    }

    private async Task SetTimeAsync()
    {
        var settings = await backend!.CallAsync("settings.get");
        var entry = new TextBox { Header = Text["network_start_time"], Text = settings.GetProperty("network_start_time").GetString() ?? "", PlaceholderText = Text["time_format"] };
        AutomationProperties.SetName(entry, Text["network_start_time"]);
        var content = new StackPanel { Spacing = 12 }; var error = new InfoBar { Severity = InfoBarSeverity.Error };
        content.Children.Add(entry); content.Children.Add(error);
        var dialog = new ContentDialog { Title = Text["time"], Content = content, PrimaryButtonText = Text["save"], CloseButtonText = Text["cancel"] };
        dialog.PrimaryButtonClick += async (_, args) =>
        {
            var deferral = args.GetDeferral();
            try
            {
                if (!SettingsValidation.NetworkTime(entry.Text)) throw new ArgumentException(Text["network_time_error"]);
                await backend.CallAsync("settings.set", new { key = "network_start_time", value = entry.Text });
                await backend.CallAsync("settings.set", new { key = "network_host_time", value = false });
                if (running) await backend.CallAsync("session.network_time");
            }
            catch (Exception failure) { args.Cancel = true; error.Message = failure.Message; error.IsOpen = true; }
            finally { deferral.Complete(); }
        };
        await ShowDialogAsync(dialog);
    }

    private async Task InfoAsync()
    {
        var content = new StackPanel { Spacing = 12 };
        content.Children.Add(Label(firmware.Name, 20)); content.Children.Add(Label(firmware.Path));
        content.Children.Add(Label($"{chipset} · {lcd.Width}×{lcd.Height}"));
        var network = lastState.ValueKind == JsonValueKind.Object && lastState.TryGetProperty("virtual_cell", out var cell) ? cell : default;
        var notice = network.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined
            ? Text["virtual_network_menu"] + ": " + Text["power_off"]
            : network.GetString() == "configured" ? Text["virtual_network_active"] + ": " + Text["power_on"] : Text["virtual_network_unavailable"];
        content.Children.Add(Label(notice));
        foreach (var metric in layout?.Metrics ?? [])
        {
            var value = lastState.ValueKind == JsonValueKind.Object && lastState.TryGetProperty("metrics", out var m) && m.TryGetProperty(metric.Key, out var v) ? v.ToString() : "—";
            content.Children.Add(Label(metric.Title + ": " + value + "\n" + metric.Description));
        }
        await ShowDialogAsync(new() { Title = Text["library_info"], Content = new ScrollViewer { Content = content }, CloseButtonText = Text["close"] });
    }

    private async Task SettingsAsync()
    {
        await ShowSettingsAsync(backend!, RestartAsync);
    }

    protected override void ForceShutdown()
    {
        backendLifetime.Cancel();
        backend?.Abort();
        secondary?.DisposeWindow();
        secondary = null;
        screen.Stop();
    }

    protected override async Task ShutdownAsync()
    {
        await initialize;
        await mutation.WaitAsync();
        try
        {
            await StopPollingAsync();
            if (backend is not null)
            {
                try { await ReleaseAllAsync(); await backend.CallAsync("session.stop").WaitAsync(TimeSpan.FromSeconds(10)); }
                catch (Exception error) { System.Diagnostics.Debug.WriteLine(error); }
                finally { await backend.DisposeAsync(); }
            }
        }
        finally { mutation.Release(); secondary?.DisposeWindow(); screen.Stop(); }
    }
}
