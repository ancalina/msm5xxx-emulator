using System.Globalization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media.Imaging;
using Msm5xxx.Desktop.Core;
using Windows.System;

namespace Msm5xxx.Desktop;

public sealed class LauncherWindow : DesktopWindow
{
    private BackendClient? backend;
    private readonly ListView list = new() { IsItemClickEnabled = true, SelectionMode = ListViewSelectionMode.Single };
    private readonly ProgressBar progress = new() { IsIndeterminate = true, Visibility = Visibility.Collapsed };
    private readonly StackPanel empty = new() { Spacing = 16, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
    private LibrarySnapshot? snapshot;
    private bool scanning;
    private bool refreshPending;
    private readonly Task initialize;

    public LauncherWindow()
    {
        MinimumClientWidth = 480; MinimumClientHeight = 300;
        empty.Visibility = Visibility.Collapsed;
        NativeWindow.ResizeClient(this, 760, 600, fitToWorkArea: true);
        Root.Loaded += (_, _) => NativeWindow.ResizeClient(this, 760, 600, fitToWorkArea: true);
        list.ItemClick += (_, args) =>
        {
            try
            {
                if (args.ClickedItem is FrameworkElement { Tag: FirmwareEntry { Available: true } entry }) App.Instance.Open(entry);
            }
            catch (Exception error) { ShowError(error); }
        };
        Body.RowDefinitions.Add(new() { Height = GridLength.Auto });
        Body.RowDefinitions.Add(new() { Height = new(1, GridUnitType.Star) });
        Body.Children.Add(progress); Grid.SetRow(list, 1); Body.Children.Add(list);
        Grid.SetRow(empty, 1); Body.Children.Add(empty);
        BuildCommands();
        AddShortcut(VirtualKey.O, ImportAsync);
        AddShortcut(VirtualKey.R, RefreshAsync);
        initialize = Guard(InitializeAsync);
    }

    private void AddShortcut(VirtualKey key, Func<Task> action)
    {
        var accelerator = new KeyboardAccelerator { Key = key, Modifiers = VirtualKeyModifiers.Control };
        accelerator.Invoked += async (_, args) =>
        {
            args.Handled = true;
            if (!DialogOpen && !IsClosing && Commands.IsEnabled) await Guard(action);
        };
        Root.KeyboardAccelerators.Add(accelerator);
    }

    private void BuildCommands()
    {
        Title = "MSM5xxx"; Commands.Subtitle = Text["library_title"];
        TitleActions.Children.Clear();
        var add = Command(Text["library_import"], Symbol.Add, ImportAsync);
        var menu = AddMenu();
        menu.Items.Add(MenuItem(Text["library_add_folder"], AddFolderAsync));
        menu.Items.Add(MenuItem(Text["library_remove_folder"], RemoveFolderAsync));
        var refresh = MenuItem(Text["library_refresh"], RefreshAsync);
        menu.Items.Add(refresh);
        menu.Items.Add(new MenuFlyoutSeparator());
        menu.Items.Add(MenuItem(Text["settings"], SettingsAsync));
        empty.Children.Clear(); empty.Children.Add(Label(Text["library_empty"], 20));
        empty.Children.Add(Button(Text["library_import"], () => Guard(ImportAsync)));
        AutomationProperties.SetName(list, Text["library_title"]);
        AutomationProperties.SetName(Commands, Text["commands"]);
        AutomationProperties.SetName(progress, Text["library_loading"]);
    }

    private async Task InitializeAsync()
    {
        Commands.IsEnabled = false;
        progress.Visibility = Visibility.Visible;
        try
        {
            backend = await BackendClient.StartAsync(App.Instance.Options);
            if (IsClosing) return;
            await ReloadLanguageAsync();
            await RefreshAsync();
        }
        finally { Commands.IsEnabled = !IsClosing; progress.Visibility = Visibility.Collapsed; }
    }

    private async Task ReloadLanguageAsync()
    {
        var hello = await backend!.CallAsync("hello");
        Text = new(hello.GetProperty("language").GetString()!);
        BuildCommands();
    }

    private async Task EnsureBackendAsync()
    {
        if (backend is { IsConnected: false }) { await backend.DisposeAsync(); backend = null; }
        if (backend is null) backend = await BackendClient.StartAsync(App.Instance.Options);
    }

    internal Task RefreshLanguageAsync() => Guard(async () =>
    {
        if (backend is null || IsClosing) return;
        var language = (await backend.CallAsync("hello")).GetProperty("language").GetString();
        if (language == Text.Language) return;
        await ReloadLanguageAsync();
        await RefreshAsync();
    });

    protected override Task RetryAsync() => RefreshAsync();

    public void RefreshAfterSession()
    {
        if (!IsClosing) _ = Guard(RefreshAsync);
    }

    private async Task RefreshAsync()
    {
        if (IsClosing) return;
        if (scanning) { refreshPending = true; return; }
        scanning = true; progress.Visibility = Visibility.Visible; empty.Visibility = Visibility.Collapsed;
        try
        {
            await EnsureBackendAsync();
            snapshot = (await backend!.CallAsync("library.scan")).As<LibrarySnapshot>();
            if (IsClosing) return;
            list.Items.Clear();
            foreach (var entry in snapshot.Entries) list.Items.Add(CreateRow(entry));
            empty.Visibility = snapshot.Entries.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
            Error.IsOpen = false;
        }
        finally
        {
            scanning = false; progress.Visibility = Visibility.Collapsed;
            if (refreshPending && !IsClosing) { refreshPending = false; _ = Guard(RefreshAsync); }
        }
    }

    private ListViewItem CreateRow(FirmwareEntry entry)
    {
        var row = new Grid { ColumnSpacing = 16, Padding = new(8), HorizontalAlignment = HorizontalAlignment.Stretch, Tag = entry };
        row.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        row.ColumnDefinitions.Add(new() { Width = new(1, GridUnitType.Star) });
        row.ColumnDefinitions.Add(new() { Width = GridLength.Auto });
        var image = new Image { Width = 56, Height = 64, Stretch = Microsoft.UI.Xaml.Media.Stretch.Uniform };
        if (!string.IsNullOrWhiteSpace(entry.Thumbnail)) image.Source = new BitmapImage(new Uri(Path.GetFullPath(entry.Thumbnail)));
        AutomationProperties.SetName(image, entry.Name);
        row.Children.Add(image);
        var subtitle = entry.Available ? $"{entry.Chipset ?? Text["library_unavailable"]} · {Path.GetFileName(entry.Path)}" : Text["library_unavailable"];
        var labels = new StackPanel { Spacing = 4, VerticalAlignment = VerticalAlignment.Center };
        var name = Label(entry.Name, 18); name.IsTextSelectionEnabled = false;
        var detail = Label(subtitle); detail.IsTextSelectionEnabled = false;
        labels.Children.Add(name); labels.Children.Add(detail); Grid.SetColumn(labels, 1); row.Children.Add(labels);
        var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, VerticalAlignment = VerticalAlignment.Center };
        var info = Button(Text["library_info"], () => Guard(() => InfoAsync(entry)));
        AutomationProperties.SetName(info, Text["library_info"] + " · " + entry.Name);
        var remove = Button(Text["library_remove"], () => Guard(() => RemoveAsync(entry)));
        AutomationProperties.SetName(remove, Text["library_remove"] + " · " + entry.Name);
        actions.Children.Add(info); actions.Children.Add(remove); Grid.SetColumn(actions, 2); row.Children.Add(actions);
        var item = new ListViewItem { Content = row, Tag = entry, HorizontalContentAlignment = HorizontalAlignment.Stretch };
        AutomationProperties.SetName(item, entry.Name + " · " + subtitle);
        return item;
    }

    private async Task ImportAsync()
    {
        var path = await PickFileAsync(); if (path is null || IsClosing) return;
        await EnsureBackendAsync(); await backend!.CallAsync("library.add_file", new { path }); await RefreshAsync();
    }

    private async Task AddFolderAsync()
    {
        var path = await PickFolderAsync(); if (path is null || IsClosing) return;
        await EnsureBackendAsync(); await backend!.CallAsync("library.add_folder", new { path }); await RefreshAsync();
    }

    private async Task RemoveFolderAsync()
    {
        var folders = snapshot?.Folders ?? [];
        if (folders.Length == 0)
        {
            await ShowDialogAsync(new() { Title = Text["library_remove_folder"], Content = Text["folder_empty"], CloseButtonText = Text["close"] }); return;
        }
        var choice = new ComboBox { ItemsSource = folders, SelectedIndex = 0, HorizontalAlignment = HorizontalAlignment.Stretch };
        AutomationProperties.SetName(choice, Text["library_remove_folder"]);
        var content = new StackPanel { Spacing = 12 }; content.Children.Add(Label(Text["folder_notice"])); content.Children.Add(choice);
        if (await ShowDialogAsync(new() { Title = Text["library_remove_folder"], Content = content, PrimaryButtonText = Text["library_remove"], CloseButtonText = Text["cancel"] }) == ContentDialogResult.Primary)
        { await backend!.CallAsync("library.remove_folder", new { path = (string)choice.SelectedItem }); await RefreshAsync(); }
    }

    private async Task RemoveAsync(FirmwareEntry entry)
    {
        if (await ShowDialogAsync(new() { Title = entry.Name, Content = Text["remove_notice"], PrimaryButtonText = Text["library_remove"], CloseButtonText = Text["cancel"] }) != ContentDialogResult.Primary) return;
        await backend!.CallAsync("library.remove", new { path = entry.Path }); await RefreshAsync();
    }

    private async Task InfoAsync(FirmwareEntry entry)
    {
        var last = entry.LastBooted is > 0 ? DateTimeOffset.FromUnixTimeMilliseconds((long)(entry.LastBooted.Value * 1000)).ToLocalTime().ToString("g", CultureInfo.CurrentCulture) : Text["library_never"];
        var content = new StackPanel { Spacing = 12 };
        foreach (var (label, value) in new[] { ("library_model", entry.Model), ("library_chipset", entry.Chipset), ("library_size", entry.Size.HasValue ? entry.Size.Value.ToString("N0") + " B" : "—"), ("library_path", entry.Path), ("library_last", last) })
            content.Children.Add(Label(Text[label] + "\n" + (value ?? "—")));
        await ShowDialogAsync(new() { Title = entry.Name, Content = new ScrollViewer { Content = content }, CloseButtonText = Text["close"] });
    }

    private async Task SettingsAsync()
    {
        await EnsureBackendAsync();
        await ShowSettingsAsync(backend!);
    }

    protected override Task<bool> CanCloseAsync() => App.Instance.CloseSessionsAsync();

    protected override async Task ShutdownAsync()
    {
        await initialize;
        if (backend is not null) await backend.DisposeAsync();
    }
}
