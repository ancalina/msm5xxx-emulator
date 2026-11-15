using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Msm5xxx.Desktop.Core;
using Windows.System;

namespace Msm5xxx.Desktop;

internal sealed class SettingsWindow : DesktopWindow
{
    private readonly BackendClient backend;
    private readonly Func<Task>? restart;
    private readonly StackPanel form = new() { Spacing = 20, Margin = new(24) };
    private readonly ScrollViewer page = new() { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
    private readonly StackPanel hardwarePanel = new() { Spacing = 16 };
    private readonly Dictionary<string, Func<string>> hardware = [];
    private readonly List<Action> translate = [];
    private readonly SemaphoreSlim saving = new(1, 1);
    private readonly Task initialize;
    private Task pending = Task.CompletedTask;
    private readonly TextBox networkTime = new();
    private string? savedLanguage;
    private string savedTime = "";
    private bool updating, timeSaving, hardwareApplying;

    public SettingsWindow(BackendClient backend, Strings text, Func<Task>? restart)
    {
        this.backend = backend; this.restart = restart; Text = text;
        Title = Text["settings"];
        page.Content = form; Body.Children.Add(page);
        MinimumClientWidth = 480; MinimumClientHeight = 420;
        NativeWindow.ResizeClient(this, 640, 740, fitToWorkArea: true);
        initialize = Guard(InitializeAsync);
    }

    protected override bool CanRetry => false;

    private TextBlock Heading(string key, double size = 20)
    {
        var label = Label(Text[key], size);
        translate.Add(() => label.Text = Text[key]);
        return label;
    }

    private async Task InitializeAsync()
    {
        page.IsEnabled = false;
        try
        {
            var current = await backend.CallAsync("settings.get");
            if (IsClosing) return;
            form.Children.Add(Heading("restart_notice", 14));
            form.Children.Add(Heading("app_settings"));
            foreach (var key in new[] { "persistent_state", "virtual_network", "network_host_time", "experimental_rex" })
            {
                var saved = current.GetProperty(key).GetBoolean();
                var toggle = new ToggleSwitch { IsOn = saved, HorizontalAlignment = HorizontalAlignment.Stretch };
                translate.Add(() =>
                {
                    toggle.Header = Text[key]; toggle.OnContent = Text["power_on"]; toggle.OffContent = Text["power_off"];
                    AutomationProperties.SetName(toggle, Text[key]);
                });
                toggle.Toggled += async (_, _) =>
                {
                    if (updating) return;
                    var requested = toggle.IsOn;
                    await ChangeAsync(toggle, async () =>
                    {
                        try
                        {
                            await backend.CallAsync("settings.set", new { key, value = requested }); saved = requested;
                            if (restart is not null) await restart();
                        }
                        catch { updating = true; toggle.IsOn = saved; updating = false; throw; }
                    });
                };
                form.Children.Add(toggle);
            }
            savedTime = current.GetProperty("network_start_time").GetString() ?? "";
            networkTime.Text = savedTime;
            translate.Add(() =>
            {
                networkTime.Header = Text["network_start_time"]; networkTime.PlaceholderText = Text["time_format"];
                AutomationProperties.SetName(networkTime, Text["network_start_time"]);
            });
            networkTime.LostFocus += async (_, _) => await SaveTimeAsync();
            networkTime.KeyDown += async (_, args) =>
            {
                if (args.Key == VirtualKey.Enter) { args.Handled = true; await SaveTimeAsync(); }
            };
            form.Children.Add(networkTime);
            var languages = new[] { "auto", "ko", "en" };
            savedLanguage = current.GetProperty("ui_language").GetString();
            var language = new ComboBox { HorizontalAlignment = HorizontalAlignment.Stretch };
            foreach (var _ in languages) language.Items.Add(new ComboBoxItem());
            translate.Add(() =>
            {
                var selected = Math.Max(0, Array.IndexOf(languages, savedLanguage));
                language.SelectedIndex = -1;
                language.Header = Text["ui_language"];
                var names = new[] { Text["default_language"], "한국어", "English" };
                for (var i = 0; i < names.Length; i++) ((ComboBoxItem)language.Items[i]).Content = names[i];
                language.SelectedIndex = selected; AutomationProperties.SetName(language, Text["ui_language"]);
            });
            language.SelectionChanged += async (_, _) =>
            {
                if (updating || language.SelectedIndex < 0) return;
                var requested = languages[language.SelectedIndex];
                await ChangeAsync(language, async () =>
                {
                    try
                    {
                        await backend.CallAsync("settings.set", new { key = "ui_language", value = requested });
                        savedLanguage = requested;
                        await App.Instance.RefreshLanguagesAsync();
                    }
                    catch { updating = true; language.SelectedIndex = Math.Max(0, Array.IndexOf(languages, savedLanguage)); updating = false; throw; }
                });
            };
            form.Children.Add(language);
            var icon = new ComboBox { HorizontalAlignment = HorizontalAlignment.Stretch };
            icon.Items.Add(new ComboBoxItem()); icon.Items.Add(new ComboBoxItem());
            translate.Add(() =>
            {
                icon.SelectedIndex = -1;
                icon.Header = Text["app_icon"];
                ((ComboBoxItem)icon.Items[0]).Content = Text["icon_full"]; ((ComboBoxItem)icon.Items[1]).Content = Text["icon_simple"];
                icon.SelectedIndex = WindowIcons.Simple ? 1 : 0; AutomationProperties.SetName(icon, Text["app_icon"]);
            });
            icon.SelectionChanged += async (_, _) =>
            {
                if (updating || icon.SelectedIndex < 0) return;
                var requested = icon.SelectedIndex == 1;
                await ChangeAsync(icon, () =>
                {
                    try { WindowIcons.SetSimple(requested); }
                    catch { updating = true; icon.SelectedIndex = WindowIcons.Simple ? 1 : 0; updating = false; throw; }
                    return Task.CompletedTask;
                });
            };
            form.Children.Add(icon);
            if (restart is not null)
            {
                form.Children.Add(Heading("hardware_settings"));
                form.Children.Add(hardwarePanel);
                var apply = new Button { HorizontalAlignment = HorizontalAlignment.Left };
                translate.Add(() => { apply.Content = Text["apply"]; AutomationProperties.SetName(apply, Text["apply"]); });
                apply.Click += async (_, _) => await ChangeAsync(apply, async () =>
                {
                    hardwareApplying = true;
                    foreach (var section in hardwarePanel.Children.OfType<Control>()) section.IsEnabled = false;
                    try
                    {
                        var values = hardware.ToDictionary(pair => pair.Key, pair => pair.Value());
                        if (values.TryGetValue("model", out var model) && string.IsNullOrWhiteSpace(model))
                            throw new FormatException(Text["validation_00"]);
                        await backend.CallAsync("session.apply_settings", new { values });
                        await restart();
                        await LoadHardwareAsync();
                    }
                    finally
                    {
                        hardwareApplying = false;
                        foreach (var section in hardwarePanel.Children.OfType<Control>()) section.IsEnabled = true;
                    }
                });
                form.Children.Add(apply);
                await LoadHardwareAsync();
            }
            Relabel();
        }
        finally { page.IsEnabled = true; }
    }

    private void Relabel()
    {
        updating = true;
        try
        {
            Title = Text["settings"]; AutomationProperties.SetName(Commands, Text["settings"]);
            foreach (var update in translate) update();
        }
        finally { updating = false; }
    }

    internal async Task RefreshLanguageAsync()
    {
        await initialize;
        if (IsClosing) return;
        var language = (await backend.CallAsync("hello")).GetProperty("language").GetString() ?? "auto";
        if (language == Text.Language) return;
        savedLanguage = (await backend.CallAsync("settings.get")).GetProperty("ui_language").GetString();
        Text = new(language); Relabel();
        if (restart is not null) await LoadHardwareAsync(preserve: true);
    }

    private async Task LoadHardwareAsync(bool preserve = false)
    {
        var settings = (await backend.CallAsync("session.settings")).As<HardwareSettings>();
        if (IsClosing) return;
        var drafts = preserve ? hardware.ToDictionary(pair => pair.Key, pair => pair.Value()) : new Dictionary<string, string>();
        hardware.Clear(); hardwarePanel.Children.Clear();
        foreach (var section in settings.Sections)
        {
            var group = new StackPanel { Spacing = 12 };
            foreach (var field in section.Fields)
            {
                var value = drafts.GetValueOrDefault(field.Name, field.Value);
                if (field.Choices is { } choices)
                {
                    var values = choices.Contains(value) ? choices : choices.Prepend(value).ToArray();
                    var picker = new ComboBox { Header = field.Label, ItemsSource = values, SelectedItem = value, HorizontalAlignment = HorizontalAlignment.Stretch };
                    AutomationProperties.SetName(picker, field.Label); group.Children.Add(picker);
                    hardware[field.Name] = () => picker.SelectedItem?.ToString() ?? value;
                }
                else
                {
                    var input = new TextBox { Header = field.Label, Text = value };
                    AutomationProperties.SetName(input, field.Label); group.Children.Add(input);
                    hardware[field.Name] = () => input.Text;
                }
            }
            hardwarePanel.Children.Add(new Expander { IsEnabled = !hardwareApplying, Header = section.Title, Content = group, HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch });
        }
    }

    private Task ChangeAsync(Control control, Func<Task> change)
    {
        var work = SaveAsync();
        pending = Task.WhenAll(pending, work);
        return work;
        async Task SaveAsync()
        {
            control.IsEnabled = false;
            await saving.WaitAsync();
            try { await Guard(async () => { await change(); Error.IsOpen = false; }); }
            finally { saving.Release(); control.IsEnabled = true; }
        }
    }

    private async Task SaveTimeAsync()
    {
        if (timeSaving || networkTime.Text == savedTime) return;
        var requested = networkTime.Text;
        if (!SettingsValidation.NetworkTime(requested)) { ShowError(new FormatException(Text["network_time_error"])); return; }
        timeSaving = true;
        try
        {
            await ChangeAsync(networkTime, async () =>
            {
                await backend.CallAsync("settings.set", new { key = "network_start_time", value = requested }); savedTime = requested;
            });
        }
        finally { timeSaving = false; }
    }

    protected override async Task ShutdownAsync()
    {
        await initialize;
        await SaveTimeAsync();
        await pending;
    }
}
