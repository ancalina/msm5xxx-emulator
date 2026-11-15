using System.Text.Json;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Msm5xxx.Desktop.Core;

namespace Msm5xxx.Desktop;

internal static class SettingsDialog
{
    public static async Task ShowAsync(DesktopWindow owner, BackendClient backend, Strings text,
        Func<Task>? restart = null)
    {
        var current = await backend.CallAsync("settings.get");
        var body = new StackPanel { Spacing = 20, MinWidth = 280 };
        var error = new InfoBar { Severity = InfoBarSeverity.Error, IsClosable = false };
        AutomationProperties.SetName(error, text["settings_error"]);
        AutomationProperties.SetLiveSetting(error, Microsoft.UI.Xaml.Automation.Peers.AutomationLiveSetting.Polite);
        body.Children.Add(DesktopWindow.Label(text["restart_notice"]));
        body.Children.Add(DesktopWindow.Label(text["app_settings"], 20));
        var booleans = new Dictionary<string, CheckBox>();
        foreach (var key in new[] { "persistent_state", "virtual_network", "network_host_time", "experimental_rex" })
        {
            var box = new CheckBox { Content = text[key], IsChecked = current.GetProperty(key).GetBoolean() };
            AutomationProperties.SetName(box, text[key]); body.Children.Add(box); booleans.Add(key, box);
        }
        var time = new TextBox { Header = text["network_start_time"], Text = current.GetProperty("network_start_time").GetString() ?? "", PlaceholderText = text["time_format"] };
        AutomationProperties.SetName(time, text["network_start_time"]);
        body.Children.Add(time);
        var languages = new[] { "auto", "ko", "en" };
        var language = new ComboBox
        {
            Header = text["ui_language"], ItemsSource = new[] { text["default_language"], "한국어", "English" },
            SelectedIndex = Math.Max(0, Array.IndexOf(languages, current.GetProperty("ui_language").GetString())),
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        AutomationProperties.SetName(language, text["ui_language"]); body.Children.Add(language);
        var icon = new ComboBox { Header = text["app_icon"], ItemsSource = new[] { text["icon_full"], text["icon_simple"] }, SelectedIndex = WindowIcons.Simple ? 1 : 0, HorizontalAlignment = HorizontalAlignment.Stretch };
        AutomationProperties.SetName(icon, text["app_icon"]); body.Children.Add(icon);
        var hardware = new Dictionary<string, Func<string>>();
        if (restart is not null)
        {
            var settings = (await backend.CallAsync("session.settings")).As<HardwareSettings>();
            body.Children.Add(DesktopWindow.Label(text["hardware_settings"], 20));
            foreach (var section in settings.Sections)
            {
                var group = new StackPanel { Spacing = 12 };
                foreach (var field in section.Fields)
                {
                    if (field.Choices is { } choices)
                    {
                        var values = choices.Contains(field.Value) ? choices : choices.Prepend(field.Value).ToArray();
                        var picker = new ComboBox { Header = field.Label, ItemsSource = values, SelectedItem = field.Value, HorizontalAlignment = HorizontalAlignment.Stretch };
                        AutomationProperties.SetName(picker, field.Label); group.Children.Add(picker);
                        hardware[field.Name] = () => picker.SelectedItem?.ToString() ?? field.Value;
                    }
                    else
                    {
                        var input = new TextBox { Header = field.Label, Text = field.Value };
                        AutomationProperties.SetName(input, field.Label); group.Children.Add(input);
                        hardware[field.Name] = () => input.Text;
                    }
                }
                body.Children.Add(new Expander { Header = section.Title, Content = group, HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Stretch });
            }
        }
        var content = new Grid { RowSpacing = 12 };
        content.RowDefinitions.Add(new() { Height = GridLength.Auto });
        content.RowDefinitions.Add(new() { Height = new(1, GridUnitType.Star) });
        content.Children.Add(error);
        var form = new ScrollViewer { Content = body, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        Grid.SetRow(form, 1); content.Children.Add(form);
        var dialog = new ContentDialog
        {
            Title = text["settings"], Content = content,
            PrimaryButtonText = text[restart is null ? "save" : "apply"], CloseButtonText = text["cancel"],
            DefaultButton = ContentDialogButton.Primary
        };
        var changed = false;
        dialog.PrimaryButtonClick += async (_, args) =>
        {
            var deferral = args.GetDeferral();
            dialog.IsPrimaryButtonEnabled = false;
            try
            {
                if (!SettingsValidation.NetworkTime(time.Text))
                { args.Cancel = true; error.Message = text["network_time_error"]; error.IsOpen = true; time.Focus(FocusState.Programmatic); return; }
                // Hardware validation runs before any app-wide values are saved.
                if (restart is not null)
                {
                    var values = hardware.ToDictionary(pair => pair.Key, pair => pair.Value());
                    if (values.TryGetValue("model", out var model) && string.IsNullOrWhiteSpace(model))
                    { args.Cancel = true; error.Message = text["validation_00"]; error.IsOpen = true; return; }
                    await backend.CallAsync("session.apply_settings", new { values });
                }
                foreach (var (key, box) in booleans)
                    if (box.IsChecked != current.GetProperty(key).GetBoolean())
                        await backend.CallAsync("settings.set", new { key, value = box.IsChecked == true });
                if (time.Text != current.GetProperty("network_start_time").GetString())
                    await backend.CallAsync("settings.set", new { key = "network_start_time", value = time.Text });
                var selected = languages[language.SelectedIndex];
                if (selected != current.GetProperty("ui_language").GetString())
                    await backend.CallAsync("settings.set", new { key = "ui_language", value = selected });
                WindowIcons.SetSimple(icon.SelectedIndex == 1);
                changed = true;
            }
            catch (Exception failure) { args.Cancel = true; error.Message = failure.Message; error.IsOpen = true; }
            finally { dialog.IsPrimaryButtonEnabled = true; deferral.Complete(); }
        };
        await owner.ShowDialogAsync(dialog);
        if (changed && restart is not null) await restart();
    }
}
