use crate::i18n::Text;
use adw::prelude::*;
use gtk::{gio, glib};

pub fn name(widget: &impl IsA<gtk::Accessible>, label: &str) {
    widget.update_property(&[gtk::accessible::Property::Label(label)]);
}
pub fn icon_button(icon: &str, label: &str) -> gtk::Button {
    let button = gtk::Button::builder()
        .icon_name(icon)
        .tooltip_text(label)
        .valign(gtk::Align::Center)
        .build();
    name(&button, label);
    button
}
pub fn menu(model: &gio::Menu, text: &Text) -> gtk::MenuButton {
    let label = text.tr("Main Menu");
    let button = gtk::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .menu_model(model)
        .primary(true)
        .tooltip_text(&label)
        .build();
    name(&button, &label);
    button
}
pub fn action(
    window: &adw::ApplicationWindow,
    name: &str,
    callback: impl Fn() + 'static,
) -> gio::SimpleAction {
    let action = gio::SimpleAction::new(name, None);
    action.connect_activate(move |_, _| callback());
    window.add_action(&action);
    action
}
pub fn alert(parent: &impl IsA<gtk::Widget>, text: &Text, heading: &str, body: &str) {
    if !parent.is_mapped() || !parent.is_sensitive() {
        return;
    }
    let dialog = adw::AlertDialog::builder()
        .heading(heading)
        .body(text.tr(body))
        .build();
    dialog.add_response("close", &text.tr("Close"));
    dialog.set_close_response("close");
    dialog.present(Some(parent));
}
pub fn info(parent: &impl IsA<gtk::Widget>, text: &Text, entry: &serde_json::Value) -> adw::Dialog {
    let dialog = adw::Dialog::builder()
        .title(entry["name"].as_str().unwrap_or(&text.tr("Info")))
        .content_width(440)
        .content_height(480)
        .build();
    let group = adw::PreferencesGroup::new();
    let size = entry["size"]
        .as_u64()
        .map(|n| format!("{:.2} MiB ({n} {})", n as f64 / 1048576., text.tr("bytes")))
        .unwrap_or_else(|| "—".into());
    let last = entry["last_booted"]
        .as_f64()
        .and_then(|n| glib::DateTime::from_unix_local(n as i64).ok())
        .and_then(|t| t.format("%x %X").ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| text.tr("Never booted"));
    let mut rows = vec![
        ("Model", entry["model"].as_str().unwrap_or("—").to_owned()),
        (
            "Chipset",
            entry["chipset"].as_str().unwrap_or("—").to_owned(),
        ),
        ("Size", size),
        ("Path", entry["path"].as_str().unwrap_or("—").to_owned()),
        ("Last booted", last),
    ];
    for (key, label) in [
        ("power", "Power"),
        ("display", "Display"),
        ("network", "Virtual Network"),
        ("secondary", "Secondary Display"),
    ] {
        if let Some(value) = entry[key].as_str() {
            rows.insert(2, (label, value.to_owned()));
        }
    }
    for (label, value) in rows {
        let row = adw::ActionRow::builder()
            .title(text.tr(label))
            .subtitle(glib::markup_escape_text(&value))
            .subtitle_selectable(true)
            .build();
        group.add(&row);
    }
    let page = adw::PreferencesPage::new();
    page.add(&group);
    let view = adw::ToolbarView::new();
    view.add_top_bar(&adw::HeaderBar::new());
    view.set_content(Some(&page));
    dialog.set_child(Some(&view));
    dialog.present(Some(parent));
    dialog
}
pub fn file_error(
    parent: &impl IsA<gtk::Widget>,
    text: &Text,
    result: &Result<gio::File, glib::Error>,
) {
    if let Err(e) = result
        && !e.matches(gtk::DialogError::Dismissed)
        && !e.matches(gio::IOErrorEnum::Cancelled)
    {
        alert(
            parent,
            text,
            &text.tr("File could not be opened"),
            &e.to_string(),
        );
    }
}
