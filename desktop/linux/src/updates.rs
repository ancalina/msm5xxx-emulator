use crate::{App, backend::Backend, i18n::Text, widgets};
use adw::prelude::*;
use gtk::glib;
use serde_json::{Value, json};
use std::{rc::{Rc, Weak}, cell::Cell};

pub fn current() -> String {
    std::env::var("MSM5XXX_VERSION").unwrap_or_else(|_| env!("CARGO_PKG_VERSION").into())
}

pub async fn check(backend: &Backend) -> Result<Value, String> {
    backend.call("updates.check", json!({"current":current()})).await
}

pub fn review(parent: &impl IsA<gtk::Widget>, release: Value, app: Weak<App>, text: Text) {
    let Some(application) = app.upgrade() else { return };
    let image = std::env::var_os("APPIMAGE").is_some();
    let dialog = adw::AlertDialog::builder()
        .heading(text.tr("Update Available"))
        .body(format!("{} {}\n\n{}", text.tr("Version"), release["version"].as_str().unwrap_or(""),
            text.tr(if image { "The app will stop running phones and restart after installing the update. Your library, settings and saved state are kept." }
                    else { "Install the new .deb with your package manager. Your library, settings and saved state are kept." })))
        .build();
    dialog.add_response("cancel", &text.tr("Cancel"));
    dialog.add_response("install", &text.tr(if image { "Install and Restart" } else { "Open Release Page" }));
    dialog.set_response_appearance("install", adw::ResponseAppearance::Suggested);
    dialog.set_default_response(Some("cancel"));
    dialog.set_close_response("cancel");
    let parent = parent.clone().upcast::<gtk::Widget>();
    dialog.connect_response(Some("install"), glib::clone!(
        #[strong] parent, #[strong] text, #[strong] application,
        move |_, _| {
            if !image {
                if let Err(error) = gtk::gio::AppInfo::launch_default_for_uri(release["page"].as_str().unwrap_or(""), None::<&gtk::gio::AppLaunchContext>) {
                    widgets::alert(&parent, &text, &text.tr("Update Failed"), &error.to_string());
                }
                return;
            }
            if application.update_installing.replace(true) {
                widgets::alert(&parent, &text, &text.tr("Installing Update"), &text.tr("An Update Is Already Being Installed"));
                return;
            }
            let spinner = gtk::Spinner::builder().spinning(true).halign(gtk::Align::Center).build();
            spinner.update_property(&[gtk::accessible::Property::Label(&text.tr("Installing Update"))]);
            let progress = adw::AlertDialog::builder()
                .heading(text.tr("Installing Update"))
                .body(text.tr("The download continues in the background. The app will restart when it is ready."))
                .extra_child(&spinner).build();
            progress.add_response("hide", &text.tr("Hide"));
            progress.set_close_response("hide");
            progress.present(Some(&parent));
            glib::spawn_future_local(glib::clone!(
                #[strong] parent, #[strong] text, #[strong] application,
                #[strong] release, #[strong] progress,
                async move {
                    let result = async {
                        application.updates.call("updates.prepare", json!({"release":release})).await?;
                        application.updates.call("updates.apply", json!({})).await
                    }.await;
                    progress.close();
                    application.update_installing.set(false);
                    match result {
                        Ok(_) => application.quit(),
                        Err(error) => widgets::alert(&parent, &text, &text.tr("Update Failed"), &error),
                    }
                }
            ));
        }
    ));
    dialog.present(Some(&parent));
}

pub fn add_settings(page: &adw::PreferencesPage, dialog: &adw::PreferencesDialog,
                    backend: Rc<Backend>, app: Weak<App>, text: &Text, automatic: bool) {
    let Some(application) = app.upgrade() else { return };
    let group = adw::PreferencesGroup::builder().title(text.tr("Updates")).build();
    let toggle = adw::SwitchRow::builder().title(text.tr("Check for Updates on Start")).active(automatic).build();
    let changing = Rc::new(Cell::new(false));
    toggle.connect_active_notify(glib::clone!(
        #[strong] dialog, #[strong] text, move |row| {
            if changing.get() { return }
            let value = row.is_active();
            row.set_sensitive(false);
            glib::spawn_future_local(glib::clone!(
                #[strong] row, #[strong] backend, #[strong] changing,
                #[strong] dialog, #[strong] text,
                async move {
                    if let Err(error) = backend.call("settings.set", json!({"key":"check_updates_on_start","value":value})).await {
                        changing.set(true); row.set_active(!value); changing.set(false);
                        widgets::alert(&dialog, &text, &text.tr("Settings Error"), &error);
                    }
                    row.set_sensitive(true);
                }
            ));
        }
    ));
    group.add(&toggle);
    let row = adw::ActionRow::builder().title(text.tr("Version")).subtitle(current()).build();
    let button = gtk::Button::with_label(&text.tr("Check for Updates"));
    button.set_valign(gtk::Align::Center);
    row.add_suffix(&button);
    button.connect_clicked(glib::clone!(
        #[strong] dialog, #[strong] text, #[strong] row, move |button| {
            button.set_sensitive(false);
            row.set_subtitle(&text.tr("Checking for Updates…"));
            glib::spawn_future_local(glib::clone!(
                #[strong] dialog, #[strong] text, #[strong] row,
                #[strong] application, #[strong] button,
                async move {
                    match check(&application.updates).await {
                        Ok(release) if !release.is_null() => {
                            row.set_subtitle(&text.tr("Update Available"));
                            review(&dialog, release, Rc::downgrade(&application), text.clone());
                        }
                        Ok(_) => row.set_subtitle(&text.tr("You’re Up to Date")),
                        Err(error) => {
                            row.set_subtitle(&current());
                            widgets::alert(&dialog, &text, &text.tr("Update Failed"), &error);
                        }
                    }
                    button.set_sensitive(true);
                }
            ));
        }
    ));
    group.add(&row); page.add(&group);
}
