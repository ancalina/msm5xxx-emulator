use crate::{App, backend::Backend, emulator::Emulator, i18n::Text, library::Library, widgets};
use adw::prelude::*;
use gtk::{gio, glib};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    rc::{Rc, Weak},
};

enum Field {
    Entry(adw::EntryRow),
    Choice(adw::ComboRow, Vec<String>),
}
impl Field {
    fn set_sensitive(&self, enabled: bool) {
        match self {
            Self::Entry(row) => row.set_sensitive(enabled),
            Self::Choice(row, _) => row.set_sensitive(enabled),
        }
    }
    fn value(&self) -> String {
        match self {
            Self::Entry(row) => row.text().trim().to_owned(),
            Self::Choice(row, choices) => choices
                .get(row.selected() as usize)
                .cloned()
                .unwrap_or_default(),
        }
    }
}
pub fn show_library(library: &Rc<Library>) {
    glib::spawn_future_local(glib::clone!(
        #[weak]
        library,
        async move {
            match library.backend.call("settings.get", json!({})).await {
                Ok(values) => {
                    let dialog = build(
                        &library.window,
                        library.backend.clone(),
                        library.text.borrow().clone(),
                        values,
                        None,
                        library.app.clone(),
                    );
                    dialog.present(Some(&library.window));
                }
                Err(e) => library.error(&e),
            }
        }
    ));
}
pub fn show_emulator(emulator: &Rc<Emulator>) {
    emulator.release_all();
    glib::spawn_future_local(glib::clone!(
        #[weak]
        emulator,
        async move {
            let values = match emulator.backend.call("settings.get", json!({})).await {
                Ok(v) => v,
                Err(e) => {
                    emulator.error(&e);
                    return;
                }
            };
            let hardware = emulator.backend.call("session.settings", json!({})).await;
            if emulator.closing.get() {
                return;
            }
            emulator.settings.replace(values.clone());
            let dialog = build(
                &emulator.window,
                emulator.backend.clone(),
                emulator.text.borrow().clone(),
                values,
                Some((emulator.clone(), hardware)),
                emulator.app.clone(),
            );
            dialog.connect_closed(glib::clone!(
                #[weak]
                emulator,
                move |_| emulator.refresh_settings()
            ));
            dialog.present(Some(&emulator.window));
        }
    ));
}
fn build(
    parent: &adw::ApplicationWindow,
    backend: Rc<Backend>,
    text: Text,
    values: Value,
    session: Option<(Rc<Emulator>, Result<Value, String>)>,
    app: Weak<App>,
) -> adw::PreferencesDialog {
    let error_owner = parent.downgrade();
    let dialog = adw::PreferencesDialog::builder()
        .title(text.tr("Settings"))
        .search_enabled(session.is_some())
        .content_width(600)
        .content_height(680)
        .build();
    let page = adw::PreferencesPage::builder()
        .title(text.tr("General"))
        .name("general")
        .icon_name("preferences-system-symbolic")
        .build();
    let boot = adw::PreferencesGroup::builder()
        .title(text.tr("Boot Settings"))
        .description(text.tr("Changes take effect the next time a phone boots."))
        .build();
    for (key, label) in [
        ("persistent_state", "Save Device State"),
        ("virtual_network", "Virtual Network (Calls Unavailable)"),
        ("network_host_time", "Use Computer Clock for Network Time"),
        ("experimental_rex", "Experimental Static REX Controller"),
    ] {
        let row = adw::SwitchRow::builder()
            .title(text.tr(label))
            .active(values[key].as_bool().unwrap_or(false))
            .build();
        let changing = Rc::new(Cell::new(false));
        row.connect_active_notify(glib::clone!(
            #[strong]
            error_owner,
            #[strong]
            backend,
            #[weak]
            dialog,
            #[strong]
            text,
            move |row| {
                if changing.get() {
                    return;
                }
                let active = row.is_active();
                row.set_sensitive(false);
                glib::spawn_future_local(glib::clone!(
                    #[strong]
                    error_owner,
                    #[strong]
                    backend,
                    #[strong]
                    text,
                    #[strong]
                    dialog,
                    #[strong]
                    row,
                    #[strong]
                    changing,
                    async move {
                        if let Err(e) = backend
                            .call("settings.set", json!({"key":key,"value":active}))
                            .await
                        {
                            changing.set(true);
                            row.set_active(!active);
                            changing.set(false);
                            settings_message(
                                &dialog,
                                &error_owner,
                                &text,
                                &text.tr("Settings Error"),
                                &e,
                            );
                        }
                        row.set_sensitive(true);
                    }
                ));
            }
        ));
        boot.add(&row);
    }
    let time = adw::EntryRow::builder()
        .title(text.tr("Network Start Time (Blank = Off)"))
        .text(values["network_start_time"].as_str().unwrap_or(""))
        .show_apply_button(true)
        .build();
    time.set_tooltip_text(Some(&text.tr("YYYY-MM-DD HH:MM")));
    time.connect_apply(glib::clone!(
        #[strong]
        error_owner,
        #[strong]
        backend,
        #[weak]
        dialog,
        #[strong]
        text,
        move |row| {
            row.set_sensitive(false);
            let value = row.text().trim().to_owned();
            glib::spawn_future_local(glib::clone!(
                #[strong]
                error_owner,
                #[strong]
                backend,
                #[strong]
                dialog,
                #[strong]
                row,
                #[strong]
                text,
                async move {
                    if let Err(e) = backend
                        .call(
                            "settings.set",
                            json!({"key":"network_start_time","value":value}),
                        )
                        .await
                    {
                        settings_message(
                            &dialog,
                            &error_owner,
                            &text,
                            &text.tr("Settings Error"),
                            &e,
                        );
                        row.add_css_class("error");
                    } else {
                        row.remove_css_class("error");
                    }
                    row.set_sensitive(true);
                }
            ));
        }
    ));
    boot.add(&time);
    page.add(&boot);
    let appearance = adw::PreferencesGroup::new();
    let languages = ["auto", "ko", "en"];
    let model = gtk::StringList::new(&[
        &text.tr("Automatic (System)"),
        &text.tr("Korean"),
        &text.tr("English"),
    ]);
    let language = adw::ComboRow::builder()
        .title(text.tr("Language"))
        .model(&model)
        .selected(
            languages
                .iter()
                .position(|s| Some(*s) == values["ui_language"].as_str())
                .unwrap_or(0) as u32,
        )
        .build();
    let language_saved = Rc::new(Cell::new(language.selected()));
    let language_changing = Rc::new(Cell::new(false));
    let icon_changing = Rc::new(Cell::new(false));
    let icon = adw::ComboRow::builder()
        .title(text.tr("App Icon"))
        .model(&gtk::StringList::new(&[
            &text.tr("Full"),
            &text.tr("Simple (MSM5)"),
        ]))
        .selected(u32::from(crate::icons::simple()))
        .build();
    let hardware_emulator = session
        .as_ref()
        .map(|(emulator, _)| Rc::downgrade(emulator));
    let session_hardware = session
        .as_ref()
        .and_then(|(_, hardware)| hardware.as_ref().ok().cloned());
    let hardware_field_titles = Rc::new(std::cell::RefCell::new(std::collections::HashMap::<
        String,
        gtk::Widget,
    >::new()));
    let hardware_group_titles = Rc::new(std::cell::RefCell::new(
        Vec::<(Vec<String>, gtk::Widget)>::new(),
    ));
    let dialog_language = Rc::new(std::cell::RefCell::new((
        values["ui_language"].as_str().unwrap_or("auto").to_owned(),
        text.language(),
    )));
    let dialog_weak = dialog.downgrade();
    if let Some(app) = app.upgrade() {
        let action = app.language.clone();
        let handler = action.connect_state_notify(glib::clone!(
            #[weak]
            dialog,
            #[strong]
            dialog_language,
            #[strong]
            dialog_weak,
            #[strong]
            language,
            #[strong]
            language_changing,
            #[strong]
            language_saved,
            #[strong]
            icon,
            #[strong]
            icon_changing,
            #[strong]
            text,
            #[strong]
            hardware_emulator,
            #[strong]
            session_hardware,
            #[strong]
            hardware_field_titles,
            #[strong]
            hardware_group_titles,
            #[strong]
            error_owner,
            move |action| {
                let Some((requested, effective)) = action
                    .state()
                    .and_then(|state| state.get::<(String, String)>())
                else {
                    return;
                };
                let target_state = (requested.clone(), effective.clone());
                let previous = dialog_language.replace(target_state.clone());
                if previous == target_state {
                    return;
                }
                let old_text = Text::new(&previous.1);
                let new_text = Text::new(&effective);
                text.set_language(&effective);
                // shortcut: Read single-line POT msgids only; parse PO continuation strings if UI messages span lines.
                let translations = include_str!("../po/msm5xxx.pot")
                    .lines()
                    .filter_map(|line| line.strip_prefix("msgid "))
                    .filter_map(|value| serde_json::from_str::<String>(value).ok())
                    .filter(|msgid| !msgid.is_empty() && !msgid.contains('\n'))
                    .map(|msgid| (old_text.tr(&msgid), new_text.tr(&msgid)))
                    .collect::<std::collections::HashMap<_, _>>();
                let mut pending = vec![dialog.clone().upcast::<gtk::Widget>()];
                while let Some(widget) = pending.pop() {
                    for property in ["title", "description", "tooltip-text"] {
                        if widget.find_property(property).is_some_and(|spec| {
                            spec.value_type() == String::static_type()
                                && spec.flags().contains(
                                    glib::ParamFlags::READABLE | glib::ParamFlags::WRITABLE,
                                )
                                && !spec.flags().contains(glib::ParamFlags::CONSTRUCT_ONLY)
                        }) && let Ok(Some(value)) =
                            widget.property_value(property).get::<Option<String>>()
                            && let Some(translated) = translations.get(&value)
                        {
                            widget.set_property(property, translated);
                        }
                    }
                    let mut child = widget.first_child();
                    while let Some(node) = child {
                        child = node.next_sibling();
                        pending.push(node);
                    }
                }

                let selected = languages
                    .iter()
                    .position(|candidate| *candidate == requested.as_str())
                    .unwrap_or(0) as u32;
                language_changing.set(true);
                language.set_model(Some(&gtk::StringList::new(&[
                    &new_text.tr("Automatic (System)"),
                    &new_text.tr("Korean"),
                    &new_text.tr("English"),
                ])));
                language.set_selected(selected);
                language_saved.set(selected);
                language_changing.set(false);
                let selected = icon.selected();
                icon_changing.set(true);
                icon.set_model(Some(&gtk::StringList::new(&[
                    &new_text.tr("Full"),
                    &new_text.tr("Simple (MSM5)"),
                ])));
                icon.set_selected(selected);
                icon_changing.set(false);

                if let (Some(emulator), Some(old_hardware)) = (
                    hardware_emulator.as_ref().and_then(std::rc::Weak::upgrade),
                    session_hardware.clone(),
                ) {
                    let dialog_language = dialog_language.clone();
                    let hardware_field_titles = hardware_field_titles.clone();
                    let hardware_group_titles = hardware_group_titles.clone();
                    let error_owner = error_owner.clone();
                    let dialog_weak = dialog_weak.clone();
                    let target_state = target_state.clone();
                    let new_text = new_text.clone();
                    glib::spawn_future_local(async move {
                        let result = emulator.backend.call("session.settings", json!({})).await;
                        if *dialog_language.borrow() != target_state
                            || dialog_weak.upgrade().is_none()
                        {
                            return;
                        }
                        match result {
                            Ok(new_hardware) => {
                                let new_sections = new_hardware["sections"]
                                    .as_array()
                                    .cloned()
                                    .unwrap_or_default();
                                for old_section in
                                    old_hardware["sections"].as_array().into_iter().flatten()
                                {
                                    let names = old_section["fields"]
                                        .as_array()
                                        .into_iter()
                                        .flatten()
                                        .filter_map(|field| {
                                            field["name"].as_str().map(str::to_owned)
                                        })
                                        .collect::<Vec<_>>();
                                    for name in &names {
                                        let new_field = new_sections
                                            .iter()
                                            .flat_map(|section| {
                                                section["fields"].as_array().into_iter().flatten()
                                            })
                                            .find(|field| field["name"] == *name);
                                        if let Some(label) =
                                            new_field.and_then(|field| field["label"].as_str())
                                            && let Some(widget) =
                                                hardware_field_titles.borrow().get(name)
                                        {
                                            widget.set_property("title", label);
                                        }
                                    }
                                    if let Some(section) = new_sections.iter().find(|section| {
                                        section["fields"].as_array().into_iter().flatten().any(
                                            |field| {
                                                field["name"].as_str().is_some_and(|name| {
                                                    names.iter().any(|n| n == name)
                                                })
                                            },
                                        )
                                    }) && let Some(title) = section["title"].as_str()
                                        && let Some((_, widget)) = hardware_group_titles
                                            .borrow()
                                            .iter()
                                            .find(|(group_names, _)| group_names == &names)
                                    {
                                        widget.set_property("title", title);
                                    }
                                }
                            }
                            Err(error) => {
                                if let Some(dialog) = dialog_weak.upgrade() {
                                    settings_message(
                                        &dialog,
                                        &error_owner,
                                        &new_text,
                                        &new_text.tr("Settings Error"),
                                        &error,
                                    );
                                }
                            }
                        }
                    });
                }
            }
        ));
        let close_action = action.clone();
        let handler = Rc::new(std::cell::RefCell::new(Some(handler)));
        let close_handler = handler.clone();
        dialog.connect_closed(move |_| {
            if let Some(handler) = close_handler.borrow_mut().take() {
                close_action.disconnect(handler);
            }
        });
    }
    language.connect_selected_notify(glib::clone!(
        #[strong]
        error_owner,
        #[strong]
        language_saved,
        #[strong]
        language_changing,
        #[strong]
        backend,
        #[strong]
        app,
        #[weak]
        dialog,
        #[strong]
        text,
        move |row| {
            if language_changing.get() {
                return;
            }
            let selected = row.selected();
            let Some(value) = languages.get(selected as usize).copied() else {
                return;
            };
            row.set_sensitive(false);
            glib::spawn_future_local(glib::clone!(
                #[strong]
                error_owner,
                #[strong]
                language_saved,
                #[strong]
                language_changing,
                #[strong]
                backend,
                #[strong]
                app,
                #[strong]
                dialog,
                #[strong]
                row,
                #[strong]
                text,
                async move {
                    match backend
                        .call("settings.set", json!({"key":"ui_language","value":value}))
                        .await
                    {
                        Ok(_) => {
                            language_saved.set(selected);
                            let result = match app.upgrade() {
                                Some(app) => app.refresh_language(&backend).await,
                                None => Err("The application is closing".into()),
                            };
                            if let Err(error) = result {
                                settings_message(
                                    &dialog,
                                    &error_owner,
                                    &text,
                                    &text.tr("Settings Error"),
                                    &error,
                                );
                            }
                        }
                        Err(e) => {
                            language_changing.set(true);
                            row.set_selected(language_saved.get());
                            language_changing.set(false);
                            settings_message(
                                &dialog,
                                &error_owner,
                                &text,
                                &text.tr("Settings Error"),
                                &e,
                            );
                        }
                    }
                    row.set_sensitive(true);
                }
            ));
        }
    ));
    appearance.add(&language);
    icon.connect_selected_notify(glib::clone!(
        #[strong]
        error_owner,
        #[strong]
        icon_changing,
        #[weak]
        dialog,
        #[strong]
        text,
        move |row| {
            if icon_changing.get() {
                return;
            }
            let previous = u32::from(crate::icons::simple());
            let simple = row.selected() == 1;
            row.set_sensitive(false);
            glib::spawn_future_local(glib::clone!(
                #[strong]
                error_owner,
                #[strong]
                icon_changing,
                #[strong]
                dialog,
                #[strong]
                text,
                #[strong]
                row,
                async move {
                    if let Err(e) = crate::icons::save(simple).await {
                        icon_changing.set(true);
                        row.set_selected(previous);
                        icon_changing.set(false);
                        settings_message(
                            &dialog,
                            &error_owner,
                            &text,
                            &text.tr("Settings Error"),
                            &text.tr(&e),
                        );
                    }
                    row.set_sensitive(true);
                }
            ));
        }
    ));
    appearance.add(&icon);
    page.add(&appearance);
    dialog.add(&page);
    if let Some((emulator, hardware)) = session {
        let fields = Rc::new(std::cell::RefCell::new(Vec::<(String, Field)>::new()));
        let hardware_page = adw::PreferencesPage::builder()
            .title(text.tr("Hardware"))
            .name("hardware")
            .icon_name("computer-symbolic")
            .build();
        let hardware_ready = hardware.is_ok();
        if let Ok(hardware) = &hardware {
            for section in hardware["sections"].as_array().unwrap_or(&vec![]) {
                let group = adw::PreferencesGroup::builder()
                    .title(section["title"].as_str().unwrap_or(""))
                    .build();
                let section_names = section["fields"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|field| field["name"].as_str().map(str::to_owned))
                    .collect::<Vec<_>>();
                for field in section["fields"].as_array().unwrap_or(&vec![]) {
                    let title = field["label"].as_str().unwrap_or("");
                    let value = field["value"].as_str().unwrap_or("");
                    let name = field["name"].as_str().unwrap_or("").to_owned();
                    if let Some(choices) = field["choices"].as_array() {
                        let choices: Vec<String> = choices
                            .iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect();
                        let strings = gtk::StringList::new(
                            &choices.iter().map(String::as_str).collect::<Vec<_>>(),
                        );
                        let row = adw::ComboRow::builder()
                            .title(title)
                            .model(&strings)
                            .selected(choices.iter().position(|s| s == value).unwrap_or(0) as u32)
                            .build();
                        group.add(&row);
                        hardware_field_titles
                            .borrow_mut()
                            .insert(name.clone(), row.clone().upcast());
                        fields
                            .borrow_mut()
                            .push((name, Field::Choice(row, choices)));
                    } else {
                        let row = adw::EntryRow::builder().title(title).text(value).build();
                        group.add(&row);
                        hardware_field_titles
                            .borrow_mut()
                            .insert(name.clone(), row.clone().upcast());
                        fields.borrow_mut().push((name, Field::Entry(row)));
                    }
                }
                hardware_group_titles
                    .borrow_mut()
                    .push((section_names, group.clone().upcast()));
                hardware_page.add(&group);
            }
        }
        if let Err(message) = hardware {
            let group = adw::PreferencesGroup::builder()
                .description(&message)
                .build();
            hardware_page.add(&group);
        }
        dialog.add(&hardware_page);
        let apply = gio::SimpleAction::new("apply", None);
        apply.set_enabled(hardware_ready);
        let action_group = gio::SimpleActionGroup::new();
        action_group.add_action(&apply);
        dialog.insert_action_group("settings", Some(&action_group));
        let mut apply_rows = Vec::new();
        for page in [&page, &hardware_page] {
            let actions = adw::PreferencesGroup::new();
            let row = adw::ButtonRow::builder()
                .title(text.tr("Apply and Restart"))
                .start_icon_name("view-refresh-symbolic")
                .action_name("settings.apply")
                .build();
            row.add_css_class("suggested-action");
            apply_rows.push(row.downgrade());
            actions.add(&row);
            page.add(&actions);
        }
        let apply_rows = Rc::new(apply_rows);
        apply.connect_activate(glib::clone!(
            #[strong]
            apply_rows,
            #[strong]
            error_owner,
            #[weak]
            dialog,
            #[weak]
            emulator,
            #[strong]
            backend,
            #[strong]
            text,
            move |action, _| {
                if emulator.busy.get() || emulator.closing.get() {
                    return;
                }
                emulator.release_all();
                emulator.busy.set(true);
                emulator.update_controls();
                action.set_enabled(false);
                for row in apply_rows.iter().filter_map(glib::WeakRef::upgrade) {
                    row.set_title(&text.tr("Applying Settings…"));
                }
                for (_, field) in fields.borrow().iter() {
                    field.set_sensitive(false);
                }
                let values: serde_json::Map<String, Value> = fields
                    .borrow()
                    .iter()
                    .map(|(name, field)| (name.clone(), json!(field.value())))
                    .collect();
                glib::spawn_future_local(glib::clone!(
                    #[strong]
                    fields,
                    #[strong]
                    apply_rows,
                    #[strong]
                    error_owner,
                    #[strong]
                    dialog,
                    #[strong]
                    emulator,
                    #[strong]
                    action,
                    #[strong]
                    backend,
                    #[strong]
                    text,
                    async move {
                        match backend
                            .call("session.apply_settings", json!({"values":values}))
                            .await
                        {
                            Ok(_) => {
                                emulator.busy.set(false);
                                dialog.close();
                                emulator.restart();
                            }
                            Err(e) => {
                                emulator.busy.set(false);
                                emulator.update_controls();
                                action.set_enabled(true);
                                for (_, field) in fields.borrow().iter() {
                                    field.set_sensitive(true);
                                }
                                for row in apply_rows.iter().filter_map(glib::WeakRef::upgrade) {
                                    row.set_title(&text.tr("Apply and Restart"));
                                }
                                settings_message(
                                    &dialog,
                                    &error_owner,
                                    &text,
                                    &text.tr("Settings Error"),
                                    &e,
                                );
                            }
                        }
                    }
                ));
            }
        ));
    }
    dialog
}

fn settings_message(
    dialog: &adw::PreferencesDialog,
    owner: &glib::WeakRef<adw::ApplicationWindow>,
    text: &Text,
    heading: &str,
    body: &str,
) {
    if dialog.is_mapped() {
        widgets::alert(dialog, text, heading, body);
    } else if let Some(parent) = owner.upgrade() {
        widgets::alert(&parent, text, heading, body);
    }
}
