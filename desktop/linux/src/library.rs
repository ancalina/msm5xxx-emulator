use crate::{App, backend::Backend, i18n::Text, settings, widgets};
use adw::prelude::*;
use gtk::{gio, glib};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    path::PathBuf,
    rc::{Rc, Weak},
};

pub struct Library {
    pub window: adw::ApplicationWindow,
    pub backend: Rc<Backend>,
    pub text: RefCell<Text>,
    app: Weak<App>,
    banner: adw::Banner,
    stack: gtk::Stack,
    model: gio::ListStore,
    folders: RefCell<Vec<String>>,
    scanning: Cell<bool>,
    closing: Cell<bool>,
    pub entries: RefCell<Vec<Value>>,
}
impl Library {
    pub fn new(app: &Rc<App>) -> Rc<Self> {
        let window = adw::ApplicationWindow::builder()
            .application(&app.application)
            .title("Firmware Library")
            .default_width(560)
            .default_height(640)
            .build();
        let this = Rc::new(Self {
            window,
            backend: Rc::new(Backend::new(&app.config)),
            text: RefCell::new(app.text.borrow().clone()),
            app: Rc::downgrade(app),
            banner: adw::Banner::new(""),
            stack: gtk::Stack::new(),
            model: gio::ListStore::new::<glib::BoxedAnyObject>(),
            folders: RefCell::new(vec![]),
            scanning: Cell::new(false),
            closing: Cell::new(false),
            entries: RefCell::new(vec![]),
        });
        this.build();
        let weak = Rc::downgrade(&this);
        this.window.connect_close_request(move |_| {
            let Some(this) = weak.upgrade() else {
                return glib::Propagation::Proceed;
            };
            this.close();
            glib::Propagation::Stop
        });
        glib::spawn_future_local(glib::clone!(
            #[weak]
            this,
            async move {
                match this.backend.call("hello", json!({})).await {
                    Ok(hello) => {
                        if this.closing.get() {
                            return;
                        }
                        if hello["protocol"] != 1 {
                            this.error("Unsupported backend protocol");
                            this.stack.set_visible_child_name("empty");
                            return;
                        }
                        let text = Text::new(hello["language"].as_str().unwrap_or("en"));
                        text.activate();
                        this.text.replace(text.clone());
                        if let Some(app) = this.app.upgrade() {
                            app.text.replace(text);
                        }
                        this.build();
                        this.refresh();
                    }
                    Err(e) => {
                        this.error(&e);
                        this.stack.set_visible_child_name("empty");
                    }
                }
            }
        ));
        this
    }
    pub fn close(self: &Rc<Self>) {
        let this = self;
        if this.closing.replace(true) {
            return;
        }
        this.window.set_sensitive(false);
        let this = this.clone();
        glib::spawn_future_local(async move {
            let _ = this.backend.close().await;
            if let Some(app) = this.app.upgrade() {
                app.library.borrow_mut().take();
            }
            this.window.destroy();
        });
    }
    pub fn build(self: &Rc<Self>) {
        let text = self.text.borrow().clone();
        self.window.set_title(Some(&text.tr("Firmware Library")));
        let header = adw::HeaderBar::new();
        let add = widgets::icon_button("list-add-symbolic", &text.tr("Import File"));
        add.set_action_name(Some("win.add-file"));
        header.pack_start(&add);
        let model = gio::Menu::new();
        let folders = gio::Menu::new();
        folders.append(Some(&text.tr("Add Folder…")), Some("win.add-folder"));
        folders.append(Some(&text.tr("Remove Folder…")), Some("win.remove-folder"));
        model.append_section(None, &folders);
        let other = gio::Menu::new();
        other.append(Some(&text.tr("Refresh")), Some("win.refresh"));
        other.append(Some(&text.tr("Settings…")), Some("win.settings"));
        model.append_section(None, &other);
        header.pack_end(&widgets::menu(&model, &text));
        for (key, op) in [
            ("add-file", 0),
            ("add-folder", 1),
            ("remove-folder", 2),
            ("refresh", 3),
            ("settings", 4),
            ("close", 5),
        ] {
            let weak = Rc::downgrade(self);
            widgets::action(&self.window, key, move || {
                if let Some(this) = weak.upgrade() {
                    match op {
                        0 => this.pick(false),
                        1 => this.pick(true),
                        2 => this.remove_folder(),
                        3 => this.refresh(),
                        4 => {
                            settings::show_library(&this);
                        }
                        _ => this.window.close(),
                    }
                }
            });
        }
        let factory = gtk::SignalListItemFactory::new();
        let weak = Rc::downgrade(self);
        factory.connect_bind(move |_, item| {
            let Some(this) = weak.upgrade() else {
                return;
            };
            let item = item.downcast_ref::<gtk::ListItem>().unwrap();
            let obj = item
                .item()
                .unwrap()
                .downcast::<glib::BoxedAnyObject>()
                .unwrap();
            let entry = obj.borrow::<Value>().clone();
            item.set_activatable(entry["available"].as_bool().unwrap_or(false));
            let text = this.text.borrow().clone();
            let filename = PathBuf::from(entry["path"].as_str().unwrap_or(""))
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let subtitle = if entry["available"].as_bool().unwrap_or(false) {
                format!("{} · {filename}", entry["chipset"].as_str().unwrap_or("—"))
            } else {
                text.tr("Unavailable")
            };
            let row = gtk::Box::builder()
                .orientation(gtk::Orientation::Horizontal)
                .spacing(12)
                .margin_start(12)
                .margin_end(12)
                .margin_top(8)
                .margin_bottom(8)
                .build();
            let labels = gtk::Box::builder()
                .orientation(gtk::Orientation::Vertical)
                .spacing(3)
                .valign(gtk::Align::Center)
                .hexpand(true)
                .build();
            let title = gtk::Label::builder()
                .label(entry["name"].as_str().unwrap_or(&filename))
                .xalign(0.)
                .ellipsize(gtk::pango::EllipsizeMode::End)
                .build();
            let subtitle_label = gtk::Label::builder()
                .label(&subtitle)
                .xalign(0.)
                .ellipsize(gtk::pango::EllipsizeMode::End)
                .css_classes(["caption", "dim-label"])
                .build();
            labels.append(&title);
            labels.append(&subtitle_label);
            row.set_tooltip_text(entry["path"].as_str());
            if let Some(path) = entry["thumbnail"]
                .as_str()
                .filter(|p| std::path::Path::new(p).is_file())
            {
                let picture = gtk::Picture::for_filename(path);
                picture.set_size_request(44, 52);
                picture.set_content_fit(gtk::ContentFit::Contain);
                widgets::name(&picture, &text.tr("Last screen"));
                row.append(&picture);
            } else {
                let image = gtk::Image::from_icon_name("phone-symbolic");
                image.set_pixel_size(32);
                row.append(&image);
            }
            row.append(&labels);
            for (icon, label, remove) in [
                ("help-about-symbolic", "Info", false),
                ("list-remove-symbolic", "Remove from Library", true),
            ] {
                let button = widgets::icon_button(icon, &text.tr(label));
                button.add_css_class("flat");
                let entry = entry.clone();
                let weak = Rc::downgrade(&this);
                button.connect_clicked(move |_| {
                    if let Some(this) = weak.upgrade() {
                        if remove {
                            this.remove(entry.clone());
                        } else {
                            widgets::info(&this.window, &this.text.borrow(), &entry);
                        }
                    }
                });
                row.append(&button);
            }
            item.set_child(Some(&row));
        });
        let selection = gtk::NoSelection::new(Some(self.model.clone()));
        let list = gtk::ListView::new(Some(selection), Some(factory));
        list.set_single_click_activate(true);
        list.add_css_class("rich-list");
        list.add_css_class("separators");
        widgets::name(&list, &text.tr("Firmware Library"));
        list.connect_activate(glib::clone!(
            #[weak(rename_to=this)]
            self,
            move |_, position| {
                let Some(obj) = this
                    .model
                    .item(position)
                    .and_downcast::<glib::BoxedAnyObject>()
                else {
                    return;
                };
                let entry = obj.borrow::<Value>();
                if entry["available"] == true
                    && let Some(app) = this.app.upgrade()
                {
                    app.open(PathBuf::from(entry["path"].as_str().unwrap()));
                }
            }
        ));
        let scroll = gtk::ScrolledWindow::builder()
            .child(&list)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .build();
        let empty = adw::StatusPage::builder()
            .icon_name("phone-symbolic")
            .title(text.tr("Add Firmware to Your Library"))
            .description(text.tr("Import a firmware image to start emulating a phone."))
            .build();
        let button = gtk::Button::builder()
            .label(text.tr("Import File"))
            .action_name("win.add-file")
            .halign(gtk::Align::Center)
            .css_classes(["pill", "suggested-action"])
            .build();
        empty.set_child(Some(&button));
        let loading = adw::StatusPage::builder()
            .title(text.tr("Checking Firmware…"))
            .build();
        let spinner = adw::Spinner::builder()
            .width_request(48)
            .height_request(48)
            .halign(gtk::Align::Center)
            .build();
        loading.set_child(Some(&spinner));
        while let Some(child) = self.stack.first_child() {
            self.stack.remove(&child);
        }
        self.stack.add_named(&scroll, Some("list"));
        self.stack.add_named(&empty, Some("empty"));
        self.stack.add_named(&loading, Some("loading"));
        self.stack.set_visible_child_name("loading");
        let box_ = gtk::Box::new(gtk::Orientation::Vertical, 0);
        if let Some(parent) = self.banner.parent().and_downcast::<gtk::Box>() {
            parent.remove(&self.banner);
        }
        box_.append(&self.banner);
        if let Some(parent) = self.stack.parent().and_downcast::<gtk::Box>() {
            parent.remove(&self.stack);
        }
        box_.append(&self.stack);
        let view = adw::ToolbarView::new();
        view.add_top_bar(&header);
        view.set_content(Some(&box_));
        self.window.set_content(Some(&view));
    }
    pub fn error(&self, message: &str) {
        self.banner.set_title(&self.text.borrow().tr(message));
        self.banner.set_revealed(true);
    }
    pub fn refresh(self: &Rc<Self>) {
        if self.closing.get() || self.scanning.replace(true) {
            return;
        }
        self.stack.set_visible_child_name("loading");
        for key in ["refresh", "add-file", "add-folder", "remove-folder"] {
            if let Some(action) = self
                .window
                .lookup_action(key)
                .and_downcast::<gio::SimpleAction>()
            {
                action.set_enabled(false);
            }
        }
        glib::spawn_future_local(glib::clone!(
            #[weak(rename_to=this)]
            self,
            async move {
                let result = this.backend.call("library.scan", json!({})).await;
                if this.closing.get() {
                    return;
                }
                this.scanning.set(false);
                for key in ["refresh", "add-file", "add-folder", "remove-folder"] {
                    if let Some(action) = this
                        .window
                        .lookup_action(key)
                        .and_downcast::<gio::SimpleAction>()
                    {
                        action.set_enabled(true);
                    }
                }
                match result {
                    Ok(value) => {
                        this.banner.set_revealed(false);
                        this.folders.replace(
                            value["folders"]
                                .as_array()
                                .unwrap_or(&vec![])
                                .iter()
                                .filter_map(|s| s.as_str().map(str::to_owned))
                                .collect(),
                        );
                        let mut entries = value["entries"].as_array().cloned().unwrap_or_default();
                        entries.sort_by_key(|e| e["name"].as_str().unwrap_or("").to_lowercase());
                        this.model.remove_all();
                        for entry in &entries {
                            this.model.append(&glib::BoxedAnyObject::new(entry.clone()));
                        }
                        this.stack.set_visible_child_name(if entries.is_empty() {
                            "empty"
                        } else {
                            "list"
                        });
                        this.entries.replace(entries);
                    }
                    Err(e) => {
                        this.error(&e);
                        this.stack
                            .set_visible_child_name(if this.model.n_items() == 0 {
                                "empty"
                            } else {
                                "list"
                            });
                    }
                }
            }
        ));
    }
    pub fn mutate(self: &Rc<Self>, method: &'static str, path: String) {
        glib::spawn_future_local(glib::clone!(
            #[weak(rename_to=this)]
            self,
            async move {
                match this.backend.call(method, json!({"path":path})).await {
                    Ok(_) => this.refresh(),
                    Err(e) => this.error(&e),
                }
            }
        ));
    }
    fn pick(self: &Rc<Self>, folder: bool) {
        let text = self.text.borrow().clone();
        let dialog = gtk::FileDialog::builder()
            .title(text.tr(if folder {
                "Add Folder…"
            } else {
                "Choose Firmware"
            }))
            .build();
        if !folder {
            let filters = gio::ListStore::new::<gtk::FileFilter>();
            let filter = gtk::FileFilter::new();
            filter.set_name(Some(&text.tr("Firmware Images")));
            for pattern in ["*.bin", "*.img", "*.rom"] {
                filter.add_pattern(pattern);
            }
            filters.append(&filter);
            let all = gtk::FileFilter::new();
            all.set_name(Some(&text.tr("All Files")));
            all.add_pattern("*");
            filters.append(&all);
            dialog.set_filters(Some(&filters));
        }
        glib::spawn_future_local(glib::clone!(
            #[weak(rename_to=this)]
            self,
            async move {
                let result = if folder {
                    dialog.select_folder_future(Some(&this.window)).await
                } else {
                    dialog.open_future(Some(&this.window)).await
                };
                widgets::file_error(&this.window, &text, &result);
                if let Ok(file) = result {
                    if let Some(path) = file.path() {
                        this.mutate(
                            if folder {
                                "library.add_folder"
                            } else {
                                "library.add_file"
                            },
                            path.to_string_lossy().into(),
                        );
                    } else {
                        this.error(&text.tr("Choose a file on this computer."));
                    }
                }
            }
        ));
    }
    fn remove_folder(self: &Rc<Self>) {
        let text = self.text.borrow().clone();
        let dialog = adw::AlertDialog::builder()
            .heading(text.tr("Remove Folder"))
            .body(text.tr("Files stay on your computer."))
            .build();
        dialog.add_response("cancel", &text.tr("Cancel"));
        dialog.set_close_response("cancel");
        let folders = self.folders.borrow().clone();
        if folders.is_empty() {
            widgets::alert(
                &self.window,
                &text,
                &text.tr("Remove Folder"),
                &text.tr("No folders have been added."),
            );
            return;
        }
        let combo = adw::ComboRow::builder()
            .title(text.tr("Folder"))
            .model(&gtk::StringList::new(
                &folders.iter().map(String::as_str).collect::<Vec<_>>(),
            ))
            .build();
        let group = adw::PreferencesGroup::new();
        group.add(&combo);
        dialog.set_extra_child(Some(&group));
        dialog.add_response("remove", &text.tr("Remove"));
        glib::spawn_future_local(glib::clone!(
            #[weak(rename_to=this)]
            self,
            async move {
                if dialog.choose_future(Some(&this.window)).await == "remove" {
                    this.mutate(
                        "library.remove_folder",
                        folders[combo.selected() as usize].clone(),
                    );
                }
            }
        ));
    }
    fn remove(self: &Rc<Self>, entry: Value) {
        let text = self.text.borrow().clone();
        let path = entry["path"].as_str().unwrap_or("").to_owned();
        let dialog = adw::AlertDialog::builder()
            .heading(text.tr("Remove from Library?"))
            .body(format!(
                "{}\n\n{}",
                entry["name"].as_str().unwrap_or(&path),
                text.tr("The firmware file stays on your computer. You can import it again.")
            ))
            .build();
        dialog.add_response("cancel", &text.tr("Cancel"));
        dialog.add_response("remove", &text.tr("Remove"));
        dialog.set_close_response("cancel");
        dialog.set_response_appearance("remove", adw::ResponseAppearance::Destructive);
        glib::spawn_future_local(glib::clone!(
            #[weak(rename_to=this)]
            self,
            async move {
                if dialog.choose_future(Some(&this.window)).await == "remove" {
                    this.mutate("library.remove", path);
                }
            }
        ));
    }
}
