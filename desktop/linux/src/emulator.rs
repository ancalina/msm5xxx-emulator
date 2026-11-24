use crate::{App, backend::Backend, display::Display, i18n::Text, settings, widgets};
use adw::prelude::*;
use gtk::{gdk, gio, glib};
use serde_json::{Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, HashSet},
    path::PathBuf,
    rc::{Rc, Weak},
    time::{Duration, Instant},
};

struct HeldKey {
    accepted: Option<Instant>,
    released: bool,
    generation: u64,
}

pub struct Emulator {
    pub window: adw::ApplicationWindow,
    pub backend: Rc<Backend>,
    pub text: RefCell<Text>,
    pub path: PathBuf,
    pub(crate) app: Weak<App>,
    pub screen: Display,
    pub keypad: crate::keypad::Keypad,
    header: adw::HeaderBar,
    title: adw::WindowTitle,
    view: adw::ToolbarView,
    phone_content: gtk::Box,
    docking: RefCell<Option<crate::dock::Docking>>,
    pub opening: Cell<(i32, i32)>,
    opening_geometry: Cell<(i32, i32)>,
    pub banner: adw::Banner,
    power: gtk::Button,
    done: gtk::Button,
    fold: gtk::Button,
    pub secondary: adw::Window,
    secondary_screen: Display,
    secondary_heading: adw::WindowTitle,
    secondary_state: Cell<(Option<bool>, bool)>,
    menu: gtk::MenuButton,
    secondary_header: adw::HeaderBar,
    pub buttons: RefCell<HashMap<i64, gtk::Button>>,
    metrics: RefCell<HashMap<String, crate::keypad::Counter>>,
    keyboard: RefCell<HashMap<String, i64>>,
    available: RefCell<HashSet<i64>>,
    mapped: RefCell<HashSet<i64>>,
    held: RefCell<HashMap<i64, HeldKey>>,
    generation: Cell<u64>,
    hold_ms: Cell<u64>,
    pub editing: Cell<bool>,
    pub running: Cell<bool>,
    pub busy: Cell<bool>,
    pub closing: Cell<bool>,
    pub ready: Cell<bool>,
    frame_busy: Cell<bool>,
    state_busy: Cell<bool>,
    settings_busy: Cell<bool>,
    seq: Cell<i64>,
    secondary_seq: Cell<i64>,
    pub secondary_seen: Cell<bool>,
    secondary_available: Cell<bool>,
    frame_source: RefCell<Option<glib::SourceId>>,
    state_source: RefCell<Option<glib::SourceId>>,
    pub state: RefCell<Value>,
    pub started: RefCell<Value>,
    pub settings: RefCell<Value>,
    info_entry: RefCell<Value>,
    input_error: RefCell<Option<String>>,
}
impl Emulator {
    #[cfg(debug_assertions)]
    pub fn inspect_layout(&self) -> Value {
        json!({
            "opening":self.opening.get(),
            "docking":self.docking.borrow().as_ref().map(|d|d.snapshot()),
            "display_backend":gtk::prelude::WidgetExt::display(&self.window).type_().name().to_string(),
            "title":self.title.title().to_string(), "subtitle":self.title.subtitle().to_string(),
            "font_dpi":self.window.settings().gtk_xft_dpi() as f64 / 1024.,
            "keypad_content_width":self.keypad.content_width(),"keypad_opening_width":self.keypad.opening_width(),"keypad_margins":[self.keypad.margin_start(),self.keypad.margin_end()],
            "secondary_title":self.secondary_heading.title().to_string(),"secondary_subtitle":self.secondary_heading.subtitle().to_string(),"secondary_transient":self.secondary.transient_for().is_some(),
            "done": {"visible":self.done.is_visible(),"bounds":self.done.compute_bounds(&self.window).map(|r|[r.x(),r.y(),r.width(),r.height()]),"classes":self.done.css_classes().iter().map(|s|s.to_string()).collect::<Vec<_>>()},
            "keypad_natural":self.keypad.measure(gtk::Orientation::Horizontal,-1).1,
            "power":{"icon":self.power.icon_name().map(|s|s.to_string()),"tooltip":self.power.tooltip_text().map(|s|s.to_string()),"classes":self.power.css_classes().iter().map(|s|s.to_string()).collect::<Vec<_>>(),"sensitive":self.power.is_sensitive()},
            "fold":self.fold.label().map(|s|s.to_string()),
            "screen_bounds":self.screen.compute_bounds(&self.window).map(|r|[r.x(),r.y(),r.width(),r.height()]),
            "secondary_bounds":self.secondary_screen.compute_bounds(&self.window).map(|r|[r.x(),r.y(),r.width(),r.height()]),
            "secondary_minimum":[self.secondary_screen.measure(gtk::Orientation::Horizontal,-1).0,self.secondary_screen.measure(gtk::Orientation::Vertical,-1).0],
            "cells":self.keypad.cells(),
            "metrics":self.metrics.borrow().iter().map(|(key,counter)|{let label=counter.label();json!({"key":key,"value":label.text().to_string(),"width":label.width(),"natural":label.measure(gtk::Orientation::Horizontal,-1).1,"ellipsized":label.layout().is_ellipsized(),"text_width":label.layout().pixel_size().0,"font":label.pango_context().font_description().map(|f|f.to_string()),"attributes":label.attributes().map(|a|a.to_string())})}).collect::<Vec<_>>(),
            "buttons":self.buttons.borrow().iter().map(|(bit,button)|json!({"bit":bit,"label":button.label().map(|s|s.to_string()),"width":button.width(),"natural":button.measure(gtk::Orientation::Horizontal,-1).1})).collect::<Vec<_>>()
        })
    }
    #[cfg(debug_assertions)]
    pub fn verify_counter(&self, key: &str, value: &str) -> bool {
        if let Some(counter) = self.metrics.borrow().get(key) {
            counter.set_label(value);
            true
        } else {
            false
        }
    }
    pub fn new(app: &Rc<App>, path: PathBuf) -> Rc<Self> {
        let text = app.text.borrow().clone();
        let stem = path.file_stem().unwrap_or_default().to_string_lossy();
        let window = adw::ApplicationWindow::builder()
            .application(&app.application)
            .title(stem.as_ref())
            .default_width(384)
            .default_height(760)
            .build();
        window.set_size_request(-1, -1);
        let title = adw::WindowTitle::new(&stem, "");
        let header = adw::HeaderBar::builder().title_widget(&title).build();
        let power = widgets::icon_button("system-shutdown-symbolic", &text.tr("Power on"));
        header.pack_start(&power);
        let menu = widgets::menu(&gio::Menu::new(), &text);
        header.pack_end(&menu);
        let done = gtk::Button::builder()
            .label(text.tr("Done"))
            .visible(false)
            .build();
        let screen = Display::new(&text.tr("Phone Screen"));
        screen.set_focusable(true);
        let keypad = crate::keypad::Keypad::new();
        let banner = adw::Banner::new("");
        let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        content.append(&banner);
        content.append(&screen);
        content.append(&keypad);
        content.set_hexpand(true);
        let view = adw::ToolbarView::new();
        view.add_top_bar(&header);
        view.set_content(Some(&content));
        window.set_content(Some(&view));
        let secondary = adw::Window::builder()
            .application(&app.application)
            .hide_on_close(true)
            .resizable(true)
            .title(stem.as_ref())
            .build();
        secondary.set_size_request(-1, -1);
        let secondary_heading = adw::WindowTitle::new(&stem, "");
        let secondary_header = adw::HeaderBar::builder()
            .title_widget(&secondary_heading)
            .build();
        // Retain utility-window controls without making the display transient.
        let controls = glib::clone!(
            #[weak]
            secondary_header,
            move |settings: &gtk::Settings| {
                let layout = settings.gtk_decoration_layout().unwrap_or_default();
                let layout = layout
                    .split(':')
                    .map(|side| {
                        side.split(',')
                            .filter(|button| button.trim() == "close")
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .collect::<Vec<_>>()
                    .join(":");
                secondary_header.set_decoration_layout(Some(&layout));
            }
        );
        controls(&secondary.settings());
        secondary
            .settings()
            .connect_gtk_decoration_layout_notify(controls);
        let secondary_screen = Display::new(&text.tr("Secondary Display"));
        secondary_screen.set_scale(1);
        secondary_screen.set_flexible(true);
        let secondary_view = adw::ToolbarView::new();
        secondary_view.add_top_bar(&secondary_header);
        secondary_view.set_content(Some(&secondary_screen));
        secondary.set_content(Some(&secondary_view));
        let fold = gtk::Button::builder()
            .label(text.tr("Close lid"))
            .sensitive(false)
            .build();
        let this = Rc::new(Self {
            window,
            backend: Rc::new(Backend::new(&app.config)),
            text: RefCell::new(text),
            path,
            app: Rc::downgrade(app),
            screen,
            keypad,
            header,
            title,
            view,
            phone_content: content,
            docking: RefCell::new(None),
            opening: Cell::new((0, 0)),
            opening_geometry: Cell::new((0, 0)),
            banner,
            power,
            done,
            fold,
            secondary,
            secondary_screen,
            secondary_heading,
            secondary_state: Cell::new((None, false)),
            menu,
            secondary_header,
            buttons: RefCell::new(HashMap::new()),
            metrics: RefCell::new(HashMap::new()),
            keyboard: RefCell::new(HashMap::new()),
            available: RefCell::new(HashSet::new()),
            mapped: RefCell::new(HashSet::new()),
            held: RefCell::new(HashMap::new()),
            generation: Cell::new(0),
            hold_ms: Cell::new(150),
            editing: Cell::new(false),
            running: Cell::new(false),
            busy: Cell::new(true),
            closing: Cell::new(false),
            ready: Cell::new(false),
            frame_busy: Cell::new(false),
            state_busy: Cell::new(false),
            settings_busy: Cell::new(false),
            seq: Cell::new(-1),
            secondary_seq: Cell::new(-1),
            secondary_seen: Cell::new(false),
            secondary_available: Cell::new(false),
            frame_source: RefCell::new(None),
            state_source: RefCell::new(None),
            state: RefCell::new(Value::Null),
            started: RefCell::new(Value::Null),
            settings: RefCell::new(Value::Null),
            info_entry: RefCell::new(Value::Null),
            input_error: RefCell::new(None),
        });
        this.docking.replace(crate::dock::Docking::install(
            &this.window,
            &this.secondary,
            &this.screen,
            &this.secondary_screen,
            this.path.clone(),
            glib::clone!(
                #[weak]
                this,
                move |error: &str| this.error(error)
            ),
        ));
        this.power.set_action_name(Some("win.power"));
        widgets::action(
            &this.window,
            "power",
            glib::clone!(
                #[weak]
                this,
                move || this.toggle_power()
            ),
        );
        this.done.connect_clicked(glib::clone!(
            #[weak]
            this,
            move |_| this.set_editing(false)
        ));
        this.fold.connect_clicked(glib::clone!(
            #[weak]
            this,
            move |_| this.fold()
        ));
        widgets::action(
            &this.window,
            "close",
            glib::clone!(
                #[weak]
                this,
                move || this.window.close()
            ),
        );
        widgets::action(
            &this.window,
            "settings",
            glib::clone!(
                #[weak]
                this,
                move || {
                    settings::show_emulator(&this);
                }
            ),
        );
        this.install_keyboard();
        this.window.connect_is_active_notify(glib::clone!(
            #[weak]
            this,
            move |window| {
                if !window.is_active() {
                    this.release_all();
                } else {
                    this.refresh_settings();
                }
            }
        ));
        this.window.connect_close_request(glib::clone!(
            #[weak]
            this,
            #[upgrade_or]
            glib::Propagation::Proceed,
            move |_| {
                this.close();
                glib::Propagation::Stop
            }
        ));
        glib::spawn_future_local(glib::clone!(
            #[weak]
            this,
            async move {
                if let Err(e) = this.initialize().await {
                    this.failed(&e);
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
        this.release_all();
        this.window.set_sensitive(false);
        this.stop_polling();
        this.docking.borrow_mut().take();
        this.busy.set(true);
        this.update_controls();

        this.secondary.set_visible(false);
        glib::spawn_future_local(glib::clone!(
            #[strong]
            this,
            async move {
                if let Err(e) = this.backend.close().await {
                    eprintln!("{e}");
                }
                this.secondary.destroy();
                if let Some(app) = this.app.upgrade() {
                    app.emulators.borrow_mut().remove(&this.path);
                    app.refresh();
                }
                this.window.destroy();
            }
        ));
    }
    async fn initialize(self: &Rc<Self>) -> Result<(), String> {
        let hello = self.backend.call("hello", json!({})).await?;
        if self.closing.get() {
            return Ok(());
        }
        if hello["protocol"] != 1 {
            return Err("Unsupported backend protocol".into());
        }
        self.text
            .replace(Text::new(hello["language"].as_str().unwrap_or("en")));
        let layout = self.backend.call("ui.layout", json!({})).await?;
        self.settings
            .replace(self.backend.call("settings.get", json!({})).await?);
        if self.closing.get() {
            return Ok(());
        }
        widgets::name(&self.screen, &self.text.borrow().tr("Phone Screen"));
        widgets::name(
            &self.secondary_screen,
            &self.text.borrow().tr("Secondary Display"),
        );
        self.build_menu();
        self.build_keypad(&layout);
        self.fit();
        self.backend
            .call("session.open", json!({"firmware":self.path}))
            .await?;
        self.start().await
    }
    fn menu_model(text: &Text) -> gio::Menu {
        let model = gio::Menu::new();
        let session = gio::Menu::new();
        for (label, key) in [
            ("Reboot", "reboot"),
            ("Capture…", "capture"),
            ("Secondary Display", "secondary"),
            ("Info", "info"),
        ] {
            session.append(Some(&text.tr(label)), Some(&format!("win.{key}")));
        }
        model.append_section(None, &session);
        let network = gio::Menu::new();
        network.append(
            Some(&text.tr("Virtual Network")),
            Some("win.virtual-network"),
        );
        let time = gio::Menu::new();
        time.append(
            Some(&text.tr("Use Computer Clock")),
            Some("win.network-time::host"),
        );
        time.append(Some(&text.tr("Set Time…")), Some("win.network-time::fixed"));
        network.append_submenu(Some(&text.tr("Network Time")), &time);
        model.append_section(None, &network);
        let tools = gio::Menu::new();
        tools.append(Some(&text.tr("Edit Key Layout")), Some("win.edit-keys"));
        tools.append(Some(&text.tr("Settings…")), Some("win.settings"));
        model.append_section(None, &tools);
        model
    }
    fn build_menu(self: &Rc<Self>) {
        let text = self.text.borrow().clone();
        self.done.set_label(&text.tr("Done"));
        self.menu.set_menu_model(Some(&Self::menu_model(&text)));
        widgets::action(
            &self.window,
            "reboot",
            glib::clone!(
                #[weak(rename_to=this)]
                self,
                move || this.restart()
            ),
        );
        widgets::action(
            &self.window,
            "capture",
            glib::clone!(
                #[weak(rename_to=this)]
                self,
                move || this.capture()
            ),
        );
        widgets::action(
            &self.window,
            "secondary",
            glib::clone!(
                #[weak(rename_to=this)]
                self,
                move || {
                    this.secondary.present();
                }
            ),
        );
        widgets::action(
            &self.window,
            "info",
            glib::clone!(
                #[weak(rename_to=this)]
                self,
                move || this.info()
            ),
        );
        let network = gio::SimpleAction::new_stateful(
            "virtual-network",
            None,
            &self.settings.borrow()["virtual_network"]
                .as_bool()
                .unwrap_or(false)
                .to_variant(),
        );
        network.connect_change_state(glib::clone!(
            #[weak(rename_to=this)]
            self,
            move |_, value| {
                if let Some(on) = value.and_then(|v| v.get::<bool>()) {
                    this.set_network(on);
                }
            }
        ));
        self.window.add_action(&network);
        let mode = if self.settings.borrow()["network_host_time"] == true {
            "host"
        } else {
            "fixed"
        };
        let time = gio::SimpleAction::new_stateful(
            "network-time",
            Some(glib::VariantTy::STRING),
            &mode.to_variant(),
        );
        time.connect_change_state(glib::clone!(
            #[weak(rename_to=this)]
            self,
            move |_, value| {
                if let Some(mode) = value.and_then(|v| v.str()) {
                    this.network_time(mode == "host");
                }
            }
        ));
        self.window.add_action(&time);
        let edit = gio::SimpleAction::new_stateful("edit-keys", None, &false.to_variant());
        edit.connect_change_state(glib::clone!(
            #[weak(rename_to=this)]
            self,
            move |_, value| {
                if let Some(on) = value.and_then(|v| v.get::<bool>()) {
                    this.set_editing(on);
                }
            }
        ));
        self.window.add_action(&edit);
        self.update_controls();
    }
    fn build_keypad(self: &Rc<Self>, layout: &Value) {
        self.hold_ms
            .set(layout["key_hold_ms"].as_u64().unwrap_or(150));
        if let Some(keys) = layout["keyboard"].as_object() {
            self.keyboard.replace(
                keys.iter()
                    .filter_map(|(name, bit)| bit.as_i64().map(|b| (name.clone(), b)))
                    .collect(),
            );
        }
        for key in layout["keys"].as_array().unwrap_or(&vec![]) {
            let bit = key["bit"].as_i64().unwrap();
            let label = key["text"].as_str().unwrap_or("");
            let button = gtk::Button::builder().label(label).hexpand(true).build();
            let access = key["accessible_name"].as_str().unwrap_or(label);
            widgets::name(&button, access);
            button.set_tooltip_text(Some(access));
            // Keep the toolkit button for keyboard/AT activation; gestures add held pointer input.
            let click = gtk::GestureClick::builder()
                .button(gdk::BUTTON_PRIMARY)
                .propagation_phase(gtk::PropagationPhase::Capture)
                .build();
            click.connect_pressed(glib::clone!(
                #[weak(rename_to=this)]
                self,
                #[weak]
                button,
                move |gesture, _, _, _| {
                    gesture.set_state(gtk::EventSequenceState::Claimed);
                    button.grab_focus();
                    if this.editing.get() {
                        this.edit_key(bit);
                    } else {
                        button.set_state_flags(gtk::StateFlags::ACTIVE, false);
                        this.press(bit);
                    }
                }
            ));
            click.connect_released(glib::clone!(
                #[weak(rename_to=this)]
                self,
                #[weak]
                button,
                move |_, _, _, _| {
                    button.unset_state_flags(gtk::StateFlags::ACTIVE);
                    this.release(bit);
                }
            ));
            click.connect_cancel(glib::clone!(
                #[weak(rename_to=this)]
                self,
                #[weak]
                button,
                move |_, _| {
                    button.unset_state_flags(gtk::StateFlags::ACTIVE);
                    this.release(bit);
                }
            ));
            button.add_controller(click);
            let secondary = gtk::GestureClick::builder()
                .button(gdk::BUTTON_SECONDARY)
                .build();
            secondary.connect_pressed(glib::clone!(
                #[weak(rename_to=this)]
                self,
                move |_, _, _, _| this.edit_key(bit)
            ));
            button.add_controller(secondary);
            button.connect_clicked(glib::clone!(
                #[weak(rename_to=this)]
                self,
                move |_| {
                    if this.editing.get() {
                        this.edit_key(bit);
                    } else {
                        this.press(bit);
                        this.release(bit);
                    }
                }
            ));
            self.keypad.attach(
                &button,
                key["column"].as_i64().unwrap() as i32,
                key["row"].as_i64().unwrap() as i32,
                1,
                1,
            );
            self.buttons.borrow_mut().insert(bit, button);
        }
        self.keypad.attach(&self.fold, 0, 3, 1, 1);
        self.keypad.attach(&self.done, 0, 8, 1, 1);
        let stats = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(1)
            .valign(gtk::Align::Start)
            .margin_top(4)
            .build();
        for metric in layout["metrics"].as_array().unwrap_or(&vec![]) {
            let key = metric["key"].as_str().unwrap();
            let title = metric["title"].as_str().unwrap();
            let description = metric["description"].as_str().unwrap();
            let name = gtk::Label::builder()
                .label(title)
                .xalign(0.)
                .css_classes(["caption", "dim-label"])
                .tooltip_text(description)
                .build();
            let value = crate::keypad::Counter::new(description);
            widgets::name(value.label(), &format!("{title}: {description}"));
            stats.append(&name);
            stats.append(&value);
            self.metrics.borrow_mut().insert(key.into(), value);
        }
        self.keypad.attach(&stats, 0, 4, 1, 4);
        self.update_controls();
    }
    pub fn fit(&self) {
        let (w, h) = self.screen.geometry();
        // Smallest unsqueezed width: keypad buttons at natural size (font-fitting counters do not widen it) and the
        // header's minimum (the model title ellipsizes), never the header's natural width.
        let natural = self
            .keypad
            .opening_width()
            .max(self.header.measure(gtk::Orientation::Horizontal, -1).0);
        let old = self.opening.get();
        let changed = self.opening_geometry.replace((w, h)) != (w, h);
        let width = natural.max(w);
        let scale = (width / w).max(1);
        self.screen.set_scale(scale);
        let height = self.screen.measure(gtk::Orientation::Vertical, width).1
            + self.keypad.measure(gtk::Orientation::Vertical, width).1
            + self.header.measure(gtk::Orientation::Vertical, width).1;
        self.opening.set((width, height));
        self.phone_content.set_size_request(width, -1);
        self.view.set_size_request(width, height);
        if changed || old.0 == 0 {
            self.window.set_default_size(width, height);
        } else if width > old.0 || height > old.1 {
            self.window.set_default_size(
                self.window.width().max(width),
                self.window.height().max(height),
            );
        }
    }
    pub async fn start(self: &Rc<Self>) -> Result<(), String> {
        if self.closing.get() {
            return Ok(());
        }
        self.busy.set(true);
        self.update_controls();

        let started = self.backend.call("session.start", json!({})).await?;
        if self.closing.get() {
            return Ok(());
        }
        self.ready.set(true);
        self.running.set(true);
        self.busy.set(false);
        self.seq.set(-1);
        self.secondary_seq.set(-1);
        self.secondary_seen.set(false);
        self.window.set_title(started["title"].as_str());
        self.title
            .set_title(started["title"].as_str().unwrap_or(""));
        self.available.replace(
            started["keys"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(Value::as_i64)
                .collect(),
        );
        self.started.replace(started);
        let _ = gtk::RecentManager::default().add_item(&gio::File::for_path(&self.path).uri());
        self.banner.set_revealed(false);
        self.input_error.borrow_mut().take();
        self.update_controls();
        self.start_polling();
        self.screen.grab_focus();
        self.load_info();
        if let Some(app) = self.app.upgrade() {
            app.refresh();
        }
        Ok(())
    }
    pub fn failed(&self, message: &str) {
        if self.closing.get() {
            return;
        }
        self.running.set(false);
        self.busy.set(false);

        self.error(message);
        self.update_controls();
    }
    fn update_secondary_title(&self) {
        let text = self.text.borrow();
        let (enabled, preview) = self.secondary_state.get();
        let power = text.tr(if !self.running.get() {
            "Off"
        } else {
            match enabled {
                Some(true) => "On",
                Some(false) => "Off",
                None => "Power Unknown",
            }
        });
        let note = text.tr(if preview {
            "Preview: colors and orientation unverified"
        } else {
            "Display purpose unknown"
        });
        let (w, h) = self.secondary_screen.geometry();
        let status = format!("{power} · {w}×{h} · {note}");
        let model = self.title.title();
        self.secondary_heading.set_title(&model);
        self.secondary_heading.set_subtitle("");
        self.secondary.set_title(Some(&model));
        self.secondary_screen.set_tooltip_text(Some(&status));
    }
    pub fn reload_language(self: &Rc<Self>, text: &Text, layout: &Value) -> Result<(), String> {
        if self.closing.get() {
            return Ok(());
        }
        self.release_all();
        self.text.borrow().set_language(&text.language());
        let text = self.text.borrow().clone();
        self.menu.set_menu_model(Some(&Self::menu_model(&text)));
        let label = text.tr("Main Menu");
        self.menu.set_tooltip_text(Some(&label));
        widgets::name(&self.menu, &label);
        self.done.set_label(&text.tr("Done"));
        widgets::name(&self.screen, &text.tr("Phone Screen"));
        widgets::name(&self.secondary_screen, &text.tr("Secondary Display"));
        for key in layout["keys"].as_array().ok_or("Invalid keypad layout")? {
            if let Some(button) = key["bit"]
                .as_i64()
                .and_then(|bit| self.buttons.borrow().get(&bit).cloned())
            {
                button.set_label(key["text"].as_str().unwrap_or(""));
                let name = key["accessible_name"].as_str().unwrap_or("");
                widgets::name(&button, name);
                button.set_tooltip_text(Some(name));
            }
        }
        for metric in layout["metrics"]
            .as_array()
            .ok_or("Invalid keypad metrics")?
        {
            if let Some(value) = metric["key"]
                .as_str()
                .and_then(|key| self.metrics.borrow().get(key).cloned())
            {
                if let Some(name) = value.prev_sibling().and_downcast::<gtk::Label>() {
                    name.set_label(metric["title"].as_str().unwrap_or(""));
                }
                let description = metric["description"].as_str().unwrap_or("");
                value.set_tooltip_text(Some(description));
                widgets::name(
                    value.label(),
                    &format!("{}: {description}", metric["title"].as_str().unwrap_or("")),
                );
            }
        }
        let state = self.state.borrow().clone();
        self.show_state(&state);
        self.update_secondary_title();
        self.update_controls();
        self.fit();
        Ok(())
    }
    pub fn refresh_settings(self: &Rc<Self>) {
        if self.closing.get() || self.settings_busy.replace(true) {
            return;
        }
        glib::spawn_future_local(glib::clone!(
            #[weak(rename_to=this)]
            self,
            async move {
                let result = this.backend.call("settings.get", json!({})).await;
                this.settings_busy.set(false);
                if this.closing.get() {
                    return;
                }
                match result {
                    Ok(values) => {
                        if let Some(action) = this
                            .window
                            .lookup_action("virtual-network")
                            .and_downcast::<gio::SimpleAction>()
                        {
                            action.set_state(
                                &values["virtual_network"]
                                    .as_bool()
                                    .unwrap_or(false)
                                    .to_variant(),
                            );
                        }
                        if let Some(action) = this
                            .window
                            .lookup_action("network-time")
                            .and_downcast::<gio::SimpleAction>()
                        {
                            action.set_state(
                                &if values["network_host_time"] == true {
                                    "host"
                                } else {
                                    "fixed"
                                }
                                .to_variant(),
                            );
                        }
                        this.settings.replace(values);
                    }
                    Err(e) => this.error(&e),
                }
            }
        ));
    }
    pub fn error(&self, message: &str) {
        if self.closing.get() {
            return;
        }
        self.banner.set_title(&self.text.borrow().tr(message));
        self.banner.set_revealed(true);
    }
    pub fn toggle_power(self: &Rc<Self>) {
        if self.busy.get() || self.closing.get() {
            return;
        }
        if self.running.get() {
            self.stop(false);
        } else {
            self.busy.set(true);
            self.update_controls();
            glib::spawn_future_local(glib::clone!(
                #[weak(rename_to=this)]
                self,
                async move {
                    if let Err(e) = this.start().await {
                        this.failed(&e);
                    }
                }
            ));
        }
    }
    pub fn restart(self: &Rc<Self>) {
        if self.busy.get() || self.closing.get() {
            return;
        }
        self.stop(true);
    }
    fn stop(self: &Rc<Self>, restart: bool) {
        self.release_all();
        self.busy.set(true);
        self.stop_polling();
        self.update_controls();

        glib::spawn_future_local(glib::clone!(
            #[weak(rename_to=this)]
            self,
            async move {
                let result = this.backend.call("session.stop", json!({})).await;
                this.powered_off();
                if this.closing.get() {
                    return;
                }
                if let Err(e) = result {
                    this.failed(&e);
                    return;
                }
                if restart {
                    if let Err(e) = this.start().await {
                        this.failed(&e);
                    }
                } else {
                    this.busy.set(false);
                    this.update_controls();
                    if let Some(app) = this.app.upgrade() {
                        app.refresh();
                    }
                }
            }
        ));
    }
    fn powered_off(&self) {
        self.clear_input_error();
        self.running.set(false);
        self.screen.clear();
        self.secondary.set_visible(false);
        self.update_secondary_title();
        self.secondary_available.set(false);
        self.fold.set_sensitive(false);

        for value in self.metrics.borrow().values() {
            value.set_label("—");
        }
        self.update_controls();
    }
    pub fn update_controls(&self) {
        let text = self.text.borrow();
        let enabled = !self.busy.get() && !self.closing.get();
        self.power.set_sensitive(enabled);
        let label = text.tr(if self.running.get() {
            "Power off"
        } else {
            "Power on"
        });
        self.power.set_tooltip_text(Some(&label));
        widgets::name(&self.power, &label);
        for (name, can) in [
            ("reboot", self.running.get()),
            ("capture", self.screen.texture().is_some()),
            ("secondary", self.secondary_available.get()),
            ("info", self.ready.get()),
            ("settings", true),
            ("virtual-network", true),
            ("network-time", true),
            ("edit-keys", self.ready.get()),
        ] {
            if let Some(action) = self
                .window
                .lookup_action(name)
                .and_downcast::<gio::SimpleAction>()
            {
                action.set_enabled(enabled && can);
            }
        }
        for (bit, button) in self.buttons.borrow().iter() {
            button.set_sensitive(
                enabled
                    && (self.editing.get()
                        || (self.running.get()
                            && (self.available.borrow().contains(bit)
                                || self.mapped.borrow().contains(bit)))),
            );
        }
    }
    fn start_polling(self: &Rc<Self>) {
        self.stop_polling();
        let weak = Rc::downgrade(self);
        self.frame_source.replace(Some(glib::timeout_add_local(Duration::from_micros(33333),move||{let Some(this)=weak.upgrade()else{return glib::ControlFlow::Break;};if this.running.get()&&!this.busy.get()&&!this.frame_busy.replace(true){glib::spawn_future_local(async move{let result=this.backend.call("session.frame",json!({"since":this.seq.get(),"secondary_since":this.secondary_seq.get()})).await;this.frame_busy.set(false);if this.closing.get()||!this.running.get()||this.busy.get(){return;}match result{Ok(frame)=>this.frame(&frame),Err(e)=>this.error(&e)}});}glib::ControlFlow::Continue})));
        let weak = Rc::downgrade(self);
        self.state_source.replace(Some(glib::timeout_add_local(
            Duration::from_millis(100),
            move || {
                let Some(this) = weak.upgrade() else {
                    return glib::ControlFlow::Break;
                };
                if this.running.get() && !this.busy.get() && !this.state_busy.replace(true) {
                    glib::spawn_future_local(async move {
                        let result = this.backend.call("session.state", json!({})).await;
                        this.state_busy.set(false);
                        if this.closing.get() || !this.running.get() || this.busy.get() {
                            return;
                        }
                        match result {
                            Ok(state) => this.show_state(&state),
                            Err(e) => this.error(&e),
                        }
                    });
                }
                glib::ControlFlow::Continue
            },
        )));
    }
    fn stop_polling(&self) {
        if let Some(id) = self.frame_source.borrow_mut().take() {
            id.remove();
        }
        if let Some(id) = self.state_source.borrow_mut().take() {
            id.remove();
        }
    }
    fn frame(self: &Rc<Self>, frame: &Value) {
        if frame["running"] == false {
            self.unexpected_stop();
            return;
        }
        if frame["rgb"].is_string() {
            let first = self.seq.get() < 0;
            match self.screen.frame(frame) {
                Ok(changed) => {
                    if changed || first {
                        self.fit();
                    }
                    self.seq.set(frame["seq"].as_i64().unwrap_or(-1));
                }
                Err(e) => self.error(&e),
            }
            self.update_controls();
        }
        let secondary = &frame["secondary"];
        let available = secondary.is_object();
        self.secondary_available.replace(available);
        if available {
            self.secondary_state
                .set((secondary["enabled"].as_bool(), secondary["preview"] == true));
            if secondary["rgb"].is_string() {
                match self.secondary_screen.frame(secondary) {
                    Ok(changed) => {
                        self.secondary_seq
                            .set(secondary["seq"].as_i64().unwrap_or(-1));
                        let (w, h) = self.secondary_screen.geometry();
                        self.update_secondary_title();
                        self.secondary_screen.set_size_request(w, h);
                        if changed || !self.secondary_seen.get() {
                            let width = w.max(self.secondary_header
                                .measure(gtk::Orientation::Horizontal, -1).0);
                            self.secondary.set_default_size(
                                width,
                                h
                                    + self
                                        .secondary_header
                                        .measure(gtk::Orientation::Vertical, width)
                                        .1,
                            );
                        }
                    }
                    Err(e) => self.error(&e),
                }
            }
            self.update_secondary_title();
            if self.secondary_screen.texture().is_some() && !self.secondary_seen.replace(true) {
                self.secondary.present();
            }
        } else {
            self.secondary.set_visible(false);
        }
        if let Some(action) = self
            .window
            .lookup_action("secondary")
            .and_downcast::<gio::SimpleAction>()
        {
            action.set_enabled(available && !self.busy.get());
        }
        self.update_controls();
    }
    fn show_state(self: &Rc<Self>, state: &Value) {
        if state["running"] == false {
            self.unexpected_stop();
            return;
        }
        let text = self.text.borrow();
        let fold = state["fold"].as_bool();
        self.fold.set_sensitive(fold.is_some() && !self.busy.get());
        self.fold.set_label(&text.tr(if fold == Some(true) {
            "Close lid"
        } else {
            "Open lid"
        }));
        widgets::name(
            &self.fold,
            &text.tr(if fold == Some(true) {
                "Close lid"
            } else {
                "Open lid"
            }),
        );
        self.fold.set_tooltip_text(Some(&text.tr(if fold.is_some() {
            "Toggle the phone lid"
        } else {
            "This firmware has no lid control"
        })));
        for (key, label) in self.metrics.borrow().iter() {
            label.set_label(state["metrics"][key].as_str().unwrap_or("—"));
        }
        self.fit();
        if let Some(error) = state["input_error"].as_str() {
            self.input_error.replace(Some(error.to_owned()));
            self.error(error);
        } else {
            self.clear_input_error();
        }
        self.state.replace(state.clone());
    }
    fn clear_input_error(&self) {
        if let Some(previous) = self.input_error.borrow_mut().take()
            && self.banner.title().as_str() == self.text.borrow().tr(&previous)
        {
            self.banner.set_revealed(false);
        }
    }
    fn unexpected_stop(self: &Rc<Self>) {
        self.stop_polling();
        self.release_all();
        self.busy.set(true);
        self.powered_off();
        self.error(
            &self
                .text
                .borrow()
                .tr("The emulator stopped. Power on to try again."),
        );
        glib::spawn_future_local(glib::clone!(
            #[weak(rename_to=this)]
            self,
            async move {
                let _ = this.backend.call("session.stop", json!({})).await;
                this.busy.set(false);
                this.update_controls();
            }
        ));
    }
    fn install_keyboard(self: &Rc<Self>) {
        let keys = gtk::EventControllerKey::new();
        keys.set_propagation_phase(gtk::PropagationPhase::Capture);
        keys.connect_key_pressed(glib::clone!(
            #[weak(rename_to=this)]
            self,
            #[upgrade_or]
            glib::Propagation::Proceed,
            move |_, key, _, modifiers| {
                #[cfg(debug_assertions)]
                if let Some(directory)=std::env::var_os("MSM5XXX_VERIFY_DIR") {
                    use std::io::Write;
                    if let Ok(mut file)=std::fs::OpenOptions::new().create(true).append(true).open(std::path::PathBuf::from(directory).join("input-events.jsonl")) {
                        let _=writeln!(file,"{}",json!({"key":key.name().map(|s|s.to_string()),"modifiers":modifiers.bits(),"active":this.window.is_active(),"focus":gtk::prelude::GtkWindowExt::focus(&this.window).map(|w|w.type_().name().to_string()),"dialog":this.window.visible_dialog().map(|d|d.title().to_string())}));
                    }
                }
                if !this.can_capture(modifiers) {
                    return glib::Propagation::Proceed;
                }
                let Some(bit) = key
                    .name()
                    .and_then(|name| this.keyboard.borrow().get(name.as_str()).copied())
                else {
                    return glib::Propagation::Proceed;
                };
                this.press(bit);
                glib::Propagation::Stop
            }
        ));
        keys.connect_key_released(glib::clone!(
            #[weak(rename_to=this)]
            self,
            move |_, key, _, _| {
                if let Some(bit) = key
                    .name()
                    .and_then(|name| this.keyboard.borrow().get(name.as_str()).copied())
                {
                    this.release(bit);
                }
            }
        ));
        self.window.add_controller(keys);
    }
    fn can_capture(&self, modifiers: gdk::ModifierType) -> bool {
        if self.editing.get()
            || self.busy.get()
            || !self.running.get()
            || self.closing.get()
            || self.window.visible_dialog().is_some()
            || modifiers.intersects(
                gdk::ModifierType::CONTROL_MASK
                    | gdk::ModifierType::ALT_MASK
                    | gdk::ModifierType::META_MASK
                    | gdk::ModifierType::SUPER_MASK,
            )
        {
            return false;
        }
        if let Some(focus) = gtk::prelude::GtkWindowExt::focus(&self.window)
            && ((focus != self.screen.clone().upcast::<gtk::Widget>()
                && !focus.is_ancestor(&self.keypad))
                || focus.is::<gtk::Entry>()
                || focus.is::<gtk::Text>()
                || focus.is::<gtk::TextView>())
        {
            return false;
        }
        true
    }
    pub fn press(self: &Rc<Self>, bit: i64) {
        if self.busy.get()
            || !self.running.get()
            || self.editing.get()
            || !self
                .buttons
                .borrow()
                .get(&bit)
                .is_some_and(|b| b.is_sensitive())
        {
            return;
        }
        if let Some(held) = self.held.borrow_mut().get_mut(&bit) {
            held.released = false;
            return;
        }
        self.generation.set(self.generation.get() + 1);
        let generation = self.generation.get();
        self.held.borrow_mut().insert(
            bit,
            HeldKey {
                accepted: None,
                released: false,
                generation,
            },
        );
        glib::spawn_future_local(glib::clone!(
            #[weak(rename_to=this)]
            self,
            async move {
                let result = this
                    .backend
                    .call("session.key", json!({"bit":bit,"pressed":true}))
                    .await;
                if this
                    .held
                    .borrow()
                    .get(&bit)
                    .is_none_or(|held| held.generation != generation)
                {
                    return;
                }
                match result {
                    Ok(value) if value == true => {
                        let released = if let Some(held) = this.held.borrow_mut().get_mut(&bit) {
                            held.accepted = Some(Instant::now());
                            held.released
                        } else {
                            false
                        };
                        if released {
                            this.release(bit);
                        }
                    }
                    Ok(_) => {
                        this.held.borrow_mut().remove(&bit);
                    }
                    Err(e) => {
                        this.held.borrow_mut().remove(&bit);
                        this.error(&e);
                    }
                }
            }
        ));
    }
    pub fn release(self: &Rc<Self>, bit: i64) {
        let (at, generation) = {
            let mut held = self.held.borrow_mut();
            let Some(held) = held.get_mut(&bit) else {
                return;
            };
            held.released = true;
            let Some(at) = held.accepted else {
                return;
            };
            (at, held.generation)
        };
        // GLib's millisecond timer truncates fractional milliseconds; round up.
        let delay = Duration::from_millis(self.hold_ms.get())
            .saturating_sub(at.elapsed())
            .saturating_add(Duration::from_millis(1));
        let weak = Rc::downgrade(self);
        glib::timeout_add_local_once(delay, move || {
            if let Some(this) = weak.upgrade()
                && this
                    .held
                    .borrow()
                    .get(&bit)
                    .is_some_and(|held| held.generation == generation && held.released)
            {
                this.held.borrow_mut().remove(&bit);
                this.send_release(bit);
            }
        });
    }
    fn send_release(self: &Rc<Self>, bit: i64) {
        glib::spawn_future_local(glib::clone!(
            #[strong(rename_to=this)]
            self,
            async move {
                if let Err(e) = this
                    .backend
                    .call("session.key", json!({"bit":bit,"pressed":false}))
                    .await
                    && !this.closing.get()
                {
                    this.error(&e);
                }
            }
        ));
    }
    pub fn release_all(self: &Rc<Self>) {
        let bits: Vec<_> = self.held.borrow_mut().drain().map(|(bit, _)| bit).collect();
        for bit in bits {
            self.send_release(bit);
        }
        for button in self.buttons.borrow().values() {
            button.unset_state_flags(gtk::StateFlags::ACTIVE);
        }
    }
    pub fn set_editing(self: &Rc<Self>, on: bool) {
        self.release_all();
        self.editing.set(on);
        self.done.set_visible(on);
        if let Some(action) = self
            .window
            .lookup_action("edit-keys")
            .and_downcast::<gio::SimpleAction>()
        {
            action.set_state(&on.to_variant());
        }
        self.update_controls();
    }
    pub fn edit_key(self: &Rc<Self>, bit: i64) {
        if !self.ready.get() || self.closing.get() {
            return;
        }
        self.release_all();
        glib::spawn_future_local(glib::clone!(
            #[weak(rename_to=this)]
            self,
            async move {
                let current = match this
                    .backend
                    .call("session.key_mapping", json!({"bit":bit}))
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        this.error(&e);
                        return;
                    }
                };
                if this.closing.get() {
                    return;
                }
                let text = this.text.borrow().clone();
                let title = this
                    .buttons
                    .borrow()
                    .get(&bit)
                    .and_then(|b| b.label())
                    .unwrap_or_default();
                let dialog = adw::AlertDialog::builder()
                    .heading(title)
                    .body(
                        text.tr("Enter the firmware event byte. Leave empty to clear the mapping."),
                    )
                    .build();
                let entry = adw::EntryRow::builder()
                    .title(text.tr("Event Byte"))
                    .activates_default(true)
                    .text(
                        current
                            .as_i64()
                            .map(|n| format!("0x{n:02X}"))
                            .unwrap_or_default(),
                    )
                    .build();
                let error = gtk::Label::builder()
                    .wrap(true)
                    .visible(false)
                    .css_classes(["error"])
                    .build();
                let group = adw::PreferencesGroup::new();
                group.add(&entry);
                let box_ = gtk::Box::new(gtk::Orientation::Vertical, 8);
                box_.append(&group);
                box_.append(&error);
                dialog.set_extra_child(Some(&box_));
                dialog.add_response("cancel", &text.tr("Cancel"));
                dialog.add_response("apply", &text.tr("Apply"));
                dialog.set_close_response("cancel");
                dialog.set_response_appearance("apply", adw::ResponseAppearance::Suggested);
                dialog.set_default_response(Some("apply"));
                loop {
                    if this.closing.get() {
                        break;
                    }
                    dialog.set_focus(Some(&entry));
                    let response = dialog.clone().choose_future(Some(&this.window)).await;
                    if this.closing.get() || response != "apply" {
                        break;
                    }
                    let result = this
                        .backend
                        .call(
                            "session.set_key_mapping",
                            json!({"bit":bit,"value":entry.text().trim()}),
                        )
                        .await;
                    if this.closing.get() {
                        break;
                    }
                    match result {
                        Ok(value) => {
                            if value.is_null() {
                                this.mapped.borrow_mut().remove(&bit);
                            } else {
                                this.mapped.borrow_mut().insert(bit);
                            }
                            let keys = this.backend.call("session.keys", json!({})).await;
                            if this.closing.get() {
                                break;
                            }
                            match keys {
                                Ok(keys) => {
                                    this.available.replace(
                                        keys.as_array()
                                            .unwrap_or(&vec![])
                                            .iter()
                                            .filter_map(Value::as_i64)
                                            .collect(),
                                    );
                                }
                                Err(e) => this.error(&e),
                            }
                            this.update_controls();
                            break;
                        }
                        Err(e) => {
                            error.set_label(&e);
                            error.set_visible(true);
                        }
                    }
                }
            }
        ));
    }
    pub fn fold(self: &Rc<Self>) {
        glib::spawn_future_local(glib::clone!(
            #[weak(rename_to=this)]
            self,
            async move {
                if let Err(e) = this.backend.call("session.fold", json!({})).await {
                    this.error(&e);
                }
            }
        ));
    }
    fn load_info(self: &Rc<Self>) {
        if let Some(app) = self.app.upgrade()
            && let Some(library) = app.library.borrow().as_ref()
        {
            let backend = library.backend.clone();
            glib::spawn_future_local(glib::clone!(
                #[weak(rename_to=this)]
                self,
                async move {
                    if let Ok(scan) = backend.call("library.scan", json!({})).await
                        && let Some(entry) = scan["entries"].as_array().and_then(|entries| {
                            entries
                                .iter()
                                .find(|e| e["path"].as_str() == this.path.to_str())
                        })
                    {
                        this.info_entry.replace(entry.clone());
                    }
                }
            ));
        }
    }
    fn info(&self) {
        let mut entry = self.info_entry.borrow().clone();
        if !entry.is_object() {
            entry = json!({"path":self.path,"name":self.started.borrow()["title"],"model":self.started.borrow()["model"],"chipset":self.started.borrow()["chipset"]});
        }
        let text = self.text.borrow();
        let state = self.state.borrow();
        if state["chipset"].is_string() {
            entry["chipset"] = state["chipset"].clone();
        }
        let (w, h) = self.screen.geometry();
        entry["display"] = json!(format!("{w}×{h}"));
        entry["network"] = json!(text.tr(
            if !self.running.get() || state["virtual_cell"].is_null() {
                "Off"
            } else if state["virtual_cell"] == "configured" {
                "Virtual Network"
            } else {
                "Virtual Network Unavailable"
            }
        ));
        entry["power"] = json!(text.tr(if self.running.get() { "On" } else { "Off" }));
        if self.secondary_seen.get() {
            entry["secondary"] = json!(if self.running.get() {
                self.secondary_screen
                    .tooltip_text()
                    .map(|s| s.to_string())
                    .unwrap_or_default()
            } else {
                text.tr("Off")
            });
        }
        widgets::info(&self.window, &self.text.borrow(), &entry);
    }
    pub fn capture(self: &Rc<Self>) {
        let Some(texture) = self.screen.texture() else {
            return;
        };
        let text = self.text.borrow().clone();
        let stem = self.path.file_stem().unwrap_or_default().to_string_lossy();
        let dialog = gtk::FileDialog::builder()
            .title(text.tr("Save Capture"))
            .initial_name(format!("{stem}.png"))
            .build();
        let filter = gtk::FileFilter::new();
        filter.set_name(Some("PNG"));
        filter.add_mime_type("image/png");
        let filters = gio::ListStore::new::<gtk::FileFilter>();
        filters.append(&filter);
        dialog.set_filters(Some(&filters));
        glib::spawn_future_local(glib::clone!(
            #[weak(rename_to=this)]
            self,
            async move {
                let result = dialog.save_future(Some(&this.window)).await;
                widgets::file_error(&this.window, &text, &result);
                if let Ok(file) = result {
                    let bytes = texture.save_to_png_bytes();
                    if let Err(e) = file
                        .replace_contents_future(
                            bytes,
                            None,
                            false,
                            gio::FileCreateFlags::REPLACE_DESTINATION,
                        )
                        .await
                    {
                        this.error(&e.1.to_string());
                    }
                }
            }
        ));
    }
    fn set_network(self: &Rc<Self>, on: bool) {
        if self.busy.replace(true) {
            return;
        }
        self.release_all();
        self.update_controls();
        glib::spawn_future_local(glib::clone!(
            #[weak(rename_to=this)]
            self,
            async move {
                let result = this
                    .backend
                    .call("settings.set", json!({"key":"virtual_network","value":on}))
                    .await;
                this.busy.set(false);
                match result {
                    Ok(_) => {
                        this.settings.borrow_mut()["virtual_network"] = json!(on);
                        if let Some(action) = this
                            .window
                            .lookup_action("virtual-network")
                            .and_downcast::<gio::SimpleAction>()
                        {
                            action.set_state(&on.to_variant());
                        }
                        if this.running.get() {
                            this.restart();
                        } else {
                            this.update_controls();
                        }
                    }
                    Err(e) => {
                        this.error(&e);
                        this.update_controls();
                    }
                }
            }
        ));
    }
    fn network_time(self: &Rc<Self>, host: bool) {
        if self.closing.get() {
            return;
        }
        if host {
            self.apply_time(true, String::new());
            return;
        }
        let text = self.text.borrow().clone();
        let dialog = adw::AlertDialog::builder()
            .heading(text.tr("Set Network Time"))
            .body(text.tr("YYYY-MM-DD HH:MM"))
            .build();
        let entry = adw::EntryRow::builder()
            .title(text.tr("Network Start Time"))
            .activates_default(true)
            .text(
                self.settings.borrow()["network_start_time"]
                    .as_str()
                    .unwrap_or(""),
            )
            .build();
        let error = gtk::Label::builder()
            .wrap(true)
            .visible(false)
            .css_classes(["error"])
            .build();
        let group = adw::PreferencesGroup::new();
        group.add(&entry);
        let box_ = gtk::Box::new(gtk::Orientation::Vertical, 8);
        box_.append(&group);
        box_.append(&error);
        dialog.set_extra_child(Some(&box_));
        dialog.add_response("cancel", &text.tr("Cancel"));
        dialog.add_response("apply", &text.tr("Apply"));
        dialog.set_close_response("cancel");
        dialog.set_default_response(Some("apply"));
        dialog.set_response_appearance("apply", adw::ResponseAppearance::Suggested);
        glib::spawn_future_local(glib::clone!(
            #[weak(rename_to=this)]
            self,
            async move {
                loop {
                    if this.closing.get() {
                        break;
                    }
                    dialog.set_focus(Some(&entry));
                    let response = dialog.clone().choose_future(Some(&this.window)).await;
                    if this.closing.get() || response != "apply" {
                        break;
                    }
                    let value = entry.text().trim().to_owned();
                    if value.is_empty() {
                        error.set_label(&text.tr("Enter a valid time in YYYY-MM-DD HH:MM format"));
                        error.set_visible(true);
                        continue;
                    }
                    let result = this
                        .backend
                        .call(
                            "settings.set",
                            json!({"key":"network_start_time","value":value}),
                        )
                        .await;
                    if this.closing.get() {
                        break;
                    }
                    match result {
                        Ok(_) => {
                            this.settings.borrow_mut()["network_start_time"] = json!(value);
                            this.apply_time(false, value);
                            break;
                        }
                        Err(e) => {
                            error.set_label(&e);
                            error.set_visible(true);
                        }
                    }
                }
            }
        ));
    }
    fn apply_time(self: &Rc<Self>, host: bool, value: String) {
        glib::spawn_future_local(glib::clone!(
            #[weak(rename_to=this)]
            self,
            async move {
                let result = async {
                    if host {
                        this.backend
                            .call(
                                "settings.set",
                                json!({"key":"network_start_time","value":""}),
                            )
                            .await?;
                    }
                    this.backend
                        .call(
                            "settings.set",
                            json!({"key":"network_host_time","value":host}),
                        )
                        .await?;
                    this.backend.call("session.network_time", json!({})).await
                }
                .await;
                match result {
                    Ok(_) => {
                        this.settings.borrow_mut()["network_host_time"] = json!(host);
                        this.settings.borrow_mut()["network_start_time"] = json!(value);
                        if let Some(action) = this
                            .window
                            .lookup_action("network-time")
                            .and_downcast::<gio::SimpleAction>()
                        {
                            action.set_state(&if host { "host" } else { "fixed" }.to_variant());
                        }
                    }
                    Err(e) => this.error(&e),
                }
            }
        ));
    }
}
