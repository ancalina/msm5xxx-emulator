mod backend;
mod display;
mod dock;
mod emulator;
mod i18n;
mod icons;
mod keypad;
mod library;
mod settings;
#[cfg(debug_assertions)]
mod verify;
mod widgets;

use adw::prelude::*;
use gtk::{gio, glib};
use std::{cell::RefCell, collections::HashMap, path::PathBuf, rc::Rc};

pub const APP_ID: &str = "io.github.ancalina.MSM5xxx";
pub struct App {
    pub application: adw::Application,
    pub config: backend::Config,
    pub library: RefCell<Option<Rc<library::Library>>>,
    pub emulators: RefCell<HashMap<PathBuf, Rc<emulator::Emulator>>>,
    pub text: RefCell<i18n::Text>,
}
impl App {
    pub fn open(self: &Rc<Self>, path: PathBuf) {
        let path = path.canonicalize().unwrap_or(path);
        if let Some(window) = self.emulators.borrow().get(&path) {
            window.window.present();
            return;
        }
        let window = emulator::Emulator::new(self, path.clone());
        self.emulators.borrow_mut().insert(path, window.clone());
        window.window.present();
    }
    pub fn refresh(&self) {
        if let Some(library) = self.library.borrow().as_ref() {
            library.refresh();
        }
    }
    pub fn quit(&self) {
        let sessions: Vec<_> = self.emulators.borrow().values().cloned().collect();
        for session in sessions {
            session.close();
        }
        if let Some(library) = self.library.borrow().as_ref() {
            library.close();
        }
    }
}
fn hide_title_icon(settings: &gtk::Settings) {
    if let Some(layout) = settings.gtk_decoration_layout() {
        let buttons = layout
            .split(':')
            .map(|side| {
                side.split(',')
                    .filter(|button| button.trim() != "icon")
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect::<Vec<_>>()
            .join(":");
        if buttons != layout.as_str() {
            settings.set_gtk_decoration_layout(Some(&buttons));
        }
    }
}
fn main() -> glib::ExitCode {
    let config = backend::Config::discover();
    // GNU gettext uses each UI thread's locale. Keep the original environment for the backend.
    // This is before GTK or background threads exist, so changing the environment is safe.
    unsafe {
        std::env::remove_var("LANGUAGE");
    }
    i18n::init(&config.bundle);
    glib::set_application_name("MSM5xxx Emulator");
    let flags = gio::ApplicationFlags::HANDLES_OPEN;
    #[cfg(debug_assertions)]
    let flags = if std::env::var_os("MSM5XXX_VERIFY_NON_UNIQUE").is_some() {
        flags | gio::ApplicationFlags::NON_UNIQUE
    } else {
        flags
    };
    let application = adw::Application::builder()
        .application_id(APP_ID)
        .flags(flags)
        .build();
    application.connect_startup(|_| {
        gio::resources_register_include!("icons.gresource").expect("Application icons");
        gtk::Window::set_default_icon_name(APP_ID);
        if let Some(settings) = gtk::Settings::default() {
            hide_title_icon(&settings);
            settings.connect_gtk_decoration_layout_notify(hide_title_icon);
        }
        if let Some(display) = gtk::gdk::Display::default() {
            gtk::IconTheme::for_display(&display)
                .add_resource_path("/io/github/ancalina/MSM5xxx/icons");
        }
    });
    icons::init(&application);
    let app = Rc::new(App {
        application: application.clone(),
        config,
        library: RefCell::new(None),
        emulators: RefCell::new(HashMap::new()),
        text: RefCell::new(i18n::Text::new("en")),
    });
    application.connect_activate(glib::clone!(
        #[weak]
        app,
        move |_| {
            if let Some(library) = app.library.borrow().as_ref() {
                library.window.present();
                return;
            }
            let library = library::Library::new(&app);
            app.library.replace(Some(library.clone()));
            library.window.present();
        }
    ));
    application.connect_open(glib::clone!(
        #[weak]
        app,
        move |_, files, _| {
            app.application.activate();
            for file in files {
                if let Some(path) = file.path() {
                    app.open(path);
                }
            }
        }
    ));
    let quit = gio::SimpleAction::new("quit", None);
    quit.connect_activate(glib::clone!(
        #[weak]
        app,
        move |_, _| app.quit()
    ));
    application.add_action(&quit);
    application.set_accels_for_action("app.quit", &["<Control>q"]);
    application.set_accels_for_action("win.close", &["<Control>w"]);
    application.set_accels_for_action("win.add-file", &["<Control>o"]);
    application.set_accels_for_action("win.settings", &["<Control>comma"]);
    application.set_accels_for_action("win.refresh", &["<Control>r", "F5"]);
    application.set_accels_for_action("win.capture", &["<Control>s"]);
    #[cfg(debug_assertions)]
    verify::install(&app);
    application.run()
}
