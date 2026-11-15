//! Development-only controls for exercising the actual widgets and capturing their rendered output.
use crate::App;
use adw::prelude::*;
use gtk::{gdk, glib, graphene};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    rc::Rc,
    time::Duration,
};
pub fn install(app: &Rc<App>) {
    let Some(directory) = std::env::var_os("MSM5XXX_VERIFY_DIR").map(PathBuf::from) else {
        return;
    };
    fs::create_dir_all(&directory).unwrap();
    let weak = Rc::downgrade(app);
    glib::timeout_add_local(Duration::from_millis(50), move || {
        let Some(app) = weak.upgrade() else {
            return glib::ControlFlow::Break;
        };
        let path = directory.join("request.json");
        if let Ok(data) = fs::read_to_string(&path) {
            let _ = fs::remove_file(&path);
            let request = serde_json::from_str::<Value>(&data);
            let directory = directory.clone();
            glib::spawn_future_local(async move {
                let result = match request {
                    Ok(request) => dispatch(&app, &request).await,
                    Err(e) => Err(e.to_string()),
                };
                let result = match result {
                    Ok(value) => json!({"ok":value}),
                    Err(error) => json!({"error":error}),
                };
                let _ = fs::write(directory.join("response.json"), result.to_string());
            });
        }
        glib::ControlFlow::Continue
    });
}
fn window(app: &App, target: &str) -> Result<gtk::Window, String> {
    if target == "library" {
        return app
            .library
            .borrow()
            .as_ref()
            .map(|l| l.window.clone().upcast())
            .ok_or("No library".into());
    }
    let sessions = app.emulators.borrow();
    let secondary = target == "secondary" || target.starts_with("secondary:");
    let stem = target.strip_prefix("secondary:").unwrap_or(target);
    let emulator = sessions
        .values()
        .find(|e| {
            if target == "secondary" {
                e.running.get() && e.secondary.is_visible()
            } else {
                e.path.file_stem().is_some_and(|s| s == stem)
            }
        })
        .ok_or("No emulator")?;
    Ok(if secondary {
        emulator.secondary.clone().upcast()
    } else {
        emulator.window.clone().upcast()
    })
}
async fn snapshot(window: &gtk::Window, path: &Path, menu: bool) -> Result<Value, String> {
    if !window.is_mapped() {
        return Err("Window is not mapped".into());
    }
    let paintable = gtk::WidgetPaintable::new(Some(window));
    window.queue_draw();
    glib::timeout_future(Duration::from_millis(700)).await;
    let snapshot = gtk::Snapshot::new();
    let (w, h) = (window.width(), window.height());
    paintable.snapshot(&snapshot, w as f64, h as f64);
    let menu_bounds = if menu {
        let button = find(window.upcast_ref(), "Main Menu")
            .or_else(|| find(window.upcast_ref(), "주 메뉴"))
            .and_downcast::<gtk::MenuButton>()
            .ok_or("No main menu")?;
        let popover = button
            .popover()
            .filter(|p| p.is_mapped())
            .ok_or("Menu is not open")?;
        let bounds = popover.compute_bounds(window).ok_or("No menu bounds")?;
        // Popup bounds include native shadows; the window paintable starts at its content.
        let (surface_x, surface_y) = window.surface_transform();
        let bounds = graphene::Rect::new(
            bounds.x() - surface_x as f32,
            bounds.y() - surface_y as f32,
            bounds.width(),
            bounds.height(),
        );
        snapshot.save();
        snapshot.translate(&graphene::Point::new(bounds.x(), bounds.y()));
        gtk::WidgetPaintable::new(Some(&popover)).snapshot(
            &snapshot,
            popover.width() as f64,
            popover.height() as f64,
        );
        snapshot.restore();
        Some([bounds.x(), bounds.y(), bounds.width(), bounds.height()])
    } else {
        None
    };
    let node = snapshot.to_node().ok_or("Empty snapshot")?;
    let renderer = window.renderer().ok_or("No renderer")?;
    let texture = renderer.render_texture(
        &node,
        Some(&graphene::Rect::new(0., 0., w as f32, h as f32)),
    );
    texture.save_to_png(path).map_err(|e| e.to_string())?;
    Ok(
        json!({"width":w,"height":h,"path":path,"menu_bounds":menu_bounds,"surface_transform":window.surface_transform()}),
    )
}
fn find(widget: &gtk::Widget, label: &str) -> Option<gtk::Widget> {
    let own = widget
        .downcast_ref::<gtk::Button>()
        .and_then(|b| b.label())
        .map(|s| s.to_string())
        .or_else(|| {
            widget
                .downcast_ref::<adw::PreferencesRow>()
                .map(|r| r.title().to_string())
        });
    if widget.is_mapped()
        && (own.as_deref() == Some(label)
            || widget.widget_name() == label
            || widget.tooltip_text().as_deref() == Some(label))
    {
        return Some(widget.clone());
    }
    let mut child = widget.first_child();
    while let Some(item) = child {
        if let Some(found) = find(&item, label) {
            return Some(found);
        }
        child = item.next_sibling();
    }
    None
}
async fn dispatch(app: &Rc<App>, request: &Value) -> Result<Value, String> {
    let target = request["target"].as_str().unwrap_or("library");
    match request["command"].as_str().unwrap_or("") {
        "layout" => app
            .emulators
            .borrow()
            .values()
            .find(|e| e.path.file_stem().is_some_and(|s| s == target))
            .map(|e| e.inspect_layout())
            .ok_or("No emulator".into()),
        "counter" => {
            let emulator = app
                .emulators
                .borrow()
                .values()
                .find(|e| e.path.file_stem().is_some_and(|s| s == target))
                .cloned()
                .ok_or("No emulator")?;
            Ok(json!(emulator.verify_counter(
                request["key"].as_str().ok_or("key")?,
                request["value"].as_str().ok_or("value")?
            )))
        }
        "open" => {
            app.open(PathBuf::from(request["path"].as_str().ok_or("path")?));
            Ok(json!(true))
        }
        "library" => {
            let library = app.library.borrow().clone().ok_or("No library")?;
            let value = library
                .backend
                .call(
                    request["method"].as_str().ok_or("method")?,
                    request["params"].clone(),
                )
                .await?;
            library.refresh();
            Ok(value)
        }
        "backend" => {
            let emulator = app
                .emulators
                .borrow()
                .values()
                .find(|e| e.path.file_stem().is_some_and(|s| s == target))
                .cloned()
                .ok_or("No emulator")?;
            emulator
                .backend
                .call(
                    request["method"].as_str().ok_or("method")?,
                    request["params"].clone(),
                )
                .await
        }
        "snapshot" => {
            snapshot(
                &window(app, target)?,
                Path::new(request["path"].as_str().ok_or("path")?),
                request["menu"].as_bool().unwrap_or(false),
            )
            .await
        }
        "main-menu" => {
            let window = window(app, target)?;
            let button = find(window.upcast_ref(), "Main Menu")
                .or_else(|| find(window.upcast_ref(), "주 메뉴"))
                .and_downcast::<gtk::MenuButton>()
                .ok_or("No main menu")?;
            if let Some(open) = request["open"].as_bool() {
                if open {
                    button.popup();
                } else {
                    button.popdown();
                }
            }
            Ok(
                json!({"icon":button.icon_name().map(|s|s.to_string()),"primary":button.is_primary(),"tooltip":button.tooltip_text().map(|s|s.to_string()),"open":button.popover().is_some_and(|p|p.is_mapped())}),
            )
        }
        "resize" => {
            let window = window(app, target)?;
            window.set_default_size(
                request["width"].as_i64().ok_or("width")? as i32,
                request["height"].as_i64().unwrap_or(1) as i32,
            );
            Ok(json!(true))
        }
        "action" => {
            let window = window(app, target)?;
            window
                .activate_action(
                    request["name"].as_str().ok_or("name")?,
                    request["value"]
                        .as_bool()
                        .map(|v| v.to_variant())
                        .or_else(|| request["value"].as_str().map(|v| v.to_variant()))
                        .as_ref(),
                )
                .map_err(|e| e.to_string())?;
            Ok(json!(true))
        }
        "activate" | "entry" | "switch" | "choice" | "apply-entry" => {
            let window = window(app, target)?;
            let widget = find(
                window.upcast_ref(),
                request["label"].as_str().ok_or("label")?,
            )
            .ok_or("Widget not found")?;
            match request["command"].as_str().unwrap() {
                "entry" => {
                    if let Some(row) = widget.downcast_ref::<adw::EntryRow>() {
                        row.set_text(request["value"].as_str().ok_or("value")?);
                    } else {
                        return Err("Not an entry".into());
                    }
                }
                "switch" => widget
                    .downcast_ref::<adw::SwitchRow>()
                    .ok_or("Not a switch")?
                    .set_active(request["value"].as_bool().ok_or("value")?),
                "choice" => widget
                    .downcast_ref::<adw::ComboRow>()
                    .ok_or("Not a choice")?
                    .set_selected(request["value"].as_u64().ok_or("value")? as u32),
                "apply-entry" => {
                    widget.emit_by_name::<()>("apply", &[]);
                }
                _ => {
                    if let Some(button) = widget.downcast_ref::<gtk::Button>() {
                        button.emit_clicked();
                    } else {
                        widget.activate();
                    }
                }
            }
            Ok(json!(true))
        }
        "response" => {
            let window = window(app, target)?;
            let dialog = window
                .downcast_ref::<adw::ApplicationWindow>()
                .and_then(|w| w.visible_dialog())
                .ok_or("No dialog")?;
            let alert = dialog
                .downcast::<adw::AlertDialog>()
                .map_err(|_| "Not an alert")?;
            alert.emit_by_name::<()>("response", &[&request["value"].as_str().ok_or("value")?]);
            alert.close();
            Ok(json!(true))
        }
        "page" => {
            let window = window(app, target)?;
            let dialog = window
                .downcast_ref::<adw::ApplicationWindow>()
                .and_then(|w| w.visible_dialog())
                .ok_or("No dialog")?
                .downcast::<adw::PreferencesDialog>()
                .map_err(|_| "Not preferences")?;
            dialog.set_search_enabled(false);
            dialog.set_visible_page_name(request["value"].as_str().ok_or("value")?);
            dialog.set_search_enabled(true);
            Ok(json!(true))
        }
        "bounds" => {
            let window = window(app, target)?;
            let widget = find(
                window.upcast_ref(),
                request["label"].as_str().ok_or("label")?,
            )
            .ok_or("Widget not found")?;
            let rect = widget.compute_bounds(&window).ok_or("No bounds")?;
            Ok(json!([rect.x(), rect.y(), rect.width(), rect.height()]))
        }
        "focus-widget" => {
            let window = window(app, target)?;
            let widget = find(
                window.upcast_ref(),
                request["label"].as_str().ok_or("label")?,
            )
            .ok_or("Widget not found")?;
            Ok(json!(widget.grab_focus()))
        }
        "processes" => {
            let mut entries = Vec::new();
            for entry in fs::read_dir("/proc").map_err(|e| e.to_string())?.flatten() {
                if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
                    continue;
                }
                if let Ok(status) = fs::read_to_string(entry.path().join("status")) {
                    let fields: Vec<_> = status
                        .lines()
                        .filter(|s| {
                            ["Name:", "Pid:", "PPid:", "VmRSS:", "Cpus_allowed_list:"]
                                .iter()
                                .any(|key| s.starts_with(key))
                        })
                        .map(str::to_owned)
                        .collect();
                    entries.push(json!({"status":fields,"stat":fs::read_to_string(entry.path().join("stat")).unwrap_or_default()}));
                }
            }
            Ok(json!(entries))
        }
        "dismiss" => {
            let window = window(app, target)?;
            if let Some(dialog) = window
                .downcast_ref::<adw::ApplicationWindow>()
                .and_then(|w| w.visible_dialog())
            {
                dialog.close();
            }
            Ok(json!(true))
        }
        "key" => {
            let window = window(app, target)?;
            let model = window.observe_controllers();
            let controller = (0..model.n_items())
                .filter_map(|i| model.item(i).and_downcast::<gtk::EventControllerKey>())
                .next()
                .ok_or("No keyboard controller")?;
            let key =
                gdk::Key::from_name(request["key"].as_str().ok_or("key")?).ok_or("Unknown key")?;
            let modifiers = if request["control"] == true {
                gdk::ModifierType::CONTROL_MASK
            } else {
                gdk::ModifierType::empty()
            };
            let pressed = request["pressed"] == true;
            if pressed {
                let captured =
                    controller.emit_by_name::<bool>("key-pressed", &[&key, &0u32, &modifiers]);
                Ok(json!({"captured":captured}))
            } else {
                controller.emit_by_name::<()>("key-released", &[&key, &0u32, &modifiers]);
                Ok(json!(true))
            }
        }
        "decorations" => {
            let settings = gtk::Settings::default().ok_or("No GTK settings")?;
            settings.set_gtk_decoration_layout(Some(request["value"].as_str().ok_or("value")?));
            Ok(json!(
                settings.gtk_decoration_layout().map(|s| s.to_string())
            ))
        }
        "icon-theme" => {
            let settings = gtk::Settings::default().ok_or("No GTK settings")?;
            settings.set_gtk_icon_theme_name(Some(request["value"].as_str().ok_or("value")?));
            Ok(json!(settings.gtk_icon_theme_name().map(|s| s.to_string())))
        }
        "font" => {
            gtk::Settings::default()
                .ok_or("No GTK settings")?
                .set_gtk_font_name(Some(request["value"].as_str().ok_or("value")?));
            glib::timeout_future(Duration::from_millis(300)).await;
            for emulator in app.emulators.borrow().values() {
                emulator.fit();
            }
            Ok(json!(true))
        }
        "theme" => {
            adw::StyleManager::default().set_color_scheme(if request["dark"] == true {
                adw::ColorScheme::ForceDark
            } else {
                adw::ColorScheme::ForceLight
            });
            Ok(json!(true))
        }
        "inspect" => {
            let mut result = json!({"windows":[],"simple_icon":crate::icons::simple(),"icon_theme":gtk::Settings::default().and_then(|s|s.gtk_icon_theme_name().map(|s|s.to_string())),"decoration_layout":gtk::Settings::default().and_then(|s|s.gtk_decoration_layout().map(|s|s.to_string())),"font":gtk::Settings::default().map(|s|s.gtk_font_name().map(|s|s.to_string())),"dark":adw::StyleManager::default().is_dark(),"high_contrast":adw::StyleManager::default().is_high_contrast()});
            result["windows"]=Value::Array(app.application.windows().iter().map(|w|json!({"icon_name":w.icon_name().map(|s|s.to_string()),"title":w.title().map(|s|s.to_string()),"visible":w.is_visible(),"active":w.is_active(),"width":w.width(),"height":w.height()})).collect());
            result["sessions"]=Value::Array(app.emulators.borrow().values().map(|e|json!({"path":e.path,"running":e.running.get(),"busy":e.busy.get(),"ready":e.ready.get(),"editing":e.editing.get(),"buttons":e.buttons.borrow().iter().map(|(bit,button)|json!({"bit":bit,"sensitive":button.is_sensitive()})).collect::<Vec<_>>(),"screen":e.screen.geometry(),"screen_area":[e.screen.width(),e.screen.height()],"keypad":[e.keypad.width(),e.keypad.height()],"secondary":e.secondary_seen.get(),"state":*e.state.borrow(),"started":*e.started.borrow(),"banner":e.banner.is_revealed(),"error":e.banner.title().to_string()})).collect());
            Ok(result)
        }
        "focus" => {
            window(app, target)?.present();
            Ok(json!(true))
        }
        "close" => {
            window(app, target)?.close();
            Ok(json!(true))
        }
        "quit" => {
            app.quit();
            Ok(json!(true))
        }
        _ => Err("Unknown command".into()),
    }
}
