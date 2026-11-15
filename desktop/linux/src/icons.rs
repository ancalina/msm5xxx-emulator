use crate::APP_ID;
use adw::prelude::*;
use gtk::{gdk, gio, glib};
use std::{cell::Cell, path::PathBuf};

thread_local! { static SIMPLE: Cell<bool> = const { Cell::new(false) }; }

fn preference_path() -> PathBuf {
    std::env::var_os("MSM5XXX_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| glib::user_config_dir().join("msm5xxx-emulator"))
        .join("linux-appearance")
}
pub fn simple() -> bool {
    SIMPLE.get()
}
fn update(window: &gtk::Window) {
    let name = format!("{APP_ID}{}", if simple() { "-simple" } else { "" });
    window.set_icon_name(Some(&name));
    if let Some(surface) = window.surface().and_downcast::<gdk::Toplevel>() {
        let resource = format!("/io/github/ancalina/MSM5xxx/icons/scalable/apps/{name}.svg");
        let textures: Vec<_> = [32, 64, 128, 256]
            .into_iter()
            .map(|size| {
                let pixbuf =
                    gtk::gdk_pixbuf::Pixbuf::from_resource_at_scale(&resource, size, size, true)
                        .expect("Embedded application icon");
                gdk::MemoryTexture::new(
                    pixbuf.width(),
                    pixbuf.height(),
                    if pixbuf.has_alpha() {
                        gdk::MemoryFormat::R8g8b8a8
                    } else {
                        gdk::MemoryFormat::R8g8b8
                    },
                    &pixbuf.read_pixel_bytes(),
                    pixbuf.rowstride() as usize,
                )
                .upcast::<gdk::Texture>()
            })
            .collect();
        surface.set_icon_list(&textures);
    }
}
pub fn init(application: &adw::Application) {
    SIMPLE.set(std::fs::read_to_string(preference_path()).is_ok_and(|s| s.trim() == "simple"));
    application.connect_window_added(|_, window| {
        update(window);
        window.connect_realize(update);
    });
}
pub async fn save(simple: bool) -> Result<(), String> {
    let path = preference_path();
    gio::spawn_blocking(move || -> Result<(), String> {
        std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
        gio::File::for_path(path)
            .replace_contents(
                if simple { b"simple\n" } else { b"full\n" },
                None,
                false,
                gio::FileCreateFlags::PRIVATE,
                gio::Cancellable::NONE,
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    })
    .await
    .map_err(|_| "Could not save appearance settings".to_owned())??;
    SIMPLE.set(simple);
    if let Some(application) = gio::Application::default().and_downcast::<gtk::Application>() {
        for window in application.windows() {
            update(&window);
        }
    }
    Ok(())
}
