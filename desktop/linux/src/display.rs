use gtk::{gdk, glib, graphene, gsk, prelude::*, subclass::prelude::*};
use std::cell::{Cell, RefCell};
mod imp {
    use super::*;
    pub struct Display {
        pub texture: RefCell<Option<gdk::Texture>>,
        pub size: Cell<(i32, i32)>,
        pub scale: Cell<i32>,
        pub flexible: Cell<bool>,
    }
    impl Default for Display {
        fn default() -> Self {
            Self {
                texture: RefCell::new(None),
                size: Cell::new((128, 128)),
                scale: Cell::new(3),
                flexible: Cell::new(false),
            }
        }
    }
    #[glib::object_subclass]
    impl ObjectSubclass for Display {
        const NAME: &'static str = "MsmPhoneDisplay";
        type Type = super::Display;
        type ParentType = gtk::Widget;
        fn class_init(class: &mut Self::Class) {
            class.set_accessible_role(gtk::AccessibleRole::Img);
        }
    }
    impl ObjectImpl for Display {}
    impl WidgetImpl for Display {
        fn request_mode(&self) -> gtk::SizeRequestMode {
            if self.flexible.get() {
                gtk::SizeRequestMode::ConstantSize
            } else {
                gtk::SizeRequestMode::HeightForWidth
            }
        }
        fn measure(&self, orientation: gtk::Orientation, for_size: i32) -> (i32, i32, i32, i32) {
            let (w, h) = self.size.get();
            if orientation == gtk::Orientation::Horizontal {
                (w, w * self.scale.get(), -1, -1)
            } else if for_size > 0 && !self.flexible.get() {
                let needed = ((for_size as f64) * h as f64 / w as f64).round() as i32;
                (needed, needed, -1, -1)
            } else {
                (h, h * self.scale.get(), -1, -1)
            }
        }
        fn snapshot(&self, snapshot: &gtk::Snapshot) {
            let obj = self.obj();
            let w = obj.width() as f32;
            let h = obj.height() as f32;
            snapshot.append_color(&gdk::RGBA::BLACK, &graphene::Rect::new(0., 0., w, h));
            if let Some(texture) = self.texture.borrow().as_ref() {
                let scale = (w / texture.width() as f32).min(h / texture.height() as f32);
                let dw = texture.width() as f32 * scale;
                let dh = texture.height() as f32 * scale;
                snapshot.append_scaled_texture(
                    texture,
                    gsk::ScalingFilter::Nearest,
                    &graphene::Rect::new((w - dw) / 2., (h - dh) / 2., dw, dh),
                );
            }
        }
    }
}
glib::wrapper! { pub struct Display(ObjectSubclass<imp::Display>) @extends gtk::Widget, @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget; }
impl Display {
    pub fn new(label: &str) -> Self {
        let obj: Self = glib::Object::new();
        obj.set_vexpand(true);
        obj.set_overflow(gtk::Overflow::Hidden);
        obj.update_property(&[gtk::accessible::Property::Label(label)]);
        obj
    }
    pub fn geometry(&self) -> (i32, i32) {
        self.imp().size.get()
    }
    pub fn set_scale(&self, scale: i32) {
        if self.imp().scale.replace(scale) != scale {
            self.queue_resize();
        }
    }
    pub fn set_flexible(&self, flexible: bool) {
        if self.imp().flexible.replace(flexible) != flexible {
            self.queue_resize();
        }
    }
    pub fn frame(&self, frame: &serde_json::Value) -> Result<bool, String> {
        use base64::Engine;
        let w = frame["width"].as_i64().unwrap_or(0) as i32;
        let h = frame["height"].as_i64().unwrap_or(0) as i32;
        if !(1..=4096).contains(&w) || !(1..=4096).contains(&h) {
            return Err("Invalid display dimensions".into());
        }
        let data = base64::engine::general_purpose::STANDARD
            .decode(frame["rgb"].as_str().unwrap_or(""))
            .map_err(|e| e.to_string())?;
        if data.len() != (w * h * 3) as usize {
            return Err("Invalid display frame length".into());
        }
        let texture = gdk::MemoryTexture::new(
            w,
            h,
            gdk::MemoryFormat::R8g8b8,
            &glib::Bytes::from_owned(data),
            w as usize * 3,
        );
        let changed = self.imp().size.replace((w, h)) != (w, h);
        self.imp().texture.replace(Some(texture.upcast()));
        if changed {
            self.queue_resize();
        }
        self.queue_draw();
        Ok(changed)
    }
    pub fn texture(&self) -> Option<gdk::Texture> {
        self.imp().texture.borrow().clone()
    }
    pub fn clear(&self) {
        self.imp().texture.take();
        self.queue_draw();
    }
}
