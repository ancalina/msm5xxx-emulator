use gtk::{glib, graphene, pango, prelude::*, subclass::prelude::*};
use std::cell::RefCell;

struct Cell {
    widget: gtk::Widget,
    column: usize,
    row: i32,
    rows: i32,
}
mod pad {
    use super::*;
    #[derive(Default)]
    pub struct Keypad {
        pub(super) cells: RefCell<Vec<Cell>>,
    }
    #[glib::object_subclass]
    impl ObjectSubclass for Keypad {
        const NAME: &'static str = "MsmKeypad";
        type Type = super::Keypad;
        type ParentType = gtk::Widget;
        fn class_init(class: &mut Self::Class) {
            class.set_css_name("phone-keypad");
        }
    }
    impl ObjectImpl for Keypad {
        fn dispose(&self) {
            for cell in self.cells.take() {
                cell.widget.unparent();
            }
        }
    }
    impl Keypad {
        pub(super) fn dimensions(&self) -> ([i32; 4], i32, i32) {
            let mut widths = [0; 4];
            let (mut height, mut rows) = (0, 0);
            for cell in self.cells.borrow().iter() {
                rows = rows.max(cell.row + cell.rows);
                // Button labels alone determine column widths.
                if cell.rows == 1 {
                    widths[cell.column] = widths[cell.column]
                        .max(cell.widget.measure(gtk::Orientation::Horizontal, -1).1);
                    height = height.max(cell.widget.measure(gtk::Orientation::Vertical, -1).1);
                }
            }
            for cell in self.cells.borrow().iter().filter(|c| c.rows > 1) {
                let needed =
                    cell.widget.measure(gtk::Orientation::Vertical, -1).1 - (cell.rows - 1) * 4;
                height = height.max((needed + cell.rows - 1) / cell.rows);
            }
            let key_width = *widths[1..].iter().max().unwrap();
            widths[1..].fill(key_width);
            (widths, height, rows)
        }
    }
    impl WidgetImpl for Keypad {
        fn snapshot(&self, snapshot: &gtk::Snapshot) {
            for cell in self.cells.borrow().iter().filter(|c| c.widget.is_visible()) {
                self.obj().snapshot_child(&cell.widget, snapshot);
            }
        }

        fn measure(&self, orientation: gtk::Orientation, _: i32) -> (i32, i32, i32, i32) {
            let (widths, height, rows) = self.dimensions();
            let size = if orientation == gtk::Orientation::Horizontal {
                widths.iter().sum::<i32>() + 12
            } else {
                rows * height + (rows - 1).max(0) * 4
            };
            (size, size, -1, -1)
        }
        fn size_allocate(&self, width: i32, _: i32, _: i32) {
            let (natural, height, _) = self.dimensions();
            let extra = (width - natural.iter().sum::<i32>() - 12).max(0);
            let key_width = natural[1] + extra / 4;
            // Put rounding pixels in column zero so columns 1–3 remain exactly equal.
            let widths = [width - 12 - key_width * 3, key_width, key_width, key_width];
            for cell in self.cells.borrow().iter().filter(|c| c.widget.is_visible()) {
                let x = widths[..cell.column].iter().sum::<i32>() + cell.column as i32 * 4;
                let y = cell.row * (height + 4);
                cell.widget.allocate(
                    widths[cell.column],
                    cell.rows * height + (cell.rows - 1) * 4,
                    -1,
                    Some(
                        gtk::gsk::Transform::new()
                            .translate(&graphene::Point::new(x as f32, y as f32)),
                    ),
                );
            }
        }
    }
}
glib::wrapper! { pub struct Keypad(ObjectSubclass<pad::Keypad>) @extends gtk::Widget, @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget; }
impl Keypad {
    pub fn new() -> Self {
        glib::Object::builder()
            .property("margin-start", 8)
            .property("margin-end", 8)
            .property("margin-top", 8)
            .property("margin-bottom", 8)
            .property("valign", gtk::Align::End)
            .build()
    }
    pub fn content_width(&self) -> i32 {
        self.imp().dimensions().0.iter().sum::<i32>() + 12
    }
    // shortcut: container styling is margin-only; include CSS padding here if container padding is introduced.
    pub fn opening_width(&self) -> i32 {
        self.content_width() + self.margin_start() + self.margin_end()
    }
    pub fn attach(&self, widget: &impl IsA<gtk::Widget>, column: i32, row: i32, _: i32, rows: i32) {
        widget.set_parent(self);
        self.imp().cells.borrow_mut().push(Cell {
            widget: widget.clone().upcast(),
            column: column as usize,
            row,
            rows,
        });
        self.queue_resize();
    }
    #[cfg(debug_assertions)]
    pub fn cells(&self) -> Vec<serde_json::Value> {
        self.imp().cells.borrow().iter().filter(|c| c.rows == 1 && c.widget.is_visible()).map(|c| {
            let bounds = c.widget.compute_bounds(self).unwrap();
            serde_json::json!({"column":c.column,"row":c.row,"width":bounds.width(),"height":bounds.height()})
        }).collect()
    }
}

mod counter {
    use super::*;
    #[derive(Default)]
    pub struct Counter {
        pub label: gtk::Label,
    }
    #[glib::object_subclass]
    impl ObjectSubclass for Counter {
        const NAME: &'static str = "MsmCounter";
        type Type = super::Counter;
        type ParentType = gtk::Widget;
    }
    impl ObjectImpl for Counter {
        fn constructed(&self) {
            self.parent_constructed();
            self.label.set_parent(&*self.obj());
            self.label.set_xalign(0.);
            self.label.set_css_classes(&["caption", "monospace"]);
            self.obj().set_overflow(gtk::Overflow::Hidden);
        }
        fn dispose(&self) {
            self.label.unparent();
        }
    }
    impl WidgetImpl for Counter {
        fn snapshot(&self, snapshot: &gtk::Snapshot) {
            self.obj().snapshot_child(&self.label, snapshot);
        }

        fn measure(&self, orientation: gtk::Orientation, _: i32) -> (i32, i32, i32, i32) {
            let size = if orientation == gtk::Orientation::Horizontal {
                0
            } else {
                self.label.create_pango_layout(Some("0")).pixel_size().1
            };
            (size, size, -1, -1)
        }
        fn size_allocate(&self, width: i32, height: i32, _: i32) {
            let layout = self.label.create_pango_layout(Some(&self.label.text()));
            let full_width = layout.pixel_size().0;
            let font = self.label.pango_context().font_description().unwrap();
            let font_size = font.size() as f64 / pango::SCALE as f64;
            let dpi = self.obj().settings().gtk_xft_dpi() as f64 / 1024.;
            let floor_size = if font.is_size_absolute() {
                7. * (if dpi > 0. { dpi } else { 96. }) / 72.
            } else {
                7.
            };
            let floor = (floor_size / font_size).min(1.);
            let scale = (width as f64 / full_width.max(1) as f64).clamp(floor, 1.);
            let attrs = pango::AttrList::new();
            attrs.insert(pango::AttrFloat::new_scale(scale));
            self.label.set_attributes(Some(&attrs));
            self.label.allocate(width, height, -1, None);
        }
    }
}
glib::wrapper! { pub struct Counter(ObjectSubclass<counter::Counter>) @extends gtk::Widget, @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget; }
impl Counter {
    pub fn new(description: &str) -> Self {
        let obj: Self = glib::Object::new();
        obj.set_tooltip_text(Some(description));
        obj.set_label("—");
        obj
    }
    pub fn label(&self) -> &gtk::Label {
        &self.imp().label
    }
    pub fn set_label(&self, value: &str) {
        self.imp().label.set_label(value);
        self.imp().label.set_tooltip_text(Some(&format!(
            "{}\n{value}",
            self.tooltip_text().unwrap_or_default()
        )));
        self.queue_allocate();
    }
}
