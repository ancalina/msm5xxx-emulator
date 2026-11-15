//! X11-only secondary-window positioning. Native Wayland never installs this controller.
use gtk::{gdk, gio, glib, glib::translate::ToGlibPtr, graphene, prelude::*};
use libc::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant},
};

// GTK's X11 compatibility API is needed only at this platform boundary.
unsafe extern "C" {
    fn gdk_x11_display_get_xdisplay(display: *mut gdk::ffi::GdkDisplay) -> *mut c_void;
    fn gdk_x11_surface_get_xid(surface: *mut gdk::ffi::GdkSurface) -> c_ulong;
    fn gdk_x11_display_error_trap_push(display: *mut gdk::ffi::GdkDisplay);
    fn gdk_x11_display_error_trap_pop_ignored(display: *mut gdk::ffi::GdkDisplay);
}
#[link(name = "X11")]
unsafe extern "C" {
    fn XGetGeometry(
        d: *mut c_void,
        window: c_ulong,
        root: *mut c_ulong,
        x: *mut c_int,
        y: *mut c_int,
        w: *mut c_uint,
        h: *mut c_uint,
        border: *mut c_uint,
        depth: *mut c_uint,
    ) -> c_int;
    fn XTranslateCoordinates(
        d: *mut c_void,
        source: c_ulong,
        target: c_ulong,
        sx: c_int,
        sy: c_int,
        x: *mut c_int,
        y: *mut c_int,
        child: *mut c_ulong,
    ) -> c_int;
    fn XInternAtom(d: *mut c_void, name: *const c_char, only_exists: c_int) -> c_ulong;
    fn XGetWindowProperty(
        d: *mut c_void,
        window: c_ulong,
        atom: c_ulong,
        offset: c_long,
        length: c_long,
        delete: c_int,
        wanted: c_ulong,
        actual: *mut c_ulong,
        format: *mut c_int,
        count: *mut c_ulong,
        after: *mut c_ulong,
        data: *mut *mut u8,
    ) -> c_int;
    fn XFree(data: *mut c_void) -> c_int;
    fn XMoveWindow(d: *mut c_void, window: c_ulong, x: c_int, y: c_int) -> c_int;
    fn XFlush(d: *mut c_void) -> c_int;
    fn XQueryPointer(
        d: *mut c_void,
        window: c_ulong,
        root: *mut c_ulong,
        child: *mut c_ulong,
        rx: *mut c_int,
        ry: *mut c_int,
        x: *mut c_int,
        y: *mut c_int,
        mask: *mut c_uint,
    ) -> c_int;
}
struct Native<'a> {
    display: &'a gdk::Display,
    xdisplay: *mut c_void,
}
impl Drop for Native<'_> {
    fn drop(&mut self) {
        unsafe {
            gdk_x11_display_error_trap_pop_ignored(self.display.to_glib_none().0);
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rect {
    xid: c_ulong,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    inset_x: i32,
    inset_y: i32,
}
impl Rect {
    #[cfg(debug_assertions)]
    fn json(self) -> Value {
        json!({"xid":self.xid,"x":self.x,"y":self.y,"width":self.width,"height":self.height,"inset_x":self.inset_x,"inset_y":self.inset_y})
    }
}
impl<'a> Native<'a> {
    fn new(display: &'a gdk::Display) -> Option<Self> {
        if display.type_().name() != "GdkX11Display" {
            return None;
        }
        unsafe {
            let xdisplay = gdk_x11_display_get_xdisplay(display.to_glib_none().0);
            if xdisplay.is_null() {
                return None;
            }
            gdk_x11_display_error_trap_push(display.to_glib_none().0);
            Some(Self { display, xdisplay })
        }
    }
    fn extents(&self, xid: c_ulong, name: &std::ffi::CStr) -> [i32; 4] {
        let mut result = [0; 4];
        unsafe {
            let atom = XInternAtom(self.xdisplay, name.as_ptr(), 0);
            let (mut actual, mut format, mut count, mut after, mut data) =
                (0, 0, 0, 0, std::ptr::null_mut());
            let status = XGetWindowProperty(
                self.xdisplay,
                xid,
                atom,
                0,
                4,
                0,
                6,
                &mut actual,
                &mut format,
                &mut count,
                &mut after,
                &mut data,
            );
            if status == 0 && actual == 6 && format == 32 && count == 4 && !data.is_null() {
                for (i, value) in result.iter_mut().enumerate() {
                    *value = (*(data.cast::<c_ulong>().add(i))).min(4096) as i32;
                }
            }
            if !data.is_null() {
                XFree(data.cast());
            }
        }
        result
    }
    fn rect(&self, window: &gtk::Window) -> Option<Rect> {
        let surface = window.surface()?;
        if surface.type_().name() != "GdkX11Toplevel"
            && !surface
                .type_()
                .is_a(glib::Type::from_name("GdkX11Surface")?)
        {
            return None;
        }
        unsafe {
            let xid = gdk_x11_surface_get_xid(surface.to_glib_none().0);
            let (mut root, mut child, mut x, mut y, mut w, mut h, mut border, mut depth) =
                (0, 0, 0, 0, 0, 0, 0, 0);
            if XGetGeometry(
                self.xdisplay,
                xid,
                &mut root,
                &mut x,
                &mut y,
                &mut w,
                &mut h,
                &mut border,
                &mut depth,
            ) == 0
            {
                return None;
            }
            if XTranslateCoordinates(self.xdisplay, xid, root, 0, 0, &mut x, &mut y, &mut child)
                == 0
            {
                return None;
            }
            let gtk = self.extents(xid, c"_GTK_FRAME_EXTENTS");
            let wm = self.extents(xid, c"_NET_FRAME_EXTENTS");
            let inset_x = gtk[0] - wm[0];
            let inset_y = gtk[2] - wm[2];
            Some(Rect {
                xid,
                x: x + inset_x,
                y: y + inset_y,
                width: w as i32 - gtk[0] - gtk[1] + wm[0] + wm[1],
                height: h as i32 - gtk[2] - gtk[3] + wm[2] + wm[3],
                inset_x,
                inset_y,
            })
        }
    }
    fn move_to(&self, rect: Rect, x: i32, y: i32) {
        unsafe {
            XMoveWindow(self.xdisplay, rect.xid, x - rect.inset_x, y - rect.inset_y);
            XFlush(self.xdisplay);
        }
    }
    fn dragging(&self, xid: c_ulong) -> bool {
        let (mut root, mut child, mut rx, mut ry, mut x, mut y, mut mask) = (0, 0, 0, 0, 0, 0, 0);
        unsafe {
            XQueryPointer(
                self.xdisplay,
                xid,
                &mut root,
                &mut child,
                &mut rx,
                &mut ry,
                &mut x,
                &mut y,
                &mut mask,
            ) != 0
                && mask & (1 << 8) != 0
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Placement {
    attached: bool,
    left: bool,
}
fn preference_path(firmware: &Path) -> PathBuf {
    let name = glib::compute_checksum_for_data(
        glib::ChecksumType::Sha256,
        firmware.as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    std::env::var_os("MSM5XXX_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| glib::user_config_dir().join("msm5xxx-emulator"))
        .join("linux-displays")
        .join(format!("{name}.json"))
}
impl Placement {
    fn load(firmware: &Path) -> Self {
        let value: Value = std::fs::read(preference_path(firmware))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Self {
            attached: value["attached"] == true,
            left: value["side"] == "left",
        }
    }
    async fn save(self, path: PathBuf) -> Result<(), String> {
        gio::spawn_blocking(move || {
            std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
            let bytes =
                json!({"attached":self.attached,"side":if self.left {"left"} else {"right"}})
                    .to_string();
            gio::File::for_path(path)
                .replace_contents(
                    bytes.as_bytes(),
                    None,
                    false,
                    gio::FileCreateFlags::PRIVATE,
                    gio::Cancellable::NONE,
                )
                .map_err(|e| e.to_string())?;
            Ok(())
        })
        .await
        .map_err(|_| "Could not save display placement".to_owned())?
    }
}
struct State {
    placement: Placement,
    main: Option<Rect>,
    secondary: Option<Rect>,
    pending_move: Option<(i32, i32, Instant)>,
    main_minimized: bool,
    pending_save: Option<Placement>,
    saving: bool,
    path: PathBuf,
    error: Box<dyn Fn(&str)>,
}
impl State {
    fn observe(
        &mut self,
        m: Rect,
        s: Rect,
        y: i32,
        threshold: i32,
        dragging: bool,
        now: Instant,
    ) -> (Option<(i32, i32)>, bool) {
        let mut changed = false;
        let mut movement = None;
        let main_changed = self.main.is_some_and(|old| old != m);
        let secondary_changed = self
            .secondary
            .is_some_and(|old| old.x != s.x || old.y != s.y);
        let resized = self
            .secondary
            .is_some_and(|old| old.width != s.width || old.height != s.height);
        let target_x = if self.placement.left {
            m.x - s.width
        } else {
            m.x + m.width
        };
        let anchor_changed = self
            .pending_move
            .is_some_and(|(x, old_y, _)| x != target_x || old_y != y);
        let pending_expired = self.pending_move.is_some_and(|(_, _, until)| now >= until);
        let pending = self.pending_move.is_some_and(|(x, y, until)| {
            now < until && ((s.x - x).abs() > 1 || (s.y - y).abs() > 1)
        });
        if !pending {
            self.pending_move = None;
        }
        if self.placement.attached {
            if !main_changed
                && !anchor_changed
                && !resized
                && (secondary_changed || pending_expired)
                && !pending
                && ((s.x - target_x).abs() > threshold || (s.y - y).abs() > threshold)
            {
                self.placement.attached = false;
                changed = true;
            } else if main_changed
                || anchor_changed
                || resized
                || self.main.is_none()
                || (!pending && !dragging && ((s.x - target_x).abs() > 1 || (s.y - y).abs() > 1))
            {
                movement = Some((target_x, y));
                self.pending_move = Some((target_x, y, now + Duration::from_millis(400)));
            }
        } else if secondary_changed
            && !resized
            && !main_changed
            && s.y + s.height > m.y
            && s.y < m.y + m.height
        {
            let left = (s.x - (m.x - s.width)).abs();
            let right = (s.x - (m.x + m.width)).abs();
            if left.min(right) <= threshold {
                self.placement = Placement {
                    attached: true,
                    left: left < right,
                };
                changed = true;
                let x = if self.placement.left {
                    m.x - s.width
                } else {
                    m.x + m.width
                };
                movement = Some((x, y));
                self.pending_move = Some((x, y, now + Duration::from_millis(400)));
            }
        }
        self.main = Some(m);
        self.secondary = Some(s);
        (movement, changed)
    }
}
fn persist(state: &Rc<RefCell<State>>) {
    {
        let mut s = state.borrow_mut();
        s.pending_save = Some(s.placement);
        if s.saving {
            return;
        }
        s.saving = true;
    }
    let state = state.clone();
    let hold = gio::Application::default().map(|a| a.hold());
    glib::spawn_future_local(async move {
        let _hold = hold;
        loop {
            let next = {
                let mut s = state.borrow_mut();
                s.pending_save.take().map(|p| (p, s.path.clone()))
            };
            let Some((placement, path)) = next else {
                state.borrow_mut().saving = false;
                break;
            };
            if let Err(error) = placement.save(path).await {
                (state.borrow().error)(&error);
            }
        }
    });
}
pub struct Docking {
    source: Option<glib::SourceId>,
    #[cfg(debug_assertions)]
    state: Rc<RefCell<State>>,
}
impl Drop for Docking {
    fn drop(&mut self) {
        if let Some(source) = self.source.take() {
            source.remove();
        }
    }
}
impl Docking {
    pub fn install(
        main: &impl IsA<gtk::Window>,
        secondary: &impl IsA<gtk::Window>,
        main_screen: &impl IsA<gtk::Widget>,
        secondary_screen: &impl IsA<gtk::Widget>,
        firmware: PathBuf,
        error: impl Fn(&str) + 'static,
    ) -> Option<Self> {
        if std::env::var("XDG_SESSION_TYPE").as_deref() == Ok("wayland")
            || gtk::prelude::WidgetExt::display(main.as_ref())
                .type_()
                .name()
                != "GdkX11Display"
        {
            return None;
        }
        let state = Rc::new(RefCell::new(State {
            placement: Placement::load(&firmware),
            main: None,
            secondary: None,
            pending_move: None,
            main_minimized: false,
            pending_save: None,
            saving: false,
            path: preference_path(&firmware),
            error: Box::new(error),
        }));
        let (main, secondary, main_screen, secondary_screen) = (
            main.as_ref().downgrade(),
            secondary.as_ref().downgrade(),
            main_screen.as_ref().downgrade(),
            secondary_screen.as_ref().downgrade(),
        );
        let owned = state.clone();
        let source = glib::timeout_add_local(Duration::from_millis(33), move || {
            let (Some(main), Some(secondary)) = (main.upgrade(), secondary.upgrade()) else {
                return glib::ControlFlow::Continue;
            };
            if !main.is_visible() || !secondary.is_visible() {
                let mut s = owned.borrow_mut();
                s.main = None;
                s.secondary = None;
                s.pending_move = None;
                return glib::ControlFlow::Continue;
            }
            let minimized = main
                .surface()
                .and_downcast::<gdk::Toplevel>()
                .is_some_and(|s| s.state().contains(gdk::ToplevelState::MINIMIZED));
            {
                let mut s = owned.borrow_mut();
                if s.placement.attached && minimized {
                    secondary.minimize();
                    s.main_minimized = true;
                    return glib::ControlFlow::Continue;
                }
                if s.main_minimized {
                    secondary.unminimize();
                    s.main_minimized = false;
                    s.pending_move = None;
                    s.main = None;
                    s.secondary = None;
                }
            }
            let (Some(main_lcd), Some(secondary_lcd)) =
                (main_screen.upgrade(), secondary_screen.upgrade())
            else {
                return glib::ControlFlow::Continue;
            };
            if !main_lcd.is_mapped()
                || !secondary_lcd.is_mapped()
                || main_lcd.width() <= 0
                || main_lcd.height() <= 0
                || secondary_lcd.width() <= 0
                || secondary_lcd.height() <= 0
            {
                return glib::ControlFlow::Continue;
            }
            let display = gtk::prelude::WidgetExt::display(&main);
            let Some(native) = Native::new(&display) else {
                return glib::ControlFlow::Continue;
            };
            let (Some(m), Some(s)) = (native.rect(&main), native.rect(&secondary)) else {
                return glib::ControlFlow::Continue;
            };
            let offset = |widget: Option<gtk::Widget>, window: &gtk::Window| {
                widget
                    .and_then(|w| w.compute_point(window, &graphene::Point::new(0., 0.)))
                    .map(|p| (p.y() * window.scale_factor() as f32).round() as i32)
                    .unwrap_or(0)
            };
            let y = m.y + offset(Some(main_lcd), &main) - offset(Some(secondary_lcd), &secondary);
            let threshold = 16 * main.scale_factor().max(1);
            let (movement, changed) = owned.borrow_mut().observe(
                m,
                s,
                y,
                threshold,
                native.dragging(s.xid),
                Instant::now(),
            );
            if let Some((x, y)) = movement {
                native.move_to(s, x, y);
            }
            if changed {
                persist(&owned);
            }
            glib::ControlFlow::Continue
        });
        Some(Self {
            source: Some(source),
            #[cfg(debug_assertions)]
            state,
        })
    }
    #[cfg(debug_assertions)]
    pub fn snapshot(&self) -> Value {
        let s = self.state.borrow();
        json!({"attached":s.placement.attached,"side":if s.placement.left {"left"}else{"right"},"main":s.main.map(Rect::json),"secondary":s.secondary.map(Rect::json)})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rect(x: i32, y: i32, width: i32, height: i32) -> Rect {
        Rect {
            xid: 1,
            x,
            y,
            width,
            height,
            inset_x: 0,
            inset_y: 0,
        }
    }
    fn state(main: Rect, secondary: Rect, attached: bool) -> State {
        State {
            placement: Placement {
                attached,
                left: true,
            },
            main: Some(main),
            secondary: Some(secondary),
            pending_move: None,
            main_minimized: false,
            pending_save: None,
            saving: false,
            path: PathBuf::new(),
            error: Box::new(|_| {}),
        }
    }
    #[test]
    fn quick_detach_survives_a_pending_move() {
        let now = Instant::now();
        let main = rect(400, 100, 384, 784);
        let secondary = rect(112, 100, 288, 238);
        let mut s = state(main, secondary, true);
        let moved_main = rect(500, 100, 384, 784);
        assert_eq!(
            s.observe(moved_main, secondary, 100, 16, false, now).0,
            Some((212, 100))
        );
        let dragged = rect(320, 200, 288, 238);
        assert_eq!(
            s.observe(
                moved_main,
                dragged,
                100,
                16,
                true,
                now + Duration::from_millis(30)
            ),
            (None, false)
        );
        assert_eq!(
            s.observe(
                moved_main,
                dragged,
                100,
                16,
                false,
                now + Duration::from_millis(200)
            ),
            (None, false)
        );
        assert_eq!(
            s.observe(
                moved_main,
                dragged,
                100,
                16,
                false,
                now + Duration::from_millis(401)
            ),
            (None, true)
        );
        assert!(!s.placement.attached);
    }
    #[test]
    fn an_anchor_correction_is_not_a_user_detach() {
        let now = Instant::now();
        let main = rect(400, 100, 384, 784);
        let secondary = rect(112, 100, 288, 238);
        let mut s = state(main, secondary, true);
        assert_eq!(
            s.observe(main, secondary, 146, 16, false, now).0,
            Some((112, 146))
        );
        let acknowledged = rect(112, 146, 288, 238);
        assert_eq!(
            s.observe(
                main,
                acknowledged,
                100,
                16,
                false,
                now + Duration::from_millis(33)
            ),
            (Some((112, 100)), false)
        );
        assert!(s.placement.attached);
    }
    #[test]
    fn resizing_a_floating_display_does_not_snap() {
        let now = Instant::now();
        let main = rect(400, 100, 384, 784);
        let secondary = rect(830, 130, 288, 238);
        let mut s = state(main, secondary, false);
        let resized = rect(792, 130, 348, 288);
        assert_eq!(s.observe(main, resized, 100, 16, false, now), (None, false));
        assert!(!s.placement.attached);
    }
    #[test]
    fn a_held_drag_can_cross_the_detach_distance() {
        let now = Instant::now();
        let main = rect(400, 100, 384, 784);
        let secondary = rect(112, 100, 288, 238);
        let mut s = state(main, secondary, true);
        assert_eq!(
            s.observe(main, rect(120, 100, 288, 238), 100, 16, true, now),
            (None, false)
        );
        assert!(s.placement.attached);
        assert_eq!(
            s.observe(
                main,
                rect(150, 100, 288, 238),
                100,
                16,
                true,
                now + Duration::from_millis(33)
            ),
            (None, true)
        );
        assert!(!s.placement.attached);
    }
}
