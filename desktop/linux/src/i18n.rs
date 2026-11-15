use std::{cell::Cell, ffi::CString, path::Path};
thread_local! { static ACTIVE_LOCALE: Cell<libc::locale_t> = const { Cell::new(std::ptr::null_mut()) }; }
unsafe extern "C" {
    fn bindtextdomain(domain: *const libc::c_char, dir: *const libc::c_char) -> *mut libc::c_char;
    fn bind_textdomain_codeset(
        domain: *const libc::c_char,
        encoding: *const libc::c_char,
    ) -> *mut libc::c_char;
}
pub fn init(bundle: &Path) {
    let bundled = bundle.join("share/locale");
    let path = if bundled.is_dir() {
        bundled
    } else {
        Path::new(env!("MSM5XXX_BUILD_LOCALE")).into()
    };
    let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    unsafe {
        libc::setlocale(libc::LC_ALL, c"".as_ptr());
        bindtextdomain(c"msm5xxx".as_ptr(), path.as_ptr());
        bind_textdomain_codeset(c"msm5xxx".as_ptr(), c"UTF-8".as_ptr());
    }
}
#[derive(Clone)]
pub struct Text {
    pub language: String,
}
impl Text {
    pub fn new(language: &str) -> Self {
        Self {
            language: language.to_owned(),
        }
    }
    pub fn activate(&self) {
        let name = if self.language == "ko" {
            c"ko_KR.UTF-8"
        } else {
            c"C.UTF-8"
        };
        unsafe {
            let locale =
                libc::newlocale(libc::LC_MESSAGES_MASK, name.as_ptr(), std::ptr::null_mut());
            if locale.is_null() {
                return;
            }
            libc::uselocale(locale);
            ACTIVE_LOCALE.with(|active| {
                let previous = active.replace(locale);
                if !previous.is_null() {
                    libc::freelocale(previous);
                }
            });
        }
    }
    pub fn tr(&self, message: &str) -> String {
        let name = if self.language == "ko" {
            c"ko_KR.UTF-8"
        } else {
            c"C.UTF-8"
        };
        unsafe {
            let locale =
                libc::newlocale(libc::LC_MESSAGES_MASK, name.as_ptr(), std::ptr::null_mut());
            if locale.is_null() {
                return message.to_owned();
            }
            let previous = libc::uselocale(locale);
            let result = gtk::glib::dgettext(Some("msm5xxx"), message).to_string();
            libc::uselocale(previous);
            libc::freelocale(locale);
            result
        }
    }
}
