use std::{env, path::PathBuf, process::Command};
fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let icons = out.ancestors().nth(3).unwrap().join("msm5xxx-icons");
    let platform = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "x86_64" => "LNX X64",
        "aarch64" => "LNX A64",
        _ => panic!("The icon generator needs a platform marking for this architecture"),
    };
    assert!(
        Command::new("python3")
            .args(["branding/chip_icon.py", "--platform", platform, "--out"])
            .arg(&icons)
            .status()
            .expect("Install Python 3")
            .success()
    );
    let id = "io.github.ancalina.MSM5xxx";
    for (source, suffix) in [
        ("full", ""),
        ("small", "-simple"),
        ("small-marking", "-symbolic"),
    ] {
        std::fs::copy(
            icons.join(format!("{source}.svg")),
            icons.join(format!("{id}{suffix}.svg")),
        )
        .unwrap();
    }
    for size in [16, 32, 48, 64, 128, 256, 512] {
        let directory = icons.join(format!("hicolor/{size}x{size}/apps"));
        std::fs::create_dir_all(&directory).unwrap();
        gdk_pixbuf::Pixbuf::from_file_at_scale(icons.join("full.svg"), size, size, true)
            .expect("GTK SVG image loader")
            .savev(directory.join(format!("{id}.png")), "png", &[])
            .expect("GTK PNG image writer");
    }
    let xml = format!(
        "<gresources><gresource prefix=\"/io/github/ancalina/MSM5xxx/icons/scalable/apps\">\
        <file>{id}.svg</file><file>{id}-simple.svg</file><file>{id}-symbolic.svg</file>\
        </gresource></gresources>"
    );
    std::fs::write(icons.join("resources.gresource.xml"), xml).unwrap();
    println!("cargo:rerun-if-changed=branding");
    println!("cargo:rerun-if-changed=../../.git");
    println!("cargo:rerun-if-changed=../../pyproject.toml");
    let branch = Command::new("git")
        .args(["symbolic-ref", "-q", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    for path in ["HEAD", &branch] {
        if let Ok(output) = Command::new("git")
            .args(["rev-parse", "--git-path", path])
            .output()
            && output.status.success()
        {
            println!(
                "cargo:rerun-if-changed={}",
                String::from_utf8_lossy(&output.stdout).trim()
            );
        }
    }
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let locale = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("locale");
    let dir = locale.join("ko/LC_MESSAGES");
    std::fs::create_dir_all(&dir).unwrap();
    assert!(
        Command::new("msgfmt")
            .args(["--check", "po/ko.po", "-o"])
            .arg(dir.join("msm5xxx.mo"))
            .status()
            .expect("Install gettext (msgfmt)")
            .success()
    );
    println!("cargo:rustc-env=MSM5XXX_BUILD_LOCALE={}", locale.display());
    println!("cargo:rerun-if-changed=po/ko.po");
    let resource = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("icons.gresource");
    assert!(
        Command::new("glib-compile-resources")
            .arg(format!("--sourcedir={}", icons.display()))
            .arg("--target")
            .arg(resource)
            .arg(icons.join("resources.gresource.xml"))
            .status()
            .expect("Install GLib development tools")
            .success()
    );
    println!("cargo:rerun-if-changed=data");
}
