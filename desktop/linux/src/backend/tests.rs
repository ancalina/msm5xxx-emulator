use super::*;
use std::{fs, time::SystemTime};

struct TestBundle(PathBuf);
impl TestBundle {
    fn new(stubborn: bool) -> Self {
        let root = PathBuf::from(
            std::env::var_os("TMPDIR").expect("Set TMPDIR for isolated tests"),
        )
        .join(format!(
            "linux-backend-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let package = root.join("src/msm5xxx_emulator");
        fs::create_dir_all(&package).unwrap();
        fs::write(package.join("__init__.py"), "").unwrap();
        let source = format!(
            r#"
import json, os, sys, time
from pathlib import Path
root=Path(__file__).resolve().parents[2]
for line in sys.stdin:
    request=json.loads(line)
    with (root/'requests').open('a') as log:
        log.write(request['method']+'\n')
    if request['method'] == 'hang':
        (root/'blocked').write_text(str(os.getpid()))
        time.sleep(60)
    # Shutdown must close stdin without waiting for a stop reply.
    if request['method'] != 'session.stop':
        print(json.dumps({{'id':request['id'],'result':None}}),flush=True)
(root/'eof').write_text(str(os.getpid()))
if {stubborn}:
    time.sleep(60)
"#,
            stubborn = if stubborn { "True" } else { "False" }
        );
        fs::write(package.join("backend.py"), source).unwrap();
        Self(root)
    }
    fn backend(&self) -> Backend {
        Backend::new(&Config {
            bundle: self.0.clone(),
            python: "python3".into(),
            qemu: "unused".into(),
            language: None,
        })
    }
}
impl Drop for TestBundle {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn close_sends_stop_then_eof_without_waiting_for_a_reply() {
    let fixture = TestBundle::new(false);
    let backend = fixture.backend();
    gtk::glib::MainContext::new().block_on(async {
        backend
            .call("session.open", json!({"firmware":"unused"}))
            .await
            .unwrap();
        backend.close().await.unwrap();
        assert!(backend.call("hello", json!({})).await.is_err());
    });
    assert_eq!(
        fs::read_to_string(fixture.0.join("requests")).unwrap(),
        "session.open\nsession.stop\n"
    );
    assert!(fixture.0.join("eof").is_file());
}

#[test]
fn unresponsive_backend_is_reaped_ten_seconds_after_eof() {
    let fixture = TestBundle::new(true);
    let backend = fixture.backend();
    let elapsed = gtk::glib::MainContext::new().block_on(async {
        backend
            .call("session.open", json!({"firmware":"unused"}))
            .await
            .unwrap();
        let start = Instant::now();
        let error = backend.close().await.unwrap_err();
        assert!(error.contains("10 seconds"), "{error}");
        start.elapsed()
    });
    assert!(elapsed >= Duration::from_millis(9900), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(30), "{elapsed:?}");
    let pid: i32 = fs::read_to_string(fixture.0.join("eof"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        unsafe { libc::kill(pid, 0) },
        -1,
        "Backend survived shutdown"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
}

#[test]
fn close_deadline_interrupts_an_already_blocked_rpc() {
    let fixture = TestBundle::new(false);
    let backend = fixture.backend();
    gtk::glib::MainContext::new().block_on(async {
        backend.call("session.open", json!({})).await.unwrap();
        let (sender, receiver) = oneshot::channel();
        backend.sender.send(Request::Call("hang".into(), json!({}), sender)).unwrap();
        let wait_until = Instant::now() + Duration::from_secs(5);
        while !fixture.0.join("blocked").is_file() {
            assert!(Instant::now() < wait_until, "Backend never entered the blocked RPC");
            thread::sleep(Duration::from_millis(10));
        }
        let start = Instant::now();
        let error = backend.close().await.unwrap_err();
        assert!(error.contains("10 seconds"), "{error}");
        assert!(start.elapsed() >= Duration::from_millis(9900));
        assert!(start.elapsed() < Duration::from_secs(20));
        assert!(receiver.await.unwrap().is_err());
    });
    let pid: i32 = fs::read_to_string(fixture.0.join("blocked")).unwrap().parse().unwrap();
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "Backend survived shutdown");
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
}
