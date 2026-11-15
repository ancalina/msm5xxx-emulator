use futures_channel::oneshot;
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    io::{BufRead, BufReader, Write},
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

pub type Reply = Result<Value, String>;
#[derive(Clone)]
pub struct Config {
    pub bundle: PathBuf,
    python: PathBuf,
    qemu: PathBuf,
    language: Option<OsString>,
}
impl Config {
    pub fn discover() -> Self {
        let exe = std::env::current_exe().unwrap_or_default();
        let bundle = std::env::var_os("MSM5XXX_BUNDLE")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                exe.parent()
                    .and_then(|p| p.parent())
                    .unwrap_or(std::path::Path::new("."))
                    .to_owned()
            });
        let python = std::env::var_os("MSM5XXX_PYTHON")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                [
                    bundle.join("python/bin/python3"),
                    bundle.join("python/python3"),
                    bundle.join("python/bin/python"),
                ]
                .into_iter()
                .find(|p| p.is_file())
                .unwrap_or_else(|| "python3".into())
            });
        let qemu = std::env::var_os("MSM5XXX_QEMU")
            .map(PathBuf::from)
            .unwrap_or_else(|| bundle.join("bin/qemu-system-arm"));
        Self {
            bundle,
            python,
            qemu,
            language: std::env::var_os("LANGUAGE"),
        }
    }
    fn spawn(&self) -> Result<Child, String> {
        let mut command = Command::new(&self.python);
        command.process_group(0);
        command
            .args(["-m", "msm5xxx_emulator.backend", "--qemu"])
            .arg(&self.qemu)
            .env("PYTHONPATH", self.bundle.join("src"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(language) = &self.language {
            command.env("LANGUAGE", language);
        }
        command
            .spawn()
            .map_err(|e| format!("{}: {e}", self.python.display()))
    }
}
enum Request {
    Call(String, Value, oneshot::Sender<Reply>),
    Close(oneshot::Sender<Reply>),
}
pub struct Backend {
    sender: mpsc::Sender<Request>,
}
impl Backend {
    pub fn new(config: &Config) -> Self {
        let (sender, receiver) = mpsc::channel();
        let config = config.clone();
        thread::spawn(move || run(config, receiver));
        Self { sender }
    }
    pub async fn call(&self, method: &str, params: Value) -> Reply {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Request::Call(method.into(), params, sender))
            .map_err(|_| "Backend connection closed".to_owned())?;
        receiver
            .await
            .map_err(|_| "Backend connection closed".to_owned())?
    }
    pub async fn close(&self) -> Reply {
        let (sender, receiver) = oneshot::channel();
        if self.sender.send(Request::Close(sender)).is_err() {
            return Ok(Value::Null);
        }
        receiver
            .await
            .map_err(|_| "Backend connection closed".to_owned())?
    }
}
fn finish(child: &mut Child) -> Result<(), String> {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(format!("Backend exited: {status}"))
                };
            }
            Err(error) => return Err(error.to_string()),
            _ => {}
        }
        if Instant::now() >= until {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    // The backend and QEMU share a dedicated process group.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
    Err("Backend did not exit within 10 seconds".into())
}

fn run(config: Config, receiver: mpsc::Receiver<Request>) {
    let mut child = match config.spawn() {
        Ok(child) => child,
        Err(error) => {
            for request in receiver {
                match request {
                    Request::Call(_, _, reply) => {
                        let _ = reply.send(Err(error.clone()));
                    }
                    Request::Close(reply) => {
                        let _ = reply.send(Ok(Value::Null));
                        break;
                    }
                }
            }
            return;
        }
    };
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut id = 0u64;
    let mut session = false;
    #[cfg(debug_assertions)]
    let mut trace = std::env::var_os("MSM5XXX_TRACE").and_then(|p| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .ok()
    });
    #[cfg(debug_assertions)]
    let epoch = Instant::now();
    let mut transact = |method: &str, params: Value| -> Reply {
        id += 1;
        let request = json!({"id":id,"method":method,"params":params});
        serde_json::to_writer(&mut input, &request).map_err(|e| e.to_string())?;
        input
            .write_all(b"\n")
            .and_then(|_| input.flush())
            .map_err(|e| e.to_string())?;
        let mut line = String::new();
        if output.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Err("Backend process exited".into());
        }
        let value: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        if value["id"] != id {
            return Err("Backend response ID mismatch".into());
        }
        #[cfg(debug_assertions)]
        if let Some(trace) = trace.as_mut() {
            let mut summary = value.clone();
            if method == "session.frame"
                && let Some(v) = summary["result"].as_object_mut()
            {
                v.remove("rgb");
                if let Some(s) = v.get_mut("secondary").and_then(Value::as_object_mut) {
                    s.remove("rgb");
                }
            }
            let _ = writeln!(
                trace,
                "{} {} {} {}",
                child.id(),
                epoch.elapsed().as_millis(),
                request,
                summary
            );
        }
        if let Some(error) = value.get("error") {
            Err(error["message"]
                .as_str()
                .unwrap_or("Backend error")
                .to_owned())
        } else {
            Ok(value["result"].clone())
        }
    };
    for request in receiver {
        match request {
            Request::Call(method, params, reply) => {
                let result = transact(&method, params);
                if method == "session.open" && result.is_ok() {
                    session = true;
                }
                let _ = reply.send(result);
            }
            Request::Close(reply) => {
                let sent = if session {
                    id += 1;
                    let request = json!({"id":id,"method":"session.stop","params":{}});
                    serde_json::to_writer(&mut input, &request)
                        .map_err(|e| e.to_string())
                        .and_then(|_| {
                            input
                                .write_all(b"\n")
                                .and_then(|_| input.flush())
                                .map_err(|e| e.to_string())
                        })
                } else {
                    Ok(())
                };
                // EOF initiates graceful shutdown even if the stop reply is delayed.
                drop(input);
                let exited = finish(&mut child);
                let result = sent.and(exited).map(|_| Value::Null);
                let _ = reply.send(result);
                return;
            }
        }
    }
    drop(input);
    let _ = finish(&mut child);
}

#[cfg(test)]
mod tests;
