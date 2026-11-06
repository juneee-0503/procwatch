//! What a long-running service owes the system around it: telling the
//! service manager it is alive, saying why it is stopping, and answering
//! read-only questions.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);
static SIGNAL: AtomicI32 = AtomicI32::new(0);

/// Why the service should stop, once it should.
pub fn stop_requested() -> Option<String> {
    STOP.load(Ordering::Relaxed).then(|| match SIGNAL.load(Ordering::Relaxed) {
        0 => "stop requested".to_string(),
        n => format!("signal {n}"),
    })
}

#[cfg(windows)]
pub fn request_stop() {
    STOP.store(true, Ordering::Relaxed);
}

#[cfg(unix)]
pub fn catch_signals() {
    extern "C" fn on_signal(n: libc::c_int) {
        // Only this is safe here: the main loop does the rest.
        SIGNAL.store(n, Ordering::Relaxed);
        STOP.store(true, Ordering::Relaxed);
    }
    let handler = on_signal as extern "C" fn(libc::c_int) as usize;
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

#[cfg(windows)]
pub fn catch_signals() {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    unsafe extern "system" fn on_control(_: u32) -> i32 {
        STOP.store(true, Ordering::Relaxed);
        1
    }
    unsafe { SetConsoleCtrlHandler(Some(on_control), 1) };
}

/// Run under the Windows service manager: `main` does the work, and stops
/// when `stop_requested` says so.
#[cfg(windows)]
pub fn run_as_service(main: fn() -> i32) -> i32 {
    use std::sync::atomic::AtomicPtr;
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerW, SetServiceStatus, StartServiceCtrlDispatcherW, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    };
    static MAIN: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
    static HANDLE: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
    fn report(state: u32, exit: u32) {
        let accepts = if state == SERVICE_RUNNING { SERVICE_ACCEPT_STOP } else { 0 };
        let s = SERVICE_STATUS { dwServiceType: SERVICE_WIN32_OWN_PROCESS, dwCurrentState: state, dwControlsAccepted: accepts, dwWin32ExitCode: exit, dwServiceSpecificExitCode: 0, dwCheckPoint: 0, dwWaitHint: 10_000 };
        unsafe { SetServiceStatus(HANDLE.load(Ordering::Relaxed) as SERVICE_STATUS_HANDLE, &s) };
    }
    unsafe extern "system" fn control(code: u32) {
        if code == SERVICE_CONTROL_STOP {
            report(SERVICE_STOP_PENDING, 0);
            request_stop();
        }
    }
    unsafe extern "system" fn entry(_: u32, _: *mut *mut u16) {
        let name: Vec<u16> = "procwatch".encode_utf16().chain(Some(0)).collect();
        let handle = unsafe { RegisterServiceCtrlHandlerW(name.as_ptr(), Some(control)) };
        HANDLE.store(handle as *mut _, Ordering::Relaxed);
        report(SERVICE_RUNNING, 0);
        let main: fn() -> i32 = unsafe { std::mem::transmute(MAIN.load(Ordering::Relaxed)) };
        let code = main();
        // A non-zero exit makes the recovery settings restart the service.
        report(SERVICE_STOPPED, code as u32);
    }
    MAIN.store(main as *mut (), Ordering::Relaxed);
    let mut name: Vec<u16> = "procwatch".encode_utf16().chain(Some(0)).collect();
    let table = [SERVICE_TABLE_ENTRYW { lpServiceName: name.as_mut_ptr(), lpServiceProc: Some(entry) }, SERVICE_TABLE_ENTRYW { lpServiceName: std::ptr::null_mut(), lpServiceProc: None }];
    i32::from(unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0)
}

/// A message to systemd, if it is watching.
pub fn sd_notify(message: &str) {
    #[cfg(unix)]
    if let Some(path) = std::env::var_os("NOTIFY_SOCKET") {
        if let Ok(s) = std::os::unix::net::UnixDatagram::unbound() {
            let _ = s.send_to(message.as_bytes(), path);
        }
    }
    #[cfg(not(unix))]
    let _ = message;
}

/// Half systemd's watchdog interval, if it set one.
pub fn watchdog_period() -> Option<Duration> {
    std::env::var("WATCHDOG_USEC").ok()?.parse::<u64>().ok().map(|us| Duration::from_micros(us / 2))
}

/// Whether the core has done real work lately. The watchdog is fed only on
/// this, from the main loop: a thread that fed it regardless would keep a
/// dead service looking alive.
pub fn core_alive(modules: &[crate::kernel::ModuleStatus], before: &mut std::collections::HashMap<&'static str, (u64, Instant)>, now: Instant, limit: Duration) -> bool {
    use crate::kernel::ModuleState::{Degraded, Running};
    let mut alive = true;
    for m in modules.iter().filter(|m| matches!(m.name, "process" | "performance" | "defense") && matches!(m.state, Running | Degraded)) {
        let e = before.entry(m.name).or_insert((m.ticks, now));
        if m.ticks != e.0 {
            *e = (m.ticks, now);
        }
        alive &= now.duration_since(e.1) < limit;
    }
    alive
}

/// On Windows no service manager watches a process's heartbeat, so this
/// does: a main loop silent for too long ends the process, and the recovery
/// settings on the service restart it.
pub struct Watchdog(std::sync::Arc<std::sync::atomic::AtomicU64>);

impl Watchdog {
    pub fn start(limit: Duration) -> Watchdog {
        let beat = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let seen = beat.clone();
        let _ = std::thread::Builder::new().name("watchdog".into()).spawn(move || {
            let mut last = (0, Instant::now());
            loop {
                std::thread::sleep(limit / 4);
                let now = seen.load(Ordering::Relaxed);
                if now != last.0 {
                    last = (now, Instant::now());
                } else if last.1.elapsed() >= limit {
                    crate::common::audit::record("watchdog", "the main loop stopped; exiting so the service manager can restart");
                    std::process::abort();
                }
            }
        });
        Watchdog(beat)
    }

    pub fn feed(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg_attr(windows, allow(dead_code))]
/// One question to the read-only query interface. Input comes from another
/// process, so anything unexpected is refused, never acted on.
pub fn answer(question: &str, health: &crate::kernel::supervisor::Health) -> String {
    const MAX: usize = 64;
    if question.len() > MAX || !question.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
        return r#"{"v":1,"error":"bad request"}"#.to_string();
    }
    match question.trim() {
        "health" => serde_json::json!({ "v": 1, "health": health }).to_string(),
        "version" => serde_json::json!({ "v": 1, "version": env!("CARGO_PKG_VERSION"), "instance": &*crate::kernel::model::identity().instance }).to_string(),
        _ => r#"{"v":1,"error":"unknown question"}"#.to_string(),
    }
}

#[cfg(unix)]
pub fn query_path() -> Option<std::path::PathBuf> {
    crate::common::paths::data_dir().map(|d| d.join("query.sock"))
}

/// A Unix socket only this user and root may use, checked by the kernel's
/// word about who connected.
#[cfg(unix)]
pub fn serve_queries(kernel: crate::kernel::Kernel) {
    use std::io::{BufRead, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    let Some(path) = query_path() else { return };
    let _ = std::fs::remove_file(&path);
    let Ok(listener) = UnixListener::bind(&path) else { return };
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    let _ = std::thread::Builder::new().name("query".into()).spawn(move || {
        let me = unsafe { libc::geteuid() };
        for stream in listener.incoming().flatten() {
            if !peer_allowed(&stream, me) {
                continue;
            }
            let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let mut line = String::new();
            let limited = (&stream).take(128);
            if std::io::BufReader::new(limited).read_line(&mut line).is_ok() {
                let _ = writeln!(&stream, "{}", answer(line.trim_end(), &kernel.health()));
            }
        }
    });
}

#[cfg(all(unix, target_os = "linux"))]
fn peer_allowed(s: &std::os::unix::net::UnixStream, me: u32) -> bool {
    use std::os::fd::AsRawFd;
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&cred) as u32;
    let r = unsafe { libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &mut len) };
    r == 0 && (cred.uid == me || cred.uid == 0)
}

/// The socket's mode is the check here.
#[cfg(all(unix, not(target_os = "linux")))]
fn peer_allowed(_: &std::os::unix::net::UnixStream, _: u32) -> bool {
    true
}

/// `--query`.
pub fn ask(question: &str) -> i32 {
    #[cfg(unix)]
    {
        use std::io::{Read, Write};
        let Some(path) = query_path() else { return 2 };
        match std::os::unix::net::UnixStream::connect(&path) {
            Ok(mut s) => {
                let _ = writeln!(s, "{question}");
                let mut text = String::new();
                let _ = s.read_to_string(&mut text);
                print!("{text}");
                0
            }
            Err(e) => {
                eprintln!("procwatch: no agent to ask at {}: {e}", path.display());
                2
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = question;
        eprintln!("the query socket isn't available on this platform yet");
        2
    }
}

/// `--diagnose`: everything needed to understand a problem, with no secrets.
pub fn diagnose(path: &std::path::Path) -> i32 {
    use std::fmt::Write;
    let mut text = String::new();
    let _ = writeln!(text, "procwatch {} on {} {}", env!("CARGO_PKG_VERSION"), std::env::consts::OS, std::env::consts::ARCH);
    let _ = writeln!(text, "environment: {:?}", crate::common::environment::detect());
    let _ = writeln!(text, "program hash: {:?}", crate::common::integrity::program_hash());
    let _ = writeln!(text, "maintenance left: {:?}", crate::common::maintenance::remaining());
    let _ = writeln!(text, "\n[modules.conf]\n{}", crate::engine::load_config().serialize());
    match crate::defense::config::DefenseConfig::load() {
        Ok(mut c) => {
            // Addresses of webhooks are secrets.
            let n = c.alarms.len();
            c.alarms.clear();
            c.heartbeat.url.clear();
            c.sync.url.clear();
            c.exporter.token.clear();
            let _ = writeln!(text, "[defense.yml, {n} alarm destinations hidden]\n{}", serde_yaml::to_string(&c).unwrap_or_default());
        }
        Err(e) => {
            let _ = writeln!(text, "[defense.yml]\n{e}");
        }
    }
    let _ = writeln!(text, "\n[recent audit]");
    crate::common::audit::recent(100).iter().for_each(|l| {
        let _ = writeln!(text, "{l}");
    });
    match crate::common::paths::write_new(path, &text) {
        Ok(()) => {
            println!("Wrote {}", path.display());
            0
        }
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health() -> crate::kernel::supervisor::Health {
        crate::kernel::supervisor::Registry::default().boot(crate::kernel::Bus::default(), Default::default()).health()
    }

    /// T-12: malformed input is refused and nothing breaks.
    #[test]
    fn odd_questions_get_an_error_not_a_crash() {
        let h = health();
        assert!(answer("health", &h).contains("\"health\""));
        assert!(answer("version", &h).contains("version"));
        for bad in ["", "drop tables", "\0\0\0", &"x".repeat(100_000), "健康", "health\nversion"] {
            assert!(answer(bad, &h).contains("error"), "{bad:?}");
        }
    }

    #[test]
    fn the_watchdog_needs_real_work() {
        let m = |ticks| {
            let mut s = crate::kernel::supervisor::Registry::default().statuses();
            s.clear();
            let mut r = crate::kernel::supervisor::Registry::default();
            struct N;
            impl crate::kernel::Module for N {
                fn capabilities(&self) -> Vec<crate::kernel::Capability> {
                    Vec::new()
                }
            }
            r.add("process", "x", || Box::new(N));
            let mut one = r.statuses().remove(0);
            one.state = crate::kernel::ModuleState::Running;
            one.ticks = ticks;
            s.push(one);
            s
        };
        let (mut seen, t) = (std::collections::HashMap::new(), Instant::now());
        let limit = Duration::from_secs(30);
        assert!(core_alive(&m(1), &mut seen, t, limit));
        assert!(core_alive(&m(2), &mut seen, t + Duration::from_secs(29), limit));
        assert!(core_alive(&m(2), &mut seen, t + Duration::from_secs(58), limit));
        assert!(!core_alive(&m(2), &mut seen, t + Duration::from_secs(59), limit), "no progress for the whole limit");
    }
}
