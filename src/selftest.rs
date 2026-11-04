//! `procwatch --selftest`: measured quality of this build on this machine,
//! using only harmless workloads (`sh`, `sleep`, temporary files).
//!
//! - process capture: how many short-lived children periodic sampling and
//!   deep trace each see, by child lifetime
//! - event order: spawn ≤ exec ≤ exit for every traced child
//! - PID-reuse protection: an action aimed at a stale (pid, start) pair
//!   must be refused and leave the process alone
//! - file-change latency in a watched folder
//! - procwatch's own CPU and memory while sampling

use std::collections::HashMap;
#[cfg(unix)]
use std::collections::HashSet;
use std::time::{Duration, Instant};

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Capture {
    pub lifetime: String,
    pub launched: usize,
    pub sampled: usize,
    pub deep_trace: usize,
}

#[derive(Debug, Serialize, Default)]
pub struct Report {
    pub platform: String,
    pub verification: String,
    pub sampling_interval_ms: u64,
    pub deep_trace_method: String,
    pub capture: Vec<Capture>,
    pub order_violations: usize,
    pub pid_reuse_refused: Option<bool>,
    pub pid_reuse_target_survived: Option<bool>,
    pub checked_action_worked: Option<bool>,
    pub file_event_latency_ms: Option<u64>,
    pub own_cpu_percent: Option<f32>,
    pub own_memory_mb: Option<f64>,
    /// What each capture source saw of a known workload.
    pub activity: Vec<String>,
    pub notes: Vec<String>,
}

#[cfg(unix)]
const LIFETIMES: [&str; 4] = ["0", "0.05", "0.3", "2"];
#[cfg(unix)]
const PER_LIFETIME: usize = 4;

pub fn platform_status() -> (&'static str, &'static str) {
    if cfg!(target_os = "macos") {
        ("macOS", "verified on a real system (interactive and automated tests)")
    } else if cfg!(target_os = "linux") {
        ("Linux", "unit tests, self-test and soak run in CI; not yet used interactively on a real system")
    } else if cfg!(windows) {
        ("Windows", "unit tests, self-test and soak run in CI (Windows Server); not yet used interactively on a real system")
    } else {
        ("other", "unsupported")
    }
}

#[cfg(unix)]
fn capture(r: &mut Report) {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    // One parent runs children of each lifetime in sequence.
    // The first sleep gives the watcher time to attach before measuring.
    let script: String = "sleep 0.4; ".to_string() + &LIFETIMES.iter().map(|d| format!("for i in 1 2 3 4; do sleep {d}; done; ")).collect::<String>() + "sleep 0.2";
    let (tx, rx) = std::sync::mpsc::channel();
    let Some(w) = crate::deeptrace::Watcher::start(tx) else {
        r.notes.push("deep trace watcher could not start".into());
        return;
    };
    r.deep_trace_method = w.method().into();
    let mut parent = match std::process::Command::new("/bin/sh").args(["-c", &script]).spawn() {
        Ok(p) => p,
        Err(e) => {
            r.notes.push(format!("couldn't start the test workload: {e}"));
            return;
        }
    };
    let ppid = parent.id();
    w.watch(ppid);
    // Sampling, as the main view does it.
    let interval = Duration::from_millis(r.sampling_interval_ms);
    let mut sys = System::new();
    let mut sampled: HashMap<u32, String> = HashMap::new();
    let refresh = ProcessRefreshKind::new().with_cmd(UpdateKind::Always);
    let started = Instant::now();
    loop {
        sys.refresh_processes_specifics(ProcessesToUpdate::All, refresh);
        for (pid, p) in sys.processes() {
            if p.parent().map(|x| x.as_u32()) == Some(ppid) {
                let cmd: Vec<String> = p.cmd().iter().map(|s| s.to_string_lossy().into_owned()).collect();
                sampled.insert(pid.as_u32(), cmd.join(" "));
            }
        }
        if parent.try_wait().ok().flatten().is_some() || started.elapsed() > Duration::from_secs(60) {
            break;
        }
        std::thread::sleep(interval);
    }
    let _ = parent.wait();
    // Deep-trace events.
    let mut deep: Vec<crate::deeptrace::DtEvent> = Vec::new();
    let until = Instant::now() + Duration::from_millis(800);
    while Instant::now() < until {
        if let Ok(crate::sampler::WorkerMsg::Deep(evs)) = rx.recv_timeout(Duration::from_millis(100)) {
            deep.extend(evs);
        }
    }
    // Final command line per traced child.
    let mut final_args: HashMap<u32, String> = HashMap::new();
    for e in deep.iter().filter(|e| e.kind != crate::deeptrace::DtKind::Exit) {
        if let Some(a) = &e.args {
            final_args.insert(e.pid, a.clone());
        }
    }
    let spawned: HashSet<u32> = deep.iter().filter(|e| e.kind == crate::deeptrace::DtKind::Spawn && e.ppid == Some(ppid)).map(|e| e.pid).collect();
    for d in LIFETIMES {
        let want = format!("sleep {d}");
        let s = sampled.values().filter(|c| c.trim() == want).count();
        let t = spawned.iter().filter(|p| final_args.get(p).is_some_and(|a| a.trim() == want)).count();
        // Children whose exec we didn't see still count as captured spawns,
        // just unnamed; attribute them by order below.
        r.capture.push(Capture { lifetime: format!("{} ms", (d.parse::<f64>().unwrap_or(0.0) * 1000.0) as u64), launched: PER_LIFETIME, sampled: s, deep_trace: t });
    }
    let unnamed = spawned.iter().filter(|p| !final_args.get(p).is_some_and(|a| a.starts_with("sleep"))).count();
    if unnamed > 0 {
        r.notes.push(format!("{unnamed} child process(es) were seen by deep trace but exited before their command line could be read"));
    }
    // Order: per pid, spawn ≤ exec ≤ exit.
    let mut seen: HashMap<u32, Vec<&crate::deeptrace::DtEvent>> = HashMap::new();
    for e in &deep {
        seen.entry(e.pid).or_default().push(e);
    }
    for evs in seen.values() {
        let rank = |k: crate::deeptrace::DtKind| match k {
            crate::deeptrace::DtKind::Spawn => 0,
            crate::deeptrace::DtKind::Exec => 1,
            crate::deeptrace::DtKind::Exit => 2,
        };
        for w in evs.windows(2) {
            if rank(w[1].kind) < rank(w[0].kind) || w[1].at < w[0].at {
                r.order_violations += 1;
            }
        }
    }
}

#[cfg(unix)]
fn pid_reuse(r: &mut Report) {
    use crate::process::actions::{apply_checked, process_exists, Action, Outcome, Sig};
    let Ok(mut child) = std::process::Command::new("/bin/sleep").arg("30").spawn() else { return };
    let pid = child.id();
    std::thread::sleep(Duration::from_millis(200));
    let Some(start) = crate::process::native::start_time(pid) else {
        r.notes.push("couldn't read the test process's start time".into());
        let _ = child.kill();
        return;
    };
    // Pretend we selected a different, older process that had this PID.
    let stale = apply_checked(pid, start.saturating_sub(3600), Action::Signal(Sig::Term));
    r.pid_reuse_refused = Some(matches!(stale, Outcome::PidReused { .. }));
    r.pid_reuse_target_survived = Some(process_exists(pid) && child.try_wait().ok().flatten().is_none());
    let ok = apply_checked(pid, start, Action::Signal(Sig::Term));
    let _ = child.wait();
    r.checked_action_worked = Some(ok == Outcome::Done);
}

/// Windows: a cmd.exe parent starting four `cmd /c exit` children (tens of
/// milliseconds each) and two `ping -n 3 127.0.0.1` (~2 s each), after a
/// first ping that gives the watcher time to attach.
#[cfg(windows)]
fn capture_windows(r: &mut Report) {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let (tx, rx) = std::sync::mpsc::channel();
    let Some(w) = crate::deeptrace::Watcher::start(tx) else {
        r.notes.push("deep trace watcher could not start".into());
        return;
    };
    r.deep_trace_method = w.method().into();
    let script = "ping -n 2 127.0.0.1 >NUL & cmd /c exit & cmd /c exit & cmd /c exit & cmd /c exit & ping -n 3 127.0.0.1 >NUL & ping -n 3 127.0.0.1 >NUL";
    let mut parent = match std::process::Command::new("cmd").args(["/C", script]).stdout(std::process::Stdio::null()).spawn() {
        Ok(p) => p,
        Err(e) => {
            r.notes.push(format!("couldn't start the test workload: {e}"));
            return;
        }
    };
    let ppid = parent.id();
    w.watch(ppid);
    let interval = Duration::from_millis(r.sampling_interval_ms);
    let mut sys = System::new();
    let mut sampled: HashMap<u32, String> = HashMap::new();
    let started = Instant::now();
    loop {
        sys.refresh_processes_specifics(ProcessesToUpdate::All, ProcessRefreshKind::new());
        for (pid, p) in sys.processes() {
            if p.parent().map(|x| x.as_u32()) == Some(ppid) {
                sampled.insert(pid.as_u32(), p.name().to_string_lossy().to_lowercase());
            }
        }
        if parent.try_wait().ok().flatten().is_some() || started.elapsed() > Duration::from_secs(60) {
            break;
        }
        std::thread::sleep(interval);
    }
    let mut deep: Vec<crate::deeptrace::DtEvent> = Vec::new();
    let until = Instant::now() + Duration::from_millis(800);
    while Instant::now() < until {
        if let Ok(crate::sampler::WorkerMsg::Deep(evs)) = rx.recv_timeout(Duration::from_millis(100)) {
            deep.extend(evs);
        }
    }
    let spawned: HashMap<u32, String> = deep
        .iter()
        .filter(|e| e.kind == crate::deeptrace::DtKind::Spawn && e.ppid == Some(ppid))
        .map(|e| (e.pid, e.path.as_deref().and_then(|p| p.rsplit('\\').next()).unwrap_or("").to_lowercase()))
        .collect();
    let count = |m: &HashMap<u32, String>, n: &str| m.values().filter(|v| v.as_str() == n).count();
    r.capture.push(Capture { lifetime: "~30 ms (cmd)".into(), launched: 4, sampled: count(&sampled, "cmd.exe"), deep_trace: count(&spawned, "cmd.exe") });
    r.capture.push(Capture { lifetime: "1–2 s (ping)".into(), launched: 3, sampled: count(&sampled, "ping.exe"), deep_trace: count(&spawned, "ping.exe") });
    let unnamed = spawned.values().filter(|v| v.is_empty()).count();
    if unnamed > 0 {
        r.notes.push(format!("{unnamed} child process(es) were seen by deep trace but exited before their image path could be read"));
    }
}

#[cfg(windows)]
fn pid_reuse_windows(r: &mut Report) {
    use crate::process::actions::{apply_checked, process_exists, Action, Outcome, Sig};
    let Ok(mut child) = std::process::Command::new("ping").args(["-n", "30", "127.0.0.1"]).stdout(std::process::Stdio::null()).spawn() else { return };
    let pid = child.id();
    std::thread::sleep(Duration::from_millis(300));
    let Some(start) = crate::process::native::start_time(pid) else {
        r.notes.push("couldn't read the test process's start time".into());
        let _ = child.kill();
        return;
    };
    let stale = apply_checked(pid, start.saturating_sub(3600), Action::Signal(Sig::Kill));
    r.pid_reuse_refused = Some(matches!(stale, Outcome::PidReused { .. }));
    r.pid_reuse_target_survived = Some(process_exists(pid) && child.try_wait().ok().flatten().is_none());
    let ok = apply_checked(pid, start, Action::Signal(Sig::Kill));
    let _ = child.wait();
    r.checked_action_worked = Some(ok == Outcome::Done);
}

fn file_latency(r: &mut Report) {
    let dir = std::env::temp_dir().join(format!("procwatch-selftest-{}", std::process::id()));
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let (_w, errors) = crate::fswatch::start(&[dir.display().to_string()], tx);
    if !errors.is_empty() {
        r.notes.push(format!("file watch: {}", errors.join("; ")));
    }
    std::thread::sleep(Duration::from_millis(300));
    let f = dir.join("probe.txt");
    let t0 = Instant::now();
    let _ = std::fs::write(&f, b"selftest");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(crate::sampler::WorkerMsg::Fs(e)) = rx.recv_timeout(Duration::from_millis(50)) {
            if e.path.ends_with("probe.txt") {
                r.file_event_latency_ms = Some(t0.elapsed().as_millis() as u64);
                break;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A child does the work: a capture ignores procwatch's own operations.
fn activity_workload(dir: &std::path::Path) {
    #[cfg(unix)]
    let _ = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("cd \"$1\" && echo x > a.txt && echo y >> a.txt && cat a.txt > /dev/null && mv a.txt b.txt && rm b.txt")
        .arg("sh")
        .arg(dir)
        .status();
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd").args(["/C", "echo x> a.txt & type a.txt > NUL & ren a.txt b.txt & del b.txt"]).current_dir(dir).status();
        let key = r"HKCU\Software\procwatch-selftest";
        let _ = std::process::Command::new("reg").args(["add", key, "/v", "probe", "/d", "1", "/f"]).stdout(std::process::Stdio::null()).status();
        let _ = std::process::Command::new("reg").args(["delete", key, "/f"]).stdout(std::process::Stdio::null()).status();
    }
}

fn activity_probe(r: &mut Report) {
    use crate::activity::Class;
    let dir = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir()).join(format!("procwatch-selftest-activity-{}", std::process::id()));
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    match crate::activity::start(tx) {
        Err(e) => r.activity.push(format!("capture: not available ({e})")),
        Ok(c) => {
            std::thread::sleep(Duration::from_millis(700));
            activity_workload(&dir);
            let mut ops: std::collections::BTreeMap<String, u32> = Default::default();
            let needle = dir.display().to_string().to_lowercase();
            let until = Instant::now() + Duration::from_secs(3);
            let mut unnamed: Vec<String> = Vec::new();
            while Instant::now() < until {
                if let Ok(crate::sampler::WorkerMsg::Activity(batch)) = rx.recv_timeout(Duration::from_millis(100)) {
                    for a in batch {
                        let path = a.path.to_lowercase();
                        let ours = path.contains(&needle) || path.contains("procwatch-selftest") || path.ends_with("a.txt") || path.ends_with("b.txt");
                        if ours && matches!(a.class, Class::File | Class::Registry) {
                            *ops.entry(format!("{} {}", a.class.label(), a.op)).or_default() += a.count;
                        }
                        // Operations with a poor name say more than any count.
                        if !path.contains('/') && !path.contains('\\') && unnamed.len() < 4 {
                            unnamed.push(format!("{} '{}'", a.op, a.path));
                        }
                    }
                }
            }
            if !unnamed.is_empty() {
                r.activity.push(format!("operations without a full path: {}", unnamed.join(", ")));
            }
            r.activity.push(format!("capture via {}: {}", c.method, if ops.is_empty() { "saw nothing of the workload".to_string() } else { ops.iter().map(|(k, n)| format!("{k} ×{n}")).collect::<Vec<_>>().join(", ") }));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Accuracy on real traffic, when CI names a file of known size to fetch.
fn traffic_download_probe(r: &mut Report) {
    let Ok(url) = std::env::var("PW_SELFTEST_URL") else { return };
    let (tx, rx) = std::sync::mpsc::channel();
    let Ok(t) = crate::netio::start(tx) else { return };
    std::thread::sleep(Duration::from_millis(500));
    let dest = std::env::temp_dir().join(format!("procwatch-selftest-download-{}", std::process::id()));
    // The pause keeps the socket around for counters that end with it.
    let spawned = std::process::Command::new("curl").args(["-s", "-L", "--max-time", "30", "-o"]).arg(&dest).arg(&url).spawn();
    let Ok(mut child) = spawned else { return };
    let pid = child.id();
    let mut seen = (0, 0);
    let until = Instant::now() + Duration::from_secs(12);
    while Instant::now() < until {
        if let Ok(crate::sampler::WorkerMsg::Traffic(m)) = rx.recv_timeout(Duration::from_millis(200)) {
            if let Some(v) = m.get(&pid) {
                seen = *v;
            }
        }
    }
    let _ = child.wait();
    let size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
    let _ = std::fs::remove_file(&dest);
    r.activity.push(format!("traffic via {} on a real download: file {size} bytes, counted {} in, {} out", t.method, seen.0, seen.1));
}

fn traffic_probe(r: &mut Report) {
    use std::io::{Read, Write};
    const SIZE: usize = 4 << 20;
    let (tx, rx) = std::sync::mpsc::channel();
    let t = match crate::netio::start(tx) {
        Ok(t) => t,
        Err(e) => {
            r.activity.push(format!("traffic: not available ({e})"));
            return;
        }
    };
    let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:0") else { return };
    let Ok(addr) = listener.local_addr() else { return };
    let writer = std::thread::spawn(move || {
        if let Ok(mut c) = std::net::TcpStream::connect(addr) {
            let _ = c.write_all(&vec![0u8; SIZE]);
            // Held open: a closed socket is gone from per-socket counters.
            std::thread::sleep(Duration::from_secs(5));
        }
    });
    // Held open too: per-socket counters end with the socket.
    let mut _reader = None;
    if let Ok((mut c, _)) = listener.accept() {
        let mut buf = vec![0u8; 1 << 16];
        let mut got = 0;
        while got < SIZE {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
        _reader = Some(c);
    }
    let me = std::process::id();
    let mut seen = (0, 0);
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        if let Ok(crate::sampler::WorkerMsg::Traffic(m)) = rx.recv_timeout(Duration::from_millis(200)) {
            if let Some(v) = m.get(&me) {
                seen = *v;
            }
        }
    }
    let _ = writer.join();
    r.activity.push(format!("traffic via {}: {} MiB moved over loopback, counted {:.1} MiB in, {:.1} MiB out", t.method, SIZE >> 20, seen.0 as f64 / 1_048_576.0, seen.1 as f64 / 1_048_576.0));
}

/// A throwaway folder with a canonical path: rules match resolved paths.
fn enforce_dir() -> Option<std::path::PathBuf> {
    let d = std::env::current_dir().ok()?.join(format!("procwatch-selftest-enforce-{}", std::process::id()));
    std::fs::create_dir_all(&d).ok()?;
    std::fs::canonicalize(d).ok()
}

/// Ending a process after it starts, on every platform.
fn enforce_kill_probe(r: &mut Report) {
    use crate::enforce::{self, Policy};
    let Some(dir) = enforce_dir() else { return };
    #[cfg(unix)]
    let (original, name, args) = ("/bin/sleep", "pw-selftest-victim", vec!["20"]);
    #[cfg(windows)]
    let (original, name, args) = ("C:\\Windows\\System32\\ping.exe", "pw-selftest-victim.exe", vec!["-n", "20", "127.0.0.1"]);
    let victim = dir.join(name);
    if std::fs::copy(original, &victim).is_err() {
        return;
    }
    let text = format!("mode: enforce\nrules:\n  - {{ id: t, on: start, action: kill, path: ['{}'] }}\n", victim.display());
    let policy = match Policy::parse(&text) {
        Ok(p) => p,
        Err(e) => {
            r.activity.push(format!("enforce kill: policy refused ({e})"));
            return;
        }
    };
    let (tx, rx) = std::sync::mpsc::channel();
    match enforce::start(policy, tx) {
        Err(e) => r.activity.push(format!("enforce kill: not available ({e})")),
        Ok(run) => {
            std::thread::sleep(Duration::from_millis(1500));
            let t = Instant::now();
            if let Ok(mut c) = std::process::Command::new(&victim).args(&args).stdout(std::process::Stdio::null()).spawn() {
                let mut ended = false;
                while t.elapsed() < Duration::from_secs(8) {
                    if matches!(c.try_wait(), Ok(Some(_))) {
                        ended = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let took = t.elapsed();
                let _ = c.kill();
                let _ = c.wait();
                r.activity.push(format!("enforce kill: running process ended: {} after {} ms; decision logged: {}", ended, took.as_millis(), rx.try_recv().is_ok()));
            }
            drop(run);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Real prevention of exec on Linux, as root.
#[cfg(target_os = "linux")]
fn enforce_block_probe(r: &mut Report) {
    use crate::enforce::{self, Policy};
    if unsafe { libc::geteuid() } != 0 {
        r.activity.push("enforce block: needs root".into());
        return;
    }
    let Some(dir) = enforce_dir() else { return };
    let (blocked, allowed) = (dir.join("blocked"), dir.join("allowed"));
    if std::fs::copy("/bin/true", &blocked).is_err() || std::fs::copy("/bin/true", &allowed).is_err() {
        return;
    }
    let run_one = |mode: &str| -> Result<(bool, bool, usize), String> {
        let text = format!("mode: {mode}\nrules:\n  - {{ id: t, on: exec, action: block, path: ['{}'] }}\n", blocked.display());
        let (tx, rx) = std::sync::mpsc::channel();
        let run = enforce::start(Policy::parse(&text)?, tx)?;
        std::thread::sleep(Duration::from_millis(300));
        let ran = |p: &std::path::Path| std::process::Command::new(p).status().is_ok_and(|s| s.success());
        let (b, a) = (ran(&blocked), ran(&allowed));
        drop(run);
        std::thread::sleep(Duration::from_millis(400));
        Ok((b, a, rx.try_iter().count()))
    };
    for mode in ["audit", "enforce"] {
        match run_one(mode) {
            Ok((b, a, n)) => r.activity.push(format!("enforce block ({mode}): matching program ran: {b}; other program ran: {a}; decisions logged: {n}")),
            Err(e) => r.activity.push(format!("enforce block ({mode}): {e}")),
        }
    }
    let after = std::process::Command::new(&blocked).status().is_ok_and(|s| s.success());
    r.activity.push(format!("enforce block: runs again once enforcement ends: {after}"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Real prevention of connections on Windows, as administrator.
#[cfg(windows)]
fn enforce_block_probe(r: &mut Report) {
    use crate::enforce::{self, Policy};
    let curl = "C:\\Windows\\System32\\curl.exe";
    let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:0") else { return };
    let Ok(addr) = listener.local_addr() else { return };
    let _ = listener.set_nonblocking(true);
    let url = format!("http://{addr}/");
    // Accepting is enough for curl to connect; it then times out on the reply.
    let connected = |l: &std::net::TcpListener| -> bool {
        let _ = std::process::Command::new(curl).args(["-s", "--max-time", "2", &url]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
        l.accept().is_ok()
    };
    let before = connected(&listener);
    let text = format!("mode: enforce\nrules:\n  - {{ id: t, on: connect, action: block, path: ['{curl}'] }}\n");
    let (tx, _rx) = std::sync::mpsc::channel();
    let policy = match Policy::parse(&text) {
        Ok(p) => p,
        Err(e) => {
            r.activity.push(format!("enforce block: policy refused ({e})"));
            return;
        }
    };
    match enforce::start(policy, tx) {
        Err(e) => r.activity.push(format!("enforce block: not available ({e})")),
        Ok(run) => {
            let during = connected(&listener);
            drop(run);
            std::thread::sleep(Duration::from_millis(300));
            let after = connected(&listener);
            r.activity.push(format!("enforce block: curl connected before: {before}; with the filter: {during}; after it ended: {after}"));
        }
    }
}

#[cfg(windows)]
fn handle_probe(r: &mut Report) {
    let path = std::env::temp_dir().join(format!("procwatch-handle-probe-{}", std::process::id()));
    let Ok(_held) = std::fs::File::create(&path) else { return };
    let me = std::process::id();
    let t = Instant::now();
    let mine = crate::handles::for_process(me);
    let took = t.elapsed();
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    match mine {
        Ok(items) => r.activity.push(format!("handles: {} named in this process in {} ms; held test file found: {}", items.len(), took.as_millis(), items.iter().any(|i| i.name.contains(&name)))),
        Err(e) => r.activity.push(format!("handles: {e}")),
    }
    let mut child = match std::process::Command::new("ping").args(["-n", "6", "127.0.0.1"]).stdout(std::process::Stdio::null()).spawn() {
        Ok(c) => c,
        Err(_) => return,
    };
    std::thread::sleep(Duration::from_millis(300));
    match crate::handles::for_process(child.id()) {
        Ok(items) => {
            let kinds: std::collections::BTreeSet<&str> = items.iter().map(|i| i.kind.as_str()).collect();
            r.activity.push(format!("handles of another process: {} named, kinds {kinds:?}", items.len()));
        }
        Err(e) => r.activity.push(format!("handles of another process: {e}")),
    }
    let _ = child.kill();
    let _ = child.wait();
    let t = Instant::now();
    match crate::handles::all_files(Duration::from_secs(20)) {
        Ok(f) => r.activity.push(format!("open files system-wide: {} in {} ms", f.len(), t.elapsed().as_millis())),
        Err(e) => r.activity.push(format!("open files system-wide: {e}")),
    }
    drop(_held);
    let _ = std::fs::remove_file(&path);
}

fn own_cost(r: &mut Report) {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
    let me = Pid::from_u32(std::process::id());
    let mut monitor = crate::process::ProcessMonitor::new();
    let mut sys = System::new();
    let t0 = Instant::now();
    for _ in 0..4 {
        let _ = monitor.snapshot();
        std::thread::sleep(Duration::from_millis(r.sampling_interval_ms.min(1500)));
        sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[me]), ProcessRefreshKind::everything());
    }
    let _ = t0;
    if let Some(p) = sys.process(me) {
        r.own_cpu_percent = Some(p.cpu_usage());
        r.own_memory_mb = Some(p.memory() as f64 / 1_048_576.0);
    }
}

pub fn run(json: bool) -> i32 {
    let (platform, verification) = platform_status();
    let mut r = Report {
        platform: platform.into(),
        verification: verification.into(),
        sampling_interval_ms: crate::config::Config::load().interval_ms,
        ..Default::default()
    };
    eprintln!("procwatch self-test — about 30 seconds, harmless workloads only…");
    #[cfg(unix)]
    {
        capture(&mut r);
        pid_reuse(&mut r);
    }
    #[cfg(windows)]
    {
        capture_windows(&mut r);
        pid_reuse_windows(&mut r);
    }
    file_latency(&mut r);
    activity_probe(&mut r);
    traffic_probe(&mut r);
    traffic_download_probe(&mut r);
    r.activity.extend(crate::process::ProcessMonitor::refresh_costs());
    enforce_kill_probe(&mut r);
    #[cfg(any(target_os = "linux", windows))]
    enforce_block_probe(&mut r);
    #[cfg(windows)]
    handle_probe(&mut r);
    own_cost(&mut r);
    if json {
        println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
    } else {
        println!("Platform: {} — {}", r.platform, r.verification);
        println!("\nShort-lived process capture (children of a test shell; sampling every {} ms vs deep trace via {}):", r.sampling_interval_ms, r.deep_trace_method);
        println!("  {:<12} {:>9} {:>10} {:>12}", "lifetime", "launched", "sampled", "deep trace");
        for c in &r.capture {
            println!("  {:<12} {:>9} {:>10} {:>12}", c.lifetime, c.launched, c.sampled, c.deep_trace);
        }
        println!("  event order violations (spawn ≤ exec ≤ exit): {}", r.order_violations);
        let yn = |b: Option<bool>| match b {
            Some(true) => "yes",
            Some(false) => "NO",
            None => "not tested",
        };
        println!("\nPID-reuse protection:");
        println!("  stale (pid, start) refused:     {}", yn(r.pid_reuse_refused));
        println!("  target left running:            {}", yn(r.pid_reuse_target_survived));
        println!("  correct (pid, start) acted on:  {}", yn(r.checked_action_worked));
        println!("\nFile change notification latency: {}", r.file_event_latency_ms.map(|m| format!("{m} ms")).unwrap_or_else(|| "no event within 5 s".into()));
        println!("\nActivity sources:");
        for l in &r.activity {
            println!("  {l}");
        }
        println!("Own cost while sampling: {} CPU, {} memory", r.own_cpu_percent.map(|c| format!("{c:.1}%")).unwrap_or_default(), r.own_memory_mb.map(|m| format!("{m:.0} MB")).unwrap_or_default());
        for n in &r.notes {
            println!("note: {n}");
        }
    }
    let ok = r.pid_reuse_refused != Some(false) && r.pid_reuse_target_survived != Some(false) && r.order_violations == 0;
    i32::from(!ok)
}
