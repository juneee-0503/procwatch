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
        println!("Own cost while sampling: {} CPU, {} memory", r.own_cpu_percent.map(|c| format!("{c:.1}%")).unwrap_or_default(), r.own_memory_mb.map(|m| format!("{m:.0} MB")).unwrap_or_default());
        for n in &r.notes {
            println!("note: {n}");
        }
    }
    let ok = r.pid_reuse_refused != Some(false) && r.pid_reuse_target_survived != Some(false) && r.order_violations == 0;
    i32::from(!ok)
}
