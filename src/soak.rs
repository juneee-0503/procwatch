//! `procwatch --soak MINUTES`: run the whole pipeline headless — sampler,
//! investigation hooks, detection, deep trace, timeline rebuilds, and
//! rendering of every page into an off-screen buffer — under a harmless
//! process-churn workload, and report memory, CPU and buffer sizes over
//! time. Fails if memory keeps growing after warm-up or a worker panics.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use ratatui::{backend::TestBackend, Terminal};

use crate::app::{App, Tab};
use crate::config::Config;
use crate::sampler::{self, SamplerCtl};

/// What the main loop is doing right now, for the watchdog.
static PHASE: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
static BEAT: AtomicU64 = AtomicU64::new(0);

fn phase(p: impl Into<String>) {
    if let Ok(mut s) = PHASE.lock() {
        *s = p.into();
    }
    BEAT.fetch_add(1, Ordering::Relaxed);
}

/// Fail fast with a diagnosis if the loop stops making progress, instead of
/// hanging until an outer timeout.
fn watchdog(limit: Duration) {
    let _ = std::thread::Builder::new().name("soak-watchdog".into()).spawn(move || {
        let mut last = BEAT.load(Ordering::Relaxed);
        let mut since = Instant::now();
        loop {
            std::thread::sleep(Duration::from_secs(5));
            let now = BEAT.load(Ordering::Relaxed);
            if now != last {
                last = now;
                since = Instant::now();
            } else if since.elapsed() >= limit {
                let p = PHASE.lock().map(|s| s.clone()).unwrap_or_default();
                println!("soak: FAILED — main loop stuck for {} s in: {p}", since.elapsed().as_secs());
                std::process::exit(3);
            }
        }
    });
}

struct Sample {
    minute: f64,
    rss_mb: f64,
    cpu: f32,
    timeline: usize,
    net: usize,
    deep: usize,
    detections: usize,
}

fn own_usage(sys: &mut sysinfo::System) -> (f64, f32) {
    let me = sysinfo::Pid::from_u32(std::process::id());
    sys.refresh_processes_specifics(sysinfo::ProcessesToUpdate::Some(&[me]), sysinfo::ProcessRefreshKind::everything());
    sys.process(me).map(|p| (p.memory() as f64 / 1_048_576.0, p.cpu_usage())).unwrap_or((0.0, 0.0))
}

/// Harmless churn: a shell starting short-lived children for the whole run.
struct Workload {
    pid: u32,
    /// Start time, so a reused PID is never touched.
    #[cfg(unix)]
    start: u64,
    #[cfg(windows)]
    child: std::process::Child,
}

/// Detached from procwatch on Unix (it never traces its own helpers).
fn workload(minutes: u64) -> Option<Workload> {
    #[cfg(unix)]
    {
        let loops = minutes * 60 * 5;
        let inner = format!("i=0; while [ $i -lt {loops} ]; do /bin/echo x >/dev/null; sleep 0.2; i=$((i+1)); done");
        let out = std::process::Command::new("/bin/sh").args(["-c", &format!("/bin/sh -c '{inner}' >/dev/null 2>&1 & echo $!")]).output().ok()?;
        let pid: u32 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
        Some(Workload { pid, start: crate::process::native::start_time(pid).unwrap_or(0) })
    }
    #[cfg(windows)]
    {
        // ping -n 2 waits about a second, so this lasts the whole run.
        let loops = minutes * 60 + 30;
        let child = std::process::Command::new("cmd")
            .args(["/C", &format!("for /L %i in (1,1,{loops}) do @(ver >NUL & ping -n 2 127.0.0.1 >NUL)")])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        Some(Workload { pid: child.id(), child })
    }
}

/// Stop the workload: by handle on Windows; on Unix only if the PID is
/// still the same process. Never by bare PID — it may have been reused.
fn stop(w: &mut Workload) {
    #[cfg(unix)]
    if crate::process::native::start_time(w.pid).is_some_and(|s| s.abs_diff(w.start) <= 2) {
        unsafe {
            libc::kill(w.pid as libc::pid_t, libc::SIGTERM);
        }
    }
    #[cfg(windows)]
    {
        let _ = w.child.kill();
        let _ = w.child.wait();
    }
}

fn msg_name(m: &crate::sampler::WorkerMsg) -> &'static str {
    use crate::sampler::WorkerMsg::*;
    match m {
        Snapshot(_) => "Snapshot",
        Gpu(_) => "Gpu",
        Inspected { .. } => "Inspected",
        Fs(_) => "Fs",
        Persistence(_) => "Persistence",
        Logs(_) => "Logs",
        FileReport(_) => "FileReport",
        Artifacts { .. } => "Artifacts",
        Yara { .. } => "Yara",
        Memory { .. } => "Memory",
        Deep(_) => "Deep",
        DeepSnap { .. } => "DeepSnap",
        Error(_) => "Error",
        Evidence(_) => "Evidence",
        Stack { .. } => "Stack",
        FileList(_) => "FileList",
        TraceFiles(_) => "TraceFiles",
        Found { .. } => "Found",
        ActionDone { .. } => "ActionDone",
    }
}

pub fn run(minutes: u64) -> i32 {
    let minutes = minutes.clamp(1, 24 * 60);
    // Record worker panics (they are caught per worker) instead of printing.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().name() == Some("main") {
            default_hook(info);
        } else if let Ok(mut last) = crate::WORKER_PANIC.lock() {
            *last = Some(info.to_string());
        }
    }));
    // Soak runs never write to the user's event history.
    let cfg = Config { interval_ms: 1000, history: false, ..Config::load() };
    let (tx, rx) = mpsc::channel();
    let ctl = Arc::new(SamplerCtl { interval_ms: AtomicU64::new(cfg.interval_ms), paused: AtomicBool::new(false), refresh_now: AtomicBool::new(false) });
    if let Err(e) = sampler::spawn_sampler(tx.clone(), ctl.clone()) {
        eprintln!("soak: couldn't start sampler: {e}");
        return 2;
    }
    let mut app = App::new(tx, ctl, cfg);
    let mut term = match Terminal::new(TestBackend::new(160, 45)) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("soak: {e}");
            return 2;
        }
    };
    let mut child = workload(minutes);
    let child_pid = child.as_ref().map(|w| w.pid);
    if let Some(p) = child_pid {
        // Our child on Windows, but it is the thing under test.
        app.ir.launched.insert(p);
    }
    let mut traced = false;
    let mut sys = sysinfo::System::new();
    let start = Instant::now();
    let end = start + Duration::from_secs(minutes * 60);
    let mut last_tick = Instant::now();
    let mut last_draw = Instant::now();
    let mut last_sample = Instant::now() - Duration::from_secs(60);
    let mut samples: Vec<Sample> = Vec::new();
    let mut frames = 0u64;
    let mut panics = Vec::new();
    let tabs = Tab::ALL;
    watchdog(Duration::from_secs(90));
    println!("soak: {minutes} min, sampling every 1 s, churn workload {}", if child.is_some() { "running" } else { "unavailable" });
    println!("{:>7} {:>9} {:>6} {:>9} {:>7} {:>7} {:>11}", "minute", "RSS MB", "CPU%", "timeline", "net", "deep", "detections");
    while Instant::now() < end {
        while let Ok(msg) = rx.try_recv() {
            phase(format!("handling worker message {}", msg_name(&msg)));
            app.on_worker_msg(msg);
        }
        phase("loop top");
        if let Some(m) = crate::WORKER_PANIC.lock().ok().and_then(|mut m| m.take()) {
            panics.push(m);
        }
        if last_tick.elapsed() >= Duration::from_millis(250) {
            phase(format!("on_tick (page {:?})", app.tab));
            app.on_tick();
            last_tick = Instant::now();
        }
        if !traced {
            if let Some(c) = child_pid {
                if app.tree.get(c).is_some() {
                    app.deep_enroll(c, "soak workload".into(), false);
                    traced = true;
                }
            }
        }
        // Render a different page each second, like a user clicking around.
        if last_draw.elapsed() >= Duration::from_secs(1) {
            app.tab = tabs[(frames as usize) % tabs.len()];
            if frames % 7 == 3 {
                if let Some(c) = child_pid {
                    phase("opening the workspace");
                    let k = app.proc_key(c);
                    app.open_workspace_for(k);
                }
            } else if frames % 7 == 5 {
                app.mode = crate::app::Mode::Normal;
            }
            phase(format!("rendering page {:?} (mode {})", app.tab, if app.mode == crate::app::Mode::Normal { "normal" } else { "overlay" }));
            if let Err(e) = term.draw(|f| crate::ui::draw(f, &mut app)) {
                panics.push(format!("render: {e}"));
            }
            frames += 1;
            last_draw = Instant::now();
        }
        if last_sample.elapsed() >= Duration::from_secs(30) {
            let (rss, cpu) = own_usage(&mut sys);
            let s = Sample {
                minute: start.elapsed().as_secs_f64() / 60.0,
                rss_mb: rss,
                cpu,
                timeline: app.ir.timeline.len(),
                net: app.ir.net_events.len(),
                deep: app.ir.deep.events.len(),
                detections: app.ir.det.store.items.len(),
            };
            println!("{:>7.1} {:>9.1} {:>6.1} {:>9} {:>7} {:>7} {:>11}", s.minute, s.rss_mb, s.cpu, s.timeline, s.net, s.deep, s.detections);
            samples.push(s);
            last_sample = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    phase("stopping the workload");
    if let Some(w) = child.as_mut() {
        stop(w);
    }
    phase("final measurements");
    let (rss, _) = own_usage(&mut sys);
    // Growth after warm-up (first sample past the first minute).
    let base = samples.iter().find(|s| s.minute >= 1.0).or(samples.first()).map(|s| s.rss_mb).unwrap_or(rss);
    let growth = rss - base;
    let limit = (base * 0.5).max(64.0);
    println!("frames rendered: {frames} · final RSS {rss:.1} MB · growth after warm-up {growth:+.1} MB (limit {limit:.0} MB)");
    for p in &panics {
        println!("PANIC: {p}");
    }
    if !panics.is_empty() || growth > limit {
        println!("soak: FAILED");
        1
    } else {
        println!("soak: ok");
        0
    }
}
