//! `procwatch --agent POLICY`: monitoring, blocking and playbooks as one
//! long-running process, with a tamper-evident log.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::app::config::Config;
use crate::app::App;
use crate::common::emit::Emit;
use crate::common::pacing::{self as sampler, SamplerCtl};
use crate::process::actions::{apply_checked, Action, Outcome, Sig};
use crate::response::agent::{verify, AgentPolicy, ChainLog, Cooldowns, Step};
use crate::response::enforce::{self, Mode, Policy};
use crate::response::tamper::{self, Watched};

const TAMPER_CHECK_EVERY: Duration = Duration::from_secs(30);

fn default_log() -> Option<PathBuf> {
    crate::common::paths::data_dir().map(|d| d.join("agent.jsonl"))
}

/// The parent: keeps a worker running. A real deployment also has the
/// service manager restart this one; see docs/edr.md.
pub fn run(policy: &Path, log: Option<&Path>, minutes: Option<u64>) -> i32 {
    if let Err(e) = AgentPolicy::load(policy) {
        eprintln!("{}:\n{e}", policy.display());
        return 1;
    }
    let Ok(me) = std::env::current_exe() else {
        eprintln!("agent: can't find my own program file");
        return 2;
    };
    let mut args = vec!["--agent-worker".to_string(), policy.display().to_string()];
    if let Some(l) = log {
        args.extend(["--output".to_string(), l.display().to_string()]);
    }
    if let Some(m) = minutes {
        args.extend(["--minutes".to_string(), m.to_string()]);
    }
    tamper::guard(|| std::process::Command::new(&me).args(&args).status().ok().and_then(|s| s.code()), |n| eprintln!("agent: {n}"), std::thread::sleep)
}

/// What the log records of a process, and what a kill would lose.
fn process_facts(app: &App, pid: u32) -> serde_json::Value {
    let Some(n) = app.tree.get(pid) else { return json!({ "pid": pid, "gone": true }) };
    let i = &n.info;
    let sha256 = i.exe_path.as_deref().and_then(|p| crate::files::info::sha256_file(Path::new(p)).ok());
    json!({
        "pid": pid, "start": i.start_time_secs, "name": i.name, "exe": i.exe_path, "sha256": sha256,
        "parent": i.ppid, "command": i.cmd,
    })
}

fn outcome_text(o: &Outcome) -> String {
    match o {
        Outcome::Done => "done".into(),
        Outcome::AlreadyExited => "already exited".into(),
        Outcome::PidReused { .. } => "skipped: the pid now belongs to another process".into(),
        Outcome::Failed(e) => format!("failed: {e}"),
    }
}

fn record(chain: &mut ChainLog, event: serde_json::Value) {
    if let Err(e) = chain.append(&event) {
        eprintln!("agent: log: {e}");
    }
}

pub fn worker(policy_path: &Path, log: Option<&Path>, minutes: Option<u64>) -> i32 {
    let policy = match AgentPolicy::load(policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}:\n{e}", policy_path.display());
            return 1;
        }
    };
    let Some(log_path) = log.map(Path::to_path_buf).or_else(default_log) else {
        eprintln!("agent: no data folder for the log: name one with --output");
        return 2;
    };
    let mut chain = match ChainLog::open(&log_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("agent: {e}");
            return 2;
        }
    };
    let hardened = tamper::harden();
    // With the driver loaded, it refuses handles that could end this process.
    #[cfg(windows)]
    let _driver = crate::response::driver::Client::connect().ok().filter(|c| {
        crate::response::driver::encode(false, std::process::id(), &[]).and_then(|m| c.send(&m)).is_ok()
    });
    let mut watched: Vec<Watched> = Vec::new();
    let exe = std::env::current_exe().ok();
    for (what, path) in [("program", exe.as_deref()), ("policy", Some(policy_path))] {
        if let Some(p) = path {
            match Watched::new(what, p) {
                Ok(w) => watched.push(w),
                Err(e) => eprintln!("agent: can't watch {what}: {e}"),
            }
        }
    }
    // Blocking runs alongside, and its decisions join the same log.
    let (dtx, drx) = mpsc::sync_channel(4096);
    let mut blocking = None;
    if let Some(p) = policy.enforce_path(policy_path) {
        match Policy::load(&p) {
            Ok(rules) => {
                let out = Emit::new(move |d| {
                    let _ = dtx.try_send(d);
                    true
                });
                match enforce::start(rules, out) {
                    Ok(r) => blocking = Some(r),
                    Err(e) => {
                        eprintln!("agent: {}: {e}", p.display());
                        return 2;
                    }
                }
                if let Ok(w) = Watched::new("blocking policy", &p) {
                    watched.push(w);
                }
            }
            Err(e) => {
                eprintln!("{}:\n{e}", p.display());
                return 1;
            }
        }
    }
    let cfg = Config { interval_ms: 1000, history: false, ..Config::load() };
    let (tx, rx) = mpsc::channel();
    let ctl = Arc::new(SamplerCtl {
        interval_ms: AtomicU64::new(cfg.interval_ms),
        paused: AtomicBool::new(false),
        refresh_now: AtomicBool::new(false),
        snapshots_queued: Default::default(),
    });
    let kernel = crate::engine::start(tx.clone(), ctl.clone(), crate::app::watch_paths(&cfg));
    let mut app = App::new(tx, ctl, cfg);
    app.kernel = Some(kernel);
    let mode = if policy.mode == Mode::Enforce { "enforce" } else { "audit" };
    record(&mut chain, json!({ "kind": "agent started", "mode": mode, "policy": policy_path.display().to_string(), "pid": std::process::id(), "hardening": hardened }));
    eprintln!("agent: mode {mode}, {} playbooks, logging to {}", policy.playbooks.len(), log_path.display());
    if policy.activity {
        app.ir.activity_out = Some(Vec::new());
        let until = Instant::now() + Duration::from_secs(5);
        let mut asked = false;
        while app.ir.capture_method.is_none() && app.ir.capture_error.is_none() && Instant::now() < until {
            asked = asked || app.publish_capture_start();
            sampler::drain_for(&rx, Duration::from_millis(100), |m| app.on_worker_msg(m));
        }
        if app.ir.capture_method.is_none() {
            record(&mut chain, json!({ "kind": "activity capture unavailable", "reason": app.ir.capture_error }));
        }
    }
    let spared: HashSet<u32> = enforce::own_line();
    let mut cooldowns = Cooldowns::default();
    let mut logged: HashMap<(String, u32), Instant> = HashMap::new();
    let end = minutes.map(|m| Instant::now() + Duration::from_secs(m.saturating_mul(60)));
    let (mut last_tick, mut last_scan, mut last_check) = (Instant::now(), Instant::now(), Instant::now());
    while end.is_none_or(|e| Instant::now() < e) {
        if sampler::drain_for(&rx, Duration::from_millis(100), |m| app.on_worker_msg(m)).disconnected {
            record(&mut chain, json!({ "kind": "agent stopped", "reason": "sampler ended" }));
            return 1;
        }
        while let Ok(d) = drx.try_recv() {
            record(&mut chain, json!({ "kind": "blocking", "decision": d }));
        }
        if last_tick.elapsed() >= Duration::from_millis(250) {
            app.on_tick();
            last_tick = Instant::now();
        }
        if last_check.elapsed() >= TAMPER_CHECK_EVERY {
            last_check = Instant::now();
            for w in &mut watched {
                if let Some(change) = w.changed() {
                    eprintln!("agent: TAMPER: {change}");
                    record(&mut chain, json!({ "kind": "tamper", "detail": change }));
                }
            }
            if !chain.intact() {
                eprintln!("agent: TAMPER: the log file shrank or disappeared");
            }
        }
        if last_scan.elapsed() < Duration::from_secs(1) {
            continue;
        }
        last_scan = Instant::now();
        // One entry per second: each is flushed to disk.
        let lines = app.take_activity_lines();
        if !lines.is_empty() {
            record(&mut chain, json!({ "kind": "activity", "events": lines }));
        }
        let hits: Vec<_> = app.ir.det.store.items.iter().filter(|d| d.suppressed.is_none() && d.active).map(|d| (d.rule_id.clone(), d.rule_name.clone(), d.severity, d.pid, d.subject_label.clone())).collect();
        let now = Instant::now();
        for (rule, name, severity, pid, subject) in hits {
            if logged.get(&(rule.clone(), pid.unwrap_or(0))).is_none_or(|t| now.duration_since(*t) >= Duration::from_secs(3600)) {
                logged.insert((rule.clone(), pid.unwrap_or(0)), now);
                record(&mut chain, json!({ "kind": "detection", "rule": rule, "name": name, "severity": severity.label(), "pid": pid, "subject": subject }));
            }
            let Some(pid) = pid else { continue };
            let Some((start, exe)) = app.tree.get(pid).map(|n| (n.info.start_time_secs, n.info.exe_path.clone().unwrap_or_default())) else { continue };
            let books: Vec<_> = policy.matching(&rule, &name, severity).cloned().collect();
            for book in books {
                if !cooldowns.ready(&book, pid, start, now) {
                    continue;
                }
                let refused = (spared.contains(&pid) || enforce::is_essential(&exe)).then_some("the system or procwatch needs this process");
                for step in &book.steps {
                    let result = match (step, policy.mode, refused) {
                        (Step::Collect, _, _) => {
                            record(&mut chain, json!({ "kind": "collected", "playbook": book.id, "rule": rule, "process": process_facts(&app, pid) }));
                            continue;
                        }
                        (_, _, Some(why)) => format!("refused: {why}"),
                        (Step::Suspend, Mode::Audit, _) => "would suspend".to_string(),
                        (Step::Kill, Mode::Audit, _) => "would kill".to_string(),
                        (Step::Suspend, Mode::Enforce, _) => outcome_text(&apply_checked(pid, start, Action::Signal(Sig::Stop))),
                        (Step::Kill, Mode::Enforce, _) => outcome_text(&apply_checked(pid, start, Action::Signal(Sig::Kill))),
                    };
                    record(&mut chain, json!({ "kind": "response", "playbook": book.id, "rule": rule, "step": step, "pid": pid, "exe": exe, "result": result }));
                }
            }
        }
    }
    drop(blocking);
    record(&mut chain, json!({ "kind": "agent stopped", "reason": "time limit" }));
    0
}

/// `--agent-check`: what a policy would do.
pub fn check(path: &Path) -> i32 {
    match AgentPolicy::load(path) {
        Err(e) => {
            eprintln!("{}:\n{e}", path.display());
            1
        }
        Ok(p) => {
            println!("mode: {:?}{}", p.mode, if p.mode == Mode::Audit { " (nothing is acted on)" } else { "" });
            for b in &p.playbooks {
                println!("  {}: rules {:?}, severity at least {:?}: {:?}, once per process per {} s", b.id, b.when.rule, b.when.min_severity, b.steps, b.cooldown_seconds);
            }
            if let Some(e) = p.enforce_path(path) {
                println!("blocking policy: {}", e.display());
                return enforce::check(&e);
            }
            0
        }
    }
}

/// `--agent-verify`: check a log's chain.
pub fn verify_log(path: Option<&Path>) -> i32 {
    let Some(path) = path.map(Path::to_path_buf).or_else(default_log) else {
        eprintln!("name a log file");
        return 2;
    };
    match verify(&path) {
        Ok(v) => {
            println!("{}: {} entries, chain intact, head {}", path.display(), v.lines, v.head);
            0
        }
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            1
        }
    }
}
