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
use crate::defense::ban;
use crate::defense::config::DefenseConfig;
use crate::response::agent::{verify, AgentPolicy, ChainLog, Cooldowns, Playbook, Step};
use crate::response::enforce::{self, Mode, Policy};
use crate::response::tamper::{self, Watched};

const TAMPER_CHECK_EVERY: Duration = Duration::from_secs(30);
/// No progress from the core for this long means the service is broken.
const WATCHDOG: Duration = Duration::from_secs(45);

/// Beats to the receiving end, sent from the main loop so that a dead loop
/// falls silent. Sending happens on a thread: the network can hang.
struct Heart {
    url: String,
    key: Option<Vec<u8>>,
    every: Duration,
    seq: std::sync::atomic::AtomicU64,
}

impl Heart {
    fn new(c: &DefenseConfig) -> Heart {
        let key = (!c.heartbeat.url.is_empty()).then(|| crate::defense::heartbeat::read_key(&c.heartbeat.key_file)).and_then(|k| k.map_err(|e| eprintln!("agent: heartbeat off: {e}")).ok());
        Heart { url: c.heartbeat.url.clone(), key, every: Duration::from_secs(c.heartbeat.interval_seconds.max(1)), seq: Default::default() }
    }

    /// Copies the log off this machine as it grows. What can't be sent stays
    /// in the file: the place reached is saved, so nothing is lost or sent
    /// twice however long the outage.
    fn keep_in_sync(&self, log: &Path, url: &str) {
        use std::io::{BufRead, Seek, SeekFrom};
        let (Some(key), false) = (self.key.clone(), url.is_empty()) else { return };
        let (log, url) = (log.to_path_buf(), url.to_string());
        let mark = {
            let mut p = log.clone().into_os_string();
            p.push(".synced");
            PathBuf::from(p)
        };
        let _ = std::thread::Builder::new().name("log-sync".into()).spawn(move || {
            let mut sent: u64 = std::fs::read_to_string(&mark).ok().and_then(|t| t.trim().parse().ok()).unwrap_or(0);
            loop {
                std::thread::sleep(Duration::from_secs(3));
                let Ok(mut f) = std::fs::File::open(&log) else { continue };
                // A new segment starts again from its beginning.
                if f.metadata().is_ok_and(|m| m.len() < sent) {
                    sent = 0;
                }
                if f.seek(SeekFrom::Start(sent)).is_err() {
                    continue;
                }
                let lines: Vec<String> = std::io::BufReader::new(f).lines().map_while(Result::ok).take(200).collect();
                if lines.is_empty() {
                    continue;
                }
                let id = crate::kernel::model::identity();
                let beat = crate::defense::heartbeat::Lines { v: 1, host: id.host.to_string(), lines };
                let Ok(body) = crate::defense::heartbeat::seal(&beat, &key) else { continue };
                if crate::defense::heartbeat::post(&url, &body).is_ok() {
                    sent += beat.lines.iter().map(|l| l.len() as u64 + 1).sum::<u64>();
                    let _ = crate::common::paths::write_atomic(&mark, &sent.to_string());
                }
            }
        });
    }

    fn send(&self, chain: &ChainLog, last_words: Option<String>, first: bool) {
        use crate::common::integrity as i;
        use crate::defense::heartbeat::{post, seal, Beat, PROTOCOL};
        let Some(key) = &self.key else { return };
        let id = crate::kernel::model::identity();
        let (chain_seq, head) = chain.head();
        let beat = Beat {
            v: PROTOCOL,
            host: id.host.to_string(),
            instance: id.instance.to_string(),
            seq: self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
            time: chrono::Local::now().to_rfc3339(),
            health: "ok".to_string(),
            program: i::program_hash().unwrap_or_default(),
            config: i::config_digest(),
            chain_seq,
            chain_head: head.to_string(),
            anchors: if first { chain.anchors() } else { Vec::new() },
            maintenance: crate::common::maintenance::remaining().map(|d| d.as_secs()),
            last_words: last_words.clone(),
        };
        let Ok(body) = seal(&beat, key) else { return };
        let url = self.url.clone();
        // A goodbye must get out before the process does.
        if last_words.is_some() {
            let _ = post(&url, &body);
        } else {
            let _ = std::thread::Builder::new().name("heartbeat".into()).spawn(move || {
                let _ = post(&url, &body);
            });
        }
    }
}

fn default_log() -> Option<PathBuf> {
    crate::common::paths::data_dir().map(|d| d.join("agent.jsonl"))
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

/// Carries out one playbook against one finding.
struct Responder<'a> {
    policy: &'a AgentPolicy,
    spared: &'a HashSet<u32>,
    allow: &'a [crate::defense::filter::Cidr],
    bans: Vec<Instant>,
    banned: bool,
}

impl Responder<'_> {
    fn ban(&mut self, book: &Playbook, ip: Option<std::net::IpAddr>) -> String {
        let Some(ip) = ip else { return "skipped: this finding has no source address".into() };
        let (sessions, gateway) = ban::guarded();
        if let Some(why) = ban::refused(ip, self.allow, &sessions, gateway) {
            return format!("refused: {why}");
        }
        if self.policy.mode == Mode::Audit {
            return format!("would ban {ip}");
        }
        self.bans.retain(|t| t.elapsed() < Duration::from_secs(3600));
        if self.bans.len() >= ban::MAX_PER_HOUR {
            return "refused: too many bans this hour; the source may be forged".into();
        }
        match ban::ban(ip, book.ban_seconds) {
            Ok(()) => {
                self.bans.push(Instant::now());
                self.banned = true;
                format!("banned {ip} for {} s", book.ban_seconds)
            }
            Err(e) => format!("failed: {e}"),
        }
    }

    fn process(&self, step: Step, pid: Option<u32>, app: &App) -> String {
        let Some(pid) = pid else { return "skipped: this finding has no process".into() };
        let Some((start, exe)) = app.tree.get(pid).map(|n| (n.info.start_time_secs, n.info.exe_path.clone().unwrap_or_default())) else {
            return "skipped: the process has gone".into();
        };
        if self.spared.contains(&pid) || enforce::is_essential(&exe) {
            return "refused: the system or procwatch needs this process".into();
        }
        let signal = if step == Step::Kill { Sig::Kill } else { Sig::Stop };
        match self.policy.mode {
            Mode::Audit => format!("would {step:?}").to_lowercase(),
            Mode::Enforce => outcome_text(&apply_checked(pid, start, Action::Signal(signal))),
        }
    }
}

fn record(chain: &mut ChainLog, event: serde_json::Value) {
    if let Err(e) = chain.append(&event) {
        eprintln!("agent: log: {e}");
    }
}

/// Runs as a service: restarting after a failure is the service manager's
/// job, because it is the one thing an attacker here can't reach as easily.
pub fn run(policy_path: &Path, log: Option<&Path>, minutes: Option<u64>) -> i32 {
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
    if let Some(d) = chain.damage.clone() {
        eprintln!("agent: TAMPER: the log was damaged: {d}");
        record(&mut chain, json!({ "kind": "tamper", "detail": format!("previous log damaged: {d}") }));
    }
    let hardened = tamper::harden();
    super::service::catch_signals();
    let config = DefenseConfig::load().unwrap_or_default();
    let beats = Heart::new(&config);
    if let crate::common::integrity::Check::Changed { was, now } = crate::common::integrity::check_program() {
        if !cfg!(debug_assertions) {
            let text = format!("the program changed: approved {was}, running {now}; refusing to run. After an upgrade, run --accept-program");
            eprintln!("agent: {text}");
            record(&mut chain, json!({ "kind": "tamper", "detail": text }));
            crate::common::audit::record("start refused", &text);
            beats.send(&chain, Some(text), true);
            return 3;
        }
    }
    for w in crate::common::integrity::take_warnings() {
        eprintln!("agent: TAMPER: {w}");
        record(&mut chain, json!({ "kind": "tamper", "detail": w }));
    }
    beats.keep_in_sync(&log_path, &config.sync.url);
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
    let alarms = kernel.alarms().subscribe();
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
    #[cfg(unix)]
    if let Some(k) = app.kernel.clone() {
        super::service::serve_queries(k);
    }
    super::service::sd_notify("READY=1");
    let feed_every = super::service::watchdog_period();
    let internal = cfg!(windows).then(|| super::service::Watchdog::start(WATCHDOG));
    let (mut last_feed, mut progress) = (Instant::now(), HashMap::new());
    beats.send(&chain, None, true);
    let mut last_beat = Instant::now();
    let spared: HashSet<u32> = enforce::own_line();
    let allow = DefenseConfig::load().and_then(|c| c.allowed()).unwrap_or_default();
    let mut responder = Responder { policy: &policy, spared: &spared, allow: &allow, bans: Vec::new(), banned: false };
    let mut threats_seen = app.ir.threat_seq;
    let mut incident_stages: HashMap<u64, usize> = HashMap::new();
    let mut cooldowns = Cooldowns::default();
    let mut logged: HashMap<(String, u32), Instant> = HashMap::new();
    let end = minutes.map(|m| Instant::now() + Duration::from_secs(m.saturating_mul(60)));
    let (mut last_tick, mut last_scan, mut last_check) = (Instant::now(), Instant::now(), Instant::now());
    let mut leaving = "time limit".to_string();
    while end.is_none_or(|e| Instant::now() < e) {
        if let Some(why) = super::service::stop_requested() {
            leaving = why;
            break;
        }
        // Only the main loop feeds the watchdogs, and only for real progress.
        if let Some(every) = feed_every.or(internal.as_ref().map(|_| WATCHDOG / 3)) {
            if last_feed.elapsed() >= every {
                last_feed = Instant::now();
                if super::service::core_alive(&app.kernel.as_ref().map(|k| k.status()).unwrap_or_default(), &mut progress, Instant::now(), WATCHDOG) {
                    super::service::sd_notify("WATCHDOG=1");
                    if let Some(w) = &internal {
                        w.feed();
                    }
                }
            }
        }
        if last_beat.elapsed() >= beats.every {
            last_beat = Instant::now();
            beats.send(&chain, None, false);
        }
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
                if let Some(k) = &app.kernel {
                    k.alarms().send(crate::kernel::alarm::Input::Raise { event: crate::kernel::alarm::AlarmEvent::new("log-tampered", "log-tampered", "The agent's log shrank or disappeared", crate::kernel::alarm::Priority::High, "agent"), lasts: None });
                }
            }
            let _ = crate::response::agent::prune(&log_path, config.retention.days, config.retention.max_mb.saturating_mul(1 << 19));
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
        for i in &app.ir.incidents {
            if incident_stages.insert(i.id, i.stages.len()) != Some(i.stages.len()) {
                record(&mut chain, json!({ "kind": "incident", "incident": i }));
            }
        }
        for e in alarms.try_iter() {
            record(&mut chain, json!({ "kind": "alarm", "alarm": e }));
        }
        let fresh = (app.ir.threat_seq - threats_seen).min(app.ir.threats.len() as u64) as usize;
        threats_seen = app.ir.threat_seq;
        let threats: Vec<_> = app.ir.threats.iter().rev().take(fresh).rev().cloned().collect();
        for t in threats {
            record(&mut chain, json!({ "kind": "threat", "threat": t }));
            let books: Vec<_> = policy.matching(t.rule, &t.title, t.severity).cloned().collect();
            for book in books {
                for step in &book.steps {
                    let result = match step {
                        Step::Collect => {
                            let facts = t.pid.map(|p| process_facts(&app, p));
                            record(&mut chain, json!({ "kind": "collected", "playbook": book.id, "rule": t.rule, "process": facts, "source": t.source }));
                            continue;
                        }
                        Step::Ban => responder.ban(&book, t.source),
                        step => responder.process(*step, t.pid, &app),
                    };
                    record(&mut chain, json!({ "kind": "response", "playbook": book.id, "rule": t.rule, "step": step, "source": t.source, "pid": t.pid, "result": result }));
                }
            }
        }
        let hits: Vec<_> = app.ir.det.store.items.iter().filter(|d| d.suppressed.is_none() && d.active).map(|d| (d.rule_id.clone(), d.rule_name.clone(), d.severity, d.pid, d.subject_label.clone())).collect();
        let now = Instant::now();
        for (rule, name, severity, pid, subject) in hits {
            if logged.get(&(rule.clone(), pid.unwrap_or(0))).is_none_or(|t| now.duration_since(*t) >= Duration::from_secs(3600)) {
                logged.insert((rule.clone(), pid.unwrap_or(0)), now);
                record(&mut chain, json!({ "kind": "detection", "rule": rule, "name": name, "severity": severity.label(), "pid": pid, "subject": subject }));
            }
            let Some(pid) = pid else { continue };
            let Some(start) = app.tree.get(pid).map(|n| n.info.start_time_secs) else { continue };
            let books: Vec<_> = policy.matching(&rule, &name, severity).cloned().collect();
            for book in books {
                if !cooldowns.ready(&book, pid, start, now) {
                    continue;
                }
                for step in &book.steps {
                    let result = match step {
                        Step::Collect => {
                            record(&mut chain, json!({ "kind": "collected", "playbook": book.id, "rule": rule, "process": process_facts(&app, pid) }));
                            continue;
                        }
                        Step::Ban => "skipped: this finding has no source address".to_string(),
                        step => responder.process(*step, Some(pid), &app),
                    };
                    record(&mut chain, json!({ "kind": "response", "playbook": book.id, "rule": rule, "step": step, "pid": pid, "exe": exe, "result": result }));
                }
            }
        }
    }
    super::service::sd_notify("STOPPING=1");
    record(&mut chain, json!({ "kind": "last words", "reason": leaving }));
    beats.send(&chain, Some(leaving.clone()), false);
    drop(blocking);
    if responder.banned {
        if let Err(e) = ban::clear() {
            eprintln!("agent: {e}: lift bans with procwatch --unban-all");
        }
    }
    record(&mut chain, json!({ "kind": "agent stopped", "reason": leaving }));
    // Stopped from outside: the exit status tells the service manager this
    // wasn't a clean end of work, so it applies its restart policy.
    i32::from(leaving != "time limit")
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
