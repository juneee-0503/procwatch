//! The defense module: follows logs, reads the kernel's tables, checks the
//! host, and publishes what it finds.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::Local;

use super::baseline::Baseline;
use super::chain::{Chains, Incident};
use super::config::DefenseConfig;
use super::filter::Gate;
use super::host::{Host, Saved};
use super::tail::Tail;
use super::{auth, ebpf, netattack, sniff, web, Threat};
use crate::common::model::Severity;
use crate::kernel::alarm::{AlarmEvent, Priority};
use crate::kernel::model::{Sample, Unit, SAMPLES};
use crate::kernel::{Capability, Context, Event, Module};

pub const THREATS: &str = "defense.threat";
pub const INCIDENTS: &str = "defense.incident";

const NET_EVERY: Duration = Duration::from_secs(2);
const HOST_EVERY: Duration = Duration::from_secs(30);
const HIDDEN_EVERY: Duration = Duration::from_secs(600);
const SAVE_EVERY: Duration = Duration::from_secs(300);
/// Most process numbers searched for hidden ones.
const HIDDEN_LIMIT: u32 = 65_536;
/// What the baseline learns.
const LEARNED: &[&str] = &["net.rx", "net.tx", "disk.iops", "cpu.run_queue"];

fn default_auth() -> Vec<PathBuf> {
    ["/var/log/auth.log", "/var/log/secure"].iter().map(PathBuf::from).collect()
}

fn default_web() -> Vec<PathBuf> {
    ["/var/log/nginx/access.log", "/var/log/apache2/access.log", "/var/log/httpd/access_log"].iter().map(PathBuf::from).collect()
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct State {
    host: Option<Saved>,
    baseline: Baseline,
}

fn state_path() -> Option<PathBuf> {
    crate::common::paths::data_dir().map(|d| d.join("defense-state.json"))
}

fn priority_of(s: Severity) -> Option<Priority> {
    match s {
        Severity::Critical | Severity::High => Some(Priority::High),
        Severity::Medium => Some(Priority::Medium),
        Severity::Low => Some(Priority::Low),
        Severity::Info => None,
    }
}

pub struct DefenseModule {
    /// Why this can't run: bad settings must show, not silently weaken it.
    problem: Option<String>,
    sensor_problem: Option<String>,
    config: DefenseConfig,
    root: PathBuf,
    state_file: Option<PathBuf>,
    auth_tails: Vec<Tail>,
    web_tails: Vec<Tail>,
    journal: Option<Journal>,
    login: auth::Detector,
    http: web::Detector,
    net: netattack::Detector,
    syn: sniff::Detector,
    #[cfg(target_os = "linux")]
    sniffer: Option<sniff::Sniffer>,
    #[cfg(target_os = "linux")]
    sensor: Option<ebpf::Sensor>,
    calls: ebpf::realtime::Detector,
    host: Option<Host>,
    gate: Gate,
    chains: Chains,
    baseline: Baseline,
    last_net: Option<Instant>,
    last_host: Option<Instant>,
    last_hidden: Option<Instant>,
    last_save: Instant,
    found: [u64; 5],
}

/// journalctl following the login services, where there's no log file.
struct Journal {
    child: std::process::Child,
    rx: std::sync::mpsc::Receiver<String>,
}

impl Journal {
    fn start() -> Option<Journal> {
        use std::io::BufRead;
        let mut child = crate::common::command::tool("journalctl")
            .args(["-f", "-n", "0", "-o", "short-iso", "-t", "sshd", "-t", "sshd-session", "-t", "sudo", "-t", "su", "-t", "useradd", "-t", "usermod"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        let out = child.stdout.take()?;
        let (tx, rx) = std::sync::mpsc::sync_channel(8192);
        let _ = std::thread::Builder::new().name("journal".into()).spawn(move || {
            for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
                let _ = tx.try_send(line);
            }
        });
        Some(Journal { child, rx })
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl DefenseModule {
    pub fn new(config: DefenseConfig) -> DefenseModule {
        DefenseModule::at(config, Path::new("/"), state_path(), false)
    }

    pub fn unusable(problem: String) -> DefenseModule {
        DefenseModule { problem: Some(problem), ..DefenseModule::new(DefenseConfig::default()) }
    }

    /// `include_loopback` is for testing against this machine.
    pub fn at(config: DefenseConfig, root: &Path, state_file: Option<PathBuf>, include_loopback: bool) -> DefenseModule {
        let limits = config.thresholds.clone();
        let quiet = config.quiet_seconds as i64;
        let allow = config.allowed().unwrap_or_default();
        DefenseModule {
            problem: None,
            sensor_problem: None,
            root: root.to_path_buf(),
            state_file,
            auth_tails: Vec::new(),
            web_tails: Vec::new(),
            journal: None,
            login: auth::Detector::new(limits.clone()),
            http: web::Detector::new(limits.clone()),
            net: netattack::Detector::new(limits.clone(), include_loopback),
            syn: sniff::Detector::new(limits, include_loopback),
            #[cfg(target_os = "linux")]
            sniffer: None,
            #[cfg(target_os = "linux")]
            sensor: None,
            calls: ebpf::realtime::Detector::new(include_loopback),
            host: None,
            gate: Gate::new(allow, quiet),
            chains: Chains::default(),
            baseline: Baseline::default(),
            last_net: None,
            last_host: None,
            last_hidden: None,
            last_save: Instant::now(),
            found: [0; 5],
            config,
        }
    }

    fn report(&mut self, ctx: &Context, found: Vec<Threat>) {
        for mut t in found {
            if !self.gate.admit(&t) {
                continue;
            }
            t.identify(&self.root);
            self.found[t.severity as usize] += 1;
            if let Some(priority) = priority_of(t.severity) {
                let key = format!("threat|{}|{}|{}|{}", t.rule, t.source.map(|s| s.to_string()).unwrap_or_default(), t.pid.unwrap_or(0), t.started.unwrap_or(0));
                let event = AlarmEvent::new(key, t.rule, t.title.clone(), priority, "defense").detail(t.evidence.clone());
                // A high alarm stays until someone has seen it.
                let lasts = match priority {
                    Priority::High => None,
                    Priority::Medium => Some(Duration::from_secs(1800)),
                    Priority::Low => Some(Duration::from_secs(600)),
                };
                ctx.raise(event, lasts);
            }
            if let Some(incident) = self.chains.feed(&t) {
                if let Some(priority) = priority_of(incident.severity) {
                    let event = AlarmEvent::new(format!("attack|{}", incident.id), "attack-chain", incident.summary(), priority, "defense").detail(incident.steps.iter().rev().take(8).rev().map(|s| format!("{} {}", s.stage.label(), s.title)).collect::<Vec<_>>().join("\n"));
                    ctx.raise(event, None);
                }
                ctx.publish::<Incident>(INCIDENTS, incident);
            }
            ctx.publish(THREATS, t);
        }
    }

    fn read_logs(&mut self, ctx: &Context) {
        let now = Local::now();
        let mut found = Vec::new();
        for t in &mut self.auth_tails {
            for line in t.poll() {
                found.extend(self.login.feed(&line, now));
            }
        }
        if let Some(j) = &self.journal {
            for line in j.rx.try_iter() {
                found.extend(self.login.feed(&line, now));
            }
        }
        for t in &mut self.web_tails {
            for line in t.poll() {
                found.extend(self.http.feed(&line, now));
            }
        }
        self.report(ctx, found);
    }

    fn read_network(&mut self, ctx: &Context) {
        let read = |p: &str| std::fs::read_to_string(self.root.join(p)).unwrap_or_default();
        let mut socks = netattack::parse_tcp(&read("proc/net/tcp"));
        socks.extend(netattack::parse_tcp(&read("proc/net/tcp6")));
        if socks.is_empty() {
            return;
        }
        let stats = read("proc/net/netstat");
        let counters = netattack::Counters {
            syncookies: netattack::counter(&stats, "TcpExt:", "SyncookiesSent").unwrap_or(0),
            listen_drops: netattack::counter(&stats, "TcpExt:", "ListenDrops").unwrap_or(0),
        };
        let found = self.net.check(&socks, counters, Local::now());
        self.report(ctx, found);
    }

    #[cfg(target_os = "linux")]
    fn read_syns(&mut self, ctx: &Context) {
        let now = Local::now();
        let mut found = Vec::new();
        if let Some(s) = &self.sniffer {
            for (ip, port) in s.rx.try_iter().take(100_000) {
                found.extend(self.syn.feed(ip, port, now));
            }
        }
        self.report(ctx, found);
    }

    #[cfg(not(target_os = "linux"))]
    fn read_syns(&mut self, _: &Context) {
        let _ = (&self.syn, &mut self.calls);
    }

    #[cfg(target_os = "linux")]
    fn read_calls(&mut self, ctx: &Context) {
        let now = Local::now();
        let mut found = Vec::new();
        if let Some(s) = &self.sensor {
            for e in s.rx.try_iter().take(100_000) {
                found.extend(self.calls.feed(&e, now));
            }
        }
        self.report(ctx, found);
    }

    #[cfg(not(target_os = "linux"))]
    fn read_calls(&mut self, _: &Context) {}

    fn save(&mut self) {
        let Some(path) = &self.state_file else { return };
        let Some(host) = &mut self.host else { return };
        host.saved.logins = self.login.known_sources().clone();
        let state = State { host: Some(host.saved.clone()), baseline: self.baseline.clone() };
        if let Ok(text) = serde_json::to_string(&state) {
            let _ = crate::common::paths::write_atomic(path, &text);
        }
    }
}

impl Module for DefenseModule {
    fn capabilities(&self) -> Vec<Capability> {
        if !cfg!(target_os = "linux") {
            return vec![
                Capability::partly("server attack detection", "log and socket sources are Linux only"),
                Capability::no("SYN capture", "needs Linux packet sockets"),
                Capability::partly("host integrity", "/etc files only: no /proc"),
            ];
        }
        let raw = if is_root() { Capability::yes("SYN capture") } else { Capability::no("SYN capture", "needs root or CAP_NET_RAW") };
        let calls = if is_root() { Capability::partly("real-time system calls", "eBPF: needs Linux 5.8 or later; otherwise the 30-second checks carry on") } else { Capability::no("real-time system calls", "needs root") };
        vec![Capability::yes("login attack detection"), Capability::yes("web attack detection"), Capability::yes("network flood detection"), raw, calls, Capability::yes("host integrity")]
    }

    fn subscribes(&self) -> Vec<&'static str> {
        vec![SAMPLES]
    }

    fn importance(&self) -> crate::kernel::module::Importance {
        crate::kernel::module::Importance::Core
    }

    fn interval(&self) -> Option<Duration> {
        Some(Duration::from_millis(250))
    }

    fn watchdog(&self) -> Duration {
        Duration::from_secs(120)
    }

    fn start(&mut self, _: &Context) -> Result<(), String> {
        if let Some(p) = &self.problem {
            return Err(p.clone());
        }
        let state: Option<State> = self.state_file.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|t| serde_json::from_str(&t).ok());
        let (saved, baseline) = state.map_or((None, Baseline::default()), |s| (s.host, s.baseline));
        self.baseline = baseline;
        if let Some(s) = &saved {
            self.login.learn(s.logins.clone());
        }
        self.host = Some(Host::new(&self.root, saved, false));
        let auth = if self.config.auth_logs.is_empty() { default_auth() } else { self.config.auth_logs.clone() };
        let web = if self.config.web_logs.is_empty() { default_web() } else { self.config.web_logs.clone() };
        self.auth_tails = auth.iter().filter(|p| p.exists()).map(|p| Tail::new(p)).collect();
        self.web_tails = web.iter().filter(|p| p.exists()).map(|p| Tail::new(p)).collect();
        if cfg!(target_os = "linux") && self.auth_tails.is_empty() {
            self.journal = Journal::start();
        }
        #[cfg(target_os = "linux")]
        {
            self.sniffer = sniff::Sniffer::start().ok();
            match ebpf::Sensor::start() {
                Ok(s) if !s.partly.is_empty() => {
                    self.sensor_problem = Some(format!("blind on some CPUs: {}", s.partly.join("; ")));
                    self.sensor = Some(s);
                }
                Ok(s) => self.sensor = Some(s),
                Err(e) => self.sensor_problem = Some(e),
            }
        }
        Ok(())
    }

    fn on_event(&mut self, e: &Event, ctx: &Context) {
        let Some(batch) = e.get::<Vec<Sample>>() else { return };
        let now = Local::now();
        let mut found = Vec::new();
        for metric in LEARNED {
            let total: f64 = batch.iter().filter(|s| s.metric == *metric).map(|s| s.value).sum();
            if batch.iter().any(|s| s.metric == *metric) {
                found.extend(self.baseline.feed(metric, total, now));
            }
        }
        self.report(ctx, found);
    }

    fn tick(&mut self, ctx: &Context) {
        if let Some(p) = self.sensor_problem.take() {
            // Running on, with less: that is a state to show, not a fault.
            ctx.degraded(Some(format!("no real-time sensor, using slower checks: {}", p.lines().next().unwrap_or(""))));
        }
        self.read_logs(ctx);
        self.read_syns(ctx);
        self.read_calls(ctx);
        if self.last_net.is_none_or(|t| t.elapsed() >= NET_EVERY) {
            self.last_net = Some(Instant::now());
            self.read_network(ctx);
        }
        if self.last_host.is_none_or(|t| t.elapsed() >= HOST_EVERY) {
            self.last_host = Some(Instant::now());
            let found = self.host.as_mut().map(|h| h.check(Local::now())).unwrap_or_default();
            self.report(ctx, found);
        }
        if cfg!(target_os = "linux") && self.last_hidden.is_none_or(|t| t.elapsed() >= HIDDEN_EVERY) {
            self.last_hidden = Some(Instant::now());
            let found = self.host.as_ref().map(|h| h.hidden_processes(Local::now(), HIDDEN_LIMIT)).unwrap_or_default();
            self.report(ctx, found);
        }
        if self.last_save.elapsed() >= SAVE_EVERY {
            self.last_save = Instant::now();
            self.save();
            let labels = ["info", "low", "medium", "high", "critical"];
            let mut samples: Vec<Sample> = labels.iter().zip(self.found).map(|(l, n)| Sample::new("defense.threats", n as f64, Unit::Count).label("severity", *l)).collect();
            samples.push(Sample::new("defense.baseline_hours", self.baseline.coverage() as f64, Unit::Count));
            #[cfg(target_os = "linux")]
            if let Some(s) = &self.sniffer {
                samples.push(Sample::new("defense.syns_lost", s.lost.load(std::sync::atomic::Ordering::Relaxed) as f64, Unit::Count));
            }
            #[cfg(target_os = "linux")]
            if let Some(s) = &self.sensor {
                samples.push(Sample::new("defense.ebpf_events", s.seen.load(std::sync::atomic::Ordering::Relaxed) as f64, Unit::Count));
                samples.push(Sample::new("defense.ebpf_lost", s.lost() as f64, Unit::Count));
            }
            ctx.samples(samples);
        }
    }

    fn stop(&mut self) {
        self.save();
    }
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(target_os = "linux"))]
fn is_root() -> bool {
    false
}
