//! Registration, lifecycle, scheduling and supervision.
//!
//! Every module runs on its own thread behind a panic boundary and beats a
//! heartbeat each pass of its loop. A crash restarts it, waiting 1, 2, 4 … 60
//! seconds. Too many failures in a row open the circuit: `Failed`, with no
//! more restarts until someone acts. A module that stops beating is marked
//! stuck. It can't be killed, so it is abandoned: its run is invalidated, so
//! nothing more it publishes counts, and a new instance takes over.
//!
//! Nothing here collects anything or waits on anything a module controls.

use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::alarm::{AlarmEvent, Engine, Hub, Input, Priority};
use super::bus::Bus;
use super::config::KernelConfig;
use super::model::{Sample, Unit, SAMPLES};
use super::module::{Capability, Context, Importance, Module, RunHealth};

/// Bus topic announcing state changes, carrying `ModuleStatus`.
pub const MODULE_STATE: &str = "kernel.module";

const QUEUE: usize = 256;
const WATCH_EVERY: Duration = Duration::from_millis(250);
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// More failures in a row than this and restarting has stopped helping.
const MAX_FAILURES: u32 = 6;
/// A run this long without trouble clears the count of failures.
const STABLE: Duration = Duration::from_secs(120);
/// Collections failing in a row before the module counts as broken.
const MAX_ERRORS: u64 = 20;
const SELF_REPORT: Duration = Duration::from_secs(5);
/// Own CPU, in percent of a core, above which load is shed.
const CPU_BUDGET: f32 = 15.0;
/// Passes over budget, and under it, before changing course.
const OVER_BUDGET_PASSES: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleState {
    Disabled,
    Starting,
    Running,
    /// Can't run here; the reason says why. Not a fault.
    Unavailable,
    /// Running with less than it could offer; `degraded` says why.
    Degraded,
    /// Stopped beating; being replaced.
    Stuck,
    /// Waiting to be restarted.
    Crashed,
    /// Failed too often in a row; waits to be enabled again by hand.
    Failed,
}

impl ModuleState {
    pub fn label(&self) -> &'static str {
        match self {
            ModuleState::Disabled => "disabled",
            ModuleState::Starting => "starting",
            ModuleState::Running => "running",
            ModuleState::Unavailable => "unavailable",
            ModuleState::Degraded => "degraded",
            ModuleState::Stuck => "stuck",
            ModuleState::Crashed => "restarting",
            ModuleState::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleStatus {
    pub name: &'static str,
    pub description: &'static str,
    pub state: ModuleState,
    pub restarts: u32,
    pub last_error: Option<String>,
    pub capabilities: Vec<Capability>,
    /// What its self-test said when it last loaded.
    pub self_test: Option<String>,
    /// Why it is degraded.
    pub degraded: Option<String>,
    pub stuck: u32,
    pub failures_in_a_row: u32,
    pub ticks: u64,
    pub errors: u64,
    pub last_tick_us: u64,
    pub max_tick_us: u64,
    pub queue_depth: u64,
    pub queue_dropped: u64,
}

/// The kernel's own account of itself.
#[derive(Debug, Clone, Serialize)]
pub struct Health {
    pub modules: Vec<ModuleStatus>,
    pub bus_published: u64,
    pub bus_dropped: u64,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    /// Load is being shed to keep the machine responsive.
    pub degraded: bool,
    pub alarms_firing: u64,
    pub alarm_eval_us: u64,
    pub notify_failed: u64,
}

type Factory = Box<dyn Fn() -> Box<dyn Module> + Send + Sync>;

struct Slot {
    name: &'static str,
    factory: Factory,
    /// Each run has a number; only the current one's output counts.
    run: Arc<AtomicU64>,
    /// When the run last beat, since the epoch of `Kernel::start`.
    beat: Arc<AtomicU64>,
    /// Longest allowed between beats, in ms, as declared by the module.
    limit: Arc<AtomicU64>,
    ticks: AtomicU64,
    last_tick_us: AtomicU64,
    max_tick_us: AtomicU64,
    depth: AtomicU64,
    dropped: AtomicU64,
    importance: Mutex<Importance>,
    provides: Mutex<Vec<&'static str>>,
    health: Mutex<Arc<RunHealth>>,
    state: Mutex<Shared>,
}

struct Shared {
    status: ModuleStatus,
    wants_run: bool,
    /// Set by the thread when its run ends on a crash.
    crashed: Option<String>,
    retry_at: Option<Instant>,
    last_failure: Option<Instant>,
}

struct Inner {
    slots: Vec<Slot>,
    bus: Bus,
    epoch: Instant,
    stopping: AtomicBool,
    config: Mutex<KernelConfig>,
    hub: Hub,
    /// Multiplies every module's interval: 1 unless shedding load.
    stretch: AtomicUsize,
    cpu_x10: AtomicU64,
    memory: AtomicU64,
}

/// A handle to the running kernel. Cheap to clone.
#[derive(Clone)]
pub struct Kernel(Arc<Inner>);

/// Reports this process's CPU percent and resident bytes. Given to the
/// kernel, which collects nothing itself.
pub type SelfProbe = Box<dyn FnMut() -> (f32, u64) + Send>;

/// Modules are registered before the kernel starts.
#[derive(Default)]
pub struct Registry {
    slots: Vec<Slot>,
    probe: Option<SelfProbe>,
}

impl Registry {
    pub fn add(&mut self, name: &'static str, description: &'static str, factory: impl Fn() -> Box<dyn Module> + Send + Sync + 'static) {
        let capabilities = catch_unwind(AssertUnwindSafe(|| factory().capabilities())).unwrap_or_default();
        self.slots.push(Slot {
            name,
            factory: Box::new(factory),
            run: Arc::default(),
            beat: Arc::default(),
            limit: Arc::new(AtomicU64::new(30_000)),
            ticks: AtomicU64::new(0),
            last_tick_us: AtomicU64::new(0),
            max_tick_us: AtomicU64::new(0),
            depth: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            importance: Mutex::new(Importance::Normal),
            provides: Mutex::new(Vec::new()),
            health: Mutex::default(),
            state: Mutex::new(Shared {
                status: ModuleStatus { name, description, state: ModuleState::Disabled, restarts: 0, last_error: None, capabilities, self_test: None, degraded: None, stuck: 0, failures_in_a_row: 0, ticks: 0, errors: 0, last_tick_us: 0, max_tick_us: 0, queue_depth: 0, queue_dropped: 0 },
                wants_run: false,
                crashed: None,
                retry_at: None,
                last_failure: None,
            }),
        });
    }

    pub fn self_probe(&mut self, probe: SelfProbe) {
        self.probe = Some(probe);
    }

    /// What is registered, without starting anything.
    pub fn statuses(&self) -> Vec<ModuleStatus> {
        self.slots.iter().filter_map(|s| s.state.lock().ok().map(|g| g.status.clone())).collect()
    }

    /// Start with the configured modules running.
    pub fn start(self, bus: Bus, config: KernelConfig) -> Kernel {
        let disabled: BTreeSet<String> = config.disabled.clone();
        let k = self.boot(bus, config);
        for s in &k.0.slots {
            if let Ok(mut g) = s.state.lock() {
                g.wants_run = !disabled.contains(s.name);
            }
        }
        k
    }

    /// Start the kernel alone. Modules wait for `activate`.
    pub fn boot(self, bus: Bus, config: KernelConfig) -> Kernel {
        let rules = config.rules();
        let probe = self.probe.unwrap_or_else(|| Box::new(|| (0.0, 0)));
        let k = Kernel(Arc::new(Inner { slots: self.slots, bus, epoch: Instant::now(), stopping: AtomicBool::new(false), config: Mutex::new(config), hub: Hub::default(), stretch: AtomicUsize::new(1), cpu_x10: AtomicU64::new(0), memory: AtomicU64::new(0) }));
        k.spawn_alarms(Engine::new(rules));
        let watcher = k.clone();
        let _ = std::thread::Builder::new().name("kernel".into()).spawn(move || watcher.supervise());
        let reporter = k.clone();
        let _ = std::thread::Builder::new().name("kernel-self".into()).spawn(move || reporter.report_self(probe));
        k
    }
}

fn panic_message(e: &(dyn std::any::Any + Send)) -> String {
    e.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| e.downcast_ref::<String>().cloned()).unwrap_or_else(|| "unknown panic".into())
}

impl Kernel {
    pub fn bus(&self) -> &Bus {
        &self.0.bus
    }

    pub fn alarms(&self) -> &Hub {
        &self.0.hub
    }

    pub fn status(&self) -> Vec<ModuleStatus> {
        self.0
            .slots
            .iter()
            .filter_map(|s| {
                let mut st = s.state.lock().ok()?.status.clone();
                st.ticks = s.ticks.load(Ordering::Relaxed);
                st.last_tick_us = s.last_tick_us.load(Ordering::Relaxed);
                st.max_tick_us = s.max_tick_us.load(Ordering::Relaxed);
                st.queue_depth = s.depth.load(Ordering::Relaxed);
                st.queue_dropped = s.dropped.load(Ordering::Relaxed);
                if let Ok(h) = s.health.lock() {
                    st.errors = h.total_errors.load(Ordering::Relaxed);
                    st.degraded = h.degraded.lock().ok().and_then(|d| d.clone());
                }
                Some(st)
            })
            .collect()
    }

    /// Everything the kernel can say about itself. Reads shared counters
    /// only, so any front end can call it at any time.
    pub fn health(&self) -> Health {
        let stats = self.0.hub.stats();
        Health {
            modules: self.status(),
            bus_published: self.0.bus.published(),
            bus_dropped: self.0.bus.dropped(),
            cpu_percent: self.0.cpu_x10.load(Ordering::Relaxed) as f32 / 10.0,
            memory_bytes: self.0.memory.load(Ordering::Relaxed),
            degraded: self.0.stretch.load(Ordering::Relaxed) > 1,
            alarms_firing: stats.firing.load(Ordering::Relaxed),
            alarm_eval_us: stats.eval_us.load(Ordering::Relaxed),
            notify_failed: stats.notify_failed.load(Ordering::Relaxed),
        }
    }

    /// Start a running module again, so new settings take effect.
    pub fn reload(&self, name: &str) {
        let Some((i, s)) = self.0.slots.iter().enumerate().find(|(_, s)| s.name == name) else { return };
        if !self.wanted(name) {
            return;
        }
        s.run.fetch_add(1, Ordering::Relaxed);
        s.beat.store(0, Ordering::Relaxed);
        if let Ok(mut g) = s.state.lock() {
            g.retry_at = None;
            g.status.failures_in_a_row = 0;
            g.status.last_error = None;
        }
        self.set_state(i, ModuleState::Disabled, None);
    }

    /// Whether a module is meant to be running now.
    pub fn wanted(&self, name: &str) -> bool {
        self.0.slots.iter().find(|s| s.name == name).is_some_and(|s| s.state.lock().is_ok_and(|g| g.wants_run))
    }

    /// Load these modules now, for this session only.
    pub fn activate(&self, names: &[String]) {
        for s in &self.0.slots {
            if let Ok(mut g) = s.state.lock() {
                g.wants_run = names.iter().any(|n| n == s.name);
                g.status.failures_in_a_row = 0;
                g.retry_at = None;
                if g.wants_run && g.status.state == ModuleState::Failed {
                    g.status.state = ModuleState::Disabled;
                }
            }
        }
    }

    /// Turn a module on or off while running. Enabling also clears `Failed`.
    pub fn set_enabled(&self, name: &str, enabled: bool) {
        if let Some(s) = self.0.slots.iter().find(|s| s.name == name) {
            if let Ok(mut g) = s.state.lock() {
                g.wants_run = enabled;
                g.status.failures_in_a_row = 0;
                g.retry_at = None;
                if enabled && g.status.state == ModuleState::Failed {
                    g.status.state = ModuleState::Disabled;
                }
            }
        }
        if let Ok(mut c) = self.0.config.lock() {
            if enabled {
                c.disabled.remove(name);
            } else {
                c.disabled.insert(name.to_string());
            }
        }
    }

    pub fn config(&self) -> KernelConfig {
        self.0.config.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// Stop everything. Modules get a moment to finish; a stuck one is left.
    pub fn shutdown(&self) {
        self.0.stopping.store(true, Ordering::Relaxed);
        for s in &self.0.slots {
            s.run.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn now_ms(&self) -> u64 {
        // 0 means idle, so a real time is never 0.
        self.0.epoch.elapsed().as_millis() as u64 + 1
    }

    fn set_state(&self, slot: usize, state: ModuleState, error: Option<String>) {
        let Some(s) = self.0.slots.get(slot) else { return };
        let status = match s.state.lock() {
            Ok(mut g) => {
                if g.status.state == state && error.is_none() {
                    return;
                }
                g.status.state = state;
                if error.is_some() {
                    g.status.last_error = error;
                }
                g.status.clone()
            }
            Err(_) => return,
        };
        self.0.bus.publish(MODULE_STATE, "kernel", Arc::new(status));
    }

    /// The alarm engine, on its own thread: evaluating can't touch
    /// collection, and notifying happens elsewhere again.
    fn spawn_alarms(&self, mut engine: Engine) {
        let samples = self.0.bus.subscribe(&[SAMPLES], QUEUE * 4);
        let (tx, rx) = channel();
        self.0.hub.connect(tx);
        let k = self.clone();
        let _ = std::thread::Builder::new().name("kernel-alarm".into()).spawn(move || {
            let hub = k.0.hub.clone();
            let stats = || hub.stats();
            while !k.0.stopping.load(Ordering::Relaxed) {
                let began = Instant::now();
                let mut out: Vec<AlarmEvent> = Vec::new();
                for e in samples.try_iter() {
                    if let Some(batch) = e.get::<Vec<Sample>>() {
                        out.extend(engine.feed(batch, Instant::now()));
                    }
                }
                out.extend(engine.expire(Instant::now()));
                let spent = began.elapsed().as_micros() as u64;
                stats().eval_us.store(spent, Ordering::Relaxed);
                stats().firing.store(engine.firing() as u64, Ordering::Relaxed);
                out.into_iter().for_each(|e| hub.publish(e));
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(input) => {
                        let Some(e) = Self::alarm_input(&mut engine, input) else { continue };
                        hub.publish(e);
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return,
                }
                for input in rx.try_iter() {
                    if let Some(e) = Self::alarm_input(&mut engine, input) {
                        hub.publish(e);
                    }
                }
                let _ = &k;
            }
        });
    }

    fn alarm_input(engine: &mut Engine, input: Input) -> Option<AlarmEvent> {
        match input {
            Input::Raise { event, lasts } => engine.raise(event, lasts, Instant::now()),
            Input::Clear(key) => engine.clear(&key),
            Input::Acknowledge(key) => engine.acknowledge(&key),
            Input::SetRules(rules) => {
                engine.set_rules(rules);
                None
            }
        }
    }

    /// Own CPU and memory, per-module figures as metrics, and the decision
    /// to shed load. On its own thread: the probe can take a moment.
    fn report_self(self, mut probe: SelfProbe) {
        let (mut over, mut under) = (0, 0);
        while !self.0.stopping.load(Ordering::Relaxed) {
            std::thread::sleep(SELF_REPORT);
            let (cpu, memory) = probe();
            self.0.cpu_x10.store((cpu * 10.0) as u64, Ordering::Relaxed);
            self.0.memory.store(memory, Ordering::Relaxed);
            let budget = cpu > CPU_BUDGET;
            (over, under) = if budget { (over + 1, 0) } else { (0, under + 1) };
            if over >= OVER_BUDGET_PASSES {
                self.0.stretch.store(4, Ordering::Relaxed);
            } else if under >= OVER_BUDGET_PASSES {
                self.0.stretch.store(1, Ordering::Relaxed);
            }
            let degraded = self.0.stretch.load(Ordering::Relaxed) > 1;
            let mut out = vec![
                Sample::new("kernel.cpu", f64::from(cpu), Unit::Percent),
                Sample::new("kernel.memory", memory as f64, Unit::Bytes),
                Sample::new("kernel.bus_dropped", self.0.bus.dropped() as f64, Unit::Count),
                Sample::new("kernel.bus_published", self.0.bus.published() as f64, Unit::Count),
                Sample::new("kernel.degraded", f64::from(u8::from(degraded)), Unit::Count),
            ];
            let stats = self.0.hub.stats();
            out.push(Sample::new("alarm.firing", stats.firing.load(Ordering::Relaxed) as f64, Unit::Count));
            out.push(Sample::new("alarm.eval_ms", stats.eval_us.load(Ordering::Relaxed) as f64 / 1000.0, Unit::Milliseconds));
            out.push(Sample::new("alarm.notify_failed", stats.notify_failed.load(Ordering::Relaxed) as f64, Unit::Count));
            for m in self.status().iter().filter(|m| m.ticks > 0) {
                out.push(Sample::new("kernel.module_tick", m.last_tick_us as f64 / 1000.0, Unit::Milliseconds).label("module", m.name));
                out.push(Sample::new("kernel.module_queue", m.queue_depth as f64, Unit::Count).label("module", m.name));
                out.push(Sample::new("kernel.module_restarts", f64::from(m.restarts), Unit::Count).label("module", m.name));
            }
            self.0.bus.publish(SAMPLES, "kernel", Arc::new(out));
        }
    }

    /// The kernel's own loop: start what should run, stop what shouldn't,
    /// restart what crashed, replace what hangs.
    fn supervise(self) {
        while !self.0.stopping.load(Ordering::Relaxed) {
            for i in 0..self.0.slots.len() {
                self.check(i);
            }
            std::thread::sleep(WATCH_EVERY);
        }
    }

    fn check(&self, i: usize) {
        let Some(s) = self.0.slots.get(i) else { return };
        let (wants, state, crashed, due) = match s.state.lock() {
            Ok(mut g) => (g.wants_run, g.status.state.clone(), g.crashed.take(), g.retry_at.is_none_or(|t| Instant::now() >= t)),
            Err(_) => return,
        };
        if let Some(err) = crashed {
            self.note_crash(i, err);
            return;
        }
        let beat = s.beat.load(Ordering::Relaxed);
        let alive = matches!(state, ModuleState::Running | ModuleState::Degraded | ModuleState::Starting);
        if alive && beat != 0 && self.now_ms().saturating_sub(beat) > s.limit.load(Ordering::Relaxed) {
            // It can't be interrupted. Disown it and start over.
            s.run.fetch_add(1, Ordering::Relaxed);
            s.beat.store(0, Ordering::Relaxed);
            if let Ok(mut g) = s.state.lock() {
                g.status.stuck += 1;
            }
            self.set_state(i, ModuleState::Stuck, Some("stopped responding".to_string()));
            self.note_crash(i, "stopped responding".to_string());
            return;
        }
        if matches!(state, ModuleState::Running) {
            if let Ok(mut g) = s.state.lock() {
                if g.last_failure.is_some_and(|t| t.elapsed() >= STABLE) {
                    g.status.failures_in_a_row = 0;
                    g.last_failure = None;
                }
            }
        }
        let degraded = s.health.lock().ok().and_then(|h| h.degraded.lock().ok().and_then(|d| d.clone()));
        match (&state, degraded) {
            (ModuleState::Running, Some(why)) => self.set_state(i, ModuleState::Degraded, Some(why)),
            (ModuleState::Degraded, None) => self.set_state(i, ModuleState::Running, None),
            _ => {}
        }
        match (wants, &state) {
            (true, ModuleState::Disabled) | (true, ModuleState::Crashed) if due => self.launch(i),
            (false, ModuleState::Running | ModuleState::Starting | ModuleState::Unavailable | ModuleState::Crashed | ModuleState::Failed) => {
                s.run.fetch_add(1, Ordering::Relaxed);
                s.beat.store(0, Ordering::Relaxed);
                self.set_state(i, ModuleState::Disabled, None);
            }
            _ => {}
        }
    }

    fn note_crash(&self, i: usize, error: String) {
        let Some(s) = self.0.slots.get(i) else { return };
        let mut gave_up = false;
        if let Ok(mut g) = s.state.lock() {
            let now = Instant::now();
            g.status.restarts += 1;
            g.status.failures_in_a_row += 1;
            g.last_failure = Some(now);
            let n = g.status.failures_in_a_row;
            gave_up = n > MAX_FAILURES;
            g.retry_at = Some(now + backoff(n));
        }
        let provides = s.provides.lock().map(|p| p.clone()).unwrap_or_default();
        let priority = if gave_up { Priority::High } else { Priority::Medium };
        let what = if gave_up { "has failed and won't restart" } else { "lost its signal" };
        let event = AlarmEvent::new(format!("module-lost|{}", s.name), "module-lost", format!("Module {} {what}", s.name), priority, "kernel.module").detail(format!("{error}; provides: {}", provides.join(", ")));
        self.0.hub.send(Input::Raise { event, lasts: None });
        self.set_state(i, if gave_up { ModuleState::Failed } else { ModuleState::Crashed }, Some(error));
    }

    fn launch(&self, i: usize) {
        let Some(s) = self.0.slots.get(i) else { return };
        let generation = s.run.fetch_add(1, Ordering::Relaxed) + 1;
        s.beat.store(self.now_ms(), Ordering::Relaxed);
        self.set_state(i, ModuleState::Starting, None);
        let health = Arc::new(RunHealth::default());
        if let Ok(mut h) = s.health.lock() {
            *h = health.clone();
        }
        let ctx = Context { name: s.name, bus: self.0.bus.clone(), generation, current: s.run.clone(), hub: self.0.hub.clone(), health };
        let k = self.clone();
        let name = format!("module-{}", s.name);
        if std::thread::Builder::new().name(name).spawn(move || k.run_module(i, ctx)).is_err() {
            self.note_crash(i, "couldn't start a thread".into());
        }
    }

    /// One run of one module. Returns when replaced, stopped or crashed.
    fn run_module(&self, i: usize, ctx: Context) {
        let Some(s) = self.0.slots.get(i) else { return };
        let beat = || s.beat.store(self.now_ms(), Ordering::Relaxed);
        let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
            let mut m = (s.factory)();
            s.limit.store(m.watchdog().as_millis() as u64, Ordering::Relaxed);
            let caps = m.capabilities();
            if let Ok(mut g) = s.state.lock() {
                g.status.capabilities = caps;
            }
            if let Ok(mut p) = s.provides.lock() {
                *p = m.provides();
            }
            if let Ok(mut p) = s.importance.lock() {
                *p = m.importance();
            }
            let tested = m.self_test();
            if let Ok(mut g) = s.state.lock() {
                g.status.self_test = Some(tested.clone().unwrap_or_else(|e| e));
            }
            if let Err(e) = tested {
                if ctx.current() {
                    self.set_state(i, ModuleState::Unavailable, Some(format!("self-test failed: {e}")));
                }
                return Ok(());
            }
            // No topics means no queue: an empty list would subscribe to all.
            let topics = m.subscribes();
            let events = (!topics.is_empty()).then(|| self.0.bus.subscribe(&topics, QUEUE));
            beat();
            let started = m.start(&ctx);
            if let Err(e) = started {
                if ctx.current() {
                    self.set_state(i, ModuleState::Unavailable, Some(e));
                }
                return Ok(());
            }
            if !ctx.current() {
                m.stop();
                return Ok(());
            }
            self.set_state(i, ModuleState::Running, None);
            self.0.hub.send(Input::Clear(format!("module-lost|{}", s.name)));
            let importance = m.importance();
            let mut next = Instant::now();
            while ctx.current() {
                beat();
                let wait = match m.interval() {
                    Some(_) => next.saturating_duration_since(Instant::now()).min(WATCH_EVERY),
                    None => WATCH_EVERY,
                };
                match &events {
                    Some(rx) => {
                        s.depth.store(rx.depth() as u64, Ordering::Relaxed);
                        s.dropped.store(rx.dropped(), Ordering::Relaxed);
                        if let Ok(ev) = rx.recv_timeout(wait) {
                            m.on_event(&ev, &ctx);
                        }
                    }
                    None => std::thread::sleep(wait),
                }
                beat();
                // Under load, optional modules wait and the rest slow down.
                let stretch = self.0.stretch.load(Ordering::Relaxed) as u32;
                if stretch > 1 && importance == Importance::Optional {
                    continue;
                }
                if let Some(every) = m.interval() {
                    if Instant::now() >= next && ctx.current() {
                        let began = Instant::now();
                        m.tick(&ctx);
                        let spent = began.elapsed().as_micros() as u64;
                        s.ticks.fetch_add(1, Ordering::Relaxed);
                        s.last_tick_us.store(spent, Ordering::Relaxed);
                        s.max_tick_us.fetch_max(spent, Ordering::Relaxed);
                        let factor = if importance == Importance::Core { 1 } else { stretch };
                        next = Instant::now() + every * factor;
                        if ctx.health.errors.load(Ordering::Relaxed) >= MAX_ERRORS {
                            m.stop();
                            return Err(format!("{MAX_ERRORS} collections failed in a row"));
                        }
                    }
                }
            }
            m.stop();
            Ok(())
        }));
        s.beat.store(0, Ordering::Relaxed);
        let failure = match result {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e),
            Err(e) => Some(panic_message(&*e)),
        };
        // Only the current run's failure matters; a disowned one is history.
        if let (Some(e), true) = (failure, ctx.current()) {
            if let Ok(mut g) = s.state.lock() {
                g.crashed = Some(e);
            }
        }
    }
}

fn backoff(failures: u32) -> Duration {
    FIRST_BACKOFF.saturating_mul(1 << failures.saturating_sub(1).min(16)).min(MAX_BACKOFF)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::model::Unit;
    use std::sync::atomic::AtomicU32;

    struct Probe {
        ticks: Arc<AtomicU32>,
        panics_left: Arc<AtomicU32>,
        hangs_left: Arc<AtomicU32>,
    }

    impl Module for Probe {
        fn capabilities(&self) -> Vec<Capability> {
            vec![Capability::yes("ticking"), Capability::no("flying", "no wings")]
        }
        fn interval(&self) -> Option<Duration> {
            Some(Duration::from_millis(5))
        }
        fn watchdog(&self) -> Duration {
            Duration::from_millis(300)
        }
        fn tick(&mut self, ctx: &Context) {
            if self.hangs_left.load(Ordering::SeqCst) > 0 {
                self.hangs_left.fetch_sub(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_secs(30));
            }
            if self.panics_left.load(Ordering::SeqCst) > 0 {
                self.panics_left.fetch_sub(1, Ordering::SeqCst);
                panic!("probe failed");
            }
            self.ticks.fetch_add(1, Ordering::SeqCst);
            ctx.publish("probe.tick", 1u8);
        }
    }

    struct Fixture {
        ticks: Arc<AtomicU32>,
        panics: Arc<AtomicU32>,
        hangs: Arc<AtomicU32>,
    }

    fn registry() -> (Registry, Fixture) {
        let f = Fixture { ticks: Arc::default(), panics: Arc::default(), hangs: Arc::default() };
        let (t, p, h) = (f.ticks.clone(), f.panics.clone(), f.hangs.clone());
        let mut r = Registry::default();
        r.add("probe", "test module", move || Box::new(Probe { ticks: t.clone(), panics_left: p.clone(), hangs_left: h.clone() }));
        (r, f)
    }

    fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
        let t = Instant::now();
        while !ok() {
            assert!(t.elapsed() < Duration::from_secs(12), "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn state(k: &Kernel) -> ModuleState {
        k.status()[0].state.clone()
    }

    #[test]
    fn capabilities_are_known_before_anything_starts() {
        let (r, _) = registry();
        let s = r.statuses();
        assert_eq!(s[0].capabilities.len(), 2);
        assert_eq!(s[0].state, ModuleState::Disabled);
    }

    #[test]
    fn a_crashing_module_comes_back_and_the_kernel_carries_on() {
        let (r, f) = registry();
        f.panics.store(2, Ordering::SeqCst);
        let k = r.start(Bus::default(), KernelConfig::default());
        wait_for("recovery", || f.ticks.load(Ordering::SeqCst) > 3);
        let s = &k.status()[0];
        assert_eq!(s.restarts, 2);
        assert_eq!(s.state, ModuleState::Running);
        assert!(s.last_error.as_deref().is_some_and(|e| e.contains("probe failed")));
        k.shutdown();
    }

    #[test]
    fn a_hung_module_is_replaced_and_its_output_ignored() {
        let (r, f) = registry();
        f.hangs.store(1, Ordering::SeqCst);
        let bus = Bus::default();
        let k = r.start(bus.clone(), KernelConfig::default());
        wait_for("replacement", || f.ticks.load(Ordering::SeqCst) > 3);
        let s = &k.status()[0];
        assert_eq!(s.restarts, 1);
        assert_eq!(s.last_error.as_deref(), Some("stopped responding"));
        k.shutdown();
    }

    #[test]
    fn a_module_that_keeps_crashing_stops_being_restarted() {
        let (r, f) = registry();
        f.panics.store(u32::MAX, Ordering::SeqCst);
        let k = r.start(Bus::default(), KernelConfig::default());
        // Backoff would take minutes, so count on the state machine directly.
        for _ in 0..=MAX_FAILURES {
            k.note_crash(0, "again".into());
        }
        assert_eq!(state(&k), ModuleState::Failed);
        f.panics.store(0, Ordering::SeqCst);
        k.set_enabled("probe", true);
        wait_for("manual recovery", || f.ticks.load(Ordering::SeqCst) > 0);
        k.shutdown();
    }

    #[test]
    fn modules_turn_off_and_on_while_running() {
        let (r, f) = registry();
        let k = r.start(Bus::default(), KernelConfig { disabled: BTreeSet::from(["probe".to_string()]), ..Default::default() });
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(f.ticks.load(Ordering::SeqCst), 0, "disabled by configuration");
        k.set_enabled("probe", true);
        wait_for("enabling", || f.ticks.load(Ordering::SeqCst) > 0);
        k.set_enabled("probe", false);
        wait_for("disabling", || state(&k) == ModuleState::Disabled);
        std::thread::sleep(Duration::from_millis(50));
        let n = f.ticks.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(f.ticks.load(Ordering::SeqCst), n, "it really stopped");
        assert!(k.config().disabled.contains("probe"), "the choice is kept");
        k.shutdown();
    }

    struct Refuses;
    impl Module for Refuses {
        fn capabilities(&self) -> Vec<Capability> {
            Vec::new()
        }
        fn start(&mut self, _ctx: &Context) -> Result<(), String> {
            Err("needs root".into())
        }
    }

    #[test]
    fn unavailable_is_not_a_crash() {
        let mut r = Registry::default();
        r.add("refuses", "x", || Box::new(Refuses));
        let k = r.start(Bus::default(), KernelConfig::default());
        wait_for("settling", || state(&k) == ModuleState::Unavailable);
        std::thread::sleep(Duration::from_millis(400));
        let s = &k.status()[0];
        assert_eq!((s.restarts, s.last_error.as_deref()), (0, Some("needs root")));
        k.shutdown();
    }

    #[test]
    fn modules_without_topics_take_no_share_of_the_bus() {
        let (r, f) = registry();
        let bus = Bus::default();
        let k = r.start(bus.clone(), KernelConfig::default());
        wait_for("publishing", || f.ticks.load(Ordering::SeqCst) > 300);
        assert_eq!(bus.dropped(), 0, "nothing is queued for a module that reads no events");
        k.shutdown();
    }

    #[test]
    fn output_from_a_replaced_run_is_discarded() {
        let bus = Bus::default();
        let rx = bus.subscribe(&["t"], 8);
        let current = Arc::new(AtomicU64::new(2));
        let old = Context { name: "m", bus: bus.clone(), generation: 1, current: current.clone(), hub: Hub::default(), health: Arc::default() };
        let new = Context { name: "m", bus, generation: 2, current, hub: Hub::default(), health: Arc::default() };
        old.publish("t", 1u8);
        new.publish("t", 2u8);
        assert_eq!(rx.try_iter().map(|e| *e.get::<u8>().unwrap()).collect::<Vec<_>>(), vec![2]);
    }

    #[test]
    fn alarms_flow_from_samples_to_their_own_channel() {
        let bus = Bus::default();
        let cfg = KernelConfig { alerts: vec![crate::kernel::alarm::Rule::parse("cpu.run_queue > 1 for 0s").unwrap()], no_default_rules: true, ..Default::default() };
        let k = Registry::default().start(bus.clone(), cfg);
        let rx = k.alarms().subscribe();
        std::thread::sleep(Duration::from_millis(150));
        bus.publish(SAMPLES, "t", Arc::new(vec![Sample::new("cpu.run_queue", 5.0, Unit::Count)]));
        let e = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(e.phase, crate::kernel::alarm::Phase::Firing);
        k.alarms().send(Input::Acknowledge(e.key.clone()));
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap().phase, crate::kernel::alarm::Phase::Acknowledged);
        k.shutdown();
    }

    #[test]
    fn backoff_doubles_up_to_a_ceiling() {
        let secs: Vec<u64> = (1..=9).map(|n| backoff(n).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(backoff(u32::MAX).as_secs(), 60);
    }

    #[test]
    fn a_stuck_module_is_marked_and_a_lost_signal_raises_an_alarm() {
        let (r, f) = registry();
        f.hangs.store(1, Ordering::SeqCst);
        let k = r.start(Bus::default(), KernelConfig::default());
        let rx = k.alarms().subscribe();
        wait_for("replacement", || f.ticks.load(Ordering::SeqCst) > 3);
        assert_eq!(k.status()[0].stuck, 1);
        let e = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(e.rule, "module-lost");
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap().phase, crate::kernel::alarm::Phase::Recovered, "it came back");
        k.shutdown();
    }

    struct Failing;
    impl Module for Failing {
        fn capabilities(&self) -> Vec<Capability> {
            Vec::new()
        }
        fn interval(&self) -> Option<Duration> {
            Some(Duration::from_millis(1))
        }
        fn tick(&mut self, ctx: &Context) {
            ctx.error();
        }
    }

    #[test]
    fn a_module_that_only_returns_errors_counts_as_broken() {
        let mut r = Registry::default();
        r.add("failing", "x", || Box::new(Failing));
        let k = r.start(Bus::default(), KernelConfig::default());
        // The count rises just before the reason is written.
        wait_for("failure", || k.status()[0].last_error.as_deref().is_some_and(|e| e.contains("in a row")));
        assert!(k.status()[0].restarts >= 1);
        k.shutdown();
    }

    struct Partial;
    impl Module for Partial {
        fn capabilities(&self) -> Vec<Capability> {
            Vec::new()
        }
        fn start(&mut self, ctx: &Context) -> Result<(), String> {
            ctx.degraded(Some("needs root for half of this".into()));
            Ok(())
        }
    }

    #[test]
    fn degraded_is_a_state_not_a_failure() {
        let mut r = Registry::default();
        r.add("partial", "x", || Box::new(Partial));
        let k = r.start(Bus::default(), KernelConfig::default());
        wait_for("degrading", || state(&k) == ModuleState::Degraded);
        let s = &k.status()[0];
        assert_eq!((s.restarts, s.degraded.as_deref()), (0, Some("needs root for half of this")));
        k.shutdown();
    }

    #[test]
    fn nothing_runs_until_activated() {
        let (r, f) = registry();
        let k = r.boot(Bus::default(), KernelConfig::default());
        std::thread::sleep(Duration::from_millis(350));
        assert_eq!(f.ticks.load(Ordering::SeqCst), 0);
        assert!(!k.wanted("probe"));
        k.activate(&["probe".to_string()]);
        assert!(k.wanted("probe"));
        wait_for("loading", || f.ticks.load(Ordering::SeqCst) > 0);
        k.activate(&[]);
        wait_for("unloading", || state(&k) == ModuleState::Disabled);
        assert!(k.health().modules[0].ticks > 0);
        k.shutdown();
    }

    #[test]
    fn a_module_can_be_reloaded_and_comes_back_new() {
        let builds = Arc::new(AtomicU32::new(0));
        let count = builds.clone();
        let mut r = Registry::default();
        r.add("failing", "x", move || {
            count.fetch_add(1, Ordering::SeqCst);
            Box::new(Partial)
        });
        let k = r.start(Bus::default(), KernelConfig::default());
        wait_for("running", || state(&k) == ModuleState::Degraded);
        let before = builds.load(Ordering::SeqCst);
        k.reload("failing");
        wait_for("a new instance", || builds.load(Ordering::SeqCst) > before);
        wait_for("running again", || state(&k) == ModuleState::Degraded);
        k.reload("nothing such");
        k.shutdown();
    }

    #[test]
    fn the_kernel_reports_on_itself() {
        let (r, f) = registry();
        let k = r.start(Bus::default(), KernelConfig::default());
        wait_for("ticks", || f.ticks.load(Ordering::SeqCst) > 5);
        let h = k.health();
        assert!(h.modules[0].ticks > 0);
        assert!(!h.degraded);
        k.shutdown();
    }
}
