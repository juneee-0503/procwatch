//! Registration, lifecycle, scheduling and supervision.
//!
//! Every module runs on its own thread behind a panic boundary. A crash
//! restarts it with growing delays. A stuck module can't be killed, so it is
//! abandoned: its run is invalidated, so nothing more it publishes counts, and
//! a new instance takes over. Whatever a module does, the kernel carries on.

use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::alerts::{Engine, ALERTS};
use super::bus::Bus;
use super::config::KernelConfig;
use super::model::{Sample, SAMPLES};
use super::module::{Capability, Context, Module};

/// Bus topic announcing state changes, carrying `ModuleStatus`.
pub const MODULE_STATE: &str = "kernel.module";

const QUEUE: usize = 256;
const WATCH_EVERY: Duration = Duration::from_millis(250);
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// More crashes than this in `CRASH_WINDOW` and restarting has stopped helping.
const MAX_CRASHES: u32 = 6;
const CRASH_WINDOW: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleState {
    Disabled,
    Starting,
    Running,
    /// Can't run here; the reason says why. Not a fault.
    Unavailable,
    /// Waiting to be restarted.
    Crashed,
    /// Restarted too often; waits to be enabled again by hand.
    Failed,
}

impl ModuleState {
    pub fn label(&self) -> &'static str {
        match self {
            ModuleState::Disabled => "disabled",
            ModuleState::Starting => "starting",
            ModuleState::Running => "running",
            ModuleState::Unavailable => "unavailable",
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
}

type Factory = Box<dyn Fn() -> Box<dyn Module> + Send + Sync>;

struct Slot {
    name: &'static str,
    factory: Factory,
    /// Each run has a number; only the current one's output counts.
    run: Arc<AtomicU64>,
    /// Since the epoch of `Kernel::start`; 0 when idle.
    busy_since: Arc<AtomicU64>,
    /// Longest allowed, in ms, as declared by the module.
    limit: Arc<AtomicU64>,
    state: Mutex<Shared>,
}

struct Shared {
    status: ModuleStatus,
    wants_run: bool,
    /// Set by the thread when its run ends on a crash.
    crashed: Option<String>,
    retry_at: Option<Instant>,
    crashes: Vec<Instant>,
}

struct Inner {
    slots: Vec<Slot>,
    bus: Bus,
    epoch: Instant,
    stopping: AtomicBool,
    config: Mutex<KernelConfig>,
}

/// A handle to the running kernel. Cheap to clone.
#[derive(Clone)]
pub struct Kernel(Arc<Inner>);

/// Modules are registered before the kernel starts.
#[derive(Default)]
pub struct Registry {
    slots: Vec<Slot>,
}

impl Registry {
    pub fn add(&mut self, name: &'static str, description: &'static str, factory: impl Fn() -> Box<dyn Module> + Send + Sync + 'static) {
        let capabilities = catch_unwind(AssertUnwindSafe(|| factory().capabilities())).unwrap_or_default();
        self.slots.push(Slot {
            name,
            factory: Box::new(factory),
            run: Arc::default(),
            busy_since: Arc::default(),
            limit: Arc::new(AtomicU64::new(30_000)),
            state: Mutex::new(Shared {
                status: ModuleStatus { name, description, state: ModuleState::Disabled, restarts: 0, last_error: None, capabilities },
                wants_run: false,
                crashed: None,
                retry_at: None,
                crashes: Vec::new(),
            }),
        });
    }

    /// What is registered, without starting anything.
    pub fn statuses(&self) -> Vec<ModuleStatus> {
        self.slots.iter().filter_map(|s| s.state.lock().ok().map(|g| g.status.clone())).collect()
    }

    pub fn start(self, bus: Bus, config: KernelConfig) -> Kernel {
        let disabled: BTreeSet<String> = config.disabled.clone();
        let rules = config.alerts.clone();
        let k = Kernel(Arc::new(Inner { slots: self.slots, bus, epoch: Instant::now(), stopping: AtomicBool::new(false), config: Mutex::new(config) }));
        if !rules.is_empty() {
            k.spawn_alerts(Engine::new(rules));
        }
        for s in &k.0.slots {
            if let Ok(mut g) = s.state.lock() {
                g.wants_run = !disabled.contains(s.name);
            }
        }
        let watcher = k.clone();
        let _ = std::thread::Builder::new().name("kernel".into()).spawn(move || watcher.supervise());
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

    pub fn status(&self) -> Vec<ModuleStatus> {
        self.0.slots.iter().filter_map(|s| s.state.lock().ok().map(|g| g.status.clone())).collect()
    }

    /// Turn a module on or off while running. Enabling also clears `Failed`.
    pub fn set_enabled(&self, name: &str, enabled: bool) {
        if let Some(s) = self.0.slots.iter().find(|s| s.name == name) {
            if let Ok(mut g) = s.state.lock() {
                g.wants_run = enabled;
                g.crashes.clear();
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
        let s = &self.0.slots[slot];
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

    fn spawn_alerts(&self, mut engine: Engine) {
        let rx = self.0.bus.subscribe(&[SAMPLES], QUEUE);
        let k = self.clone();
        let _ = std::thread::Builder::new().name("kernel-alerts".into()).spawn(move || {
            while let Ok(e) = rx.recv() {
                if k.0.stopping.load(Ordering::Relaxed) {
                    return;
                }
                if let Some(samples) = e.get::<Vec<Sample>>() {
                    for a in engine.feed(samples, Instant::now()) {
                        k.0.bus.publish(ALERTS, "kernel", Arc::new(a));
                    }
                }
            }
        });
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
        let s = &self.0.slots[i];
        let (wants, state, crashed, due) = match s.state.lock() {
            Ok(mut g) => (g.wants_run, g.status.state.clone(), g.crashed.take(), g.retry_at.is_none_or(|t| Instant::now() >= t)),
            Err(_) => return,
        };
        if let Some(err) = crashed {
            self.note_crash(i, err);
            return;
        }
        let since = s.busy_since.load(Ordering::Relaxed);
        if matches!(state, ModuleState::Running) && since != 0 && self.now_ms().saturating_sub(since) > s.limit.load(Ordering::Relaxed) {
            // It can't be interrupted. Disown it and start over.
            s.run.fetch_add(1, Ordering::Relaxed);
            s.busy_since.store(0, Ordering::Relaxed);
            self.note_crash(i, "stopped responding".to_string());
            return;
        }
        match (wants, &state) {
            (true, ModuleState::Disabled) | (true, ModuleState::Crashed) if due => self.launch(i),
            (false, ModuleState::Running | ModuleState::Starting | ModuleState::Unavailable | ModuleState::Crashed | ModuleState::Failed) => {
                s.run.fetch_add(1, Ordering::Relaxed);
                s.busy_since.store(0, Ordering::Relaxed);
                self.set_state(i, ModuleState::Disabled, None);
            }
            _ => {}
        }
    }

    fn note_crash(&self, i: usize, error: String) {
        let s = &self.0.slots[i];
        let mut gave_up = false;
        if let Ok(mut g) = s.state.lock() {
            let now = Instant::now();
            g.crashes.retain(|t| now.duration_since(*t) < CRASH_WINDOW);
            g.crashes.push(now);
            g.status.restarts += 1;
            let n = g.crashes.len() as u32;
            gave_up = n > MAX_CRASHES;
            let wait = FIRST_BACKOFF.saturating_mul(1 << (n - 1).min(16)).min(MAX_BACKOFF);
            g.retry_at = Some(now + wait);
        }
        self.set_state(i, if gave_up { ModuleState::Failed } else { ModuleState::Crashed }, Some(error));
    }

    fn launch(&self, i: usize) {
        let s = &self.0.slots[i];
        let generation = s.run.fetch_add(1, Ordering::Relaxed) + 1;
        s.busy_since.store(0, Ordering::Relaxed);
        self.set_state(i, ModuleState::Starting, None);
        let ctx = Context { name: s.name, bus: self.0.bus.clone(), generation, current: s.run.clone() };
        let k = self.clone();
        let name = format!("module-{}", s.name);
        if std::thread::Builder::new().name(name).spawn(move || k.run_module(i, ctx)).is_err() {
            self.note_crash(i, "couldn't start a thread".into());
        }
    }

    /// One run of one module. Returns when replaced, stopped or crashed.
    fn run_module(&self, i: usize, ctx: Context) {
        let s = &self.0.slots[i];
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut m = (s.factory)();
            s.limit.store(m.watchdog().as_millis() as u64, Ordering::Relaxed);
            let caps = m.capabilities();
            if let Ok(mut g) = s.state.lock() {
                g.status.capabilities = caps;
            }
            // No topics means no queue: an empty list would subscribe to all.
            let topics = m.subscribes();
            let events = (!topics.is_empty()).then(|| self.0.bus.subscribe(&topics, QUEUE));
            s.busy_since.store(self.now_ms(), Ordering::Relaxed);
            let started = m.start(&ctx);
            s.busy_since.store(0, Ordering::Relaxed);
            if let Err(e) = started {
                if ctx.current() {
                    self.set_state(i, ModuleState::Unavailable, Some(e));
                }
                return;
            }
            if !ctx.current() {
                m.stop();
                return;
            }
            self.set_state(i, ModuleState::Running, None);
            let mut next = Instant::now();
            while ctx.current() {
                let wait = match m.interval() {
                    Some(_) => next.saturating_duration_since(Instant::now()).min(WATCH_EVERY),
                    None => WATCH_EVERY,
                };
                match &events {
                    Some(rx) => {
                        if let Ok(ev) = rx.recv_timeout(wait) {
                            s.busy_since.store(self.now_ms(), Ordering::Relaxed);
                            m.on_event(&ev, &ctx);
                            s.busy_since.store(0, Ordering::Relaxed);
                        }
                    }
                    None => std::thread::sleep(wait),
                }
                if let Some(every) = m.interval() {
                    if Instant::now() >= next && ctx.current() {
                        s.busy_since.store(self.now_ms(), Ordering::Relaxed);
                        m.tick(&ctx);
                        s.busy_since.store(0, Ordering::Relaxed);
                        next = Instant::now() + every;
                    }
                }
            }
            m.stop();
        }));
        s.busy_since.store(0, Ordering::Relaxed);
        if let Err(e) = result {
            // Only the current run's crash matters; a disowned one is history.
            if ctx.current() {
                if let Ok(mut g) = s.state.lock() {
                    g.crashed = Some(panic_message(&*e));
                }
            }
        }
    }
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
        for _ in 0..=MAX_CRASHES {
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
        let old = Context { name: "m", bus: bus.clone(), generation: 1, current: current.clone() };
        let new = Context { name: "m", bus, generation: 2, current };
        old.publish("t", 1u8);
        new.publish("t", 2u8);
        assert_eq!(rx.try_iter().map(|e| *e.get::<u8>().unwrap()).collect::<Vec<_>>(), vec![2]);
    }

    #[test]
    fn alerts_flow_from_samples_through_the_bus() {
        let bus = Bus::default();
        let rx = bus.subscribe(&[ALERTS], 8);
        let cfg = KernelConfig { alerts: vec![crate::kernel::alerts::Rule::parse("cpu.run_queue > 1").unwrap()], ..Default::default() };
        let k = Registry::default().start(bus.clone(), cfg);
        std::thread::sleep(Duration::from_millis(50));
        bus.publish(SAMPLES, "t", Arc::new(vec![Sample::new("cpu.run_queue", 5.0, Unit::Count)]));
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap().get::<crate::kernel::alerts::Alert>().is_some());
        k.shutdown();
    }
}
