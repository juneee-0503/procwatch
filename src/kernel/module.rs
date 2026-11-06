//! What a module is. A module says what it can do here, reacts to ticks and
//! bus events, and publishes what it finds. It never calls another module.

use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use super::alarm::{AlarmEvent, Hub, Input};
use super::bus::{Bus, Event};
use super::model::{Sample, SAMPLES};

/// Whether something works on this system. Absent features are declared, so
/// the interface can say so instead of showing a zero or an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "support", content = "reason", rename_all = "snake_case")]
pub enum Support {
    Yes,
    /// Works, but limited; the reason says how.
    Partly(String),
    No(String),
}

impl Support {
    pub fn label(&self) -> &'static str {
        match self {
            Support::Yes => "supported",
            Support::Partly(_) => "partial",
            Support::No(_) => "not supported",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Capability {
    pub name: &'static str,
    pub support: Support,
}

impl Capability {
    pub fn new(name: &'static str, support: Support) -> Capability {
        Capability { name, support }
    }
    pub fn yes(name: &'static str) -> Capability {
        Capability::new(name, Support::Yes)
    }
    pub fn partly(name: &'static str, why: impl Into<String>) -> Capability {
        Capability::new(name, Support::Partly(why.into()))
    }
    pub fn no(name: &'static str, why: impl Into<String>) -> Capability {
        Capability::new(name, Support::No(why.into()))
    }
}

/// What the kernel gives a module. Tied to one run of the module: after a
/// restart, anything the old instance still publishes is discarded.
#[derive(Clone)]
pub struct Context {
    pub(super) name: &'static str,
    pub(super) bus: Bus,
    pub(super) generation: u64,
    pub(super) current: Arc<AtomicU64>,
    pub(super) hub: Hub,
    pub(super) health: Arc<RunHealth>,
}

/// What a run has told the kernel about itself.
#[derive(Default)]
pub struct RunHealth {
    /// Errors in a row; a success resets it.
    pub(super) errors: AtomicU64,
    pub(super) total_errors: AtomicU64,
    pub(super) degraded: std::sync::Mutex<Option<String>>,
}

impl Context {
    /// False once this run has been replaced or stopped.
    pub fn current(&self) -> bool {
        self.current.load(Ordering::Relaxed) == self.generation
    }

    pub fn publish<T: Any + Send + Sync>(&self, topic: &'static str, payload: T) {
        if self.current() {
            self.bus.publish(topic, self.name, Arc::new(payload));
        }
    }

    /// Raise an alarm. These never go by the bus, where they could be lost.
    pub fn raise(&self, event: AlarmEvent, lasts: Option<Duration>) {
        if self.current() {
            self.hub.send(Input::Raise { event, lasts });
        }
    }

    pub fn alarms(&self) -> &Hub {
        &self.hub
    }

    /// A collection failed. A few are normal; many in a row and the kernel
    /// treats the module as broken.
    pub fn error(&self) {
        self.health.errors.fetch_add(1, Ordering::Relaxed);
        self.health.total_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// A collection worked.
    pub fn ok(&self) {
        self.health.errors.store(0, Ordering::Relaxed);
    }

    /// Running, but with less than it could offer, such as without the
    /// privileges for part of its work. None when back to full strength.
    pub fn degraded(&self, reason: Option<String>) {
        if let Ok(mut d) = self.health.degraded.lock() {
            *d = reason;
        }
    }

    pub fn samples(&self, samples: Vec<Sample>) {
        if !samples.is_empty() {
            self.publish(SAMPLES, samples);
        }
    }
}

/// What to give up first when the machine is busiest. Monitoring must not
/// add to the load at the moment it matters most.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Importance {
    /// Paused first.
    Optional,
    /// Slowed down.
    Normal,
    /// Keeps its pace.
    Core,
}

pub trait Module: Send {
    /// What works here, and what doesn't and why.
    fn capabilities(&self) -> Vec<Capability>;

    fn importance(&self) -> Importance {
        Importance::Normal
    }

    /// Metric prefixes this module provides. If it stops, alarms about them
    /// say nothing true, and are silenced.
    fn provides(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// Run when loaded, before the module starts: can it work here?
    fn self_test(&mut self) -> Result<String, String> {
        Ok("ok".to_string())
    }

    /// Topics to receive in `on_event`.
    fn subscribes(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// Prepare to run. An error means unavailable here, which isn't a crash
    /// and doesn't trigger restarts.
    fn start(&mut self, _ctx: &Context) -> Result<(), String> {
        Ok(())
    }

    /// How often `tick` runs; None for modules driven only by events.
    fn interval(&self) -> Option<Duration> {
        None
    }

    fn tick(&mut self, _ctx: &Context) {}

    fn on_event(&mut self, _event: &Event, _ctx: &Context) {}

    fn stop(&mut self) {}

    /// Longest a single tick or event may take before it counts as stuck.
    fn watchdog(&self) -> Duration {
        Duration::from_secs(30)
    }
}
