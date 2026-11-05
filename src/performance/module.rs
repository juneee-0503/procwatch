//! The performance modules: system metrics and services, and GPU load, which
//! is slow enough on Windows to deserve its own schedule.

use std::time::{Duration, Instant};

use super::gpu::{self, GpuSnapshot};
use super::metrics::{samples, Collector, Metrics, INTERVAL};
use super::services::Service;
use crate::kernel::{Capability, Context, Module};

pub const METRICS: &str = "performance.metrics";
pub const SERVICES: &str = "performance.services";
pub const GPU: &str = "performance.gpu";

const SERVICES_EVERY: Duration = Duration::from_secs(60);
const GPU_EVERY: Duration = Duration::from_secs(3);

pub struct PerformanceModule {
    collector: Collector,
    listed: Option<Instant>,
}

impl PerformanceModule {
    pub fn new() -> Self {
        PerformanceModule { collector: Collector::new(), listed: None }
    }
}

impl Module for PerformanceModule {
    fn capabilities(&self) -> Vec<Capability> {
        self.collector.capabilities()
    }

    fn interval(&self) -> Option<Duration> {
        Some(INTERVAL)
    }

    fn watchdog(&self) -> Duration {
        Duration::from_secs(60)
    }

    fn tick(&mut self, ctx: &Context) {
        let m: Metrics = self.collector.sample();
        ctx.samples(samples(&m));
        ctx.publish(METRICS, m);
        if self.listed.is_none_or(|t| t.elapsed() >= SERVICES_EVERY) {
            self.listed = Some(Instant::now());
            ctx.publish::<Result<Vec<Service>, String>>(SERVICES, self.collector.services());
        }
    }
}

#[derive(Default)]
pub struct GpuModule {
    unavailable: bool,
}

impl Module for GpuModule {
    fn capabilities(&self) -> Vec<Capability> {
        vec![if cfg!(any(target_os = "macos", windows)) {
            Capability::partly("gpu load", "system-wide only; no platform has a stable per-process interface")
        } else {
            Capability::no("gpu load", "no probe for this platform")
        }]
    }

    fn interval(&self) -> Option<Duration> {
        (!self.unavailable).then_some(GPU_EVERY)
    }

    fn watchdog(&self) -> Duration {
        Duration::from_secs(60)
    }

    fn tick(&mut self, ctx: &Context) {
        let snap: GpuSnapshot = gpu::system_gpu_usage();
        self.unavailable = !snap.available;
        ctx.publish(GPU, snap);
    }
}
