//! The performance modules: system metrics and services, and GPU load, which
//! is slow enough on Windows to deserve its own schedule.

use std::time::{Duration, Instant};

use super::gpu::{self, GpuSnapshot};
use super::metrics::{samples, Collector, Metrics, INTERVAL};
use super::services::Service;
use crate::kernel::model::{CounterRate, Sample, Unit};
use crate::kernel::module::Importance;
use crate::kernel::{Capability, Context, Module};

pub const METRICS: &str = "performance.metrics";
pub const SERVICES: &str = "performance.services";
pub const GPU: &str = "performance.gpu";

const SERVICES_EVERY: Duration = Duration::from_secs(60);
const GPU_EVERY: Duration = Duration::from_secs(3);

pub struct PerformanceModule {
    collector: Collector,
    listed: Option<Instant>,
    system: sysinfo::System,
    disks: sysinfo::Disks,
    opens: CounterRate,
}

impl PerformanceModule {
    pub fn new() -> Self {
        PerformanceModule { collector: Collector::new(), listed: None, system: sysinfo::System::new(), disks: sysinfo::Disks::new_with_refreshed_list(), opens: CounterRate::default() }
    }
}

impl PerformanceModule {
    /// The percentages alarms are written against.
    fn usage(&mut self) -> Vec<Sample> {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        self.disks.refresh_list();
        let mut out = vec![Sample::new("cpu.usage", f64::from(self.system.global_cpu_usage()), Unit::Percent)];
        let total = self.system.total_memory();
        if total > 0 {
            out.push(Sample::new("memory.used_percent", self.system.used_memory() as f64 * 100.0 / total as f64, Unit::Percent));
        }
        for d in self.disks.list().iter().filter(|d| d.total_space() > 0) {
            let used = 1.0 - d.available_space() as f64 / d.total_space() as f64;
            out.push(Sample::new("disk.used_percent", used * 100.0, Unit::Percent).label("mount", d.mount_point().display().to_string()));
        }
        let snmp = std::fs::read_to_string("/proc/net/snmp").unwrap_or_default();
        let mut lines = snmp.lines().filter(|l| l.starts_with("Tcp:"));
        if let (Some(names), Some(values)) = (lines.next(), lines.next()) {
            let value = |name: &str| names.split_whitespace().position(|n| n == name).and_then(|i| values.split_whitespace().nth(i)).and_then(|v| v.parse::<f64>().ok());
            if let (Some(a), Some(p)) = (value("ActiveOpens"), value("PassiveOpens")) {
                out.extend(self.opens.update("tcp", a + p, Instant::now()).map(|r| Sample::new("net.tcp_opens", r, Unit::PerSecond)));
            }
        }
        out
    }
}

impl Module for PerformanceModule {
    fn capabilities(&self) -> Vec<Capability> {
        self.collector.capabilities()
    }

    fn importance(&self) -> Importance {
        Importance::Core
    }

    fn provides(&self) -> Vec<&'static str> {
        vec!["cpu.", "memory.", "disk.", "net.", "sensor."]
    }

    fn interval(&self) -> Option<Duration> {
        Some(INTERVAL)
    }

    fn watchdog(&self) -> Duration {
        Duration::from_secs(60)
    }

    fn tick(&mut self, ctx: &Context) {
        let m: Metrics = self.collector.sample();
        let mut out = samples(&m);
        out.extend(self.usage());
        ctx.samples(out);
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
