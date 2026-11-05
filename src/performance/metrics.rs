//! System-wide health figures beyond CPU and memory percentages: scheduling,
//! paging, disk queues, network errors, temperature and power.
//!
//! Each figure is optional. What this system doesn't expose stays `None`
//! with a reason in `notes`: an invented zero would read as "all fine".

use std::time::{Duration, Instant};

use serde::Serialize;

use crate::kernel::{Capability, Sample, Support, Unit};

/// Cumulative counters of one disk.
#[derive(Debug, Clone, Default)]
pub struct RawDisk {
    pub name: String,
    pub read_ops: u64,
    pub write_ops: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ms: u64,
    pub write_ms: u64,
    pub busy_ms: u64,
    pub weighted_ms: u64,
}

/// Cumulative counters of one network interface.
#[derive(Debug, Clone, Default)]
pub struct RawNic {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errs: u64,
    pub tx_errs: u64,
    pub rx_drop: u64,
    pub tx_drop: u64,
}

/// Everything that needs a previous sample to mean anything.
#[derive(Debug, Clone, Default)]
pub struct Raw {
    pub context_switches: Option<u64>,
    pub interrupts: Option<u64>,
    pub page_faults: Option<u64>,
    pub major_faults: Option<u64>,
    pub swap_in_pages: Option<u64>,
    pub swap_out_pages: Option<u64>,
    pub retransmits: Option<u64>,
    pub disks: Vec<RawDisk>,
    pub nics: Vec<RawNic>,
    /// Energy counters in microjoules, by name.
    pub energy: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Disk {
    pub name: String,
    pub read_rate: f64,
    pub write_rate: f64,
    pub iops: f64,
    /// Requests waiting or in service, averaged over the interval.
    pub queue_depth: Option<f64>,
    /// Share of time the device was busy, 0–100.
    pub busy_pct: Option<f64>,
    /// Average time per request.
    pub await_ms: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Nic {
    pub name: String,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub errors_total: u64,
    pub drops_total: u64,
    pub errors_per_sec: f64,
    pub drops_per_sec: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Reading {
    pub label: String,
    pub value: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Metrics {
    pub context_switches_per_sec: Option<f64>,
    pub interrupts_per_sec: Option<f64>,
    /// Threads ready to run or running.
    pub run_queue: Option<f64>,
    /// Threads waiting for disk.
    pub blocked: Option<f64>,
    pub page_faults_per_sec: Option<f64>,
    pub major_faults_per_sec: Option<f64>,
    pub swap_in_pages_per_sec: Option<f64>,
    pub swap_out_pages_per_sec: Option<f64>,
    pub available_memory: Option<u64>,
    pub total_memory: Option<u64>,
    pub swap_used: Option<u64>,
    pub swap_total: Option<u64>,
    /// Share of time something stalled over 10 s (Linux PSI).
    pub cpu_pressure: Option<f32>,
    pub memory_pressure: Option<f32>,
    pub io_pressure: Option<f32>,
    pub retransmits_per_sec: Option<f64>,
    pub disks: Vec<Disk>,
    pub nics: Vec<Nic>,
    /// Degrees Celsius.
    pub temperatures: Vec<Reading>,
    /// Watts.
    pub power: Vec<Reading>,
    /// What isn't available here, and why.
    pub notes: Vec<String>,
}

fn rate(now: Option<u64>, before: Option<u64>, secs: f64) -> Option<f64> {
    Some(now?.saturating_sub(before?) as f64 / secs)
}

/// Rates between two samples. A disk or interface that just appeared has no
/// rate yet rather than its lifetime total as one.
pub fn derive(now: &Raw, before: &Raw, secs: f64, m: &mut Metrics) {
    let secs = secs.max(0.001);
    m.context_switches_per_sec = m.context_switches_per_sec.or(rate(now.context_switches, before.context_switches, secs));
    m.interrupts_per_sec = m.interrupts_per_sec.or(rate(now.interrupts, before.interrupts, secs));
    m.page_faults_per_sec = m.page_faults_per_sec.or(rate(now.page_faults, before.page_faults, secs));
    m.major_faults_per_sec = m.major_faults_per_sec.or(rate(now.major_faults, before.major_faults, secs));
    m.swap_in_pages_per_sec = m.swap_in_pages_per_sec.or(rate(now.swap_in_pages, before.swap_in_pages, secs));
    m.swap_out_pages_per_sec = m.swap_out_pages_per_sec.or(rate(now.swap_out_pages, before.swap_out_pages, secs));
    m.retransmits_per_sec = m.retransmits_per_sec.or(rate(now.retransmits, before.retransmits, secs));
    for d in &now.disks {
        let Some(p) = before.disks.iter().find(|x| x.name == d.name) else { continue };
        let (ops, ms) = ((d.read_ops + d.write_ops).saturating_sub(p.read_ops + p.write_ops), (d.read_ms + d.write_ms).saturating_sub(p.read_ms + p.write_ms));
        m.disks.push(Disk {
            name: d.name.clone(),
            read_rate: d.read_bytes.saturating_sub(p.read_bytes) as f64 / secs,
            write_rate: d.write_bytes.saturating_sub(p.write_bytes) as f64 / secs,
            iops: ops as f64 / secs,
            queue_depth: Some(d.weighted_ms.saturating_sub(p.weighted_ms) as f64 / (secs * 1000.0)),
            busy_pct: Some((d.busy_ms.saturating_sub(p.busy_ms) as f64 / (secs * 10.0)).min(100.0)),
            await_ms: (ops > 0).then(|| ms as f64 / ops as f64),
        });
    }
    for n in &now.nics {
        let Some(p) = before.nics.iter().find(|x| x.name == n.name) else { continue };
        let errs = (n.rx_errs + n.tx_errs, p.rx_errs + p.tx_errs);
        let drops = (n.rx_drop + n.tx_drop, p.rx_drop + p.tx_drop);
        m.nics.push(Nic {
            name: n.name.clone(),
            rx_rate: n.rx_bytes.saturating_sub(p.rx_bytes) as f64 / secs,
            tx_rate: n.tx_bytes.saturating_sub(p.tx_bytes) as f64 / secs,
            errors_total: errs.0,
            drops_total: drops.0,
            errors_per_sec: errs.0.saturating_sub(errs.1) as f64 / secs,
            drops_per_sec: drops.0.saturating_sub(drops.1) as f64 / secs,
        });
    }
    for (name, uj) in &now.energy {
        if let Some((_, p)) = before.energy.iter().find(|(n, _)| n == name) {
            m.power.push(Reading { label: name.clone(), value: uj.saturating_sub(*p) as f64 / 1e6 / secs });
        }
    }
}

/// How often each platform's sources may reasonably be read: tools and
/// PowerShell cost far more than `/proc`.
pub const INTERVAL: Duration = if cfg!(target_os = "linux") {
    Duration::from_secs(2)
} else if cfg!(windows) {
    Duration::from_secs(15)
} else {
    Duration::from_secs(5)
};

/// Reads this system's sources, keeping what rates need.
pub struct Collector {
    probe: Box<dyn super::probes::Probe>,
    previous: Option<(Raw, Instant)>,
    components: sysinfo::Components,
    system: sysinfo::System,
}

impl Collector {
    pub fn new() -> Collector {
        Collector { probe: super::probes::create(), previous: None, components: sysinfo::Components::new_with_refreshed_list(), system: sysinfo::System::new() }
    }

    /// One sample. The first has no rates.
    pub fn sample(&mut self) -> Metrics {
        let mut m = Metrics::default();
        self.system.refresh_memory();
        m.available_memory = Some(self.system.available_memory());
        m.total_memory = Some(self.system.total_memory());
        m.swap_used = Some(self.system.used_swap());
        m.swap_total = Some(self.system.total_swap());
        let raw = self.probe.read(&mut m);
        for c in self.components.list_mut() {
            c.refresh();
        }
        m.temperatures = self.components.iter().map(|c| (c.label(), c.temperature())).filter(|(_, t)| t.is_finite() && *t > 0.0).map(|(l, t)| Reading { label: l.to_string(), value: f64::from(t) }).collect();
        let now = Instant::now();
        if let Some((before, at)) = &self.previous {
            derive(&raw, before, now.duration_since(*at).as_secs_f64(), &mut m);
        }
        self.previous = Some((raw, now));
        for c in self.probe.capabilities() {
            match c.support {
                Support::Yes => {}
                Support::Partly(why) | Support::No(why) => m.notes.push(format!("{}: {why}", c.name)),
            }
        }
        if m.temperatures.is_empty() {
            m.notes.push("temperature: no sensors readable here".into());
        }
        m
    }

    pub fn capabilities(&self) -> Vec<Capability> {
        self.probe.capabilities()
    }

    pub fn services(&self) -> Result<Vec<super::services::Service>, String> {
        self.probe.services()
    }
}

/// The same figures under the unified model's names and units, which is what
/// alert rules see on every platform.
pub fn samples(m: &Metrics) -> Vec<Sample> {
    let mut out = Vec::new();
    let mut opt = |name: &'static str, v: Option<f64>, unit: Unit| out.extend(v.map(|v| Sample::new(name, v, unit)));
    opt("cpu.context_switches", m.context_switches_per_sec, Unit::PerSecond);
    opt("cpu.interrupts", m.interrupts_per_sec, Unit::PerSecond);
    opt("cpu.run_queue", m.run_queue, Unit::Count);
    opt("cpu.blocked", m.blocked, Unit::Count);
    opt("cpu.pressure", m.cpu_pressure.map(f64::from), Unit::Percent);
    opt("memory.available", m.available_memory.map(|v| v as f64), Unit::Bytes);
    opt("memory.swap_used", m.swap_used.map(|v| v as f64), Unit::Bytes);
    opt("memory.page_faults", m.page_faults_per_sec, Unit::PerSecond);
    opt("memory.swap_in", m.swap_in_pages_per_sec, Unit::PerSecond);
    opt("memory.swap_out", m.swap_out_pages_per_sec, Unit::PerSecond);
    opt("memory.pressure", m.memory_pressure.map(f64::from), Unit::Percent);
    opt("disk.pressure", m.io_pressure.map(f64::from), Unit::Percent);
    opt("net.tcp_retransmits", m.retransmits_per_sec, Unit::PerSecond);
    for d in &m.disks {
        let device = || d.name.clone();
        out.push(Sample::new("disk.read", d.read_rate, Unit::BytesPerSecond).label("device", device()));
        out.push(Sample::new("disk.write", d.write_rate, Unit::BytesPerSecond).label("device", device()));
        out.push(Sample::new("disk.iops", d.iops, Unit::PerSecond).label("device", device()));
        out.extend(d.queue_depth.map(|v| Sample::new("disk.queue_depth", v, Unit::Count).label("device", device())));
        out.extend(d.busy_pct.map(|v| Sample::new("disk.busy", v, Unit::Percent).label("device", device())));
        out.extend(d.await_ms.map(|v| Sample::new("disk.await", v, Unit::Milliseconds).label("device", device())));
    }
    for n in &m.nics {
        let nic = || n.name.clone();
        out.push(Sample::new("net.rx", n.rx_rate, Unit::BytesPerSecond).label("interface", nic()));
        out.push(Sample::new("net.tx", n.tx_rate, Unit::BytesPerSecond).label("interface", nic()));
        out.push(Sample::new("net.errors", n.errors_per_sec, Unit::PerSecond).label("interface", nic()));
        out.push(Sample::new("net.drops", n.drops_per_sec, Unit::PerSecond).label("interface", nic()));
    }
    for t in &m.temperatures {
        out.push(Sample::new("sensor.temperature", t.value, Unit::Celsius).label("sensor", t.label.clone()));
    }
    for p in &m.power {
        out.push(Sample::new("sensor.power", p.value, Unit::Watts).label("sensor", p.label.clone()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(ops: u64, bytes: u64, busy: u64, weighted: u64) -> RawDisk {
        RawDisk { name: "sda".into(), read_ops: ops, read_bytes: bytes, read_ms: ops * 2, busy_ms: busy, weighted_ms: weighted, ..Default::default() }
    }

    #[test]
    fn rates_come_from_differences() {
        let before = Raw { context_switches: Some(100), disks: vec![disk(0, 0, 0, 0)], nics: vec![RawNic { name: "eth0".into(), ..Default::default() }], energy: vec![("cpu".into(), 0)], ..Default::default() };
        let now = Raw {
            context_switches: Some(300),
            disks: vec![disk(100, 2000, 1000, 4000), RawDisk { name: "new".into(), read_ops: 9, ..Default::default() }],
            nics: vec![RawNic { name: "eth0".into(), rx_bytes: 4000, rx_errs: 2, tx_drop: 4, ..Default::default() }],
            energy: vec![("cpu".into(), 30_000_000)],
            ..Default::default()
        };
        let mut m = Metrics::default();
        derive(&now, &before, 2.0, &mut m);
        assert_eq!(m.context_switches_per_sec, Some(100.0));
        assert_eq!(m.interrupts_per_sec, None, "unknown stays unknown");
        assert_eq!(m.disks.len(), 1, "a new device has no rate yet");
        let d = &m.disks[0];
        assert_eq!((d.iops, d.read_rate, d.queue_depth, d.busy_pct, d.await_ms), (50.0, 1000.0, Some(2.0), Some(50.0), Some(2.0)));
        assert_eq!((m.nics[0].rx_rate, m.nics[0].errors_per_sec, m.nics[0].drops_per_sec), (2000.0, 1.0, 2.0));
        assert_eq!(m.power[0].value, 15.0);
    }

    #[test]
    fn counters_that_go_backwards_never_produce_garbage() {
        let (before, now) = (Raw { context_switches: Some(500), ..Default::default() }, Raw { context_switches: Some(10), ..Default::default() });
        let mut m = Metrics::default();
        derive(&now, &before, 1.0, &mut m);
        assert_eq!(m.context_switches_per_sec, Some(0.0));
    }

    #[test]
    fn values_get_unified_names_and_units_and_absence_stays_absent() {
        let m = Metrics { run_queue: Some(3.0), disks: vec![Disk { name: "sda".into(), queue_depth: Some(2.0), ..Default::default() }], ..Default::default() };
        let s = samples(&m);
        assert!(s.iter().any(|x| x.metric == "cpu.run_queue" && x.unit == Unit::Count));
        assert!(s.iter().any(|x| x.metric == "disk.queue_depth" && x.labels[0].1 == "sda"));
        assert!(!s.iter().any(|x| x.metric == "cpu.context_switches"), "unknown isn't zero");
        assert!(!s.iter().any(|x| x.metric == "disk.busy"));
    }

    #[test]
    fn a_real_sample_never_panics() {
        let mut c = Collector::new();
        let first = c.sample();
        assert!(first.available_memory.is_some());
        let _ = c.sample();
    }
}
