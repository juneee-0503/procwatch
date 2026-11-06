//! Every metric: its meaning, kind and how it varies by platform. Rules,
//! storage and documentation all read this one table.

use serde::Serialize;

use super::model::Unit;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A value at a moment. Keep the latest; average to downsample.
    Gauge,
    /// A running total. Only differences mean anything: use `CounterRate`.
    Counter,
    /// A counter already turned into a rate. Average to downsample.
    Rate,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Metric {
    pub name: &'static str,
    pub unit: Unit,
    pub kind: Kind,
    pub meaning: &'static str,
    /// How the figure changes by platform or environment.
    pub caveat: &'static str,
}

const fn m(name: &'static str, unit: Unit, kind: Kind, meaning: &'static str, caveat: &'static str) -> Metric {
    Metric { name, unit, kind, meaning, caveat }
}

const CGROUP: &str = "in a container this may describe the host unless cgroup limits are read";

pub const METRICS: &[Metric] = &[
    m("cpu.usage", Unit::Percent, Kind::Gauge, "share of all CPUs in use", CGROUP),
    m("cpu.run_queue", Unit::Count, Kind::Gauge, "tasks ready to run", "Linux: instantaneous; Windows: processor queue length"),
    m("cpu.blocked", Unit::Count, Kind::Gauge, "tasks waiting on I/O", "Linux only"),
    m("cpu.pressure", Unit::Percent, Kind::Gauge, "time tasks waited for CPU", "Linux PSI only"),
    m("cpu.context_switches", Unit::PerSecond, Kind::Rate, "context switches", "not available on macOS"),
    m("cpu.interrupts", Unit::PerSecond, Kind::Rate, "interrupts", ""),
    m("memory.available", Unit::Bytes, Kind::Gauge, "memory available without swapping", CGROUP),
    m("memory.used_percent", Unit::Percent, Kind::Gauge, "share of memory in use", CGROUP),
    m("memory.swap_used", Unit::Bytes, Kind::Gauge, "swap in use", ""),
    m("memory.page_faults", Unit::PerSecond, Kind::Rate, "page faults", ""),
    m("memory.swap_in", Unit::PerSecond, Kind::Rate, "pages swapped in", ""),
    m("memory.swap_out", Unit::PerSecond, Kind::Rate, "pages swapped out", ""),
    m("memory.pressure", Unit::Percent, Kind::Gauge, "time tasks waited for memory", "Linux PSI only"),
    m("disk.pressure", Unit::Percent, Kind::Gauge, "time tasks waited for I/O", "Linux PSI only"),
    m("disk.used_percent", Unit::Percent, Kind::Gauge, "share of a file system in use", "label mount"),
    m("disk.read", Unit::BytesPerSecond, Kind::Rate, "bytes read", "label device"),
    m("disk.write", Unit::BytesPerSecond, Kind::Rate, "bytes written", "label device"),
    m("disk.iops", Unit::PerSecond, Kind::Rate, "I/O operations", "label device"),
    m("disk.queue_depth", Unit::Count, Kind::Gauge, "requests in flight", "not available on macOS"),
    m("disk.busy", Unit::Percent, Kind::Gauge, "time the device was busy", "not available on macOS"),
    m("disk.await", Unit::Milliseconds, Kind::Gauge, "average request time", "not available on macOS"),
    m("net.rx", Unit::BytesPerSecond, Kind::Rate, "bytes received", "label interface"),
    m("net.tx", Unit::BytesPerSecond, Kind::Rate, "bytes sent", "label interface"),
    m("net.errors", Unit::PerSecond, Kind::Rate, "interface errors", "label interface"),
    m("net.drops", Unit::PerSecond, Kind::Rate, "packets dropped", "label interface"),
    m("net.tcp_retransmits", Unit::PerSecond, Kind::Rate, "TCP retransmissions", ""),
    m("net.tcp_opens", Unit::PerSecond, Kind::Rate, "TCP connections opened, both directions", "Linux only"),
    m("sensor.temperature", Unit::Celsius, Kind::Gauge, "a temperature sensor", "label sensor; rarely present in virtual machines"),
    m("sensor.power", Unit::Watts, Kind::Gauge, "a power sensor", "label sensor"),
    m("defense.threats", Unit::Count, Kind::Counter, "findings since start", "label severity; resets on restart"),
    m("defense.baseline_hours", Unit::Count, Kind::Gauge, "hours of the week learned", "of 168"),
    m("defense.syns_lost", Unit::Count, Kind::Counter, "SYN records lost", "resets on restart"),
    m("defense.ebpf_events", Unit::Count, Kind::Counter, "system call records read", "resets on restart"),
    m("defense.ebpf_lost", Unit::Count, Kind::Counter, "system call records lost", "resets on restart"),
    m("kernel.bus_dropped", Unit::Count, Kind::Counter, "events lost to full queues", "resets on restart"),
    m("kernel.bus_published", Unit::Count, Kind::Counter, "events published", "resets on restart"),
    m("kernel.cpu", Unit::Percent, Kind::Gauge, "procwatch's own CPU use", "percent of one core"),
    m("kernel.memory", Unit::Bytes, Kind::Gauge, "procwatch's own resident memory", ""),
    m("kernel.degraded", Unit::Count, Kind::Gauge, "1 when load has slowed collection", ""),
    m("kernel.module_tick", Unit::Milliseconds, Kind::Gauge, "how long a module's last collection took", "label module"),
    m("kernel.module_queue", Unit::Count, Kind::Gauge, "events waiting for a module", "label module"),
    m("kernel.module_restarts", Unit::Count, Kind::Counter, "restarts of a module", "label module"),
    m("alarm.firing", Unit::Count, Kind::Gauge, "alarms firing now", ""),
    m("alarm.eval_ms", Unit::Milliseconds, Kind::Gauge, "last rule evaluation time", ""),
    m("alarm.notify_failed", Unit::Count, Kind::Counter, "notifications that couldn't be delivered", "resets on restart"),
];

#[cfg(test)]
pub fn lookup(name: &str) -> Option<&'static Metric> {
    METRICS.iter().find(|m| m.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_and_well_formed() {
        let mut names: Vec<_> = METRICS.iter().map(|m| m.name).collect();
        names.sort_unstable();
        let total = names.len();
        names.dedup();
        assert_eq!(names.len(), total);
        assert!(names.iter().all(|n| n.contains('.') && n.chars().all(|c| c.is_ascii_lowercase() || c == '.' || c == '_')));
    }

    /// A metric missing from the table has no agreed meaning.
    #[test]
    fn everything_published_is_in_the_dictionary() {
        for file in [include_str!("../performance/metrics.rs"), include_str!("../performance/module.rs"), include_str!("../defense/module.rs"), include_str!("supervisor.rs")] {
            for part in file.split("Sample::new(\"").skip(1) {
                let name = part.split('"').next().unwrap_or("");
                assert!(lookup(name).is_some(), "{name} isn't in the dictionary");
            }
        }
    }
}
