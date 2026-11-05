//! Linux: `/proc`, `/sys`, systemd.

use crate::kernel::Capability;

use super::super::metrics::{Metrics, Raw};
use super::super::services::Service;
use super::Probe;

pub struct Linux;

impl Probe for Linux {
    fn capabilities(&self) -> Vec<Capability> {
        let exists = |p: &str| std::path::Path::new(p).exists();
        vec![
            Capability::yes("scheduling"),
            Capability::yes("disk queue depth"),
            Capability::yes("packet errors"),
            if exists("/proc/pressure/cpu") { Capability::yes("pressure") } else { Capability::no("pressure", "this kernel has no PSI (CONFIG_PSI)") },
            if exists("/sys/class/powercap") { Capability::partly("power", "RAPL energy counters need root") } else { Capability::partly("power", "only batteries report here") },
            if exists("/run/systemd/system") { Capability::yes("services") } else { Capability::no("services", "systemd isn't running") },
        ]
    }

    fn read(&mut self, m: &mut Metrics) -> Raw {
        use super::super::parse;
        use std::fs::read_to_string as file;
        let mut raw = Raw::default();
        match file("/proc/stat") {
            Ok(t) => {
                let (ctx, intr, running, blocked) = parse::proc_stat(&t);
                (raw.context_switches, raw.interrupts) = (ctx, intr);
                m.run_queue = running.map(|v| v as f64);
                m.blocked = blocked.map(|v| v as f64);
            }
            Err(e) => m.notes.push(format!("/proc/stat: {e}")),
        }
        if let Ok(t) = file("/proc/vmstat") {
            (raw.page_faults, raw.major_faults, raw.swap_in_pages, raw.swap_out_pages) = parse::vmstat(&t);
        }
        if let Ok(t) = file("/proc/diskstats") {
            // Only whole devices: partitions would count everything twice.
            raw.disks = parse::diskstats(&t).into_iter().filter(|d| !d.name.starts_with("loop") && !d.name.starts_with("ram") && std::path::Path::new("/sys/block").join(&d.name).exists()).collect();
        }
        if let Ok(t) = file("/proc/net/dev") {
            raw.nics = parse::net_dev(&t);
        }
        raw.retransmits = file("/proc/net/snmp").ok().and_then(|t| parse::snmp_retrans(&t));
        let psi = |p: &str| file(format!("/proc/pressure/{p}")).ok().and_then(|t| parse::psi(&t));
        (m.cpu_pressure, m.memory_pressure, m.io_pressure) = (psi("cpu"), psi("memory"), psi("io"));
        for e in std::fs::read_dir("/sys/class/powercap").into_iter().flatten().flatten() {
            let p = e.path();
            // Top-level packages only: their sub-zones are part of them.
            if p.file_name().is_some_and(|n| n.to_string_lossy().matches(':').count() == 1) {
                if let (Ok(name), Ok(uj)) = (file(p.join("name")), file(p.join("energy_uj"))) {
                    if let Ok(v) = uj.trim().parse() {
                        raw.energy.push((name.trim().to_string(), v));
                    }
                }
            }
        }
        for e in std::fs::read_dir("/sys/class/power_supply").into_iter().flatten().flatten() {
            let p = e.path();
            if let Some(uw) = file(p.join("power_now")).ok().and_then(|t| t.trim().parse::<f64>().ok()) {
                m.power.push(super::super::metrics::Reading { label: e.file_name().to_string_lossy().into_owned(), value: uw / 1e6 });
            }
        }
        raw
    }

    fn services(&self) -> Result<Vec<Service>, String> {
        let mut c = crate::common::command::tool("systemctl");
        c.args(["list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager"]);
        super::super::services::run(&mut c, super::super::parse::systemctl)
    }
}
