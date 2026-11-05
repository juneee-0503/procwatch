//! macOS: the system's own command-line tools, read every few seconds.

use crate::kernel::Capability;

use super::super::metrics::{Metrics, Raw};
use super::super::services::Service;
use super::Probe;

pub struct MacOs;

impl Probe for MacOs {
    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::no("scheduling", "macOS has no public interface for context switches or the run queue"),
            Capability::no("disk queue depth", "iostat reports throughput only"),
            Capability::yes("packet errors"),
            Capability::no("pressure", "Linux PSI has no macOS equivalent"),
            Capability::partly("power", "only the battery is readable; on mains it shows 0 W. powermetrics needs root"),
            Capability::yes("services"),
        ]
    }

    fn read(&mut self, m: &mut Metrics) -> Raw {
        use super::super::parse;
        use crate::common::command::{run_command, tool};
        use std::time::Duration;
        const T: Duration = Duration::from_secs(6);
        let text = |name: &str, args: &[&str]| -> Option<String> {
            run_command(tool(name).args(args), T).ok().map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        };
        let mut raw = Raw::default();
        if let Some(t) = text("vm_stat", &[]) {
            (raw.page_faults, raw.swap_in_pages, raw.swap_out_pages) = parse::vm_stat(&t);
        }
        if let Some(t) = text("iostat", &["-d", "-c", "2", "-w", "1"]) {
            for (name, tps, mbs) in parse::iostat(&t) {
                m.disks.push(super::super::metrics::Disk { name, iops: tps, read_rate: mbs * 1_048_576.0, ..Default::default() });
            }
        }
        if let Some(t) = text("netstat", &["-ibn"]) {
            raw.nics = parse::netstat_ib(&t);
        }
        raw.retransmits = text("netstat", &["-s", "-p", "tcp"]).and_then(|t| parse::tcp_retrans(&t));
        if let Some(w) = text("ioreg", &["-rn", "AppleSmartBattery"]).and_then(|t| parse::battery_watts(&t)) {
            m.power.push(super::super::metrics::Reading { label: "battery".into(), value: w });
        }
        raw
    }

    fn services(&self) -> Result<Vec<Service>, String> {
        let mut c = crate::common::command::tool("launchctl");
        c.args(["list"]);
        super::super::services::run(&mut c, super::super::parse::launchctl)
    }
}
