//! Windows: performance counters and WMI, through PowerShell.

use crate::kernel::Capability;

use super::super::metrics::{Metrics, Raw};
use super::super::services::Service;
use super::Probe;

pub struct Windows;

impl Probe for Windows {
    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::yes("scheduling"),
            Capability::yes("disk queue depth"),
            Capability::yes("packet errors"),
            Capability::no("pressure", "Linux PSI has no Windows equivalent"),
            Capability::partly("power", "Windows reports only battery discharge"),
            Capability::yes("services"),
        ]
    }

    fn read(&mut self, m: &mut Metrics) -> Raw {
        use super::super::parse;
        use crate::common::command::{run_command, tool};
        use std::time::Duration;
        const SCRIPT: &str = r#"
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $names = '\System\Context Switches/sec','\System\Processor Queue Length','\Processor(_Total)\Interrupts/sec','\Memory\Page Faults/sec','\Memory\Pages Input/sec','\Memory\Pages Output/sec','\PhysicalDisk(*)\Current Disk Queue Length','\PhysicalDisk(*)\Disk Read Bytes/sec','\PhysicalDisk(*)\Disk Write Bytes/sec','\PhysicalDisk(*)\Disk Transfers/sec','\PhysicalDisk(*)\% Disk Time','\PhysicalDisk(*)\Avg. Disk sec/Transfer','\Network Interface(*)\Bytes Received/sec','\Network Interface(*)\Bytes Sent/sec','\Network Interface(*)\Packets Received Errors','\Network Interface(*)\Packets Outbound Errors','\Network Interface(*)\Packets Received Discarded','\Network Interface(*)\Packets Outbound Discarded','\TCPv4\Segments Retransmitted/sec'
    (Get-Counter -Counter $names -ErrorAction SilentlyContinue).CounterSamples | ForEach-Object { "$($_.Path)|$($_.CookedValue)" }
    try { Get-CimInstance -Namespace root\wmi -ClassName BatteryStatus -ErrorAction Stop | ForEach-Object { "\battery\discharge|$($_.DischargeRate)" } } catch {}
    "#;
        let raw = Raw::default();
        let out = run_command(tool("powershell").args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT]), Duration::from_secs(14));
        let text = match out {
            Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
            Err(e) => {
                m.notes.push(format!("performance counters: {e}"));
                return raw;
            }
        };
        let c = parse::counters(&text);
        if c.is_empty() {
            m.notes.push("performance counters returned nothing (counter names are localised on non-English Windows)".into());
        }
        let one = |suffix: &str| c.iter().find(|(p, _)| p.ends_with(suffix)).map(|(_, v)| *v);
        m.context_switches_per_sec = one("\\context switches/sec");
        m.run_queue = one("\\processor queue length");
        m.interrupts_per_sec = one("\\interrupts/sec");
        m.page_faults_per_sec = one("\\page faults/sec");
        m.swap_in_pages_per_sec = one("\\pages input/sec");
        m.swap_out_pages_per_sec = one("\\pages output/sec");
        m.retransmits_per_sec = one("\\segments retransmitted/sec");
        if let Some(mw) = one("\\battery\\discharge").filter(|v| *v > 0.0) {
            m.power.push(super::super::metrics::Reading { label: "battery".into(), value: mw / 1000.0 });
        }
        // `...\physicaldisk(0 c:)\disk read bytes/sec`: group by the instance.
        let instance = |p: &str, object: &str| -> Option<String> {
            let (_, rest) = p.split_once(object)?;
            Some(rest.split_once(')')?.0.to_string())
        };
        let group = |object: &str| -> Vec<String> {
            let mut names: Vec<String> = c.iter().filter_map(|(p, _)| instance(p, object)).filter(|n| n != "_total").collect();
            names.sort();
            names.dedup();
            names
        };
        let value = |object: &str, name: &str, suffix: &str| c.iter().find(|(p, _)| p.ends_with(suffix) && instance(p, object).as_deref() == Some(name)).map(|(_, v)| *v);
        for name in group("physicaldisk(") {
            let v = |s: &str| value("physicaldisk(", &name, s);
            m.disks.push(super::super::metrics::Disk {
                read_rate: v("\\disk read bytes/sec").unwrap_or(0.0),
                write_rate: v("\\disk write bytes/sec").unwrap_or(0.0),
                iops: v("\\disk transfers/sec").unwrap_or(0.0),
                queue_depth: v("\\current disk queue length"),
                busy_pct: v("\\% disk time").map(|b| b.min(100.0)),
                await_ms: v("\\avg. disk sec/transfer").map(|s| s * 1000.0),
                name,
            });
        }
        for name in group("network interface(") {
            let v = |s: &str| value("network interface(", &name, s).unwrap_or(0.0);
            // Cumulative here, unlike the byte rates.
            let (errs, drops) = (v("\\packets received errors") + v("\\packets outbound errors"), v("\\packets received discarded") + v("\\packets outbound discarded"));
            m.nics.push(super::super::metrics::Nic { rx_rate: v("\\bytes received/sec"), tx_rate: v("\\bytes sent/sec"), errors_total: errs as u64, drops_total: drops as u64, name, ..Default::default() });
        }
        raw
    }

    fn services(&self) -> Result<Vec<Service>, String> {
        let mut c = crate::common::command::tool("powershell");
        c.args(["-NoProfile", "-NonInteractive", "-Command", "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-CimInstance Win32_Service | ForEach-Object { \"$($_.Name)|$($_.State)|$($_.StartMode)|$($_.ProcessId)|$($_.DisplayName)\" }"]);
        super::super::services::run(&mut c, super::super::parse::windows_services)
    }
}
