//! Reading each operating system's sources.

use super::metrics::{Metrics, Raw};

#[cfg(target_os = "linux")]
pub const POWER_NOTE: &str = "power: no RAPL or battery readings (RAPL needs root)";
#[cfg(target_os = "macos")]
pub const POWER_NOTE: &str = "power: only the battery is readable; on mains it shows 0 W. powermetrics needs root";
#[cfg(windows)]
pub const POWER_NOTE: &str = "power: Windows reports only battery discharge";
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub const POWER_NOTE: &str = "power: not available on this platform";

#[cfg(target_os = "linux")]
pub fn read(m: &mut Metrics) -> Raw {
    use super::parse;
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
    if m.cpu_pressure.is_none() {
        m.notes.push("pressure: this kernel has no PSI (CONFIG_PSI)".into());
    }
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
            m.power.push(super::metrics::Reading { label: e.file_name().to_string_lossy().into_owned(), value: uw / 1e6 });
        }
    }
    raw
}

#[cfg(target_os = "macos")]
pub fn read(m: &mut Metrics) -> Raw {
    use super::parse;
    use crate::common::command::{run_command, tool};
    use std::time::Duration;
    const T: Duration = Duration::from_secs(6);
    let text = |name: &str, args: &[&str]| -> Option<String> {
        run_command(tool(name).args(args), T).ok().map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    };
    let mut raw = Raw::default();
    m.notes.push("context switches, interrupts, disk queue depth and pressure: macOS has no public interface for these".into());
    if let Some(t) = text("vm_stat", &[]) {
        (raw.page_faults, raw.swap_in_pages, raw.swap_out_pages) = parse::vm_stat(&t);
    }
    if let Some(t) = text("iostat", &["-d", "-c", "2", "-w", "1"]) {
        for (name, tps, mbs) in parse::iostat(&t) {
            m.disks.push(super::metrics::Disk { name, iops: tps, read_rate: mbs * 1_048_576.0, ..Default::default() });
        }
    }
    if let Some(t) = text("netstat", &["-ibn"]) {
        raw.nics = parse::netstat_ib(&t);
    }
    raw.retransmits = text("netstat", &["-s", "-p", "tcp"]).and_then(|t| parse::tcp_retrans(&t));
    if let Some(w) = text("ioreg", &["-rn", "AppleSmartBattery"]).and_then(|t| parse::battery_watts(&t)) {
        m.power.push(super::metrics::Reading { label: "battery".into(), value: w });
    }
    raw
}

#[cfg(windows)]
pub fn read(m: &mut Metrics) -> Raw {
    use super::parse;
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
    m.notes.push("pressure: Windows has no equivalent of Linux PSI".into());
    let one = |suffix: &str| c.iter().find(|(p, _)| p.ends_with(suffix)).map(|(_, v)| *v);
    m.context_switches_per_sec = one("\\context switches/sec");
    m.run_queue = one("\\processor queue length");
    m.interrupts_per_sec = one("\\interrupts/sec");
    m.page_faults_per_sec = one("\\page faults/sec");
    m.swap_in_pages_per_sec = one("\\pages input/sec");
    m.swap_out_pages_per_sec = one("\\pages output/sec");
    m.retransmits_per_sec = one("\\segments retransmitted/sec");
    if let Some(mw) = one("\\battery\\discharge").filter(|v| *v > 0.0) {
        m.power.push(super::metrics::Reading { label: "battery".into(), value: mw / 1000.0 });
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
        m.disks.push(super::metrics::Disk {
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
        m.nics.push(super::metrics::Nic { rx_rate: v("\\bytes received/sec"), tx_rate: v("\\bytes sent/sec"), errors_total: errs as u64, drops_total: drops as u64, name, ..Default::default() });
    }
    raw
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn read(_m: &mut Metrics) -> Raw {
    Raw::default()
}
