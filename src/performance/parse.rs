//! Parsers for what each system reports. Pure functions over text, kept
//! away from the platform code so all of them can be tested anywhere.
//! Each platform build uses only its own, hence the allowance below.
#![cfg_attr(not(test), allow(dead_code))]

use super::metrics::{RawDisk, RawNic};
use super::services::{Service, ServiceState};

/// One number after a key, in `key value` lines.
fn after<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix([' ', ':', '\t'])).map(str::trim))
}

fn num(text: &str, key: &str) -> Option<u64> {
    after(text, key)?.split_whitespace().next()?.parse().ok()
}

// ── Linux ───────────────────────────────────────────────────────────────

/// `/proc/stat`: context switches, interrupts, runnable, blocked.
pub fn proc_stat(text: &str) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
    (num(text, "ctxt"), num(text, "intr"), num(text, "procs_running"), num(text, "procs_blocked"))
}

/// `/proc/vmstat`: page faults, major faults, pages swapped in and out.
pub fn vmstat(text: &str) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
    (num(text, "pgfault"), num(text, "pgmajfault"), num(text, "pswpin"), num(text, "pswpout"))
}

/// `/proc/diskstats`, which counts in 512-byte sectors.
pub fn diskstats(text: &str) -> Vec<RawDisk> {
    const SECTOR: u64 = 512;
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let n = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok());
            Some(RawDisk {
                name: f.get(2)?.to_string(),
                read_ops: n(3)?,
                read_bytes: n(5)?.saturating_mul(SECTOR),
                read_ms: n(6)?,
                write_ops: n(7)?,
                write_bytes: n(9)?.saturating_mul(SECTOR),
                write_ms: n(10)?,
                busy_ms: n(12)?,
                weighted_ms: n(13)?,
            })
        })
        .collect()
}

/// `/proc/net/dev`.
pub fn net_dev(text: &str) -> Vec<RawNic> {
    text.lines()
        .filter_map(|l| {
            let (name, rest) = l.split_once(':')?;
            let f: Vec<u64> = rest.split_whitespace().filter_map(|v| v.parse().ok()).collect();
            Some(RawNic {
                name: name.trim().to_string(),
                rx_bytes: *f.first()?,
                rx_errs: *f.get(2)?,
                rx_drop: *f.get(3)?,
                tx_bytes: *f.get(8)?,
                tx_errs: *f.get(10)?,
                tx_drop: *f.get(11)?,
            })
        })
        .collect()
}

/// TCP segments retransmitted, from `/proc/net/snmp`: a header line names
/// the columns of the line after it.
pub fn snmp_retrans(text: &str) -> Option<u64> {
    let mut lines = text.lines().filter(|l| l.starts_with("Tcp:"));
    let (head, values) = (lines.next()?, lines.next()?);
    let at = head.split_whitespace().position(|c| c == "RetransSegs")?;
    values.split_whitespace().nth(at)?.parse().ok()
}

/// The share of time something was stalled over the last 10 seconds, from
/// `/proc/pressure/*`.
pub fn psi(text: &str) -> Option<f32> {
    text.lines().find(|l| l.starts_with("some"))?.split_whitespace().find_map(|f| f.strip_prefix("avg10="))?.parse().ok()
}

/// `systemctl list-units --type=service --all --plain --no-legend`.
pub fn systemctl(text: &str) -> Vec<Service> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let name = f.next()?.trim_end_matches(".service").to_string();
            let (_load, active, sub) = (f.next()?, f.next()?, f.next()?);
            let state = match (active, sub) {
                ("failed", _) => ServiceState::Failed,
                ("active", "running") => ServiceState::Running,
                ("active", _) | ("activating", _) | ("reloading", _) | ("deactivating", _) => ServiceState::Other,
                _ => ServiceState::Stopped,
            };
            Some(Service { name, state, pid: None, detail: f.collect::<Vec<_>>().join(" ") })
        })
        .collect()
}

// ── macOS ───────────────────────────────────────────────────────────────

/// `vm_stat`: page faults, pages swapped in and out.
pub fn vm_stat(text: &str) -> (Option<u64>, Option<u64>, Option<u64>) {
    let get = |k: &str| after(text, k).and_then(|v| v.trim_end_matches('.').parse().ok());
    (get("Translation faults"), get("Swapins"), get("Swapouts"))
}

/// The last sample of `iostat -d -c 2 -w 1`: per disk, transfers per second
/// and megabytes per second.
pub fn iostat(text: &str) -> Vec<(String, f64, f64)> {
    let lines: Vec<&str> = text.lines().collect();
    let Some(names) = lines.first() else { return Vec::new() };
    let Some(last) = lines.last().filter(|_| lines.len() >= 3) else { return Vec::new() };
    let values: Vec<f64> = last.split_whitespace().filter_map(|v| v.parse().ok()).collect();
    names.split_whitespace().enumerate().filter_map(|(i, n)| Some((n.to_string(), *values.get(i * 3 + 1)?, *values.get(i * 3 + 2)?))).collect()
}

/// `netstat -ibn`: the link line of each interface.
pub fn netstat_ib(text: &str) -> Vec<RawNic> {
    let mut out: Vec<RawNic> = Vec::new();
    for l in text.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if !f.get(2).is_some_and(|n| n.starts_with("<Link#")) {
            continue;
        }
        // An address column is present or absent; count from the end.
        let n = f.len();
        if n < 8 {
            continue;
        }
        let v = |i: usize| f.get(n - i).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
        out.push(RawNic { name: f[0].to_string(), rx_errs: v(6), rx_bytes: v(5), tx_errs: v(3), tx_bytes: v(2), rx_drop: 0, tx_drop: v(1) });
    }
    out
}

/// `netstat -s -p tcp`: data packets retransmitted.
pub fn tcp_retrans(text: &str) -> Option<u64> {
    text.lines().find(|l| l.contains("retransmitted") && l.contains("data packet"))?.split_whitespace().next()?.parse().ok()
}

/// `ioreg -rn AppleSmartBattery`: watts flowing, either way.
pub fn battery_watts(text: &str) -> Option<f64> {
    let get = |k: &str| {
        text.lines().find_map(|l| {
            let (key, value) = l.trim_start_matches([' ', '|']).split_once(" = ")?;
            (key.trim_matches('"') == k).then(|| value.trim().parse::<i64>().ok()).flatten()
        })
    };
    let (volts, amps) = (get("Voltage")? as f64 / 1000.0, get("InstantAmperage").or_else(|| get("Amperage"))?);
    // Some models report a negative current as an unsigned 64-bit value.
    let amps = amps as f64 / 1000.0;
    Some((volts * amps).abs())
}

/// `launchctl list`: PID, last exit status, label.
pub fn launchctl(text: &str) -> Vec<Service> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (pid, status, name) = (f.next()?, f.next()?, f.next()?);
            let pid = pid.parse::<u32>().ok();
            let failed = status.parse::<i32>().is_ok_and(|s| s != 0);
            let state = match (pid, failed) {
                (Some(_), _) => ServiceState::Running,
                (None, true) => ServiceState::Failed,
                (None, false) => ServiceState::Stopped,
            };
            Some(Service { name: name.to_string(), state, pid, detail: if failed { format!("last exit {status}") } else { String::new() } })
        })
        .collect()
}

// ── Windows ─────────────────────────────────────────────────────────────

/// Our `name|state|startmode|pid|display name` lines from Win32_Service.
pub fn windows_services(text: &str) -> Vec<Service> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.trim().splitn(5, '|');
            let (name, state, mode, pid, shown) = (f.next()?, f.next()?, f.next()?, f.next()?, f.next().unwrap_or(""));
            if name.is_empty() {
                return None;
            }
            let auto = mode.eq_ignore_ascii_case("Auto");
            let state = match state {
                "Running" => ServiceState::Running,
                // Set to start automatically, yet not running.
                "Stopped" if auto => ServiceState::Failed,
                "Stopped" => ServiceState::Stopped,
                _ => ServiceState::Other,
            };
            Some(Service { name: name.to_string(), state, pid: pid.parse().ok().filter(|p| *p != 0), detail: shown.to_string() })
        })
        .collect()
}

/// `path|value` lines from `Get-Counter`.
pub fn counters(text: &str) -> Vec<(String, f64)> {
    text.lines().filter_map(|l| l.trim().rsplit_once('|')).filter_map(|(p, v)| Some((p.to_lowercase(), v.trim().parse().ok()?))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_proc_files() {
        let stat = "cpu 1 2 3\nintr 500 1 2\nctxt 1000\nbtime 1\nprocesses 9\nprocs_running 3\nprocs_blocked 1\n";
        assert_eq!(proc_stat(stat), (Some(1000), Some(500), Some(3), Some(1)));
        assert_eq!(proc_stat(""), (None, None, None, None));
        assert_eq!(vmstat("pgfault 7\npgmajfault 2\npswpin 3\npswpout 4\n"), (Some(7), Some(2), Some(3), Some(4)));
        let d = diskstats("   8       0 sda 100 0 2000 50 200 0 4000 80 2 120 130 0 0 0 0\nbad line\n");
        assert_eq!(d.len(), 1);
        assert_eq!((d[0].read_bytes, d[0].write_bytes, d[0].busy_ms, d[0].weighted_ms), (1_024_000, 2_048_000, 120, 130));
        let n = net_dev("Inter-|   Receive\n face |bytes\n  eth0: 100 5 1 2 0 0 0 0 200 6 3 4 0 0 0 0\n");
        assert_eq!((n[0].name.as_str(), n[0].rx_bytes, n[0].rx_errs, n[0].rx_drop, n[0].tx_bytes, n[0].tx_errs, n[0].tx_drop), ("eth0", 100, 1, 2, 200, 3, 4));
        assert_eq!(snmp_retrans("Ip: a\nIp: 1\nTcp: RtoAlgorithm OutSegs RetransSegs\nTcp: 1 900 42\n"), Some(42));
        assert_eq!(snmp_retrans("Tcp: a\n"), None);
        assert_eq!(psi("some avg10=1.50 avg60=0.20 avg300=0.00 total=1\nfull avg10=0.10 avg60=0 avg300=0 total=1\n"), Some(1.5));
        assert_eq!(psi("garbage"), None);
    }

    #[test]
    fn systemd_units() {
        let s = systemctl("ssh.service loaded active running OpenBSD Secure Shell\nbad.service loaded failed failed Thing\nx.service loaded inactive dead X\none.service loaded active exited Y\n");
        assert_eq!(s[0].name, "ssh");
        assert_eq!(s[0].detail, "OpenBSD Secure Shell");
        assert_eq!(s.iter().map(|x| x.state).collect::<Vec<_>>(), vec![ServiceState::Running, ServiceState::Failed, ServiceState::Stopped, ServiceState::Other]);
    }

    #[test]
    fn macos_tools() {
        let v = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free:      100.\nTranslation faults:   9000.\nSwapins:     5.\nSwapouts:    6.\n";
        assert_eq!(vm_stat(v), (Some(9000), Some(5), Some(6)));
        let io = "              disk0               disk1\n    KB/t  tps  MB/s     KB/t  tps  MB/s\n   40.93   41  1.63     5.27    0  0.00\n    8.00    8  0.06     0.00    2  1.50\n";
        assert_eq!(iostat(io), vec![("disk0".to_string(), 8.0, 0.06), ("disk1".to_string(), 2.0, 1.5)]);
        assert!(iostat("").is_empty());
        let n = "Name  Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\nen0 1500 <Link#6> aa:bb:cc 100 2 3000 200 4 5000 7\nen0 1500 192.168 192.168.1.2 100 - 3000 200 - 5000 -\nlo0 16384 <Link#1> 5 0 60 5 0 70 0\n";
        let nics = netstat_ib(n);
        assert_eq!(nics.len(), 2);
        assert_eq!((nics[0].rx_errs, nics[0].rx_bytes, nics[0].tx_errs, nics[0].tx_bytes), (2, 3000, 4, 5000));
        assert_eq!(nics[1].tx_bytes, 70, "no address column");
        assert_eq!(tcp_retrans("tcp:\n\t\t12 data packets (9 bytes) retransmitted\n"), Some(12));
        assert_eq!(tcp_retrans("\t\t0 data packet (0 byte) retransmitted\n"), Some(0));
        let w = battery_watts("  |   \"Voltage\" = 12000\n  |   \"InstantAmperage\" = -2000\n  |   \"Amperage\" = 0\n").unwrap();
        assert!((w - 24.0).abs() < 0.01);
        assert_eq!(battery_watts("nothing"), None);
        let l = launchctl("PID\tStatus\tLabel\n1172\t0\tcom.a\n-\t0\tcom.b\n-\t78\tcom.c\n");
        assert_eq!(l.iter().map(|x| x.state).collect::<Vec<_>>(), vec![ServiceState::Running, ServiceState::Stopped, ServiceState::Failed]);
        assert_eq!(l[0].pid, Some(1172));
    }

    #[test]
    fn windows_lines() {
        let s = windows_services("Dnscache|Running|Auto|1200|DNS Client\nFoo|Stopped|Auto|0|Foo | bar\nBar|Stopped|Manual|0|Bar\n|x\n");
        assert_eq!(s.len(), 3);
        assert_eq!((s[0].pid, s[1].pid), (Some(1200), None));
        assert_eq!(s[1].state, ServiceState::Failed, "automatic but not running");
        assert_eq!(s[1].detail, "Foo | bar");
        assert_eq!(s[2].state, ServiceState::Stopped);
        assert_eq!(counters("\\\\h\\System\\Context Switches/sec|1234.5\nno value\nx|abc\n"), vec![("\\\\h\\system\\context switches/sec".to_string(), 1234.5)]);
    }
}
