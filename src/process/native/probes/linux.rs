pub fn start_time(pid: u32) -> Option<u64> {
    // Field 22 of /proc/PID/stat: start in clock ticks after boot.
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(')')?.1;
    let ticks: u64 = after.split_whitespace().nth(19)?.parse().ok()?;
    let btime: u64 = std::fs::read_to_string("/proc/stat").ok()?.lines().find_map(|l| l.strip_prefix("btime ")?.trim().parse().ok())?;
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
    Some(btime + ticks / hz)
}

use super::super::{Native, ThreadInfo};
use std::collections::HashMap;
use std::fs;
use std::sync::OnceLock;

fn clk_tck() -> f64 {
    static TCK: OnceLock<f64> = OnceLock::new();
    *TCK.get_or_init(|| {
        let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if v > 0 { v as f64 } else { 100.0 }
    })
}

/// Fields of a `stat` line after the `(comm)` part, which can itself
/// contain spaces and parentheses.
fn stat_fields(text: &str) -> Option<(String, Vec<&str>)> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let comm = text.get(open + 1..close)?.to_string();
    Some((comm, text.get(close + 1..)?.split_whitespace().collect()))
}

fn field<T: std::str::FromStr>(f: &[&str], i: usize) -> Option<T> {
    f.get(i).and_then(|s| s.parse().ok())
}

pub fn collect(pids: &[u32]) -> HashMap<u32, Native> {
    let tck = clk_tck();
    pids.iter()
        .filter_map(|&pid| {
            let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            let (_, f) = stat_fields(&text)?;
            // Indices relative to the field after `)`: state=0,
            // utime=11, stime=12, priority=15, nice=16, threads=17.
            let ut: Option<f64> = field(&f, 11);
            let st: Option<f64> = field(&f, 12);
            Some((
                pid,
                Native {
                    threads: field(&f, 17),
                    nice: field(&f, 16),
                    priority: field(&f, 15),
                    cpu_time: ut.zip(st).map(|(u, s)| (u + s) / tck),
                    footprint: None,
                },
            ))
        })
        .collect()
}

pub fn threads(pid: u32) -> anyhow::Result<Vec<ThreadInfo>> {
    let tck = clk_tck();
    let mut out = Vec::new();
    for entry in fs::read_dir(format!("/proc/{pid}/task"))? {
        let Ok(entry) = entry else { continue };
        let Ok(tid) = entry.file_name().to_string_lossy().parse::<u64>() else { continue };
        let Ok(text) = fs::read_to_string(entry.path().join("stat")) else { continue };
        let Some((comm, f)) = stat_fields(&text) else { continue };
        out.push(ThreadInfo {
            id: tid,
            name: comm,
            state: f.first().copied().unwrap_or("?").to_string(),
            cpu_pct: None,
            priority: field(&f, 15),
            user_time: field::<f64>(&f, 11).map(|v| v / tck),
            system_time: field::<f64>(&f, 12).map(|v| v / tck),
        });
    }
    out.sort_by_key(|t| t.id);
    Ok(out)
}

pub fn set_nice(pid: u32, nice: i32) -> anyhow::Result<()> {
    if unsafe { libc::setpriority(libc::PRIO_PROCESS as _, pid as libc::id_t, nice) } != 0 {
        anyhow::bail!("{}", std::io::Error::last_os_error());
    }
    Ok(())
}
