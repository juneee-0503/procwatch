//! Per-process scheduler data that `sysinfo` doesn't expose: thread count,
//! nice / priority, accumulated CPU time, plus per-thread listings and
//! priority changes. Read straight from the OS:
//!
//!   - macOS:   `proc_pidinfo(PROC_PIDTASKINFO / PROC_PIDTHREADINFO)`
//!   - Linux:   `/proc/<pid>/stat`, `/proc/<pid>/task/*/stat`
//!   - Windows: Toolhelp32 snapshots + `GetProcessTimes`
//!
//! Everything is best-effort: fields the OS refuses (other users'
//! processes without privileges) come back as `None`.

mod probes;
use probes as imp;

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Default)]
pub struct Native {
    pub threads: Option<u32>,
    /// Unix nice value (-20..19). On Windows, derived from the priority
    /// class so the column means the same thing everywhere.
    pub nice: Option<i32>,
    /// Kernel scheduling priority as the OS reports it.
    pub priority: Option<i32>,
    /// User + system CPU time consumed so far, in seconds.
    pub cpu_time: Option<f64>,
    /// macOS "physical footprint" — what Activity Monitor calls Memory.
    /// More meaningful than RSS for apps that share or compress pages.
    pub footprint: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct ThreadInfo {
    pub id: u64,
    pub name: String,
    pub state: String,
    pub cpu_pct: Option<f32>,
    pub priority: Option<i32>,
    pub user_time: Option<f64>,
    pub system_time: Option<f64>,
}

/// Collect scheduler data for every PID in `pids` in one pass.
pub fn collect(pids: &[u32]) -> HashMap<u32, Native> {
    imp::collect(pids)
}

/// Enumerate the threads of a single process.
pub fn threads(pid: u32) -> anyhow::Result<Vec<ThreadInfo>> {
    imp::threads(pid)
}

/// Set the nice value (lower = higher priority). Lowering below the
/// current value usually requires root / administrator.
pub fn set_nice(pid: u32, nice: i32) -> anyhow::Result<()> {
    imp::set_nice(pid, nice.clamp(-20, 19))
}

/// Start time (seconds since the epoch) of whatever process has `pid`
/// right now, or None if there is none / it can't be read. Used to make
/// sure an action still targets the same process instance.
pub fn start_time(pid: u32) -> Option<u64> {
    imp::start_time(pid)
}

#[cfg(windows)]
pub fn exists(pid: u32) -> bool {
    imp::exists(pid)
}





#[cfg(test)]
mod tests {
    #[test]
    fn start_time_agrees_with_sysinfo() {
        use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
        let me = std::process::id();
        let mut sys = System::new();
        sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[Pid::from_u32(me)]), ProcessRefreshKind::new());
        let theirs = sys.process(Pid::from_u32(me)).map(|p| p.start_time()).unwrap();
        let ours = super::start_time(me).unwrap();
        assert!(ours.abs_diff(theirs) <= 2, "{ours} vs {theirs}");
    }

    #[test]
    fn own_start_time_is_readable() {
        let t = super::start_time(std::process::id()).expect("own start time");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert!(t <= now && now - t < 3600, "{t} vs {now}");
    }

    #[test]
    fn reads_own_process() {
        let pid = std::process::id();
        let map = super::collect(&[pid]);
        let me = map.get(&pid).expect("own process visible");
        assert!(me.threads.unwrap_or(1) >= 1);
        assert!(me.cpu_time.unwrap_or(0.0) >= 0.0);
        let threads = super::threads(pid).expect("own threads");
        assert!(!threads.is_empty());
    }
}
