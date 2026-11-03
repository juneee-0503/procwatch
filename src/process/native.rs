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

// ── macOS ──────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod imp {
    pub fn start_time(pid: u32) -> Option<u64> {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let n = unsafe { libc::proc_pidinfo(pid as libc::c_int, libc::PROC_PIDTBSDINFO, 0, &mut info as *mut _ as *mut libc::c_void, size) };
        (n == size).then_some(info.pbi_start_tvsec)
    }

    use super::{Native, ThreadInfo};
    use std::collections::HashMap;
    use std::mem::{size_of, MaybeUninit};
    use std::sync::OnceLock;

    // Not exported by the libc crate.
    const PROC_PIDLISTTHREADS: libc::c_int = 6;

    /// `pti_total_*` are Mach absolute-time units, which are *not*
    /// nanoseconds on Apple Silicon; convert with the timebase.
    fn ticks_to_secs(ticks: u64) -> f64 {
        static TB: OnceLock<(u32, u32)> = OnceLock::new();
        #[repr(C)]
        struct Timebase {
            numer: u32,
            denom: u32,
        }
        extern "C" {
            fn mach_timebase_info(info: *mut Timebase) -> libc::c_int;
        }
        let (numer, denom) = *TB.get_or_init(|| {
            let mut info = Timebase { numer: 0, denom: 0 };
            let ok = unsafe { mach_timebase_info(&mut info) } == 0;
            if ok && info.denom != 0 { (info.numer, info.denom) } else { (1, 1) }
        });
        ticks as f64 * numer as f64 / denom as f64 / 1e9
    }

    fn task_info(pid: u32) -> Option<libc::proc_taskinfo> {
        let mut info = MaybeUninit::<libc::proc_taskinfo>::zeroed();
        let size = size_of::<libc::proc_taskinfo>() as libc::c_int;
        let n = unsafe {
            libc::proc_pidinfo(pid as libc::c_int, libc::PROC_PIDTASKINFO, 0, info.as_mut_ptr().cast(), size)
        };
        (n == size).then(|| unsafe { info.assume_init() })
    }

    fn footprint(pid: u32) -> Option<u64> {
        let mut info = MaybeUninit::<libc::rusage_info_v2>::zeroed();
        let rc = unsafe { libc::proc_pid_rusage(pid as libc::c_int, libc::RUSAGE_INFO_V2, info.as_mut_ptr().cast()) };
        (rc == 0).then(|| unsafe { info.assume_init() }.ri_phys_footprint).filter(|v| *v > 0)
    }

    fn nice(pid: u32) -> Option<i32> {
        unsafe {
            *libc::__error() = 0;
            let v = libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t);
            (v != -1 || *libc::__error() == 0).then_some(v)
        }
    }

    pub fn collect(pids: &[u32]) -> HashMap<u32, Native> {
        pids.iter()
            .map(|&pid| {
                let ti = task_info(pid);
                let native = Native {
                    threads: ti.map(|t| t.pti_threadnum.max(0) as u32),
                    nice: nice(pid),
                    priority: ti.map(|t| t.pti_priority),
                    cpu_time: ti.map(|t| ticks_to_secs(t.pti_total_user + t.pti_total_system)),
                    footprint: footprint(pid),
                };
                (pid, native)
            })
            .collect()
    }

    pub fn threads(pid: u32) -> anyhow::Result<Vec<ThreadInfo>> {
        let count = task_info(pid).map(|t| t.pti_threadnum.max(1) as usize).unwrap_or(64);
        let mut ids = vec![0u64; count + 16];
        let bytes = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                PROC_PIDLISTTHREADS,
                0,
                ids.as_mut_ptr().cast(),
                (ids.len() * size_of::<u64>()) as libc::c_int,
            )
        };
        if bytes <= 0 {
            anyhow::bail!("{} (other users' processes need root)", std::io::Error::last_os_error());
        }
        ids.truncate(bytes as usize / size_of::<u64>());

        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let mut info = MaybeUninit::<libc::proc_threadinfo>::zeroed();
            let size = size_of::<libc::proc_threadinfo>() as libc::c_int;
            let n = unsafe {
                libc::proc_pidinfo(pid as libc::c_int, libc::PROC_PIDTHREADINFO, id, info.as_mut_ptr().cast(), size)
            };
            if n != size {
                continue; // thread exited between list and query
            }
            let info = unsafe { info.assume_init() };
            let name = unsafe { std::ffi::CStr::from_ptr(info.pth_name.as_ptr()) }.to_string_lossy().into_owned();
            let state = match info.pth_run_state {
                1 => "running",
                2 => "stopped",
                3 => "waiting",
                4 => "uninterruptible",
                5 => "halted",
                _ => "?",
            };
            out.push(ThreadInfo {
                id,
                name,
                state: state.to_string(),
                // TH_USAGE_SCALE = 1000 → tenths of a percent.
                cpu_pct: Some(info.pth_cpu_usage as f32 / 10.0),
                priority: Some(info.pth_curpri),
                user_time: Some(info.pth_user_time as f64 / 1e9),
                system_time: Some(info.pth_system_time as f64 / 1e9),
            });
        }
        Ok(out)
    }

    pub fn set_nice(pid: u32, nice: i32) -> anyhow::Result<()> {
        if unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, nice) } != 0 {
            anyhow::bail!("{}", std::io::Error::last_os_error());
        }
        Ok(())
    }
}

// ── Linux ──────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod imp {
    pub fn start_time(pid: u32) -> Option<u64> {
        // Field 22 of /proc/PID/stat: start in clock ticks after boot.
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after = stat.rsplit_once(')')?.1;
        let ticks: u64 = after.split_whitespace().nth(19)?.parse().ok()?;
        let btime: u64 = std::fs::read_to_string("/proc/stat").ok()?.lines().find_map(|l| l.strip_prefix("btime ")?.trim().parse().ok())?;
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
        Some(btime + ticks / hz)
    }

    use super::{Native, ThreadInfo};
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
}

// ── Windows ────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod imp {
    use super::{Native, ThreadInfo};
    use std::collections::{HashMap, HashSet};
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, Thread32First, Thread32Next,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, SetPriorityClass, ABOVE_NORMAL_PRIORITY_CLASS,
        BELOW_NORMAL_PRIORITY_CLASS, HIGH_PRIORITY_CLASS, IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION,
    };

    pub fn start_time(pid: u32) -> Option<u64> {
        let h = Handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
        if h.0.is_null() {
            return None;
        }
        let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut c, mut e, mut k, mut u) = (z, z, z, z);
        if unsafe { GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u) } == 0 {
            return None;
        }
        let ft = ((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64;
        (ft / 10_000_000).checked_sub(11_644_473_600)
    }

    /// Closes the wrapped handle on drop.
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    fn snapshot(flags: u32) -> anyhow::Result<Handle> {
        let h = unsafe { CreateToolhelp32Snapshot(flags, 0) };
        if h == INVALID_HANDLE_VALUE {
            anyhow::bail!("{}", std::io::Error::last_os_error());
        }
        Ok(Handle(h))
    }

    fn filetime_secs(ft: &FILETIME) -> f64 {
        (((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64) as f64 / 1e7
    }

    /// Map the base priority of the class to a unix-like nice value.
    fn class_to_nice(base: i32) -> i32 {
        match base {
            ..=4 => 19,
            5..=6 => 10,
            7..=8 => 0,
            9..=10 => -10,
            11..=13 => -15,
            _ => -20,
        }
    }

    fn cpu_time(pid: u32) -> Option<f64> {
        let h = Handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
        if h.0.is_null() {
            return None;
        }
        let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut c, mut e, mut k, mut u) = (zero, zero, zero, zero);
        let ok = unsafe { GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u) } != 0;
        ok.then(|| filetime_secs(&k) + filetime_secs(&u))
    }

    pub fn collect(pids: &[u32]) -> HashMap<u32, Native> {
        let wanted: HashSet<u32> = pids.iter().copied().collect();
        let mut out = HashMap::with_capacity(pids.len());
        let Ok(snap) = snapshot(TH32CS_SNAPPROCESS) else { return out };
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = unsafe { Process32FirstW(snap.0, &mut entry) } != 0;
        while ok {
            let pid = entry.th32ProcessID;
            if wanted.contains(&pid) {
                out.insert(
                    pid,
                    Native {
                        threads: Some(entry.cntThreads),
                        nice: Some(class_to_nice(entry.pcPriClassBase)),
                        priority: Some(entry.pcPriClassBase),
                        cpu_time: cpu_time(pid),
                        footprint: None,
                    },
                );
            }
            ok = unsafe { Process32NextW(snap.0, &mut entry) } != 0;
        }
        out
    }

    pub fn threads(pid: u32) -> anyhow::Result<Vec<ThreadInfo>> {
        let snap = snapshot(TH32CS_SNAPTHREAD)?;
        let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        let mut out = Vec::new();
        let mut ok = unsafe { Thread32First(snap.0, &mut entry) } != 0;
        while ok {
            if entry.th32OwnerProcessID == pid {
                out.push(ThreadInfo {
                    id: entry.th32ThreadID as u64,
                    name: String::new(),
                    state: "-".to_string(),
                    cpu_pct: None,
                    priority: Some(entry.tpBasePri + entry.tpDeltaPri),
                    user_time: None,
                    system_time: None,
                });
            }
            ok = unsafe { Thread32Next(snap.0, &mut entry) } != 0;
        }
        Ok(out)
    }

    pub fn set_nice(pid: u32, nice: i32) -> anyhow::Result<()> {
        let class = match nice {
            ..=-15 => HIGH_PRIORITY_CLASS, // never REALTIME: it can starve the system
            -14..=-5 => ABOVE_NORMAL_PRIORITY_CLASS,
            -4..=4 => NORMAL_PRIORITY_CLASS,
            5..=14 => BELOW_NORMAL_PRIORITY_CLASS,
            _ => IDLE_PRIORITY_CLASS,
        };
        let h = Handle(unsafe { OpenProcess(PROCESS_SET_INFORMATION, 0, pid) });
        if h.0.is_null() {
            anyhow::bail!("{}", std::io::Error::last_os_error());
        }
        if unsafe { SetPriorityClass(h.0, class) } == 0 {
            anyhow::bail!("{}", std::io::Error::last_os_error());
        }
        Ok(())
    }
}

// ── other platforms ────────────────────────────────────────────────────

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
mod imp {
    pub fn start_time(_pid: u32) -> Option<u64> {
        None
    }
    use super::{Native, ThreadInfo};
    use std::collections::HashMap;

    pub fn collect(_pids: &[u32]) -> HashMap<u32, Native> {
        HashMap::new()
    }
    pub fn threads(_pid: u32) -> anyhow::Result<Vec<ThreadInfo>> {
        anyhow::bail!("not supported on this platform")
    }
    pub fn set_nice(_pid: u32, _nice: i32) -> anyhow::Result<()> {
        anyhow::bail!("not supported on this platform")
    }
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
