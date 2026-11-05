use super::super::{Native, ThreadInfo};
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

/// Unlike a failed open, access denied means it does exist: protected
/// processes refuse even the most limited handle.
pub fn exists(pid: u32) -> bool {
    let h = Handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
    !h.0.is_null() || unsafe { windows_sys::Win32::Foundation::GetLastError() } == windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED
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
