//! Deep trace: event-driven lifecycle tracking for chosen processes and
//! everything they start.
//!
//! - macOS: kqueue `EVFILT_PROC` notifications (fork, exec, exit) for each
//!   watched process. On a fork the new children are listed immediately
//!   and watched in turn, so short-lived children are seen even when they
//!   live far less than one refresh. No special entitlement is needed.
//! - Linux: `/proc/PID/task/*/children` and `/proc/PID/exe` polled every
//!   50 ms for watched processes only.
//! - Windows: a ToolHelp process snapshot every 100 ms, filtered to
//!   children of watched processes.
//!
//! Every event carries a millisecond timestamp taken when it was noticed,
//! and the watcher reports how it observed it, so the timeline can say how
//! precise each entry is.

use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{Receiver, Sender};
#[cfg(any(test, target_os = "linux", target_os = "windows"))]
use std::time::Duration;

use chrono::{DateTime, Local};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DtKind {
    Spawn,
    Exec,
    Exit,
}

impl DtKind {
    pub fn label(self) -> &'static str {
        match self {
            DtKind::Spawn => "spawn",
            DtKind::Exec => "exec",
            DtKind::Exit => "exit",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DtEvent {
    #[serde(serialize_with = "ser_time")]
    pub at: DateTime<Local>,
    pub kind: DtKind,
    pub pid: u32,
    pub ppid: Option<u32>,
    /// Process start time (s), 0 if it was gone before it could be read.
    pub start: u64,
    pub path: Option<String>,
    pub args: Option<String>,
    /// "kqueue", "procfs poll 50ms", "toolhelp poll 100ms".
    pub via: &'static str,
}

fn ser_time<S: serde::Serializer>(t: &DateTime<Local>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&t.to_rfc3339_opts(chrono::SecondsFormat::Millis, false))
}

pub enum Cmd {
    Watch(u32),
    /// Watch and confirm (true = registered) before returning.
    WatchSync(u32, Sender<bool>),
    Unwatch(u32),
}

/// Handle to the watcher thread.
pub struct Watcher {
    tx: Sender<Cmd>,
    pub method: &'static str,
}

impl Watcher {
    /// Start the watcher; events are delivered through `out` in batches.
    pub fn start(out: Sender<crate::sampler::WorkerMsg>) -> Option<Watcher> {
        let (tx, rx) = std::sync::mpsc::channel();
        let method = imp::METHOD;
        std::thread::Builder::new()
            .name("deeptrace".into())
            .spawn(move || {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| imp::run(rx, &out)));
                if let Err(e) = r {
                    let _ = out.send(crate::sampler::WorkerMsg::Error(format!("deep trace stopped: {}", crate::sampler::panic_text(&e))));
                }
            })
            .ok()?;
        Some(Watcher { tx, method })
    }

    pub fn watch(&self, pid: u32) {
        let _ = self.tx.send(Cmd::Watch(pid));
    }

    /// Watch `pid` and wait until the watcher has it (used before letting
    /// a stopped, freshly launched program continue).
    pub fn watch_sync(&self, pid: u32) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        if self.tx.send(Cmd::WatchSync(pid, tx)).is_err() {
            return false;
        }
        rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap_or(false)
    }

    pub fn unwatch(&self, pid: u32) {
        let _ = self.tx.send(Cmd::Unwatch(pid));
    }
}

/// Shared bookkeeping for the polling implementations.
#[allow(dead_code)]
struct Book {
    watched: HashSet<u32>,
    exe: HashMap<u32, Option<String>>,
}

#[allow(dead_code)]
fn send(out: &Sender<crate::sampler::WorkerMsg>, batch: &mut Vec<DtEvent>) -> bool {
    if batch.is_empty() {
        return true;
    }
    out.send(crate::sampler::WorkerMsg::Deep(std::mem::take(batch))).is_ok()
}

#[allow(dead_code)]
fn drain(rx: &Receiver<Cmd>, mut f: impl FnMut(Cmd)) -> bool {
    loop {
        match rx.try_recv() {
            Ok(c) => f(c),
            Err(std::sync::mpsc::TryRecvError::Empty) => return true,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return false,
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    pub const METHOD: &str = "kqueue process notifications";

    fn path(pid: u32) -> Option<String> {
        let mut buf = vec![0u8; 4096];
        let n = unsafe { libc::proc_pidpath(pid as libc::c_int, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32) };
        (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
    }

    /// argv via KERN_PROCARGS2 (own user's processes, or any as root).
    fn args(pid: u32) -> Option<String> {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
        let mut size: libc::size_t = 0;
        if unsafe { libc::sysctl(mib.as_mut_ptr(), 3, std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0) } != 0 || size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size];
        if unsafe { libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr() as *mut libc::c_void, &mut size, std::ptr::null_mut(), 0) } != 0 {
            return None;
        }
        buf.truncate(size);
        let argc = u32::from_ne_bytes(buf.get(0..4)?.try_into().ok()?) as usize;
        let mut parts = buf[4..].split(|b| *b == 0).filter(|s| !s.is_empty());
        let _exe = parts.next();
        let argv: Vec<String> = parts.take(argc).map(|s| String::from_utf8_lossy(s).into_owned()).collect();
        (!argv.is_empty()).then(|| argv.join(" "))
    }

    fn children(pid: u32) -> Vec<u32> {
        let mut buf = vec![0 as libc::c_int; 1024];
        let n = unsafe { libc::proc_listchildpids(pid as libc::pid_t, buf.as_mut_ptr() as *mut libc::c_void, (buf.len() * 4) as libc::c_int) };
        if n <= 0 {
            return Vec::new();
        }
        // Returns a count of pids on current macOS (bytes on some older).
        let count = if n as usize > buf.len() { n as usize / 4 } else { n as usize };
        buf[..count.min(buf.len())].iter().filter(|p| **p > 0).map(|p| *p as u32).collect()
    }

    fn register(kq: i32, pid: u32) -> bool {
        let ev = libc::kevent {
            ident: pid as usize,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags: libc::NOTE_FORK | libc::NOTE_EXEC | libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        unsafe { libc::kevent(kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) == 0 }
    }

    fn info(kind: DtKind, pid: u32, ppid: Option<u32>) -> DtEvent {
        DtEvent {
            at: Local::now(),
            kind,
            pid,
            ppid,
            start: crate::process::native::start_time(pid).unwrap_or(0),
            path: path(pid),
            args: args(pid),
            via: "kqueue",
        }
    }

    pub fn run(rx: Receiver<Cmd>, out: &Sender<crate::sampler::WorkerMsg>) {
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            let _ = out.send(crate::sampler::WorkerMsg::Error("deep trace: kqueue unavailable".into()));
            return;
        }
        let mut watched: HashSet<u32> = HashSet::new();
        let mut parent: HashMap<u32, u32> = HashMap::new();
        let mut batch: Vec<DtEvent> = Vec::new();
        let mut events = vec![
            libc::kevent { ident: 0, filter: 0, flags: 0, fflags: 0, data: 0, udata: std::ptr::null_mut() };
            64
        ];
        // Short timeout: new watch requests are picked up within 20 ms.
        let timeout = libc::timespec { tv_sec: 0, tv_nsec: 20_000_000 };
        loop {
            let alive = drain(&rx, |c| match c {
                Cmd::Watch(pid) => {
                    if watched.insert(pid) && !register(kq, pid) {
                        watched.remove(&pid);
                    }
                }
                Cmd::WatchSync(pid, reply) => {
                    let ok = register(kq, pid);
                    if ok {
                        watched.insert(pid);
                    }
                    let _ = reply.send(ok);
                }
                Cmd::Unwatch(pid) => {
                    watched.remove(&pid);
                }
            });
            if !alive {
                break;
            }
            let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, events.as_mut_ptr(), events.len() as i32, &timeout) };
            for ev in events.iter().take(n.max(0) as usize) {
                let pid = ev.ident as u32;
                if !watched.contains(&pid) {
                    continue;
                }
                if ev.fflags & libc::NOTE_FORK != 0 {
                    for child in children(pid) {
                        if watched.insert(child) {
                            parent.insert(child, pid);
                            // Watch first, then read: an exec right after
                            // the fork then still produces an event.
                            let registered = register(kq, child);
                            batch.push(info(DtKind::Spawn, child, Some(pid)));
                            if !registered {
                                // Already gone: we saw it, but only just.
                                batch.push(DtEvent { at: Local::now(), kind: DtKind::Exit, pid: child, ppid: Some(pid), start: 0, path: None, args: None, via: "kqueue" });
                                watched.remove(&child);
                            }
                        }
                    }
                }
                if ev.fflags & libc::NOTE_EXEC != 0 {
                    batch.push(info(DtKind::Exec, pid, parent.get(&pid).copied()));
                }
                if ev.fflags & libc::NOTE_EXIT != 0 {
                    batch.push(DtEvent { at: Local::now(), kind: DtKind::Exit, pid, ppid: parent.get(&pid).copied(), start: 0, path: None, args: None, via: "kqueue" });
                    watched.remove(&pid);
                    parent.remove(&pid);
                }
            }
            if !send(out, &mut batch) {
                break;
            }
        }
        unsafe { libc::close(kq) };
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    pub const METHOD: &str = "procfs polling every 50 ms";

    fn exe(pid: u32) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.display().to_string())
    }

    fn args(pid: u32) -> Option<String> {
        let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let s: Vec<String> = raw.split(|b| *b == 0).filter(|p| !p.is_empty()).map(|p| String::from_utf8_lossy(p).into_owned()).collect();
        (!s.is_empty()).then(|| s.join(" "))
    }

    fn children(pid: u32) -> Vec<u32> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/task")) {
            for t in rd.flatten() {
                if let Ok(s) = std::fs::read_to_string(t.path().join("children")) {
                    out.extend(s.split_whitespace().filter_map(|x| x.parse::<u32>().ok()));
                }
            }
        }
        out
    }

    fn ev(kind: DtKind, pid: u32, ppid: Option<u32>) -> DtEvent {
        DtEvent { at: Local::now(), kind, pid, ppid, start: crate::process::native::start_time(pid).unwrap_or(0), path: exe(pid), args: args(pid), via: "procfs poll" }
    }

    pub fn run(rx: Receiver<Cmd>, out: &Sender<crate::sampler::WorkerMsg>) {
        let mut b = Book { watched: HashSet::new(), exe: HashMap::new() };
        let mut parent: HashMap<u32, u32> = HashMap::new();
        let mut batch = Vec::new();
        loop {
            let alive = drain(&rx, |c| match c {
                Cmd::Watch(pid) => {
                    b.watched.insert(pid);
                    b.exe.insert(pid, exe(pid));
                }
                Cmd::WatchSync(pid, reply) => {
                    b.watched.insert(pid);
                    b.exe.insert(pid, exe(pid));
                    let _ = reply.send(true);
                }
                Cmd::Unwatch(pid) => {
                    b.watched.remove(&pid);
                }
            });
            if !alive {
                break;
            }
            let current: Vec<u32> = b.watched.iter().copied().collect();
            for pid in current {
                if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
                    batch.push(DtEvent { at: Local::now(), kind: DtKind::Exit, pid, ppid: parent.get(&pid).copied(), start: 0, path: None, args: None, via: "procfs poll" });
                    b.watched.remove(&pid);
                    continue;
                }
                let now_exe = exe(pid);
                if b.exe.get(&pid).is_some_and(|e| *e != now_exe) {
                    batch.push(ev(DtKind::Exec, pid, parent.get(&pid).copied()));
                }
                b.exe.insert(pid, now_exe);
                for child in children(pid) {
                    if b.watched.insert(child) {
                        parent.insert(child, pid);
                        let e = ev(DtKind::Spawn, child, Some(pid));
                        b.exe.insert(child, e.path.clone());
                        batch.push(e);
                    }
                }
            }
            if !send(out, &mut batch) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[cfg(target_os = "windows")]
mod imp {
    use super::*;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
    use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};

    pub const METHOD: &str = "ETW Kernel-Process events (administrator) or process snapshots every 100 ms";

    /// Real-time ETW session on Microsoft-Windows-Kernel-Process: exact
    /// start/stop events for every process. Needs administrator rights.
    mod etw {
        use ferrisetw::parser::Parser;
        use ferrisetw::provider::Provider;
        use ferrisetw::schema_locator::SchemaLocator;
        use ferrisetw::trace::UserTrace;
        use ferrisetw::EventRecord;
        use std::sync::mpsc::Sender;
        use std::sync::Mutex;

        pub enum Ev {
            Start { pid: u32, ppid: u32, image: String },
            Stop { pid: u32 },
        }

        const KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";
        const KEYWORD_PROCESS: u64 = 0x10;

        pub fn start(tx: Sender<Ev>) -> Option<UserTrace> {
            let tx = Mutex::new(tx);
            let provider = Provider::by_guid(KERNEL_PROCESS)
                .any(KEYWORD_PROCESS)
                .add_callback(move |r: &EventRecord, sl: &SchemaLocator| {
                    let id = r.event_id();
                    if id != 1 && id != 2 {
                        return;
                    }
                    let Ok(schema) = sl.event_schema(r) else { return };
                    let p = Parser::create(r, &schema);
                    let pid: u32 = p.try_parse("ProcessID").unwrap_or(0);
                    let ev = if id == 1 {
                        Ev::Start { pid, ppid: p.try_parse("ParentProcessID").unwrap_or(0), image: p.try_parse("ImageName").unwrap_or_default() }
                    } else {
                        Ev::Stop { pid }
                    };
                    if let Ok(t) = tx.lock() {
                        let _ = t.send(ev);
                    }
                })
                .build();
            // A stale session from a crashed run would block the name.
            let _ = ferrisetw::trace::stop_trace_by_name("procwatch-deeptrace");
            UserTrace::new().named("procwatch-deeptrace".into()).enable(provider).start_and_process().ok()
        }
    }

    /// ETW image names are NT device paths; map the volume to a drive.
    fn dos_path(nt: &str) -> String {
        use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
        if !nt.starts_with("\\Device\\") {
            return nt.to_string();
        }
        for letter in b'A'..=b'Z' {
            let drive: Vec<u16> = format!("{}:", letter as char).encode_utf16().chain(std::iter::once(0)).collect();
            let mut buf = [0u16; 512];
            let n = unsafe { QueryDosDeviceW(drive.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
            if n > 0 {
                let dev = String::from_utf16_lossy(&buf[..buf.iter().position(|c| *c == 0).unwrap_or(0)]);
                if !dev.is_empty() && nt.starts_with(&dev) {
                    return format!("{}:{}", letter as char, &nt[dev.len()..]);
                }
            }
        }
        nt.to_string()
    }

    fn path(pid: u32) -> Option<String> {
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) };
        unsafe { CloseHandle(h) };
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }

    /// (pid, ppid) of every process.
    fn snapshot() -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        let h = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if h == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = unsafe { Process32FirstW(h, &mut e) };
        while ok != 0 {
            out.push((e.th32ProcessID, e.th32ParentProcessID));
            ok = unsafe { Process32NextW(h, &mut e) };
        }
        unsafe { CloseHandle(h) };
        out
    }

    pub fn run(rx: Receiver<Cmd>, out: &Sender<crate::sampler::WorkerMsg>) {
        let mut watched: HashMap<u32, u64> = HashMap::new();
        let mut parent: HashMap<u32, u32> = HashMap::new();
        let mut batch = Vec::new();
        let (etx, erx) = std::sync::mpsc::channel();
        if let Some(_trace) = etw::start(etx) {
            // Event-driven: exact starts/stops; _trace stops on drop.
            loop {
                let alive = drain(&rx, |c| match c {
                    Cmd::Watch(pid) => {
                        watched.insert(pid, 0);
                    }
                    Cmd::WatchSync(pid, reply) => {
                        watched.insert(pid, 0);
                        let _ = reply.send(true);
                    }
                    Cmd::Unwatch(pid) => {
                        watched.remove(&pid);
                    }
                });
                if !alive {
                    return;
                }
                while let Ok(ev) = erx.recv_timeout(Duration::from_millis(20)) {
                    match ev {
                        etw::Ev::Start { pid, ppid, image } if watched.contains_key(&ppid) => {
                            watched.insert(pid, 0);
                            parent.insert(pid, ppid);
                            batch.push(DtEvent {
                                at: Local::now(),
                                kind: DtKind::Spawn,
                                pid,
                                ppid: Some(ppid),
                                start: crate::process::native::start_time(pid).unwrap_or(0),
                                path: Some(dos_path(&image)),
                                args: None,
                                via: "ETW",
                            });
                        }
                        etw::Ev::Stop { pid } if watched.remove(&pid).is_some() => {
                            batch.push(DtEvent { at: Local::now(), kind: DtKind::Exit, pid, ppid: parent.remove(&pid), start: 0, path: None, args: None, via: "ETW" });
                        }
                        _ => {}
                    }
                }
                if !send(out, &mut batch) {
                    return;
                }
            }
        }
        loop {
            let alive = drain(&rx, |c| match c {
                Cmd::Watch(pid) => {
                    watched.insert(pid, crate::process::native::start_time(pid).unwrap_or(0));
                }
                Cmd::WatchSync(pid, reply) => {
                    watched.insert(pid, crate::process::native::start_time(pid).unwrap_or(0));
                    let _ = reply.send(true);
                }
                Cmd::Unwatch(pid) => {
                    watched.remove(&pid);
                }
            });
            if !alive {
                break;
            }
            let snap = snapshot();
            let present: HashSet<u32> = snap.iter().map(|(p, _)| *p).collect();
            for pid in watched.keys().copied().collect::<Vec<_>>() {
                if !present.contains(&pid) {
                    batch.push(DtEvent { at: Local::now(), kind: DtKind::Exit, pid, ppid: parent.get(&pid).copied(), start: 0, path: None, args: None, via: "toolhelp poll" });
                    watched.remove(&pid);
                }
            }
            for (pid, ppid) in &snap {
                // Windows reuses PIDs: a child must start after its parent.
                if let Some(pstart) = watched.get(ppid).copied() {
                    if !watched.contains_key(pid) {
                        let start = crate::process::native::start_time(*pid).unwrap_or(0);
                        if start + 1 >= pstart {
                            watched.insert(*pid, start);
                            parent.insert(*pid, *ppid);
                            batch.push(DtEvent { at: Local::now(), kind: DtKind::Spawn, pid: *pid, ppid: Some(*ppid), start, path: path(*pid), args: None, via: "toolhelp poll" });
                        }
                    }
                }
            }
            if !send(out, &mut batch) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
mod imp {
    use super::*;
    pub const METHOD: &str = "unsupported";
    pub fn run(_rx: Receiver<Cmd>, _out: &Sender<crate::sampler::WorkerMsg>) {}
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Start a shell that spawns very short-lived children; the watcher
    /// must see them although each lives only milliseconds.
    #[test]
    fn sees_short_lived_children() {
        let (tx, rx) = std::sync::mpsc::channel();
        let w = Watcher::start(tx).expect("watcher");
        let mut sh = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 0.3; for i in 1 2 3 4 5; do /usr/bin/true; done; sleep 0.3"])
            .spawn()
            .unwrap();
        w.watch(sh.id());
        let _ = sh.wait();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut spawns = 0;
        let mut exits = 0;
        while std::time::Instant::now() < deadline {
            if let Ok(crate::sampler::WorkerMsg::Deep(evs)) = rx.recv_timeout(Duration::from_millis(200)) {
                spawns += evs.iter().filter(|e| e.kind == DtKind::Spawn).count();
                exits += evs.iter().filter(|e| e.kind == DtKind::Exit && e.pid == sh.id()).count();
            }
            if exits > 0 && spawns >= 6 {
                break;
            }
        }
        // sleep + 5×true + sleep = 7 children; allow a miss or two on a
        // loaded machine, but far more than sampling would catch.
        assert!(spawns >= 5, "saw {spawns} spawns");
        assert_eq!(exits, 1, "parent exit seen exactly once");
    }
}
