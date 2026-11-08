use super::super::*;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};

pub fn method() -> &'static str {
    "ETW Kernel-Process events (administrator) or process snapshots every 100 ms"
}

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

pub fn run(rx: Receiver<Cmd>, out: &Output) {
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
            // Events arrive for the whole system: on a busy host the
            // queue never empties, so stop to deliver and take commands.
            let until = std::time::Instant::now() + Duration::from_millis(50);
            while let Ok(ev) = erx.recv_timeout(until.saturating_duration_since(std::time::Instant::now())) {
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
                            path: Some(crate::common::etw::dos_path(&image)),
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
