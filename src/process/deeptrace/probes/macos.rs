use super::super::*;

pub fn method() -> &'static str {
    "kqueue process notifications"
}

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

pub fn run(rx: Receiver<Cmd>, out: &Output) {
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        out.errors.send("deep trace: kqueue unavailable".into());
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
