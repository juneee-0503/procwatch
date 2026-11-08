use super::super::*;

/// Filled in by `run`, which is the first to know what is available.
static NETLINK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn method() -> &'static str {
    if NETLINK.load(std::sync::atomic::Ordering::Relaxed) {
        "kernel process events (netlink)"
    } else {
        "procfs polling every 20 ms"
    }
}

static READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// So `method` is right from the moment the watcher exists.
pub fn wait_ready() {
    for _ in 0..100 {
        if READY.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Exact fork/exec/exit events from the kernel. Needs CAP_NET_ADMIN.
struct Netlink(libc::c_int);

impl Netlink {
    fn open() -> Option<Netlink> {
        const NETLINK_CONNECTOR: libc::c_int = 11;
        const CN_IDX_PROC: u32 = 1;
        unsafe {
            let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, NETLINK_CONNECTOR);
            if fd < 0 {
                return None;
            }
            let sock = Netlink(fd);
            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            addr.nl_groups = CN_IDX_PROC;
            let size = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, size) != 0 {
                return None;
            }
            let buffer: libc::c_int = 4 << 20;
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &buffer as *const _ as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t);
            let msg = cn_proc::listen_message();
            addr.nl_groups = CN_IDX_PROC;
            addr.nl_pid = 0;
            let sent = libc::sendto(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0, &addr as *const _ as *const libc::sockaddr, size);
            (sent == msg.len() as isize).then_some(sock)
        }
    }

    /// Wait up to `ms` for events and return what is queued.
    fn wait(&self, ms: i32) -> Vec<cn_proc::Ev> {
        let mut out = Vec::new();
        let mut p = libc::pollfd { fd: self.0, events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut p, 1, ms) } <= 0 {
            return out;
        }
        let mut buf = [0u8; 8192];
        // Bounded: commands and delivery must keep moving under load.
        for _ in 0..512 {
            let mut from: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            let n = unsafe { libc::recvfrom(self.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_DONTWAIT, &mut from as *mut _ as *mut libc::sockaddr, &mut len) };
            if n <= 0 {
                // Empty, or the queue overflowed; polling covers gaps.
                let again = std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOBUFS);
                if again {
                    continue;
                }
                break;
            }
            // Only the kernel may speak here.
            if from.nl_pid == 0 {
                out.extend(cn_proc::parse(&buf[..n as usize]));
            }
        }
        out
    }
}

impl Drop for Netlink {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

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

pub fn run(rx: Receiver<Cmd>, out: &Output) {
    let mut b = Book { watched: HashSet::new(), exe: HashMap::new() };
    let mut parent: HashMap<u32, u32> = HashMap::new();
    let mut batch = Vec::new();
    let netlink = Netlink::open();
    NETLINK.store(netlink.is_some(), std::sync::atomic::Ordering::Relaxed);
    READY.store(true, std::sync::atomic::Ordering::Release);
    let mut sweep = 0u32;
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
        if let Some(nl) = &netlink {
            for e in nl.wait(20) {
                match e {
                    cn_proc::Ev::Fork { parent: from, child } if b.watched.contains(&from) && b.watched.insert(child) => {
                        parent.insert(child, from);
                        let e = ev(DtKind::Spawn, child, Some(from));
                        b.exe.insert(child, e.path.clone());
                        batch.push(e);
                    }
                    cn_proc::Ev::Exec { pid } if b.watched.contains(&pid) => {
                        let e = ev(DtKind::Exec, pid, parent.get(&pid).copied());
                        b.exe.insert(pid, e.path.clone());
                        batch.push(e);
                    }
                    cn_proc::Ev::Exit { pid } if b.watched.remove(&pid) => {
                        batch.push(DtEvent { at: Local::now(), kind: DtKind::Exit, pid, ppid: parent.remove(&pid), start: 0, path: b.exe.remove(&pid).flatten(), args: None, via: "netlink" });
                    }
                    _ => {}
                }
            }
            // The sweep below only backstops lost events now.
            sweep += 1;
            if !sweep.is_multiple_of(25) {
                if !send(out, &mut batch) {
                    break;
                }
                continue;
            }
        }
        let current: Vec<u32> = b.watched.iter().copied().collect();
        for pid in current {
            if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
                batch.push(DtEvent { at: Local::now(), kind: DtKind::Exit, pid, ppid: parent.get(&pid).copied(), start: 0, path: None, args: None, via: "procfs poll" });
                b.watched.remove(&pid);
                b.exe.remove(&pid);
                parent.remove(&pid);
                continue;
            }
            // A zombie's exe link can't be read: that isn't an exec.
            let now_exe = exe(pid);
            if now_exe.is_some() {
                if b.exe.get(&pid).is_some_and(|e| *e != now_exe) {
                    batch.push(ev(DtKind::Exec, pid, parent.get(&pid).copied()));
                }
                b.exe.insert(pid, now_exe);
            }
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
        if netlink.is_none() {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
