use super::super::*;

const NETLINK_SOCK_DIAG: libc::c_int = 4;

fn dump(family: u8, out: &mut Vec<(u32, u64, u64)>) -> Option<()> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, NETLINK_SOCK_DIAG) };
    if fd < 0 {
        return None;
    }
    struct Close(libc::c_int);
    impl Drop for Close {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }
    let _close = Close(fd);
    let timeout = libc::timeval { tv_sec: 1, tv_usec: 0 };
    unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &timeout as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as libc::socklen_t) };
    let req = diag_request(family);
    if unsafe { libc::send(fd, req.as_ptr() as *const libc::c_void, req.len(), 0) } < 0 {
        return None;
    }
    let mut buf = vec![0u8; 64 * 1024];
    for _ in 0..10_000 {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n <= 0 {
            return None;
        }
        let (sockets, done) = parse_diag(&buf[..n as usize]);
        out.extend(sockets);
        if done {
            return Some(());
        }
    }
    Some(())
}

/// Who owns each socket inode. Only processes we may read show up.
fn owners() -> HashMap<u32, u32> {
    let mut map = HashMap::new();
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        for fd in std::fs::read_dir(e.path().join("fd")).into_iter().flatten().flatten() {
            if let Ok(link) = std::fs::read_link(fd.path()) {
                let link = link.to_string_lossy();
                if let Some(inode) = link.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')).and_then(|s| s.parse::<u32>().ok()) {
                    map.entry(inode).or_insert(pid);
                }
            }
        }
    }
    map
}

#[derive(Default)]
pub struct Counter {
    last: HashMap<u32, (u64, u64)>,
    owners: HashMap<u32, u32>,
    totals: Totals,
}

impl Counter {
    pub fn sample(&mut self) -> Option<Totals> {
        let mut sockets = Vec::new();
        dump(libc::AF_INET as u8, &mut sockets)?;
        let _ = dump(libc::AF_INET6 as u8, &mut sockets);
        if sockets.iter().any(|(inode, ..)| !self.owners.contains_key(inode)) {
            self.owners = owners();
        }
        let mut last = HashMap::with_capacity(sockets.len());
        for (inode, rx, tx) in sockets {
            // A socket seen for the first time adds what it moved so far.
            let (prev_rx, prev_tx) = self.last.get(&inode).copied().unwrap_or((0, 0));
            if let Some(pid) = self.owners.get(&inode) {
                let t = self.totals.entry(*pid).or_default();
                t.0 += rx.saturating_sub(prev_rx);
                t.1 += tx.saturating_sub(prev_tx);
            }
            last.insert(inode, (rx, tx));
        }
        self.last = last;
        let owners: std::collections::HashSet<u32> = self.owners.values().copied().collect();
        self.totals.retain(|pid, _| owners.contains(pid));
        Some(self.totals.clone())
    }
}
