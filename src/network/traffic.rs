//! Bytes per process.
//!
//! - Windows: ETW Kernel-Network, TCP and UDP (administrator).
//! - Linux: `sock_diag` per-socket counters, mapped to processes through
//!   `/proc/*/fd`. TCP only: the kernel keeps no such counters for UDP.
//! - macOS: `nettop`.
//!
//! Sends cumulative totals; the UI turns them into rates.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::time::Duration;

use crate::common::emit::Emit;

/// Per pid: bytes received, bytes sent.
pub type Totals = HashMap<u32, (u64, u64)>;

/// A connection opened or closed, on platforms with exact events.
#[cfg_attr(not(windows), allow(dead_code))]
pub struct ConnOp {
    pub pid: u32,
    pub op: &'static str,
    pub remote: String,
}

/// A running counter; stops when dropped.
pub struct Traffic {
    stop: Arc<AtomicBool>,
    pub method: &'static str,
    #[cfg(windows)]
    _trace: ferrisetw::trace::UserTrace,
}

impl Drop for Traffic {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

pub fn start(out: Emit<Totals>) -> Result<Traffic, String> {
    let stop = Arc::new(AtomicBool::new(false));
    #[cfg(windows)]
    {
        let trace = windows::start_traffic(out, stop.clone())?;
        Ok(Traffic { stop, method: "ETW Kernel-Network", _trace: trace })
    }
    #[cfg(target_os = "linux")]
    {
        let s = stop.clone();
        std::thread::Builder::new()
            .name("traffic".into())
            .spawn(move || {
                let mut c = linux::Counter::default();
                while !s.load(Ordering::Relaxed) {
                    if let Some(t) = c.sample() {
                        if !out.send(t) {
                            return;
                        }
                    }
                    std::thread::sleep(Duration::from_secs(2));
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Traffic { stop, method: "sock_diag per-socket counters (TCP only)" })
    }
    #[cfg(target_os = "macos")]
    {
        let s = stop.clone();
        std::thread::Builder::new()
            .name("traffic".into())
            .spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    if let Some(t) = macos::sample() {
                        if !out.send(t) {
                            return;
                        }
                    }
                    std::thread::sleep(Duration::from_secs(2));
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Traffic { stop, method: "nettop" })
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (out, stop);
        Err("not available on this platform".into())
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Mutex;

    use ferrisetw::parser::Parser;
    use ferrisetw::provider::Provider;
    use ferrisetw::schema_locator::SchemaLocator;
    use ferrisetw::trace::UserTrace;
    use ferrisetw::EventRecord;

    use crate::common::etw::start;

    const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
    /// Kernel-Network keywords: IPv4 and IPv6.
    const NET_KEYWORDS: u64 = 0x10 | 0x20;
    const MAX_TRAFFIC_PIDS: usize = 16_384;

    /// Who wants connection events, while an activity capture runs.
    static SINK: Mutex<Option<Emit<ConnOp>>> = Mutex::new(None);

    pub fn set_connection_sink(sink: Option<Emit<ConnOp>>) {
        if let Ok(mut s) = SINK.lock() {
            *s = sink;
        }
    }

    pub fn start_traffic(out: Emit<Totals>, stop: Arc<AtomicBool>) -> Result<UserTrace, String> {
        let totals: Arc<Mutex<Totals>> = Arc::default();
        let shared = totals.clone();
        let provider = Provider::by_guid(KERNEL_NETWORK)
            .any(NET_KEYWORDS)
            .add_callback(move |r: &EventRecord, sl: &SchemaLocator| {
                // The event says which process; the header is often System.
                let id = r.event_id();
                let (received, sent, op) = match id {
                    11 | 27 | 43 | 59 => (true, false, ""),
                    10 | 26 | 42 | 58 => (false, true, ""),
                    12 | 28 => (false, false, "connect"),
                    15 | 31 => (false, false, "accept"),
                    13 | 29 => (false, false, "disconnect"),
                    _ => return,
                };
                let Ok(schema) = sl.event_schema(r) else { return };
                let p = Parser::create(r, &schema);
                let Ok(pid) = p.try_parse::<u32>("PID") else { return };
                if received || sent {
                    let size = u64::from(p.try_parse::<u32>("size").unwrap_or(0));
                    if let Ok(mut t) = shared.lock() {
                        let e = t.entry(pid).or_default();
                        if received {
                            e.0 += size;
                        } else {
                            e.1 += size;
                        }
                    }
                    return;
                }
                if let Ok(s) = SINK.lock() {
                    if let Some(sink) = s.as_ref() {
                        let ip = p.try_parse::<IpAddr>("daddr").map(|a| a.to_string()).unwrap_or_default();
                        // Network byte order, whatever the schema says.
                        let port = p.try_parse::<u16>("dport").map(u16::swap_bytes).unwrap_or(0);
                        sink.send(ConnOp { pid, op, remote: format!("{ip}:{port}") });
                    }
                }
            })
            .build();
        let trace = start("procwatch-traffic", vec![provider])?;
        let _ = std::thread::Builder::new().name("traffic".into()).spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(2));
                let now = totals
                    .lock()
                    .map(|mut t| {
                        // Exited processes' entries; rates only need the live ones.
                        if t.len() > MAX_TRAFFIC_PIDS {
                            t.clear();
                        }
                        t.clone()
                    })
                    .unwrap_or_default();
                if !now.is_empty() && !out.send(now) {
                    return;
                }
            }
        });
        Ok(trace)
    }

}

#[cfg(windows)]
pub use windows::set_connection_sink;

/// One `name.pid,bytes_in,bytes_out,` line of `nettop -P -x`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_nettop(line: &str) -> Option<(u32, u64, u64)> {
    let mut f = line.trim_end_matches(',').rsplitn(3, ',');
    let tx: u64 = f.next()?.trim().parse().ok()?;
    let rx: u64 = f.next()?.trim().parse().ok()?;
    let pid: u32 = f.next()?.rsplit_once('.')?.1.parse().ok()?;
    Some((pid, rx, tx))
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    /// One sample per run: nettop buffers its output when writing to a pipe,
    /// so a long-running one delivers data many seconds late.
    pub fn sample() -> Option<Totals> {
        let mut cmd = std::process::Command::new("/usr/bin/nettop");
        cmd.args(["-P", "-x", "-L", "1", "-J", "bytes_in,bytes_out"]);
        let out = crate::common::command::run_command(&mut cmd, Duration::from_secs(8)).ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let totals: Totals = text.lines().filter_map(parse_nettop).map(|(pid, rx, tx)| (pid, (rx, tx))).collect();
        (!totals.is_empty()).then_some(totals)
    }
}

// ── sock_diag messages (portable for tests) ────────────────────────────

const NLMSG_HDR: usize = 16;
const DIAG_MSG: usize = 72;
const INODE_AT: usize = 68;
const INET_DIAG_INFO: u16 = 2;
const BYTES_ACKED_AT: usize = 120;
const BYTES_RECEIVED_AT: usize = 128;

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// The request that dumps TCP sockets of one family with `tcp_info`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn diag_request(family: u8) -> Vec<u8> {
    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    const FLAGS: u16 = 0x1 | 0x300; // NLM_F_REQUEST | NLM_F_DUMP
    const IPPROTO_TCP: u8 = 6;
    let total = (NLMSG_HDR + 56) as u32;
    let mut m = Vec::with_capacity(total as usize);
    m.extend(total.to_ne_bytes());
    m.extend(SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    m.extend(FLAGS.to_ne_bytes());
    m.extend(1u32.to_ne_bytes()); // seq
    m.extend(0u32.to_ne_bytes()); // pid
    m.push(family);
    m.push(IPPROTO_TCP);
    m.push(1 << (INET_DIAG_INFO - 1)); // ask for tcp_info
    m.push(0);
    m.extend(u32::MAX.to_ne_bytes()); // every state
    m.extend([0u8; 48]); // socket id: any
    m
}

/// (inode, bytes received, bytes sent) per socket in one reply datagram,
/// and whether this was the end of the dump.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_diag(mut buf: &[u8]) -> (Vec<(u32, u64, u64)>, bool) {
    const NLMSG_DONE: u16 = 3;
    const NLMSG_ERROR: u16 = 2;
    let mut out = Vec::new();
    while let Some(len) = u32_at(buf, 0).map(|l| l as usize) {
        if len < NLMSG_HDR || len > buf.len() {
            return (out, true);
        }
        let kind = u16::from_ne_bytes([buf[4], buf[5]]);
        if kind == NLMSG_DONE || kind == NLMSG_ERROR {
            return (out, true);
        }
        let msg = &buf[NLMSG_HDR..len];
        if let Some(inode) = u32_at(msg, INODE_AT) {
            let mut attrs = msg.get(DIAG_MSG..).unwrap_or_default();
            while attrs.len() >= 4 {
                let alen = u16::from_ne_bytes([attrs[0], attrs[1]]) as usize;
                let atype = u16::from_ne_bytes([attrs[2], attrs[3]]);
                if alen < 4 || alen > attrs.len() {
                    break;
                }
                if atype == INET_DIAG_INFO {
                    let info = &attrs[4..alen];
                    if let (Some(rx), Some(tx)) = (u64_at(info, BYTES_RECEIVED_AT), u64_at(info, BYTES_ACKED_AT)) {
                        out.push((inode, rx, tx));
                    }
                }
                attrs = attrs.get(((alen + 3) & !3)..).unwrap_or_default();
            }
        }
        let next = (len + 3) & !3;
        if next >= buf.len() {
            break;
        }
        buf = &buf[next..];
    }
    (out, false)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nettop_lines() {
        assert_eq!(parse_nettop("mDNSResponder.707,123557905,74609179,"), Some((707, 123557905, 74609179)));
        assert_eq!(parse_nettop("com.apple.WebKit.Net.1234,10,20,"), Some((1234, 10, 20)));
        assert_eq!(parse_nettop("odd,name.5,1,2,"), Some((5, 1, 2)));
        assert_eq!(parse_nettop("00:20:14.335570,Python.59370,4194304,4194304,"), Some((59370, 4194304, 4194304)), "with its time column");
        assert_eq!(parse_nettop(",bytes_in,bytes_out,"), None);
        assert_eq!(parse_nettop("noprocess,1,2,"), None);
        assert_eq!(parse_nettop(""), None);
    }

    fn reply(inode: u32, rx: u64, tx: u64) -> Vec<u8> {
        let mut body = vec![0u8; DIAG_MSG];
        body[INODE_AT..INODE_AT + 4].copy_from_slice(&inode.to_ne_bytes());
        let mut info = vec![0u8; 232];
        info[BYTES_RECEIVED_AT..BYTES_RECEIVED_AT + 8].copy_from_slice(&rx.to_ne_bytes());
        info[BYTES_ACKED_AT..BYTES_ACKED_AT + 8].copy_from_slice(&tx.to_ne_bytes());
        // Another attribute first, as the kernel may send.
        body.extend(8u16.to_ne_bytes());
        body.extend(99u16.to_ne_bytes());
        body.extend([0u8; 4]);
        body.extend(((info.len() + 4) as u16).to_ne_bytes());
        body.extend(INET_DIAG_INFO.to_ne_bytes());
        body.extend(info);
        let mut m = Vec::new();
        m.extend(((NLMSG_HDR + body.len()) as u32).to_ne_bytes());
        m.extend(20u16.to_ne_bytes());
        m.extend([0u8; 10]);
        m.extend(body);
        m
    }

    #[test]
    fn diag_replies_and_garbage() {
        let mut two = reply(7, 100, 200);
        two.extend(reply(8, 1, 2));
        assert_eq!(parse_diag(&two), (vec![(7, 100, 200), (8, 1, 2)], false));
        let mut done = vec![0u8; NLMSG_HDR];
        done[..4].copy_from_slice(&(NLMSG_HDR as u32).to_ne_bytes());
        done[4..6].copy_from_slice(&3u16.to_ne_bytes());
        assert_eq!(parse_diag(&done), (vec![], true));
        assert_eq!(parse_diag(&[]), (vec![], false));
        assert_eq!(parse_diag(&[0xff; 8]).0, vec![]);
        let cut = reply(7, 1, 2);
        assert_eq!(parse_diag(&cut[..80]).0, vec![], "truncated");
        assert_eq!(diag_request(2).len(), 72);
    }
}
