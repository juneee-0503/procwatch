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

mod probes;
#[cfg(target_os = "linux")]
use probes::linux;
#[cfg(target_os = "macos")]
use probes::macos;
#[cfg(windows)]
use probes::windows;

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
pub use probes::windows::set_connection_sink;

/// What this platform can count.
pub fn capability() -> crate::kernel::Capability {
    use crate::kernel::Capability;
    if cfg!(windows) {
        Capability::partly("traffic per process", "TCP and UDP, needs administrator; loopback isn't counted")
    } else if cfg!(target_os = "linux") {
        Capability::partly("traffic per process", "TCP only, and only processes whose sockets are readable")
    } else if cfg!(target_os = "macos") {
        Capability::yes("traffic per process")
    } else {
        Capability::no("traffic per process", "no probe for this platform")
    }
}

/// One `name.pid,bytes_in,bytes_out,` line of `nettop -P -x`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_nettop(line: &str) -> Option<(u32, u64, u64)> {
    let mut f = line.trim_end_matches(',').rsplitn(3, ',');
    let tx: u64 = f.next()?.trim().parse().ok()?;
    let rx: u64 = f.next()?.trim().parse().ok()?;
    let pid: u32 = f.next()?.rsplit_once('.')?.1.parse().ok()?;
    Some((pid, rx, tx))
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
