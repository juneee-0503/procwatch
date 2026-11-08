//! Seeing connection attempts as they arrive, including those to closed
//! ports, which leave no trace in any table or log.
//!
//! A filter in the kernel passes only TCP SYN packets, so a busy server hands
//! over almost nothing, and only the headers are read: payloads never leave
//! the kernel. Linux only, and it needs root.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Local};

use super::config::Thresholds;
use super::filter::{source_key, Distinct};
use super::{Stage, Threat};
use crate::common::model::Severity;

const ETHERNET_HEADER: usize = 14;

/// Source and destination port of a TCP SYN in an Ethernet frame. Every
/// length is checked: anyone can send these bytes.
pub fn parse_syn(frame: &[u8]) -> Option<(IpAddr, u16)> {
    let ethertype = u16::from_be_bytes(frame.get(12..14)?.try_into().ok()?);
    let ip = frame.get(ETHERNET_HEADER..)?;
    let (source, tcp) = match ethertype {
        0x0800 => {
            let header = usize::from(ip.first()? & 0x0f) * 4;
            if header < 20 || *ip.get(9)? != 6 {
                return None;
            }
            let octets: [u8; 4] = ip.get(12..16)?.try_into().ok()?;
            (IpAddr::V4(Ipv4Addr::from(octets)), ip.get(header..)?)
        }
        0x86dd => {
            if *ip.get(6)? != 6 {
                return None;
            }
            let octets: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
            (IpAddr::V6(Ipv6Addr::from(octets)), ip.get(40..)?)
        }
        _ => return None,
    };
    let flags = *tcp.get(13)?;
    if flags & 0x12 != 0x02 {
        return None;
    }
    Some((source, u16::from_be_bytes(tcp.get(2..4)?.try_into().ok()?)))
}

pub struct Detector {
    limits: Thresholds,
    include_loopback: bool,
    ports: Distinct<IpAddr, u16>,
    second: i64,
    in_second: usize,
}

impl Detector {
    pub fn new(limits: Thresholds, include_loopback: bool) -> Detector {
        Detector { limits, include_loopback, ports: Distinct::new(60), second: 0, in_second: 0 }
    }

    pub fn feed(&mut self, source: IpAddr, port: u16, now: DateTime<Local>) -> Option<Threat> {
        let t = now.timestamp();
        if t != self.second {
            self.second = t;
            self.in_second = 0;
        }
        self.in_second += 1;
        if self.in_second == self.limits.syns_per_second {
            return Some(Threat::new(now, "syn-rate", Severity::High, Stage::Impact, format!("{} connection attempts in a second", self.in_second)));
        }
        if source.is_loopback() && !self.include_loopback {
            return None;
        }
        let n = self.ports.add(source_key(source), port, t);
        (n >= self.limits.scan_ports).then(|| Threat::new(now, "port-scan", Severity::Medium, Stage::Recon, format!("{source} probed {n} ports")).source_ip(source))
    }
}

#[cfg(target_os = "linux")]
pub use linux::Sniffer;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc::{sync_channel, Receiver};
    use std::sync::Arc;

    const ETH_P_ALL: u16 = 0x0003;
    const PACKET_OUTGOING: u8 = 4;
    const SNAP: u32 = 128;

    /// Classic BPF: pass IPv4 or IPv6 TCP with SYN set and ACK clear.
    const fn op(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }
    const FILTER: [libc::sock_filter; 16] = [
        op(0x28, 0, 0, 12),      //  0 ldh [12]             ethertype
        op(0x15, 0, 7, 0x0800),  //  1 jeq IPv4? else 9
        op(0x30, 0, 0, 23),      //  2 ldb [23]             protocol
        op(0x15, 0, 11, 6),      //  3 jeq TCP? else drop
        op(0x28, 0, 0, 20),      //  4 ldh [20]             fragment
        op(0x45, 9, 0, 0x1fff),  //  5 jset offset? drop
        op(0xb1, 0, 0, 14),      //  6 ldxb 4*([14]&0xf)    header length
        op(0x50, 0, 0, 27),      //  7 ldb [x+27]           TCP flags
        op(0x05, 0, 0, 3),       //  8 ja 12
        op(0x15, 0, 5, 0x86dd),  //  9 jeq IPv6? else drop
        op(0x30, 0, 0, 20),      // 10 ldb [20]             next header
        op(0x15, 0, 3, 6),       // 11 jeq TCP? else drop   (falls to 12 via next)
        op(0x54, 0, 0, 0x12),    // 12 and SYN|ACK          (A holds flags or, for v6, 6)
        op(0x15, 0, 1, 0x02),    // 13 jeq SYN only? else drop
        op(0x06, 0, 0, SNAP),    // 14 accept
        op(0x06, 0, 0, 0),       // 15 drop
    ];

    pub struct Sniffer {
        pub rx: Receiver<(IpAddr, u16)>,
        pub lost: Arc<AtomicU64>,
        stop: Arc<AtomicBool>,
    }

    impl Drop for Sniffer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    impl Sniffer {
        pub fn start() -> Result<Sniffer, String> {
            let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, i32::from(ETH_P_ALL.to_be())) };
            if fd < 0 {
                return Err(format!("packet socket: {} (needs root or CAP_NET_RAW)", std::io::Error::last_os_error()));
            }
            let mut filter = FILTER;
            let program = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_mut_ptr() };
            let tv = libc::timeval { tv_sec: 0, tv_usec: 250_000 };
            unsafe {
                if libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, (&raw const program).cast(), std::mem::size_of_val(&program) as u32) != 0 {
                    let e = std::io::Error::last_os_error();
                    libc::close(fd);
                    return Err(format!("attaching the filter: {e}"));
                }
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&raw const tv).cast(), std::mem::size_of_val(&tv) as u32);
            }
            let (tx, rx) = sync_channel(65_536);
            let (stop, lost) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicU64::new(0)));
            let (halt, counter) = (stop.clone(), lost.clone());
            let spawned = std::thread::Builder::new().name("syn-sniffer".into()).spawn(move || {
                let mut frame = [0u8; SNAP as usize];
                while !halt.load(Ordering::Relaxed) {
                    let mut from: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
                    let mut len = std::mem::size_of_val(&from) as u32;
                    let n = unsafe { libc::recvfrom(fd, frame.as_mut_ptr().cast(), frame.len(), 0, (&raw mut from).cast(), &mut len) };
                    if n <= 0 || from.sll_pkttype == PACKET_OUTGOING {
                        continue;
                    }
                    if let Some(hit) = parse_syn(&frame[..n as usize]) {
                        if tx.try_send(hit).is_err() {
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                unsafe { libc::close(fd) };
            });
            if let Err(e) = spawned {
                unsafe { libc::close(fd) };
                return Err(e.to_string());
            }
            Ok(Sniffer { rx, lost, stop })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn v4(flags: u8, port: u16) -> Vec<u8> {
        let mut f = vec![0u8; 14 + 20 + 20];
        f[12..14].copy_from_slice(&[0x08, 0x00]);
        f[14] = 0x45;
        f[23] = 6;
        f[26..30].copy_from_slice(&[203, 0, 113, 4]);
        f[36..38].copy_from_slice(&port.to_be_bytes());
        f[47] = flags;
        f
    }

    #[test]
    fn reads_syn_packets_only() {
        assert_eq!(parse_syn(&v4(0x02, 22)), Some(("203.0.113.4".parse().unwrap(), 22)));
        assert_eq!(parse_syn(&v4(0x12, 22)), None, "SYN-ACK");
        assert_eq!(parse_syn(&v4(0x10, 22)), None, "ACK");
        let mut six = vec![0u8; 14 + 40 + 20];
        six[12..14].copy_from_slice(&[0x86, 0xdd]);
        six[20] = 6;
        six[22] = 0x20;
        six[56..58].copy_from_slice(&443u16.to_be_bytes());
        six[67] = 0x02;
        assert_eq!(parse_syn(&six).map(|h| h.1), Some(443));
    }

    #[test]
    fn short_or_strange_frames_are_ignored() {
        let good = v4(0x02, 22);
        for cut in 0..good.len() - 7 {
            assert_eq!(parse_syn(&good[..cut]), None, "cut at {cut}");
        }
        let mut bad = good.clone();
        bad[14] = 0x41;
        assert_eq!(parse_syn(&bad), None, "header length below minimum");
        bad[14] = 0x4f;
        assert_eq!(parse_syn(&bad[..40]), None);
    }

    #[test]
    fn scans_and_floods() {
        let at = |s: i64| Local.timestamp_opt(1_800_000_000 + s, 0).unwrap();
        let ip: IpAddr = "203.0.113.4".parse().unwrap();
        let mut d = Detector::new(Thresholds::default(), false);
        assert!((0..14).all(|p| d.feed(ip, p, at(1)).is_none()));
        assert_eq!(d.feed(ip, 99, at(1)).unwrap().rule, "port-scan");
        let mut d = Detector::new(Thresholds::default(), false);
        let n = (0..3000u32).filter_map(|i| d.feed(IpAddr::V4(i.into()), 80, at(1))).count();
        assert_eq!(n, 1);
        assert!(d.feed("127.0.0.1".parse().unwrap(), 1, at(3)).is_none());
    }
}
