//! Network attacks visible from the kernel's own tables: half-open
//! connections, one source holding many connections, and overflowing accept
//! queues. These work without capturing a single packet.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Local};

use super::config::Thresholds;
use super::filter::source_key;
use super::{Stage, Threat};
use crate::common::model::Severity;

pub const ESTABLISHED: u8 = 1;
pub const SYN_RECV: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sock {
    pub local_port: u16,
    pub remote: IpAddr,
    pub state: u8,
    pub inode: u64,
}

fn address(hex: &str) -> Option<(IpAddr, u16)> {
    let (addr, port) = hex.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match addr.len() {
        8 => IpAddr::V4(Ipv4Addr::from(u32::from_str_radix(addr, 16).ok()?.swap_bytes())),
        32 => {
            let mut octets = [0u8; 16];
            for i in 0..4 {
                let word = u32::from_str_radix(addr.get(i * 8..(i + 1) * 8)?, 16).ok()?.swap_bytes();
                octets[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
            }
            let v6 = Ipv6Addr::from(octets);
            v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
        }
        _ => return None,
    };
    Some((ip, port))
}

/// `/proc/net/tcp` or `tcp6`.
pub fn parse_tcp(text: &str) -> Vec<Sock> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (_, local_port) = address(f.get(1)?)?;
            let (remote, _) = address(f.get(2)?)?;
            Some(Sock { local_port, remote, state: u8::from_str_radix(f.get(3)?, 16).ok()?, inode: f.get(9)?.parse().ok()? })
        })
        .collect()
}

/// A value from `/proc/net/netstat` or `snmp`: name and value rows in pairs.
pub fn counter(text: &str, prefix: &str, name: &str) -> Option<u64> {
    let mut rows = text.lines().filter(|l| l.starts_with(prefix));
    while let (Some(names), Some(values)) = (rows.next(), rows.next()) {
        if let Some(i) = names.split_whitespace().position(|n| n == name) {
            return values.split_whitespace().nth(i)?.parse().ok();
        }
    }
    None
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Counters {
    pub syncookies: u64,
    pub listen_drops: u64,
}

pub struct Detector {
    limits: Thresholds,
    include_loopback: bool,
    last: Option<(i64, Counters)>,
}

impl Detector {
    pub fn new(limits: Thresholds, include_loopback: bool) -> Detector {
        Detector { limits, include_loopback, last: None }
    }

    pub fn check(&mut self, socks: &[Sock], counters: Counters, now: DateTime<Local>) -> Vec<Threat> {
        let mut half: HashMap<IpAddr, usize> = HashMap::new();
        let mut held: HashMap<IpAddr, (IpAddr, usize)> = HashMap::new();
        let mut half_total = 0;
        for s in socks.iter().filter(|s| self.include_loopback || !s.remote.is_loopback()) {
            let key = source_key(s.remote);
            match s.state {
                SYN_RECV => {
                    half_total += 1;
                    *half.entry(key).or_default() += 1;
                }
                ESTABLISHED => held.entry(key).or_insert((s.remote, 0)).1 += 1,
                _ => {}
            }
        }
        let mut out = Vec::new();
        if half_total >= self.limits.half_open {
            let (top, n) = half.iter().max_by_key(|(_, n)| **n).map_or((None, 0), |(ip, n)| (Some(*ip), *n));
            let mut t = Threat::new(now, "syn-flood", Severity::High, Stage::Impact, format!("{half_total} half-open connections from {} sources", half.len())).with_evidence(format!("largest source holds {n}"));
            // Spoofed floods have no real source to name.
            if n * 2 >= half_total {
                t.source = top;
            }
            out.push(t);
        }
        for (ip, n) in held.values().filter(|(_, n)| *n >= self.limits.connections_per_source) {
            out.push(Threat::new(now, "connection-flood", Severity::High, Stage::Impact, format!("{ip} holds {n} connections")).source_ip(*ip));
        }
        let t = now.timestamp();
        if let Some((at, before)) = self.last {
            let secs = (t - at).max(1) as u64;
            let cookies = counters.syncookies.saturating_sub(before.syncookies) / secs;
            let drops = counters.listen_drops.saturating_sub(before.listen_drops) / secs;
            if cookies >= self.limits.syncookies_per_second {
                out.push(Threat::new(now, "syn-cookies-active", Severity::High, Stage::Impact, format!("Kernel sending {cookies} SYN cookies a second: the backlog is full")));
            }
            if drops >= self.limits.listen_drops_per_second {
                out.push(Threat::new(now, "accept-queue-overflow", Severity::High, Stage::Impact, format!("{drops} connections a second dropped: a service can't keep up")));
            }
        }
        self.last = Some((t, counters));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1
   1: 00000000:0016 0571000B:C350 03 00000000:00000000 00:00000000 00000000     0        0 77 1
   bad line
";

    #[test]
    fn reads_the_kernel_socket_table() {
        let s = parse_tcp(TCP);
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].local_port, s[0].remote.to_string().as_str(), s[0].state, s[0].inode), (8080, "127.0.0.1", 1, 4242));
        assert_eq!((s[1].remote.to_string().as_str(), s[1].state), ("11.0.113.5", SYN_RECV));
        let six = parse_tcp("h\n 0: 00000000000000000000000001000000:0016 0000000000000000FFFF00000571000B:C350 01 0 0 0 0 0 9\n");
        assert_eq!(six[0].remote.to_string(), "11.0.113.5", "mapped addresses read as IPv4");
    }

    #[test]
    fn reads_counters() {
        let t = "TcpExt: SyncookiesSent ListenDrops\nTcpExt: 12 34\nIpExt: A\nIpExt: 1\n";
        assert_eq!(counter(t, "TcpExt:", "ListenDrops"), Some(34));
        assert_eq!(counter(t, "TcpExt:", "Missing"), None);
    }

    fn sock(ip: &str, state: u8) -> Sock {
        Sock { local_port: 80, remote: ip.parse().unwrap(), state, inode: 1 }
    }

    fn at(s: i64) -> DateTime<Local> {
        Local.timestamp_opt(1_800_000_000 + s, 0).unwrap()
    }

    #[test]
    fn floods_are_named_when_they_have_one_source() {
        let mut d = Detector::new(Thresholds::default(), false);
        let one: Vec<_> = (0..300).map(|_| sock("203.0.113.7", SYN_RECV)).collect();
        let t = d.check(&one, Counters::default(), at(0));
        assert_eq!((t[0].rule, t[0].source.map(|i| i.to_string())), ("syn-flood", Some("203.0.113.7".to_string())));
        let spoofed: Vec<_> = (0..300).map(|i| sock(&format!("198.51.{}.{}", i / 250, i % 250), SYN_RECV)).collect();
        assert_eq!(d.check(&spoofed, Counters::default(), at(2))[0].source, None);
        let held: Vec<_> = (0..250).map(|_| sock("203.0.113.9", ESTABLISHED)).collect();
        assert_eq!(d.check(&held, Counters::default(), at(4))[0].rule, "connection-flood");
        let local: Vec<_> = (0..300).map(|_| sock("127.0.0.1", SYN_RECV)).collect();
        assert!(d.check(&local, Counters::default(), at(6)).is_empty());
    }

    #[test]
    fn rates_come_from_counter_changes() {
        let mut d = Detector::new(Thresholds::default(), false);
        assert!(d.check(&[], Counters { syncookies: 1_000_000, listen_drops: 0 }, at(0)).is_empty(), "the first reading has no rate");
        assert!(d.check(&[], Counters { syncookies: 1_000_100, listen_drops: 0 }, at(2)).is_empty());
        let t = d.check(&[], Counters { syncookies: 1_001_000, listen_drops: 4000 }, at(4));
        assert_eq!(t.iter().map(|x| x.rule).collect::<Vec<_>>(), ["syn-cookies-active", "accept-queue-overflow"]);
    }
}
