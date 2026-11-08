//! Sliding-window counters, repeat suppression and address matching. Keys
//! come from attackers, so every map here has a limit.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;

use super::Threat;

const MAX_KEYS: usize = 65_536;
const MAX_PER_KEY: usize = 4096;

/// Events per key within the last `window` seconds.
pub struct Counter<K> {
    window: i64,
    map: HashMap<K, VecDeque<i64>>,
}

impl<K: Eq + Hash> Counter<K> {
    pub fn new(window: i64) -> Counter<K> {
        Counter { window, map: HashMap::new() }
    }

    pub fn add(&mut self, key: K, now: i64) -> usize {
        if self.map.len() >= MAX_KEYS && !self.map.contains_key(&key) {
            let window = self.window;
            self.map.retain(|_, v| v.back().is_some_and(|t| now - t < window));
            if self.map.len() >= MAX_KEYS {
                self.map.clear();
            }
        }
        let v = self.map.entry(key).or_default();
        v.push_back(now);
        while v.front().is_some_and(|t| now - t >= self.window) || v.len() > MAX_PER_KEY {
            v.pop_front();
        }
        v.len()
    }

    pub fn count(&self, key: &K, now: i64) -> usize {
        self.map.get(key).map_or(0, |v| v.iter().filter(|t| now - **t < self.window).count())
    }
}

/// Distinct values per key within a window: ports per source, sources per user.
pub struct Distinct<K, V> {
    window: i64,
    map: HashMap<K, (i64, HashSet<V>)>,
}

impl<K: Eq + Hash, V: Eq + Hash> Distinct<K, V> {
    pub fn new(window: i64) -> Distinct<K, V> {
        Distinct { window, map: HashMap::new() }
    }

    pub fn add(&mut self, key: K, value: V, now: i64) -> usize {
        if self.map.len() >= MAX_KEYS && !self.map.contains_key(&key) {
            let window = self.window;
            self.map.retain(|_, v| now - v.0 < window);
            if self.map.len() >= MAX_KEYS {
                self.map.clear();
            }
        }
        let e = self.map.entry(key).or_insert_with(|| (now, HashSet::new()));
        if now - e.0 >= self.window {
            *e = (now, HashSet::new());
        }
        if e.1.len() < MAX_PER_KEY {
            e.1.insert(value);
        }
        e.1.len()
    }
}

/// An address or a network, `10.0.0.0/8` or `2001:db8::/32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    bits: u8,
}

fn as_bits(ip: IpAddr) -> (u128, u8) {
    match ip {
        IpAddr::V4(a) => (u128::from(u32::from(a)), 32),
        IpAddr::V6(a) => (u128::from(a), 128),
    }
}

impl Cidr {
    pub fn parse(text: &str) -> Result<Cidr, String> {
        let (ip, bits) = match text.split_once('/') {
            Some((i, b)) => (i, Some(b.parse::<u8>().map_err(|_| format!("{text}: bad prefix length"))?)),
            None => (text, None),
        };
        let addr: IpAddr = ip.trim().parse().map_err(|_| format!("{text}: not an address"))?;
        let max = as_bits(addr).1;
        let bits = bits.unwrap_or(max);
        if bits > max {
            return Err(format!("{text}: prefix too long"));
        }
        Ok(Cidr { addr, bits })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let (a, width) = as_bits(self.addr);
        let (b, other) = as_bits(ip);
        if width != other {
            return false;
        }
        let shift = u32::from(width - self.bits);
        shift >= 128 || (a >> shift) == (b >> shift)
    }
}

/// One attacker on IPv6 owns a whole /64, so counting by address would let
/// them count as thousands of small sources.
pub fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => {
            let masked = u128::from(a) & !((1u128 << 64) - 1);
            IpAddr::V6(masked.into())
        }
        v4 => v4,
    }
}

/// What makes two findings the same one.
type Finding = (&'static str, Option<IpAddr>, Option<String>, Option<u32>);

/// Decides which threats reach anyone.
pub struct Gate {
    allow: Vec<Cidr>,
    quiet: i64,
    last: HashMap<Finding, i64>,
}

impl Gate {
    pub fn new(allow: Vec<Cidr>, quiet_seconds: i64) -> Gate {
        Gate { allow, quiet: quiet_seconds, last: HashMap::new() }
    }

    pub fn allowed(&self, ip: IpAddr) -> bool {
        self.allow.iter().any(|c| c.contains(ip))
    }

    /// False for trusted sources, and for repeats inside the quiet period.
    pub fn admit(&mut self, t: &Threat) -> bool {
        if t.source.is_some_and(|ip| self.allowed(ip)) {
            return false;
        }
        let now = t.time.timestamp();
        if self.last.len() >= MAX_KEYS {
            let quiet = self.quiet;
            self.last.retain(|_, at| now - *at < quiet);
            if self.last.len() >= MAX_KEYS {
                self.last.clear();
            }
        }
        let key = (t.rule, t.source.map(source_key), t.user.clone(), t.pid);
        if self.last.get(&key).is_some_and(|at| now - *at < self.quiet) {
            return false;
        }
        self.last.insert(key, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::model::Severity;
    use crate::defense::Stage;
    use chrono::{Local, TimeZone};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn counters_slide_and_stay_bounded() {
        let mut c = Counter::new(10);
        assert_eq!(c.add("a", 0), 1);
        assert_eq!(c.add("a", 5), 2);
        assert_eq!(c.add("a", 11), 2);
        assert_eq!(c.count(&"a", 100), 0);
        let mut flood = Counter::new(10);
        for i in 0..200_000u32 {
            flood.add(i, 0);
        }
        assert!(flood.map.len() <= MAX_KEYS);
    }

    #[test]
    fn networks_match() {
        let c = Cidr::parse("10.1.0.0/16").unwrap();
        assert!(c.contains(ip("10.1.2.3")));
        assert!(!c.contains(ip("10.2.0.1")));
        assert!(!c.contains(ip("::1")), "other family");
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        assert!(Cidr::parse("2001:db8::/32").unwrap().contains(ip("2001:db8:1::1")));
        assert!(Cidr::parse("1.2.3.4").unwrap().contains(ip("1.2.3.4")));
        assert!(Cidr::parse("1.2.3.4/33").is_err());
        assert!(Cidr::parse("nonsense").is_err());
    }

    #[test]
    fn a_whole_ipv6_prefix_counts_as_one_source() {
        assert_eq!(source_key(ip("2001:db8:1:2:aaaa::1")), source_key(ip("2001:db8:1:2:bbbb::2")));
        assert_ne!(source_key(ip("2001:db8:1:2::1")), source_key(ip("2001:db8:1:3::1")));
    }

    #[test]
    fn repeats_and_trusted_sources_stay_quiet() {
        let mut g = Gate::new(vec![Cidr::parse("192.0.2.0/24").unwrap()], 60);
        let at = |s| Threat::new(Local.timestamp_opt(s, 0).unwrap(), "r", Severity::High, Stage::Attempt, "t".into());
        assert!(!g.admit(&at(0).source_ip(ip("192.0.2.9"))));
        assert!(g.admit(&at(0).source_ip(ip("203.0.113.1"))));
        assert!(!g.admit(&at(30).source_ip(ip("203.0.113.1"))));
        assert!(g.admit(&at(30).source_ip(ip("203.0.113.2"))));
        assert!(g.admit(&at(61).source_ip(ip("203.0.113.1"))));
    }
}
