//! DNS: reverse names for remote addresses (resolved in the background
//! and cached), configured resolvers, and the Windows DNS client cache.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(any(target_os = "macos", windows))]
use crate::inspect::run_command;

/// Background reverse-DNS resolver with a shared cache.
pub struct Resolver {
    cache: Arc<Mutex<HashMap<IpAddr, Option<String>>>>,
    requested: HashSet<IpAddr>,
    tx: Sender<IpAddr>,
}

impl Resolver {
    pub fn new() -> Self {
        let cache: Arc<Mutex<HashMap<IpAddr, Option<String>>>> = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = channel::<IpAddr>();
        let c = cache.clone();
        let _ = thread::Builder::new().name("rdns".into()).spawn(move || {
            while let Ok(ip) = rx.recv() {
                let name = dns_lookup::lookup_addr(&ip).ok().filter(|n| n != &ip.to_string());
                if let Ok(mut m) = c.lock() {
                    m.insert(ip, name);
                }
            }
        });
        Self { cache, requested: HashSet::new(), tx }
    }

    /// Cached name for `ip`; queues a lookup the first time it's asked.
    pub fn name(&mut self, ip: &str) -> Option<String> {
        let ip: IpAddr = ip.trim_matches(['[', ']']).parse().ok()?;
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
            return None;
        }
        if let Some(hit) = self.cache.lock().ok()?.get(&ip) {
            return hit.clone();
        }
        if self.requested.len() < 5000 && self.requested.insert(ip) {
            let _ = self.tx.send(ip);
        }
        None
    }

    /// Cached name without queueing a lookup.
    pub fn cached(&self, ip: &str) -> Option<String> {
        let ip: IpAddr = ip.trim_matches(['[', ']']).parse().ok()?;
        self.cache.lock().ok()?.get(&ip).cloned().flatten()
    }

    /// Every resolved (ip, name) pair so far.
    pub fn known(&self) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = self
            .cache
            .lock()
            .map(|m| m.iter().filter_map(|(ip, n)| n.clone().map(|n| (ip.to_string(), n))).collect())
            .unwrap_or_default();
        v.sort();
        v
    }
}

/// Configured DNS servers.
pub fn resolvers() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    #[cfg(target_os = "macos")]
    if let Ok(o) = run_command(std::process::Command::new("scutil").arg("--dns"), Duration::from_secs(5)) {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            if let Some((_, v)) = l.split_once("nameserver[").and_then(|(_, r)| r.split_once(':')) {
                out.push(v.trim().to_string());
            }
        }
    }
    #[cfg(target_os = "linux")]
    if let Ok(t) = std::fs::read_to_string("/etc/resolv.conf") {
        out.extend(t.lines().filter_map(|l| l.trim().strip_prefix("nameserver").map(|v| v.trim().to_string())));
    }
    #[cfg(target_os = "windows")]
    if let Ok(o) = run_command(
        std::process::Command::new("powershell").args([
            "-NoProfile",
            "-Command",
            "Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses",
        ]),
        Duration::from_secs(15),
    ) {
        out.extend(String::from_utf8_lossy(&o.stdout).lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()));
    }
    let _ = Duration::ZERO;
    let mut seen = HashSet::new();
    out.retain(|s| seen.insert(s.clone()));
    out
}

/// Recently resolved names from the OS DNS cache (Windows only; macOS and
/// Linux don't expose theirs).
pub fn client_cache() -> Result<Vec<(String, String)>, String> {
    #[cfg(target_os = "windows")]
    {
        let o = run_command(
            std::process::Command::new("powershell").args([
                "-NoProfile",
                "-Command",
                "Get-DnsClientCache | ForEach-Object { \"$($_.Entry)`t$($_.Data)\" }",
            ]),
            Duration::from_secs(20),
        )
        .map_err(|e| e.to_string())?;
        Ok(String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| l.split_once('\t').map(|(a, b)| (a.trim().to_string(), b.trim().to_string())))
            .collect())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("this OS doesn't expose its DNS cache; names below come from reverse lookups of connected addresses".into())
    }
}

/// A DNS query a process made and the addresses it got back (Sysmon
/// event 22, live or from an EVTX file).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DnsObs {
    #[serde(serialize_with = "ser_local")]
    pub time: chrono::DateTime<chrono::Local>,
    pub pid: Option<u32>,
    pub image: String,
    pub name: String,
    pub ips: Vec<String>,
}

fn ser_local<S: serde::Serializer>(t: &chrono::DateTime<chrono::Local>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&t.to_rfc3339())
}

/// Addresses from Sysmon's QueryResults ("type: 5 cdn.x;::ffff:1.2.3.4;…").
pub fn sysmon_results(r: &str) -> Vec<String> {
    r.split(';')
        .map(str::trim)
        .filter(|t| !t.is_empty() && !t.starts_with("type:"))
        .map(|t| t.trim_start_matches("::ffff:").to_string())
        .filter(|t| t.parse::<std::net::IpAddr>().is_ok())
        .collect()
}

/// From structured Sysmon 22 fields (EVTX).
pub fn from_sysmon_fields(time: chrono::DateTime<chrono::Local>, d: &std::collections::BTreeMap<String, String>) -> Option<DnsObs> {
    let name = d.get("QueryName")?.trim().trim_end_matches('.').to_lowercase();
    Some(DnsObs {
        time,
        pid: d.get("ProcessId").and_then(|p| p.parse().ok()),
        image: d.get("Image").cloned().unwrap_or_default(),
        ips: d.get("QueryResults").map(|r| sysmon_results(r)).unwrap_or_default(),
        name,
    })
}

/// From a live Sysmon message flattened to "Key: value | Key: value".
pub fn from_sysmon_message(time: chrono::DateTime<chrono::Local>, msg: &str) -> Option<DnsObs> {
    let field = |k: &str| msg.split(" | ").find_map(|p| p.trim().strip_prefix(&format!("{k}:")).map(|v| v.trim().to_string()));
    let mut d = std::collections::BTreeMap::new();
    for k in ["QueryName", "QueryResults", "ProcessId", "Image"] {
        if let Some(v) = field(k) {
            d.insert(k.to_string(), v);
        }
    }
    from_sysmon_fields(time, &d)
}

/// The name a connection's address was resolved from: the most recent
/// query (within an hour before `at`) whose answers include `ip`,
/// preferring the same process. Returns (name, same process?).
pub fn name_for(obs: &std::collections::VecDeque<DnsObs>, ip: &str, pid: Option<u32>, at: chrono::DateTime<chrono::Local>) -> Option<(String, bool)> {
    let window = chrono::Duration::hours(1);
    let candidates = obs.iter().rev().filter(|o| o.time <= at + chrono::Duration::seconds(5) && at - o.time <= window && o.ips.iter().any(|x| x == ip));
    let mut any = None;
    for o in candidates {
        if pid.is_some() && o.pid == pid {
            return Some((o.name.clone(), true));
        }
        any.get_or_insert((o.name.clone(), false));
    }
    any
}

#[cfg(test)]
mod dns_obs_tests {
    use super::*;

    #[test]
    fn sysmon_parsing_and_correlation() {
        let now = chrono::Local::now();
        let msg = "Dns query: | RuleName: - | ProcessId: 4242 | QueryName: evil.example | QueryStatus: 0 | QueryResults: type: 5 cdn.evil.example;::ffff:203.0.113.9;::ffff:203.0.113.10; | Image: C:\\Users\\a\\x.exe";
        let o = from_sysmon_message(now - chrono::Duration::seconds(30), msg).unwrap();
        assert_eq!(o.name, "evil.example");
        assert_eq!(o.ips, vec!["203.0.113.9", "203.0.113.10"]);
        assert_eq!(o.pid, Some(4242));
        let mut q = std::collections::VecDeque::new();
        q.push_back(DnsObs { time: now - chrono::Duration::seconds(60), pid: Some(1), image: String::new(), name: "shared.example".into(), ips: vec!["203.0.113.9".into()] });
        q.push_back(o);
        assert_eq!(name_for(&q, "203.0.113.9", Some(4242), now), Some(("evil.example".into(), true)));
        assert_eq!(name_for(&q, "203.0.113.9", Some(77), now).map(|x| x.1), Some(false));
        assert!(name_for(&q, "203.0.113.9", Some(4242), now - chrono::Duration::hours(2)).is_none(), "query after the connection doesn't count");
    }
}
