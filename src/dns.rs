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
