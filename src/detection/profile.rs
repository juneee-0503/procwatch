//! Per-executable behaviour baselines: for each program (by SHA-256, or by
//! path until the hash is known) remember, across runs and sessions, where
//! it connects, what it starts, which non-system modules it loads and
//! which ports it listens on. Once a profile is established, behaviour the
//! program has never shown before is reported — a deviation from *its own*
//! history, which says far more than a generic rule.
//!
//! Stored next to the event history (`profiles.json`), local only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

/// Runs, or observed time, before a profile is trusted for deviations.
pub const MIN_RUNS: u32 = 3;
pub const MIN_OBSERVED_SECS: u64 = 3600;
const MAX_ITEMS: usize = 500;
/// Beyond this many known destinations, new ones aren't reported.
pub const DIVERSE: usize = 40;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Profile {
    pub exe: String,
    pub sha256: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub runs: u32,
    pub observed_secs: u64,
    /// "ip:port" (or "host:port") → times seen.
    pub destinations: BTreeMap<String, u32>,
    /// Child program file names → times seen.
    pub children: BTreeMap<String, u32>,
    pub modules: BTreeSet<String>,
    pub listens: BTreeSet<String>,
}

impl Profile {
    /// Trusted for deviations only after both several runs and real
    /// observation time (quick restarts alone don't make a baseline).
    pub fn established(&self) -> bool {
        self.runs >= MIN_RUNS && self.observed_secs >= MIN_OBSERVED_SECS
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Novelty {
    Destination(String),
    Child(String),
    Module(String),
    Listen(String),
}

impl Novelty {
    pub fn describe(&self) -> String {
        match self {
            Novelty::Destination(d) => format!("connected to {d}"),
            Novelty::Child(c) => format!("started {c}"),
            Novelty::Module(m) => format!("loaded {m}"),
            Novelty::Listen(p) => format!("listened on {p}"),
        }
    }
}

/// What a process did in one observation.
#[derive(Debug, Default)]
pub struct Observation {
    pub destinations: Vec<String>,
    pub children: Vec<String>,
    pub modules: Vec<String>,
    pub listens: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Profiles {
    pub by_key: BTreeMap<String, Profile>,
    #[serde(skip)]
    pub dirty: bool,
}

fn add(map: &mut BTreeMap<String, u32>, k: &str) -> bool {
    if map.len() >= MAX_ITEMS && !map.contains_key(k) {
        return false;
    }
    let e = map.entry(k.to_string()).or_insert(0);
    *e += 1;
    *e == 1
}

impl Profiles {
    pub fn path() -> Option<PathBuf> {
        crate::forensics::store::default_dir().and_then(|d| d.parent().map(|p| p.join("profiles.json")))
    }

    pub fn load() -> Profiles {
        Self::path().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&mut self) -> anyhow::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let p = Self::path().ok_or_else(|| anyhow::anyhow!("no data folder"))?;
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        crate::common::paths::write_atomic(&p, &serde_json::to_string(self)?)?;
        self.dirty = false;
        Ok(())
    }

    /// A new run of `key` started.
    pub fn new_run(&mut self, key: &str, exe: &str, sha256: Option<&str>, now: DateTime<Local>) {
        let p = self.by_key.entry(key.to_string()).or_insert_with(|| Profile { exe: exe.into(), first_seen: now.to_rfc3339(), ..Default::default() });
        p.runs += 1;
        p.sha256 = sha256.map(str::to_string).or(p.sha256.take());
        p.last_seen = now.to_rfc3339();
        self.dirty = true;
    }

    /// Record an observation; returns what was new to an *established*
    /// profile (nothing while it's still learning).
    pub fn observe(&mut self, key: &str, obs: &Observation, elapsed_secs: u64, now: DateTime<Local>) -> Vec<Novelty> {
        let Some(p) = self.by_key.get_mut(key) else { return Vec::new() };
        let established = p.established();
        p.observed_secs += elapsed_secs;
        p.last_seen = now.to_rfc3339();
        let mut new = Vec::new();
        // Programs that talk to many places (browsers, sync clients) make
        // "new destination" meaningless; loopback is local plumbing.
        let diverse = p.destinations.len() >= DIVERSE;
        for d in &obs.destinations {
            let loopback = d.starts_with("127.") || d.starts_with("[::1]") || d.starts_with("::1");
            if add(&mut p.destinations, d) && established && !diverse && !loopback {
                new.push(Novelty::Destination(d.clone()));
            }
        }
        for c in &obs.children {
            if add(&mut p.children, c) && established {
                new.push(Novelty::Child(c.clone()));
            }
        }
        for m in &obs.modules {
            if p.modules.len() < MAX_ITEMS && p.modules.insert(m.clone()) && established {
                new.push(Novelty::Module(m.clone()));
            }
        }
        for l in &obs.listens {
            if p.listens.len() < MAX_ITEMS && p.listens.insert(l.clone()) && established {
                new.push(Novelty::Listen(l.clone()));
            }
        }
        self.dirty = true;
        new
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn learns_then_reports_only_new_behaviour() {
        let mut ps = Profiles::default();
        let now = Local::now();
        let obs = Observation { destinations: vec!["10.0.0.1:443".into()], children: vec!["helper".into()], ..Default::default() };
        // Learning: three quick runs aren't enough on their own…
        for _ in 0..3 {
            ps.new_run("sha:abc", "/app/x", Some("abc"), now);
            assert!(ps.observe("sha:abc", &obs, 10, now).is_empty());
        }
        assert!(!ps.by_key["sha:abc"].established());
        // …an hour of observed behaviour completes the baseline.
        assert!(ps.observe("sha:abc", &obs, MIN_OBSERVED_SECS, now).is_empty());
        assert!(ps.by_key["sha:abc"].established());
        // Established: same behaviour is quiet, new behaviour is reported.
        ps.new_run("sha:abc", "/app/x", Some("abc"), now);
        assert!(ps.observe("sha:abc", &obs, 10, now).is_empty());
        let odd = Observation { destinations: vec!["203.0.113.9:8443".into()], children: vec!["sh".into()], ..Default::default() };
        let new = ps.observe("sha:abc", &odd, 10, now);
        assert_eq!(new, vec![Novelty::Destination("203.0.113.9:8443".into()), Novelty::Child("sh".into())]);
        // Reported once, not every refresh.
        assert!(ps.observe("sha:abc", &odd, 10, now).is_empty());
        // Loopback and destination-diverse programs stay quiet.
        let lo = Observation { destinations: vec!["127.0.0.1:9000".into()], ..Default::default() };
        assert!(ps.observe("sha:abc", &lo, 10, now).is_empty());
        let many = Observation { destinations: (0..DIVERSE).map(|i| format!("198.51.100.{i}:443")).collect(), ..Default::default() };
        ps.observe("sha:abc", &many, 10, now);
        let one_more = Observation { destinations: vec!["192.0.2.1:443".into()], ..Default::default() };
        assert!(ps.observe("sha:abc", &one_more, 10, now).is_empty());
        let json = serde_json::to_string(&ps).unwrap();
        let back: Profiles = serde_json::from_str(&json).unwrap();
        assert_eq!(back.by_key["sha:abc"].runs, 4);
    }
}
