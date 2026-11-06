//! Watching for attacks on this machine: logins, web requests, network
//! floods and scans, and signs of compromise on the host. Findings are
//! published as `Threat`s, joined into `Incident`s by `chain`, and delivered
//! by the alarm module. See `docs/defense.md`.

pub mod alarm;
pub mod auth;
pub mod ban;
pub mod baseline;
pub mod chain;
pub mod config;
pub mod ebpf;
pub mod filter;
pub mod heartbeat;
pub mod host;
pub mod module;
pub mod netattack;
pub mod sniff;
pub mod tail;
pub mod web;

use std::net::IpAddr;

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::common::model::Severity;

/// How far an attack has got, in the order attacks usually move.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Recon,
    Attempt,
    Foothold,
    Execution,
    Privilege,
    Persistence,
    Impact,
}

impl Stage {
    pub fn label(self) -> &'static str {
        match self {
            Stage::Recon => "recon",
            Stage::Attempt => "attempt",
            Stage::Foothold => "foothold",
            Stage::Execution => "execution",
            Stage::Privilege => "privilege",
            Stage::Persistence => "persistence",
            Stage::Impact => "impact",
        }
    }
}

/// The start time in a `/proc/PID/stat` line. The name before it can hold
/// spaces and brackets, so fields are counted from the last `)`.
pub fn start_time(stat: &str) -> Option<u64> {
    stat.rsplit_once(')')?.1.split_whitespace().nth(19)?.parse().ok()
}

/// One sign of an attack.
#[derive(Debug, Clone, Serialize)]
pub struct Threat {
    pub time: DateTime<Local>,
    pub rule: &'static str,
    pub title: String,
    pub severity: Severity,
    pub stage: Stage,
    pub source: Option<IpAddr>,
    pub user: Option<String>,
    pub pid: Option<u32>,
    /// With the pid, identifies the process: pids are reused.
    pub started: Option<u64>,
    pub host: std::sync::Arc<str>,
    pub evidence: String,
}

impl Threat {
    pub fn new(time: DateTime<Local>, rule: &'static str, severity: Severity, stage: Stage, title: String) -> Threat {
        Threat { time, rule, title, severity, stage, source: None, user: None, pid: None, started: None, host: crate::kernel::model::identity().host.clone(), evidence: String::new() }
    }
    pub fn source_ip(mut self, ip: IpAddr) -> Threat {
        self.source = Some(ip);
        self
    }
    pub fn of_user(mut self, user: &str) -> Threat {
        self.user = Some(crate::common::text::printable(user));
        self
    }
    pub fn of_pid(mut self, pid: u32) -> Threat {
        self.pid = Some(pid);
        self
    }
    /// Note when the process started, read while it still exists.
    pub fn identify(&mut self, root: &std::path::Path) {
        let Some(pid) = self.pid else { return };
        let stat = std::fs::read_to_string(root.join("proc").join(pid.to_string()).join("stat")).unwrap_or_default();
        self.started = start_time(&stat);
    }

    pub fn with_evidence(mut self, evidence: impl AsRef<str>) -> Threat {
        let safe = crate::common::redact::redact(&crate::common::text::printable(evidence.as_ref()));
        self.evidence = crate::common::text::truncate(&safe, 400);
        self
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn start_times_survive_hostile_names() {
        let tail = "S 1 1 1 0 -1 4194304 1 2 3 4 5 6 7 8 20 0 1 0 987654 1 2";
        assert_eq!(super::start_time(&format!("42 (bash) {tail}")), Some(987654));
        assert_eq!(super::start_time(&format!("42 (a) b) c) {tail}")), Some(987654));
        assert_eq!(super::start_time("garbage"), None);
    }
}
