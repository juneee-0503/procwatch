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
pub mod filter;
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
    pub evidence: String,
}

impl Threat {
    pub fn new(time: DateTime<Local>, rule: &'static str, severity: Severity, stage: Stage, title: String) -> Threat {
        Threat { time, rule, title, severity, stage, source: None, user: None, pid: None, evidence: String::new() }
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
    pub fn with_evidence(mut self, evidence: impl AsRef<str>) -> Threat {
        self.evidence = crate::common::text::truncate(&crate::common::text::printable(evidence.as_ref()), 400);
        self
    }
}
