//! The shared investigation model: the entities every page talks about,
//! how they relate, and what an event's timestamp actually means.
//!
//! Pages keep their own views, but anything that crosses pages — the
//! timeline, detections, the investigation graph, evidence and reports —
//! refers to things through [`Entity`], so a process seen in a log line, a
//! detection and an evidence package is recognisably the same process.

use std::fmt;

use serde::{Deserialize, Serialize};

/// One run of a process. A PID alone is not an identity: it is reused.
/// The start time (seconds since the epoch, as reported by the OS) makes
/// it unique on one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProcKey {
    pub pid: u32,
    pub start: u64,
}

impl fmt::Display for ProcKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == 0 {
            return write!(f, "{}", self.pid);
        }
        let t = chrono::DateTime::from_timestamp(self.start as i64, 0)
            .map(|t| t.with_timezone(&chrono::Local).format("%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();
        write!(f, "{}@{t}", self.pid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", content = "id", rename_all = "snake_case")]
pub enum Entity {
    Process(ProcKey),
    File(String),
    /// A remote or local address (IP only; ports live on the relation).
    Endpoint(String),
    /// A persistence entry: "category|name|location".
    Persistence(String),
    User(String),
    /// A detection rule.
    Rule(String),
    /// An evidence item id (E0001…).
    Evidence(String),
    /// The machine itself, for host-wide events (a log line without a
    /// process, a configuration change).
    Host(String),
}

impl Entity {
    pub fn kind(&self) -> &'static str {
        match self {
            Entity::Process(_) => "process",
            Entity::File(_) => "file",
            Entity::Endpoint(_) => "endpoint",
            Entity::Persistence(_) => "persistence",
            Entity::User(_) => "user",
            Entity::Rule(_) => "rule",
            Entity::Evidence(_) => "evidence",
            Entity::Host(_) => "host",
        }
    }

    /// Stable text key, used by `entity:` filters and in exports.
    pub fn key(&self) -> String {
        match self {
            Entity::Process(k) => format!("process:{}:{}", k.pid, k.start),
            Entity::File(p) => format!("file:{p}"),
            Entity::Endpoint(ip) => format!("endpoint:{ip}"),
            Entity::Persistence(id) => format!("persistence:{id}"),
            Entity::User(u) => format!("user:{u}"),
            Entity::Rule(r) => format!("rule:{r}"),
            Entity::Evidence(e) => format!("evidence:{e}"),
            Entity::Host(h) => format!("host:{h}"),
        }
    }
}

/// How two entities are connected. Read as "subject REL object".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rel {
    ChildOf,
    Spawned,
    Executes,
    ExecutedBy,
    RunsAs,
    /// user → process
    Runs,
    Opened,
    OpenedBy,
    ConnectedTo,
    ConnectedFrom,
    ListensOn,
    Launches,
    LaunchedBy,
    Changed,
    DetectedBy,
    Detects,
    CollectedIn,
    Describes,
}

impl Rel {
    pub fn label(self) -> &'static str {
        match self {
            Rel::ChildOf => "child of",
            Rel::Spawned => "spawned",
            Rel::Executes => "executes",
            Rel::ExecutedBy => "executed by",
            Rel::RunsAs => "runs as",
            Rel::Runs => "runs",
            Rel::Opened => "has open",
            Rel::OpenedBy => "open in",
            Rel::ConnectedTo => "connected to",
            Rel::ConnectedFrom => "connected from",
            Rel::ListensOn => "listens on",
            Rel::Launches => "launches",
            Rel::LaunchedBy => "launched by",
            Rel::Changed => "changed",
            Rel::DetectedBy => "detected by",
            Rel::Detects => "detects",
            Rel::CollectedIn => "collected in",
            Rel::Describes => "describes",
        }
    }
}

/// What an event's main timestamp is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    /// Recorded by the OS when the thing happened (process start time,
    /// log record time, file mtime, prefetch last-run time).
    Event,
    /// When procwatch noticed it; the real moment is earlier by up to one
    /// sampling interval (connections, exits, file notifications).
    Observed,
}

impl Basis {
    pub fn label(self) -> &'static str {
        match self {
            Basis::Event => "event",
            Basis::Observed => "observed",
        }
    }
}

/// Severity: how bad it would be if the behaviour is what it looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
    pub fn parse(s: &str) -> Severity {
        match s.trim().to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
    pub fn weight(self) -> f64 {
        match self {
            Severity::Info => 5.0,
            Severity::Low => 20.0,
            Severity::Medium => 45.0,
            Severity::High => 70.0,
            Severity::Critical => 90.0,
        }
    }
}

/// Confidence: how well the observed data supports the rule's claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
    pub fn factor(self) -> f64 {
        match self {
            Confidence::Low => 0.55,
            Confidence::Medium => 0.8,
            Confidence::High => 1.0,
        }
    }
}

/// A short stable id for an event, from the things that identify it.
pub fn event_id(parts: &[&str]) -> u64 {
    // FNV-1a: stable across runs and platforms, unlike DefaultHasher.
    let mut h: u64 = 0xcbf29ce484222325;
    for p in parts {
        for b in p.bytes().chain(std::iter::once(0x1f)) {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    h
}

pub fn short_id(id: u64) -> String {
    format!("T-{:08x}", (id >> 32) as u32 ^ id as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_ids_are_stable() {
        let a = Entity::Process(ProcKey { pid: 7, start: 100 });
        assert_eq!(a.key(), "process:7:100");
        assert_eq!(event_id(&["a", "b"]), event_id(&["a", "b"]));
        assert_ne!(event_id(&["ab", ""]), event_id(&["a", "b"]));
        assert_eq!(short_id(event_id(&["x"])).len(), 10);
        let json = serde_json::to_string(&Entity::File("/x".into())).unwrap();
        assert_eq!(json, r#"{"type":"file","id":"/x"}"#);
        assert!(Severity::High > Severity::Low);
    }
}
