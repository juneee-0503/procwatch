//! Joining findings into attacks. A scan, a guessed password, a shell and a
//! new SSH key are four alerts elsewhere; here they are one incident with a
//! story, and the incident gets worse as it moves through the stages.
//!
//! Findings join by source address. Host findings usually have none, so they
//! join the most recent open attack instead, and that link is only a
//! coincidence in time, which the incident says.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use chrono::{DateTime, Duration, Local};
use serde::Serialize;

use super::filter::source_key;
use super::{Stage, Threat};
use crate::common::model::Severity;

/// An attack goes quiet for this long before it's considered over.
const OPEN_FOR_MINUTES: i64 = 60;
const MAX_STEPS: usize = 64;
const MAX_OPEN: usize = 4096;

#[derive(Debug, Clone, Serialize)]
pub struct Incident {
    pub id: u64,
    pub source: Option<IpAddr>,
    pub first: DateTime<Local>,
    pub last: DateTime<Local>,
    pub stages: BTreeSet<Stage>,
    pub severity: Severity,
    pub steps: Vec<Threat>,
    /// Findings beyond `steps`.
    pub more: usize,
    /// Whether findings without a source joined only by timing.
    pub joined_by_time: bool,
}

impl Incident {
    pub fn summary(&self) -> String {
        let path: Vec<&str> = self.stages.iter().map(|s| s.label()).collect();
        let who = self.source.map_or_else(|| "this host".to_string(), |s| s.to_string());
        format!("Attack {} from {who}: {} ({} findings)", self.id, path.join(" → "), self.steps.len() + self.more)
    }
}

fn grade(stages: &BTreeSet<Stage>, worst: Severity) -> Severity {
    let inside = stages.iter().filter(|s| **s >= Stage::Foothold).count();
    if inside >= 2 {
        Severity::Critical
    } else if inside == 1 {
        worst.max(Severity::High)
    } else {
        worst
    }
}

#[derive(Default)]
pub struct Chains {
    open: HashMap<Option<IpAddr>, Incident>,
    next: u64,
}

impl Chains {
    /// The incident this finding moved forward, if it did.
    pub fn feed(&mut self, t: &Threat) -> Option<Incident> {
        let limit = Duration::minutes(OPEN_FOR_MINUTES);
        self.open.retain(|_, i| t.time - i.last < limit);
        if self.open.len() >= MAX_OPEN {
            self.open.clear();
        }
        let source = t.source.map(source_key);
        let (key, by_time) = match source {
            Some(s) => (Some(s), false),
            // The furthest-along attack is the likeliest parent.
            None => match self.open.iter().filter(|(k, _)| k.is_some()).max_by_key(|(_, i)| (i.stages.iter().next_back().copied(), i.last)) {
                Some((k, _)) => (*k, true),
                None => (None, false),
            },
        };
        let next = &mut self.next;
        let i = self.open.entry(key).or_insert_with(|| {
            *next += 1;
            Incident { id: *next, source: t.source, first: t.time, last: t.time, stages: BTreeSet::new(), severity: t.severity, steps: Vec::new(), more: 0, joined_by_time: false }
        });
        i.last = t.time;
        i.joined_by_time |= by_time;
        let moved = i.stages.insert(t.stage);
        if i.steps.len() < MAX_STEPS {
            i.steps.push(t.clone());
        } else {
            i.more += 1;
        }
        let worst = i.steps.iter().map(|s| s.severity).max().unwrap_or(t.severity);
        i.severity = grade(&i.stages, worst);
        (moved && i.stages.len() >= 2).then(|| i.clone())
    }

    #[cfg(test)]
    pub fn open(&self) -> impl Iterator<Item = &Incident> {
        self.open.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(min: i64) -> DateTime<Local> {
        Local.timestamp_opt(1_800_000_000 + min * 60, 0).unwrap()
    }

    fn t(min: i64, stage: Stage, source: Option<&str>) -> Threat {
        let mut x = Threat::new(at(min), "r", Severity::Medium, stage, "t".into());
        x.source = source.map(|s| s.parse().unwrap());
        x
    }

    #[test]
    fn an_attack_builds_up_and_host_findings_join_it() {
        let mut c = Chains::default();
        let ip = Some("203.0.113.1");
        assert!(c.feed(&t(0, Stage::Recon, ip)).is_none(), "one stage isn't a story");
        let two = c.feed(&t(1, Stage::Attempt, ip)).unwrap();
        assert_eq!(two.severity, Severity::Medium);
        assert!(c.feed(&t(2, Stage::Attempt, ip)).is_none(), "nothing new");
        let three = c.feed(&t(3, Stage::Foothold, ip)).unwrap();
        assert_eq!(three.severity, Severity::High);
        let four = c.feed(&t(4, Stage::Persistence, None)).unwrap();
        assert_eq!(four.severity, Severity::Critical);
        assert_eq!(four.source.unwrap().to_string(), "203.0.113.1");
        assert!(four.joined_by_time, "the link to the key is only timing");
        assert_eq!(four.summary(), "Attack 1 from 203.0.113.1: recon → attempt → foothold → persistence (5 findings)");
    }

    #[test]
    fn sources_stay_apart_and_attacks_end() {
        let mut c = Chains::default();
        c.feed(&t(0, Stage::Recon, Some("203.0.113.1")));
        assert!(c.feed(&t(1, Stage::Attempt, Some("203.0.113.2"))).is_none());
        assert_eq!(c.open().count(), 2);
        assert!(c.feed(&t(120, Stage::Attempt, Some("203.0.113.1"))).is_none(), "the old one closed");
        assert_eq!(c.open().count(), 1);
    }

    #[test]
    fn host_findings_alone_can_make_an_incident() {
        let mut c = Chains::default();
        c.feed(&t(0, Stage::Execution, None));
        let i = c.feed(&t(1, Stage::Persistence, None)).unwrap();
        assert_eq!((i.source, i.severity, i.joined_by_time), (None, Severity::Critical, false));
    }
}
