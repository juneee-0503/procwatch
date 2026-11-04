//! Event correlation: groups timeline events into *activity clusters* —
//! one process (and the processes it started while procwatch watched)
//! doing several kinds of thing within a short window, e.g. starting a
//! child, connecting out, writing a file and adding a launch agent.
//!
//! A cluster is a lead for an analyst, not a verdict. Membership is by
//! process lineage; file and persistence events (which carry no process)
//! join only through a concrete link — the file is the executable of a
//! cluster process, or the persistence entry launches one — and those
//! links are labelled as such.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Duration, Local};
use serde::Serialize;

use crate::model::{short_id, Entity, Rel};

/// Gap that ends a burst of activity.
pub const WINDOW_SECS: i64 = 120;

/// What `cluster` needs from a timeline event.
pub struct Ev<'a> {
    pub time: DateTime<Local>,
    pub id: u64,
    pub source: &'a str,
    pub kind: &'a str,
    pub pid: Option<u32>,
    pub name: &'a str,
    pub detail: &'a str,
    pub lineage: &'a [u32],
    pub links: &'a [(Rel, Entity)],
    pub subject: Option<&'a Entity>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cluster {
    pub id: usize,
    pub root_pid: u32,
    pub root_name: String,
    pub start: DateTime<Local>,
    pub end: DateTime<Local>,
    /// Indices into the event slice given to `cluster`.
    pub members: Vec<usize>,
    pub pids: BTreeSet<u32>,
    /// category → count
    pub categories: BTreeMap<&'static str, usize>,
    pub detections: usize,
    /// "lineage" or "lineage + file path" etc.
    pub links: Vec<String>,
}

impl Cluster {
    pub fn label(&self) -> String {
        let more = self.pids.len().saturating_sub(1);
        if more == 0 {
            format!("{} ({})", self.root_name, self.root_pid)
        } else {
            format!("{} ({}) + {more} descendant process{}", self.root_name, self.root_pid, if more == 1 { "" } else { "es" })
        }
    }
}

fn category(source: &str, kind: &str) -> Option<&'static str> {
    Some(match (source, kind) {
        ("process", "started") => "exec",
        ("trace", k) if k.contains("start") => "exec",
        ("network", "connect" | "listen") => "network",
        ("trace", k) if k.contains("connect") || k.contains("listen") => "network",
        ("file", _) => "file",
        ("trace", k) if k.contains("file") => "file",
        ("persist", _) => "persistence",
        ("detect" | "alert", _) => "detection",
        ("artifact", _) => "artifact",
        ("deep", "spawn" | "exec") => "exec",
        ("deep", "file open" | "file close") => "file",
        ("deep", "module load") => "module",
        _ => return None,
    })
}

/// Group events into clusters. `events` may be in any order.
pub fn cluster(events: &[Ev]) -> Vec<Cluster> {
    // Processes that started while we watched: lineage collapses to the
    // earliest such ancestor, so a freshly started tree is one subject.
    let started: BTreeSet<u32> = events.iter().filter(|e| e.source == "process" && e.kind == "started").filter_map(|e| e.pid).collect();
    let root_of = |e: &Ev| -> Option<u32> {
        let pid = e.pid?;
        let mut root = pid;
        for p in e.lineage.iter().skip(1) {
            if started.contains(p) {
                root = *p;
            } else {
                break;
            }
        }
        Some(root)
    };
    let mut by_root: HashMap<u32, Vec<usize>> = HashMap::new();
    for (i, e) in events.iter().enumerate() {
        if let Some(r) = root_of(e) {
            if category(e.source, e.kind).is_some() || e.source == "process" {
                by_root.entry(r).or_default().push(i);
            }
        }
    }
    // Executables and persistence targets of each root's processes, for
    // attaching path-only events.
    let mut out = Vec::new();
    let window = Duration::seconds(WINDOW_SECS);
    // Only these can attach by path; scanning all events for every burst
    // goes quadratic when many log events each form their own burst.
    let path_only: Vec<usize> = events.iter().enumerate().filter(|(_, e)| e.pid.is_none() && (e.source == "file" || e.source == "persist")).map(|(i, _)| i).collect();
    let mut roots: Vec<u32> = by_root.keys().copied().collect();
    roots.sort_unstable();
    for root in roots {
        let mut idx = by_root.remove(&root).unwrap_or_default();
        idx.sort_by_key(|i| events[*i].time);
        // Split into bursts.
        let mut bursts: Vec<Vec<usize>> = Vec::new();
        for i in idx {
            match bursts.last_mut() {
                Some(b) if events[i].time - events[*b.last().unwrap()].time <= window => b.push(i),
                _ => bursts.push(vec![i]),
            }
        }
        for b in bursts {
            let start = events[b[0]].time;
            let end = events[*b.last().unwrap()].time;
            let pids: BTreeSet<u32> = b.iter().filter_map(|i| events[*i].pid).collect();
            let exes: BTreeSet<String> = b
                .iter()
                .flat_map(|i| events[*i].links.iter())
                .filter(|(r, _)| *r == Rel::Executes)
                .filter_map(|(_, e)| if let Entity::File(p) = e { Some(p.clone()) } else { None })
                .collect();
            let mut members = b.clone();
            let mut links = vec!["process lineage".to_string()];
            // Path links: a changed file that is (or a persistence entry
            // that launches) the executable of a cluster process.
            for &j in if exes.is_empty() { &[][..] } else { &path_only[..] } {
                let e = &events[j];
                if e.time < start - window || e.time > end + window {
                    continue;
                }
                let path_hit = match e.subject {
                    Some(Entity::File(p)) => exes.contains(p),
                    _ => e.links.iter().any(|(r, t)| *r == Rel::Launches && matches!(t, Entity::File(p) if exes.contains(p))),
                };
                if path_hit {
                    members.push(j);
                    let l = if e.source == "file" { "file is a cluster executable" } else { "persistence entry launches a cluster executable" };
                    if !links.iter().any(|x| x == l) {
                        links.push(l.into());
                    }
                }
            }
            let mut categories: BTreeMap<&'static str, usize> = BTreeMap::new();
            for i in &members {
                if let Some(c) = category(events[*i].source, events[*i].kind) {
                    *categories.entry(c).or_default() += 1;
                }
            }
            let detections = categories.get("detection").copied().unwrap_or(0);
            let strong = ["file", "persistence", "detection"].iter().filter(|c| categories.contains_key(*c)).count();
            // exec + network alone is what every app does; require a
            // third kind of activity, or something notable.
            if categories.len() >= 3 || (categories.len() >= 2 && strong >= 1) {
                members.sort_by_key(|i| events[*i].time);
                members.dedup();
                let root_name = b
                    .iter()
                    .find(|i| events[**i].pid == Some(root))
                    .map(|i| events[*i].name.to_string())
                    .unwrap_or_else(|| format!("pid {root}"));
                out.push(Cluster {
                    id: 0,
                    root_pid: root,
                    root_name,
                    start: members.iter().map(|i| events[*i].time).min().unwrap_or(start),
                    end: members.iter().map(|i| events[*i].time).max().unwrap_or(end),
                    members,
                    pids,
                    categories,
                    detections,
                    links,
                });
            }
        }
    }
    out.sort_by(|a, b| b.detections.cmp(&a.detections).then(b.categories.len().cmp(&a.categories.len())).then(b.end.cmp(&a.end)));
    for (i, c) in out.iter_mut().enumerate() {
        c.id = i + 1;
    }
    out
}

/// Deterministic summary of a cluster: what happened, with event ids.
pub fn summarize(c: &Cluster, events: &[Ev], evidence: &[(String, String)], bookmarks: &[(u64, String)]) -> crate::case::SummaryBlock {
    let mut observed = Vec::new();
    let mut dets = Vec::new();
    let mut seen = BTreeSet::new();
    let mut net_counts: BTreeMap<String, usize> = BTreeMap::new();
    for i in &c.members {
        let e = &events[*i];
        let tag = short_id(e.id);
        let line = match (e.source, category(e.source, e.kind)) {
            ("detect", _) => {
                dets.push(format!("{} — {} [{tag}]", e.kind, e.detail));
                continue;
            }
            ("alert", _) => format!("alert: {} [{tag}]", e.detail),
            (_, Some("exec")) => format!("started {} ({}): {} [{tag}]", e.name, e.pid.unwrap_or(0), e.detail.chars().take(120).collect::<String>()),
            (_, Some("network")) => {
                // One line per remote service, with a count: reconnects
                // differ only by their ephemeral local port.
                let remote = e.detail.split(" → ").nth(1).and_then(|r| r.split_whitespace().next()).unwrap_or(e.detail);
                let verb = if e.kind == "listen" { "listened on" } else { "connected to" };
                let key = format!("{} {verb} {remote}", e.name);
                *net_counts.entry(key.clone()).or_insert(0) += 1;
                if net_counts[&key] > 1 {
                    continue;
                }
                format!("{key} [{tag}]")
            }
            (_, Some("file")) => format!("file {} {} [{tag}]", e.kind, e.detail),
            (_, Some("persistence")) => format!("persistence entry {} [{tag}]", e.detail),
            (_, Some("artifact")) => format!("{} {} [{tag}]", e.kind, e.detail),
            (_, Some("module")) => format!("{} loaded {} [{tag}]", e.name, e.detail),
            _ => continue,
        };
        // Repeated connects to the same place say little more.
        let key = line.split(" [").next().unwrap_or("").to_string();
        if seen.insert(key) && observed.len() < 14 {
            observed.push(line);
        }
    }
    for line in observed.iter_mut() {
        if let Some((k, n)) = net_counts.iter().find(|(k, n)| **n > 1 && line.starts_with(k.as_str())) {
            *line = line.replacen(k.as_str(), &format!("{k} ×{n}"), 1);
        }
    }
    let ev: Vec<String> = evidence
        .iter()
        .filter(|(_, subj)| c.pids.iter().any(|p| subj.starts_with(&format!("process:{p}:"))))
        .map(|(id, subj)| format!("{id} ({subj})"))
        .collect();
    let tags: Vec<String> = bookmarks.iter().filter(|(id, _)| c.members.iter().any(|i| events[*i].id == *id)).map(|(_, t)| t.clone()).collect();
    let mut assessment = if dets.iter().any(|d| d.starts_with("critical") || d.starts_with("high")) {
        "High-severity detections in this activity — requires investigation.".to_string()
    } else if !dets.is_empty() {
        "Detections present — requires further investigation.".to_string()
    } else {
        "Correlated activity without detections — confirm it is expected.".to_string()
    };
    if !tags.is_empty() {
        assessment += &format!(" Analyst bookmarks: {}.", tags.join(", "));
    }
    crate::case::SummaryBlock {
        subject: c.label(),
        window: format!("{} – {} ({})", c.start.format("%Y-%m-%d %H:%M:%S"), c.end.format("%H:%M:%S"), c.links.join(", ")),
        observed,
        detections: dets,
        evidence: ev,
        assessment,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_a_fresh_process_tree_and_links_files_by_path() {
        let t0 = Local::now();
        let at = |s: i64| t0 + Duration::seconds(s);
        let exe = vec![(Rel::Executes, Entity::File("/tmp/x".into()))];
        let none: Vec<(Rel, Entity)> = vec![];
        let file = Entity::File("/tmp/x".into());
        let other = Entity::File("/tmp/unrelated".into());
        let events = vec![
            Ev { time: at(0), id: 1, source: "process", kind: "started", pid: Some(10), name: "dropper", detail: "dropper", lineage: &[10, 1], links: &none, subject: None },
            Ev { time: at(5), id: 2, source: "process", kind: "started", pid: Some(11), name: "x", detail: "/tmp/x", lineage: &[11, 10, 1], links: &exe, subject: None },
            Ev { time: at(6), id: 3, source: "network", kind: "connect", pid: Some(11), name: "x", detail: "1.2.3.4:443", lineage: &[11, 10, 1], links: &none, subject: None },
            Ev { time: at(4), id: 4, source: "file", kind: "created", pid: None, name: "", detail: "/tmp/x", lineage: &[], links: &none, subject: Some(&file) },
            Ev { time: at(4), id: 5, source: "file", kind: "created", pid: None, name: "", detail: "/tmp/unrelated", lineage: &[], links: &none, subject: Some(&other) },
            // A long-running process that just connects: not a cluster.
            Ev { time: at(3), id: 6, source: "network", kind: "connect", pid: Some(50), name: "browser", detail: "", lineage: &[50, 1], links: &none, subject: None },
        ];
        let c = cluster(&events);
        assert_eq!(c.len(), 1, "{c:?}");
        assert_eq!(c[0].root_pid, 10);
        assert_eq!(c[0].pids.len(), 2);
        assert!(c[0].members.contains(&3), "linked file joins");
        assert!(!c[0].members.contains(&4), "unrelated file stays out");
        let s = summarize(&c[0], &events, &[("E0001".into(), "process:11:5".into())], &[(2, "suspicious execution".into())]);
        assert!(s.observed.iter().any(|o| o.contains("connected")));
        assert_eq!(s.evidence.len(), 1);
        assert!(s.assessment.contains("suspicious execution"));
    }
}
