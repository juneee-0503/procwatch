//! Replay for `App`: load a recorded event history (the persistent store,
//! or a case's copy) into the same views the live session uses —
//! timeline, workspace and behaviour replay, graph, state-at-time,
//! detections — without sampling the live system. A child module of `app`.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Local};

use super::*;
use crate::model::{Confidence, Entity, ProcKey, Severity};
use crate::store::{ProcRec, Rec};

fn static_str(s: &str, options: &[&'static str], default: &'static str) -> &'static str {
    options.iter().copied().find(|o| *o == s).unwrap_or(default)
}

fn tree_from(processes: &[ProcRec]) -> crate::process::ProcessTree {
    let mut nodes: HashMap<u32, crate::process::TreeNode> = HashMap::new();
    for p in processes {
        let mut i = crate::process::ProcessInfo::bare(p.pid, p.ppid, p.name.clone());
        i.exe_path = p.exe.clone();
        i.cmd = if p.cmd.is_empty() { vec![] } else { vec![p.cmd.clone()] };
        i.user = Some(p.user.clone()).filter(|u| !u.is_empty());
        i.start_time_secs = p.start;
        nodes.insert(p.pid, crate::process::TreeNode { info: i, children: Vec::new() });
    }
    let links: Vec<(u32, u32)> = nodes.values().filter_map(|n| n.info.ppid.filter(|pp| nodes.contains_key(pp)).map(|pp| (pp, n.info.pid))).collect();
    for (pp, c) in links {
        if let Some(n) = nodes.get_mut(&pp) {
            n.children.push(c);
        }
    }
    for n in nodes.values_mut() {
        n.children.sort_unstable();
    }
    let mut roots: Vec<u32> = nodes.values().filter(|n| n.info.ppid.is_none_or(|pp| !nodes.contains_key(&pp))).map(|n| n.info.pid).collect();
    roots.sort_unstable();
    crate::process::ProcessTree { nodes, roots }
}

impl App {
    pub fn replaying(&self) -> bool {
        self.ir.replay.is_some()
    }

    /// Load recorded events. Returns a one-line description.
    pub fn load_replay(&mut self, path: &Path, from: Option<DateTime<Local>>, to: Option<DateTime<Local>>) -> Result<String, String> {
        let (recs, bad) = crate::store::read(path, from, to);
        if recs.is_empty() {
            return Err(format!("no recorded events in {}{}", path.display(), if bad > 0 { format!(" ({bad} unreadable lines)") } else { String::new() }));
        }
        self.ir.store = None;
        let first = recs.first().map(|r| r.0).unwrap_or_else(Local::now);
        let last = recs.last().map(|r| r.0).unwrap_or_else(Local::now);
        let mut snapshot: Option<Vec<ProcRec>> = None;
        let mut counts = [0usize; 4];
        let host = recs.iter().find_map(|(_, r)| if let Rec::Session { host, .. } = r { Some(host.clone()) } else { None }).unwrap_or_default();
        for (t, rec) in recs {
            match rec {
                Rec::ProcStart(p) => {
                    counts[0] += 1;
                    self.events.push_front(Event {
                        at: t,
                        kind: EventKind::Started,
                        pid: p.pid,
                        name: p.name,
                        parent: p.ppid.map(|pp| format!("({pp})")).unwrap_or_default(),
                        user: p.user,
                        detail: p.cmd,
                        start: p.start,
                        ppid: p.ppid,
                        exe: p.exe,
                    });
                }
                Rec::ProcExit { pid, start, name, ran } => {
                    counts[0] += 1;
                    self.events.push_front(Event { at: t, kind: EventKind::Exited, pid, name, parent: String::new(), user: String::new(), detail: ran, start, ppid: None, exe: None });
                }
                Rec::Net { kind, pid, name, proto, local, remote, state } => {
                    counts[1] += 1;
                    let state = match state.as_str() {
                        "LISTEN" => crate::network::ConnState::Listen,
                        "ESTABLISHED" => crate::network::ConnState::Established,
                        "SYN" => crate::network::ConnState::Opening,
                        "" => crate::network::ConnState::Stateless,
                        _ => crate::network::ConnState::Other,
                    };
                    self.ir.net_events.push_back(super::ir::NetEvent {
                        time: t,
                        kind: static_str(&kind, &["connect", "close", "listen", "unlisten"], "connect"),
                        pid,
                        name,
                        conn: crate::network::Connection { protocol: static_str(&proto, &["TCP", "UDP"], "TCP"), local, remote, state },
                    });
                }
                Rec::File { kind, path } => {
                    counts[2] += 1;
                    self.ir.fs_events.push_back(crate::fswatch::FsEvent { time: t, kind: static_str(&kind, &["created", "modified", "deleted", "renamed", "changed"], "changed"), path });
                }
                Rec::Deep { kind, pid, ppid, start, path, args, .. } => {
                    let kind = match kind.as_str() {
                        "spawn" => crate::deeptrace::DtKind::Spawn,
                        "exec" => crate::deeptrace::DtKind::Exec,
                        _ => crate::deeptrace::DtKind::Exit,
                    };
                    self.ir.deep.events.push_back(crate::deeptrace::DtEvent { at: t, kind, pid, ppid, start, path, args, via: "recorded" });
                }
                Rec::Change { pid, start, kind, path } => {
                    let kind = match kind.as_str() {
                        "module load" => super::deep::ChangeKind::ModuleLoad,
                        "module unload" => super::deep::ChangeKind::ModuleUnload,
                        "file close" => super::deep::ChangeKind::FileClose,
                        _ => super::deep::ChangeKind::FileOpen,
                    };
                    self.ir.deep.changes.push_back(super::deep::Change { at: t, key: ProcKey { pid, start }, kind, path });
                }
                Rec::Detection { rule, name, severity, confidence, technique, subject, pid, evidence } => {
                    counts[3] += 1;
                    let subj = match pid {
                        Some(p) => Entity::Process(ProcKey { pid: p, start: 0 }),
                        None => Entity::Host(host.clone()),
                    };
                    self.ir.det.store.upsert(crate::detect::Detection {
                        rule_id: rule,
                        rule_name: name,
                        engine: "recorded",
                        severity: Severity::parse(&severity),
                        confidence: match confidence.as_str() {
                            "high" => Confidence::High,
                            "low" => Confidence::Low,
                            _ => Confidence::Medium,
                        },
                        technique,
                        subject: subj,
                        subject_label: subject,
                        pid,
                        evidence: vec![evidence],
                        first_seen: t,
                        last_seen: t,
                        count: 1,
                        suppressed: None,
                        active: false,
                    });
                }
                Rec::Snapshot { processes } => snapshot = Some(processes),
                Rec::Session { .. } => {}
            }
        }
        if let Some(p) = &snapshot {
            self.tree = tree_from(p);
        }
        self.ir.watch_start = first;
        self.ir.deep.auto = false;
        let desc = format!(
            "REPLAY {}{} – {} · {} process, {} network, {} file events, {} detections{}",
            if host.is_empty() { String::new() } else { format!("{host} · ") },
            first.format("%Y-%m-%d %H:%M"),
            last.format("%Y-%m-%d %H:%M"),
            counts[0],
            counts[1],
            counts[2],
            counts[3],
            if snapshot.is_none() { " · no process snapshot recorded (process list empty)" } else { "" }
        );
        self.ir.replay = Some(desc.clone());
        self.ir.timeline_dirty = true;
        self.rebuild();
        self.rebuild_timeline();
        self.tab = Tab::Timeline;
        Ok(desc)
    }
}
