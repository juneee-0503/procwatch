//! Process Investigation Workspace for `App`: one process instance and
//! everything recorded about it and its descendants, assembled into a
//! dossier — identity, related processes, events, network profile, file
//! activity, module integrity, persistence links, rule hits — plus a
//! deterministic summary that names its evidence, and behaviour replay.
//! A child module of `app`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use chrono::{DateTime, Local};
use serde::Serialize;

use super::*;
use crate::model::{Basis, Entity, ProcKey, Severity};

pub const FILE_BUCKETS: usize = 12;

#[derive(Debug, Clone, Serialize)]
pub struct Member {
    pub key: ProcKey,
    pub name: String,
    /// Negative = ancestor, 0 = the subject, positive = descendant depth.
    pub depth: i32,
    pub alive: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Endpoint {
    pub remote: String,
    pub host: Option<String>,
    pub public: bool,
    pub connects: usize,
    pub closes: usize,
    pub open_now: usize,
    pub first: String,
    pub last: String,
    /// Average seconds a connection stayed open (closed ones only).
    pub avg_open_secs: Option<f64>,
    pub beacon: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileDir {
    pub dir: String,
    pub buckets: [usize; FILE_BUCKETS],
    pub opens: usize,
    pub changes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleRow {
    pub path: String,
    pub status: String,
    pub concern: bool,
    pub loaded_later: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Statement {
    pub text: String,
    /// "observed", "rule", "inferred".
    pub basis: &'static str,
    /// Timeline event ids (T-…) or other references.
    pub refs: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Dossier {
    pub key: Option<ProcKey>,
    pub name: String,
    pub path: Option<String>,
    pub cmd: String,
    pub user: Option<String>,
    pub started: Option<String>,
    pub state: String,
    pub deep: Option<String>,
    pub priority: u8,
    pub family: Vec<Member>,
    /// Indices into the timeline, oldest first.
    #[serde(skip)]
    pub events: Vec<usize>,
    pub file_events: usize,
    pub net_events: usize,
    pub modules: Vec<ModuleRow>,
    pub detections: Vec<crate::detect::Detection>,
    pub persistence: Vec<String>,
    pub network: Vec<Endpoint>,
    pub net_per_bucket: Vec<usize>,
    pub files: Vec<FileDir>,
    pub span: Option<(String, String)>,
    pub summary: Vec<Statement>,
    pub gaps: Vec<String>,
}

#[derive(Debug, Default)]
pub struct WorkspaceState {
    pub key: Option<ProcKey>,
    pub tab: usize,
    pub cursor: usize,
    pub scroll: usize,
    pub dossier: Dossier,
    /// Libraries the executable links statically (for comparing with
    /// what is actually loaded).
    pub static_libs: Option<Vec<String>>,
}

pub const TABS: [&str; 6] = ["Summary", "Replay", "Network", "Files", "Modules", "Family"];

fn dir_of(p: &str) -> String {
    match p.rfind(['/', '\\']) {
        Some(i) if i > 0 => p[..i].to_string(),
        _ => p.to_string(),
    }
}

fn looks_executable(p: &str) -> bool {
    let l = p.to_lowercase();
    [".exe", ".dll", ".dylib", ".so", ".app/", ".sh", ".py", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr", ".bin", ".command"]
        .iter()
        .any(|x| l.ends_with(x) || l.contains(&format!("{x}/")))
}

impl App {
    /// Build the dossier for a process instance (live or exited).
    pub fn dossier(&self, key: ProcKey) -> Dossier {
        if self.ir.timeline_dirty {
            // Callers rebuild first; a stale timeline only means fewer events.
        }
        let mut d = Dossier { key: Some(key), ..Default::default() };
        let live = self.tree.get(key.pid).filter(|n| key.start == 0 || n.info.start_time_secs.abs_diff(key.start) <= 2);
        let recorded = self.events.iter().find(|e| e.pid == key.pid && (key.start == 0 || e.start.abs_diff(key.start) <= 2));
        let deep_rec = self.ir.deep.events.iter().find(|e| e.pid == key.pid && (key.start == 0 || e.start == 0 || e.start.abs_diff(key.start) <= 2));
        match (live, recorded) {
            (Some(n), _) => {
                let i = &n.info;
                d.name = i.name.clone();
                d.path = i.exe_path.clone();
                d.cmd = i.cmd.join(" ");
                d.user = i.user.clone();
                d.state = "running".into();
                d.priority = i.risk;
            }
            (None, Some(e)) => {
                d.name = e.name.clone();
                d.path = e.exe.clone();
                d.cmd = e.detail.clone();
                d.user = Some(e.user.clone()).filter(|u| !u.is_empty());
                d.state = "exited".into();
            }
            (None, None) => {
                d.name = deep_rec.and_then(|e| e.path.as_deref()).and_then(|p| p.rsplit(['/', '\\']).next()).unwrap_or("process").to_string();
                d.path = deep_rec.and_then(|e| e.path.clone());
                d.cmd = deep_rec.and_then(|e| e.args.clone()).unwrap_or_default();
                d.state = "exited".into();
            }
        }
        d.started = chrono::DateTime::from_timestamp(key.start as i64, 0).filter(|_| key.start > 0).map(|t| t.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string());
        if let Some(e) = self.ir.deep.enrolled.get(&key) {
            d.deep = Some(format!("{}{}", e.reason, e.ended.as_ref().map(|x| format!(" · {x}")).unwrap_or_default()));
            if d.state == "exited" {
                if let Some(x) = &e.ended {
                    d.state = x.clone();
                }
            }
        }

        // Family: ancestors (live tree), the subject, and descendants from
        // the tree, recorded events and the deep-trace watcher.
        let mut children: HashMap<u32, BTreeSet<u32>> = HashMap::new();
        for n in self.tree.nodes.values() {
            if let Some(pp) = n.info.ppid {
                children.entry(pp).or_default().insert(n.info.pid);
            }
        }
        for e in &self.events {
            if let Some(pp) = e.ppid {
                children.entry(pp).or_default().insert(e.pid);
            }
        }
        for e in &self.ir.deep.events {
            if let Some(pp) = e.ppid {
                children.entry(pp).or_default().insert(e.pid);
            }
        }
        let mut anc = Vec::new();
        let mut cur = live.and_then(|n| n.info.ppid).or_else(|| recorded.and_then(|e| e.ppid)).or_else(|| deep_rec.and_then(|e| e.ppid));
        while let Some(p) = cur {
            if anc.len() > 32 || anc.contains(&p) {
                break;
            }
            anc.push(p);
            cur = self.tree.get(p).and_then(|n| n.info.ppid);
        }
        for (i, p) in anc.iter().enumerate().rev() {
            d.family.push(Member { key: self.proc_key(*p), name: self.name_of(*p), depth: -(i as i32 + 1), alive: self.tree.get(*p).is_some() });
        }
        d.family.push(Member { key, name: d.name.clone(), depth: 0, alive: live.is_some() });
        let mut stack: Vec<(u32, i32)> = children.get(&key.pid).map(|c| c.iter().map(|p| (*p, 1)).collect()).unwrap_or_default();
        let mut seen: HashSet<u32> = [key.pid].into_iter().collect();
        while let Some((p, depth)) = stack.pop() {
            if !seen.insert(p) || d.family.len() > 400 {
                continue;
            }
            let name = self
                .tree
                .get(p)
                .map(|n| n.info.name.clone())
                .or_else(|| self.events.iter().find(|e| e.pid == p).map(|e| e.name.clone()))
                .or_else(|| self.ir.deep.events.iter().find(|e| e.pid == p).and_then(|e| e.path.as_deref().and_then(|x| x.rsplit(['/', '\\']).next()).map(str::to_string)))
                .unwrap_or_else(|| format!("pid {p}"));
            d.family.push(Member { key: self.proc_key(p), name, depth, alive: self.tree.get(p).is_some() });
            if let Some(cs) = children.get(&p) {
                stack.extend(cs.iter().map(|c| (*c, depth + 1)));
            }
        }
        let family_pids: HashSet<u32> = d.family.iter().filter(|m| m.depth >= 0).map(|m| m.key.pid).collect();

        // Events: anything in the subject's lineage or naming a family process.
        let mut evs: Vec<usize> = self
            .ir
            .timeline
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                e.lineage.contains(&key.pid)
                    || e.pid.is_some_and(|p| family_pids.contains(&p))
                    || e.entities().any(|x| matches!(x, Entity::Process(k) if family_pids.contains(&k.pid)))
            })
            .map(|(i, _)| i)
            .collect();
        evs.sort_by_key(|i| self.ir.timeline[*i].time);
        d.events = evs;
        let tl = &self.ir.timeline;
        d.file_events = d.events.iter().filter(|i| tl[**i].source == "file" || tl[**i].kind.starts_with("file")).count();
        d.net_events = d.events.iter().filter(|i| tl[**i].source == "network").count();
        if let (Some(a), Some(b)) = (d.events.first(), d.events.last()) {
            d.span = Some((tl[*a].time.format("%H:%M:%S").to_string(), tl[*b].time.format("%H:%M:%S").to_string()));
        }

        // Detections on any family member.
        d.detections = self
            .ir
            .det
            .store
            .items
            .iter()
            .filter(|x| x.suppressed.is_none() && matches!(&x.subject, Entity::Process(k) if family_pids.contains(&k.pid)))
            .cloned()
            .collect();
        d.detections.sort_by_key(|x| std::cmp::Reverse(x.severity));

        // Persistence entries that launch the subject's executable.
        if let Some(exe) = &d.path {
            d.persistence = self
                .persist_items()
                .iter()
                .filter(|p| p.target.as_deref() == Some(exe.as_str()) || p.command.contains(exe.as_str()))
                .map(|p| format!("{}: {} ({})", p.category, p.name, p.location))
                .collect();
        }

        self.dossier_network(&mut d, &family_pids);
        self.dossier_files(&mut d);
        self.dossier_modules(&mut d, key);
        self.dossier_summary(&mut d, key);
        d
    }

    fn dossier_network(&self, d: &mut Dossier, family: &HashSet<u32>) {
        let mut by: BTreeMap<String, Endpoint> = BTreeMap::new();
        let mut opened: HashMap<(u32, &crate::network::Connection), DateTime<Local>> = HashMap::new();
        let mut durations: HashMap<String, Vec<f64>> = HashMap::new();
        let mut times: Vec<DateTime<Local>> = Vec::new();
        for e in self.ir.net_events.iter().filter(|e| family.contains(&e.pid)) {
            let listen = e.kind.contains("listen");
            let remote = if listen { format!("listening {}", e.conn.local) } else { e.conn.remote.clone() };
            let ep = by.entry(remote.clone()).or_insert_with(|| Endpoint { remote: remote.clone(), first: e.time.format("%H:%M:%S").to_string(), ..Default::default() });
            ep.last = e.time.format("%H:%M:%S").to_string();
            match e.kind {
                "connect" | "listen" => {
                    ep.connects += 1;
                    opened.insert((e.pid, &e.conn), e.time);
                    times.push(e.time);
                }
                _ => {
                    ep.closes += 1;
                    if let Some(t0) = opened.remove(&(e.pid, &e.conn)) {
                        durations.entry(remote).or_default().push((e.time - t0).num_milliseconds() as f64 / 1000.0);
                    }
                }
            }
        }
        for p in family {
            for c in self.connections.get(p).into_iter().flatten() {
                let listen = c.state == crate::network::ConnState::Listen;
                if !listen && c.remote == "*:*" {
                    continue;
                }
                let remote = if listen { format!("listening {}", c.local) } else { c.remote.clone() };
                by.entry(remote.clone()).or_insert_with(|| Endpoint { remote, first: "before trace".into(), last: "now".into(), ..Default::default() }).open_now += 1;
            }
        }
        for ep in by.values_mut() {
            let ip = crate::filter::split_endpoint(&ep.remote).0;
            ep.public = !ep.remote.starts_with("listening") && !crate::triage::is_private(&ip);
            ep.host = self.host_for(&ip, family.iter().next().copied());
            ep.beacon = self.ir.remotes.iter().find(|r| r.ip == ip).and_then(|r| r.beacon);
            if let Some(v) = durations.get(&ep.remote) {
                ep.avg_open_secs = Some(v.iter().sum::<f64>() / v.len() as f64);
            }
        }
        let mut list: Vec<Endpoint> = by.into_values().collect();
        list.sort_by(|a, b| b.public.cmp(&a.public).then(b.connects.cmp(&a.connects)).then(b.open_now.cmp(&a.open_now)));
        d.network = list;
        // Connect rate over the event span.
        if let (Some(a), Some(b)) = (times.iter().min(), times.iter().max()) {
            let span = (*b - *a).num_milliseconds().max(1) as f64;
            let mut buckets = vec![0usize; FILE_BUCKETS];
            for t in &times {
                let i = (((*t - *a).num_milliseconds() as f64 / span) * (FILE_BUCKETS as f64 - 1.0)).round() as usize;
                buckets[i.min(FILE_BUCKETS - 1)] += 1;
            }
            d.net_per_bucket = buckets;
        }
    }

    fn dossier_files(&self, d: &mut Dossier) {
        let tl = &self.ir.timeline;
        let file_evs: Vec<&super::ir::TimelineItem> =
            d.events.iter().map(|i| &tl[*i]).filter(|e| e.source == "file" || (e.source == "deep" && e.kind.starts_with("file"))).collect();
        let (Some(a), Some(b)) = (file_evs.iter().map(|e| e.time).min(), file_evs.iter().map(|e| e.time).max()) else { return };
        let span = (b - a).num_milliseconds().max(1) as f64;
        let mut dirs: BTreeMap<String, FileDir> = BTreeMap::new();
        for e in file_evs {
            let path = e.entities().find_map(|x| if let Entity::File(p) = x { Some(p.clone()) } else { None }).unwrap_or_else(|| e.detail.clone());
            let dir = dir_of(&path);
            let entry = dirs.entry(dir.clone()).or_insert(FileDir { dir, buckets: [0; FILE_BUCKETS], opens: 0, changes: 0 });
            let i = (((e.time - a).num_milliseconds() as f64 / span) * (FILE_BUCKETS as f64 - 1.0)).round() as usize;
            entry.buckets[i.min(FILE_BUCKETS - 1)] += 1;
            if e.source == "file" {
                entry.changes += 1;
            } else {
                entry.opens += 1;
            }
        }
        let mut v: Vec<FileDir> = dirs.into_values().collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.opens + x.changes));
        v.truncate(30);
        d.files = v;
    }

    fn dossier_modules(&self, d: &mut Dossier, key: ProcKey) {
        let later: HashSet<&str> =
            self.ir.deep.changes.iter().filter(|c| c.key == key && c.kind == super::deep::ChangeKind::ModuleLoad).map(|c| c.path.as_str()).collect();
        let list: Vec<String> = self
            .ir
            .deep
            .snaps
            .get(&key)
            .and_then(|s| s.modules.clone())
            .map(|m| m.into_iter().collect())
            .or_else(|| self.deep_cache.get(&key.pid).filter(|e| e.info.modules_loaded).map(|e| e.info.loaded_modules.clone()))
            .unwrap_or_default();
        let intel = self.ir.intel.snapshot();
        for m in list {
            let path = m.split_whitespace().last().filter(|p| p.starts_with('/') || p.contains(":\\")).unwrap_or(&m).to_string();
            let mut why: Vec<String> = Vec::new();
            let exists = std::path::Path::new(&path).exists();
            // macOS system libraries live in the dyld shared cache, not on disk.
            let in_cache = path.starts_with("/usr/lib/") || path.starts_with("/System/");
            if !exists && !in_cache {
                why.push("file missing on disk (deleted or replaced after load)".into());
            }
            if crate::persistence::risky_location(&path) {
                why.push("user-writable or temporary location".into());
            }
            match intel.get(&path).map(|x| x.sig) {
                Some(crate::intel::Sig::Unsigned) => why.push("unsigned".into()),
                Some(crate::intel::Sig::Invalid) => why.push("signature invalid".into()),
                _ => {}
            }
            let loaded_later = later.contains(path.as_str());
            // Runtime-only libraries outside the OS: loaded by the program
            // itself (plug-ins, injected or side-loaded code all look so).
            let os_lib = in_cache || path.to_lowercase().contains("\\windows\\") || path.starts_with("/lib") || path.starts_with("/usr/lib");
            if let Some(statics) = &self.ir.ws.static_libs {
                let base = |p: &str| p.rsplit(['/', '\\']).next().unwrap_or(p).to_lowercase();
                if !os_lib && Some(path.as_str()) != d.path.as_deref() && !statics.iter().any(|s| base(s) == base(&path)) {
                    why.push("not a static dependency (loaded at run time)".into());
                }
            }
            let status = if why.is_empty() {
                match intel.get(&path).map(|x| x.sig) {
                    Some(crate::intel::Sig::Signed) => "signed".to_string(),
                    _ if in_cache && !exists => "system (shared cache)".to_string(),
                    _ => "not checked yet".to_string(),
                }
            } else {
                why.join(" · ")
            };
            d.modules.push(ModuleRow { concern: status.contains("missing") || status.contains("writable") || status.contains("unsigned") || status.contains("invalid"), path, status, loaded_later });
        }
        d.modules.sort_by(|a, b| b.concern.cmp(&a.concern).then(b.loaded_later.cmp(&a.loaded_later)).then(a.path.cmp(&b.path)));
    }

    fn dossier_summary(&self, d: &mut Dossier, key: ProcKey) {
        let tl = &self.ir.timeline;
        let id = |i: &usize| crate::model::short_id(tl[*i].id);
        let mut s: Vec<Statement> = Vec::new();
        let spawns: Vec<&usize> = d.events.iter().filter(|i| matches!((tl[**i].source, tl[**i].kind.as_str()), ("deep", "spawn") | ("process", "started")) && tl[**i].pid != Some(key.pid)).collect();
        if !spawns.is_empty() {
            let names: BTreeSet<&str> = spawns.iter().map(|i| tl[**i].name.as_str()).collect();
            s.push(Statement {
                text: format!("Started {} child process{}: {}", spawns.len(), if spawns.len() == 1 { "" } else { "es" }, names.into_iter().take(8).collect::<Vec<_>>().join(", ")),
                basis: "observed",
                refs: spawns.iter().take(5).map(|i| id(i)).collect(),
            });
        }
        let public: Vec<&Endpoint> = d.network.iter().filter(|e| e.public).collect();
        if !d.network.is_empty() {
            let top: Vec<String> = d.network.iter().take(4).map(|e| format!("{}{}", e.host.clone().unwrap_or_else(|| e.remote.clone()), if e.connects > 1 { format!(" ×{}", e.connects) } else { String::new() })).collect();
            s.push(Statement {
                text: format!("Network: {} endpoint(s), {} on the internet — {}", d.network.len(), public.len(), top.join(", ")),
                basis: "observed",
                refs: d.events.iter().filter(|i| tl[**i].source == "network").take(5).map(id).collect(),
            });
        }
        for e in d.network.iter().filter(|e| e.beacon.is_some()) {
            s.push(Statement { text: format!("Reconnects to {} at a regular ~{:.0} s interval", e.remote, e.beacon.unwrap_or(0.0)), basis: "rule", refs: vec!["PW-016".into()] });
        }
        let changed_exec: Vec<&usize> = d.events.iter().filter(|i| tl[**i].source == "file" && looks_executable(&tl[**i].detail)).collect();
        if !changed_exec.is_empty() {
            let paths: BTreeSet<&str> = changed_exec.iter().map(|i| tl[**i].detail.as_str()).collect();
            s.push(Statement {
                text: format!("Created or changed executable/script files: {}", paths.into_iter().take(5).collect::<Vec<_>>().join(", ")),
                basis: "observed",
                refs: changed_exec.iter().take(5).map(|i| id(i)).collect(),
            });
        }
        if !d.files.is_empty() {
            let opens: usize = d.files.iter().map(|f| f.opens).sum();
            let changes: usize = d.files.iter().map(|f| f.changes).sum();
            s.push(Statement { text: format!("File activity in {} folder(s): {opens} file opens seen, {changes} changes attributed", d.files.len()), basis: "observed", refs: vec![] });
        }
        let odd: Vec<&ModuleRow> = d.modules.iter().filter(|m| m.concern).collect();
        if !odd.is_empty() {
            s.push(Statement {
                text: format!("Modules needing review: {}", odd.iter().take(4).map(|m| format!("{} ({})", m.path, m.status)).collect::<Vec<_>>().join("; ")),
                basis: "observed",
                refs: vec![],
            });
        }
        let later: Vec<&ModuleRow> = d.modules.iter().filter(|m| m.loaded_later).collect();
        if !later.is_empty() {
            s.push(Statement { text: format!("Loaded {} module(s) after it was first inspected (dynamic loading)", later.len()), basis: "observed", refs: vec![] });
        }
        for det in d.detections.iter().filter(|x| x.severity >= Severity::Medium).take(6) {
            s.push(Statement { text: format!("{} {} — {}", det.severity.label(), det.rule_name, det.evidence.first().cloned().unwrap_or_default()), basis: "rule", refs: vec![det.rule_id.clone()] });
        }
        if !d.persistence.is_empty() {
            s.push(Statement { text: format!("Autostart entries point at its executable: {}", d.persistence.join("; ")), basis: "inferred", refs: vec![] });
        }
        if let Some(p) = self.ir.profiles.as_ref().and_then(|ps| {
            let sha = d.path.as_deref().and_then(|e| self.ir.intel.get(e)).and_then(|x| x.sha256);
            sha.map(|h| format!("sha:{h}")).or(d.path.as_ref().map(|e| format!("path:{e}"))).and_then(|k| ps.by_key.get(&k))
        }) {
            s.push(Statement {
                text: format!(
                    "History on this machine: {} runs since {}, {} destinations, {} child programs — profile {}",
                    p.runs,
                    p.first_seen.get(..10).unwrap_or(""),
                    p.destinations.len(),
                    p.children.len(),
                    if p.established() { "established (new behaviour is reported as PW-018)" } else { "still learning" }
                ),
                basis: "observed",
                refs: vec![],
            });
        }
        if s.is_empty() {
            s.push(Statement { text: "No notable activity recorded for this process.".into(), basis: "observed", refs: vec![] });
        }
        d.summary = s;

        // What this dossier can't show.
        let mut gaps = Vec::new();
        if !self.ir.deep.enrolled.contains_key(&key) {
            gaps.push("Not deep-traced: child processes and exits are sampled every refresh, so short-lived children can be missing (press D to trace).".into());
        }
        if d.modules.is_empty() {
            gaps.push("Modules not listed yet (deep trace samples them every 20 s; or open the Modules tab).".into());
        }
        if !self.ir.deep.snaps.contains_key(&key) {
            gaps.push("Open files were never snapshotted, so file changes can't be attributed to it.".into());
        } else {
            gaps.push("File opens come from snapshots every 3 s; files opened and closed in between are not seen.".into());
        }
        if self.ir.persistence.is_none() {
            gaps.push("Persistence not scanned: autostart links unknown.".into());
        }
        if !crate::health::elevated() {
            gaps.push("Running without elevation: other users' processes and some details are hidden.".into());
        }
        d.gaps = gaps;
        let _ = Basis::Event;
    }

    /// Open the workspace for the selected process (any page).
    pub fn open_workspace(&mut self) {
        let key = match self.selected_entity() {
            Some(Entity::Process(k)) => Some(k),
            _ => self.detail_pid().map(|p| self.proc_key(p)),
        };
        let Some(key) = key else {
            self.set_status(StatusLevel::Info, "Select a process first".into());
            return;
        };
        self.open_workspace_for(key);
    }

    pub fn open_workspace_for(&mut self, key: ProcKey) {
        if self.ir.timeline_dirty {
            self.rebuild_timeline();
        }
        // Ask for signatures of its modules so integrity fills in.
        if let Some(s) = self.ir.deep.snaps.get(&key).and_then(|s| s.modules.clone()) {
            for m in s {
                self.ir.intel.request(&m, false);
            }
        }
        // Reads up to 32 MB of the file: in the background.
        if let Some(exe) = self.tree.get(key.pid).and_then(|n| n.info.exe_path.clone()) {
            crate::sampler::spawn_static_libs(self.tx.clone(), key, exe);
        }
        self.ir.ws = WorkspaceState { key: Some(key), tab: 0, cursor: 0, scroll: 0, dossier: Dossier::default(), static_libs: None };
        self.ir.ws.dossier = self.dossier(key);
        self.mode = Mode::Workspace;
    }

    /// Refresh the open workspace's dossier (called while it is shown).
    pub fn refresh_workspace(&mut self) {
        if let Some(k) = self.ir.ws.key {
            if self.timeline_rebuild_due() {
                self.rebuild_timeline();
            }
            let cursor_id = self.ir.ws.dossier.events.get(self.ir.ws.cursor).map(|i| self.ir.timeline[*i].id);
            self.ir.ws.dossier = self.dossier(k);
            if let Some(id) = cursor_id {
                if let Some(p) = self.ir.ws.dossier.events.iter().position(|i| self.ir.timeline[*i].id == id) {
                    self.ir.ws.cursor = p;
                }
            }
        }
    }

    /// Replay: what was true at the event under the cursor.
    pub fn replay_state(&self) -> Vec<(String, String)> {
        let d = &self.ir.ws.dossier;
        let tl = &self.ir.timeline;
        let upto = &d.events[..(self.ir.ws.cursor + 1).min(d.events.len())];
        let mut children: BTreeSet<String> = BTreeSet::new();
        let mut conns: BTreeSet<String> = BTreeSet::new();
        let mut files: BTreeSet<String> = BTreeSet::new();
        let mut modules = 0;
        let mut detections: Vec<String> = Vec::new();
        for i in upto {
            let e = &tl[*i];
            match (e.source, e.kind.as_str()) {
                ("deep", "spawn") | ("process", "started") if e.pid != d.key.map(|k| k.pid) => {
                    children.insert(format!("{} ({})", e.name, e.pid.unwrap_or(0)));
                }
                ("deep", "exit") | ("process", "exited") => {
                    children.remove(&format!("{} ({})", e.name, e.pid.unwrap_or(0)));
                }
                ("network", "connect") | ("network", "listen") => {
                    conns.insert(e.detail.split_whitespace().nth(3).unwrap_or(&e.detail).to_string());
                }
                ("network", "close") | ("network", "unlisten") => {
                    conns.remove(e.detail.split_whitespace().nth(3).unwrap_or(&e.detail));
                }
                ("deep", "file open") | ("file", _) => {
                    files.insert(e.detail.clone());
                }
                ("deep", "module load") => modules += 1,
                ("detect", _) | ("alert", _) => detections.push(e.kind.clone()),
                _ => {}
            }
        }
        vec![
            ("children running".into(), if children.is_empty() { "none".into() } else { children.into_iter().take(6).collect::<Vec<_>>().join(", ") }),
            ("connections open".into(), if conns.is_empty() { "none".into() } else { format!("{} — {}", conns.len(), conns.into_iter().take(4).collect::<Vec<_>>().join(", ")) }),
            ("files touched so far".into(), files.len().to_string()),
            ("modules loaded later".into(), modules.to_string()),
            ("detections so far".into(), if detections.is_empty() { "none".into() } else { detections.join(", ") }),
        ]
    }

    /// Quick Analysis Report for the workspace's process, into the case.
    pub fn export_quick_report(&mut self) {
        let d = self.ir.ws.dossier.clone();
        let Some(key) = d.key else { return };
        let tl = &self.ir.timeline;
        let mut m = format!("# Quick analysis — {} (pid {})\n\n", d.name, key.pid);
        m += &format!("| | |\n|---|---|\n| Executable | {} |\n| Command line | `{}` |\n| User | {} |\n| Started | {} |\n| State | {} |\n| Deep trace | {} |\n| Priority | {} |\n\n",
            d.path.clone().unwrap_or_default(), d.cmd.replace('`', "'"), d.user.clone().unwrap_or_default(), d.started.clone().unwrap_or_default(), d.state, d.deep.clone().unwrap_or_else(|| "no".into()), d.priority);
        m += "## Behaviour summary\n\n_Each line says whether it was observed, came from a rule, or is inferred, and cites event ids._\n\n";
        for st in &d.summary {
            m += &format!("- **{}** {}{}\n", st.basis, st.text, if st.refs.is_empty() { String::new() } else { format!(" [{}]", st.refs.join(", ")) });
        }
        m += &format!("\n## Detections ({})\n\n", d.detections.len());
        for x in &d.detections {
            m += &format!("- {} / {} — {} {} — {}\n", x.severity.label(), x.confidence.label(), x.rule_id, x.rule_name, x.evidence.join(" | "));
        }
        m += &format!("\n## Network ({} endpoints)\n\n| Remote | Host | Public | Connects | Open now | Avg open (s) | First | Last |\n|---|---|---|---|---|---|---|---|\n", d.network.len());
        for e in &d.network {
            m += &format!("| {} | {} | {} | {} | {} | {} | {} | {} |\n", e.remote, e.host.clone().unwrap_or_default(), e.public, e.connects, e.open_now, e.avg_open_secs.map(|x| format!("{x:.1}")).unwrap_or_default(), e.first, e.last);
        }
        m += "\n## Files by folder\n\n| Folder | Opens | Changes |\n|---|---|---|\n";
        for f in &d.files {
            m += &format!("| {} | {} | {} |\n", f.dir, f.opens, f.changes);
        }
        m += "\n## Modules needing review\n\n";
        for x in d.modules.iter().filter(|x| x.concern || x.loaded_later) {
            m += &format!("- {} — {}{}\n", x.path, x.status, if x.loaded_later { " · loaded later" } else { "" });
        }
        m += "\n## Related processes\n\n";
        for f in &d.family {
            m += &format!("- {}{} ({}){}\n", "  ".repeat(f.depth.unsigned_abs() as usize), f.name, f.key.pid, if f.depth < 0 { " · ancestor" } else if !f.alive { " · exited" } else { "" });
        }
        m += &format!("\n## Events ({})\n\n| Time | Source | Event | Process | Detail | Id |\n|---|---|---|---|---|---|\n", d.events.len());
        for i in d.events.iter().take(500) {
            let e = &tl[*i];
            m += &format!("| {} | {} | {} | {} | {} | {} |\n", e.time.format("%H:%M:%S%.3f"), e.source, e.kind, e.name, e.detail.replace('|', "\\|"), crate::model::short_id(e.id));
        }
        m += "\n## Limits of this analysis\n\n";
        for g in &d.gaps {
            m += &format!("- {g}\n");
        }
        let json = serde_json::to_string_pretty(&d).unwrap_or_default();
        let name = format!("quick-report-{}-{}", key.pid, Local::now().format("%Y%m%d-%H%M%S"));
        let Some(case) = self.ensure_case() else { return };
        let subject = format!("process:{}:{}", key.pid, key.start);
        let prov = |what: &str| crate::case::Provenance::derived(what).subject(subject.clone());
        let r1 = case.add_text_with(&format!("{name}.md"), &m, prov("quick analysis report (process workspace)"));
        let r2 = case.add_text_with(&format!("{name}.json"), &json, prov("process dossier (process workspace)"));
        match (r1, r2) {
            (Ok((p, i)), Ok(_)) => self.set_status(StatusLevel::Success, format!("Quick report {} saved as {}", p.display(), i.id)),
            (Err(e), _) | (_, Err(e)) => self.set_status(StatusLevel::Error, format!("Couldn't save report: {e}")),
        }
    }
}
