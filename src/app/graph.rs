//! Investigation graph for `App`: the neighbours of any entity, assembled
//! on demand from live state (process tree, sockets, open files,
//! persistence, detections, evidence), so it is never stale. A child
//! module of `app`.

use std::collections::BTreeMap;

use super::*;
use crate::common::model::{Entity, ProcKey, Rel};

#[derive(Debug, Clone)]
pub struct Neighbor {
    pub rel: Rel,
    pub entity: Entity,
    pub label: String,
    pub note: String,
}

/// Graph overlay state: the pivot history (last = current) and cursor.
#[derive(Debug, Default)]
pub struct GraphState {
    pub stack: Vec<Entity>,
    pub cursor: usize,
    pub offset: usize,
}

const MAX_PER_REL: usize = 40;

impl App {
    fn live_node(&self, k: &ProcKey) -> Option<&crate::process::TreeNode> {
        self.tree.get(k.pid).filter(|n| k.start == 0 || n.info.start_time_secs == k.start)
    }

    fn proc_entity(&self, pid: u32) -> Entity {
        Entity::Process(self.proc_key(pid))
    }

    /// Display name of an entity.
    pub fn entity_label(&self, e: &Entity) -> String {
        match e {
            Entity::Process(k) => match self.live_node(k) {
                Some(n) => format!("{} ({})", n.info.name, k.pid),
                None => {
                    let name = self.events.iter().find(|ev| ev.pid == k.pid && (k.start == 0 || ev.start == k.start)).map(|ev| ev.name.clone());
                    format!("{} ({}) · exited", name.unwrap_or_else(|| "process".into()), k.pid)
                }
            },
            Entity::File(p) => p.clone(),
            Entity::Endpoint(ip) => match self.ir.resolver.known().iter().find(|(a, _)| a == ip) {
                Some((_, h)) => format!("{ip} ({h})"),
                None => ip.clone(),
            },
            Entity::Persistence(id) => {
                let mut f = id.splitn(3, '|');
                format!("{}: {}", f.next().unwrap_or(""), f.next().unwrap_or(""))
            }
            Entity::User(u) => format!("user {u}"),
            Entity::Rule(r) => r.clone(),
            Entity::Evidence(e) => format!("evidence {e}"),
            Entity::Host(h) => if h.is_empty() { self.host_name() } else { h.clone() },
        }
    }

    /// Key facts about an entity, for the graph header.
    pub fn entity_props(&self, e: &Entity) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = vec![("type".into(), e.kind().into())];
        let mut add = |k: &str, val: String| {
            if !val.is_empty() {
                v.push((k.into(), val));
            }
        };
        match e {
            Entity::Process(k) => {
                if let Some(n) = self.live_node(k) {
                    let i = &n.info;
                    add("started", crate::common::model::ProcKey { pid: 0, start: i.start_time_secs }.to_string().trim_start_matches("0@").to_string());
                    add("user", i.user.clone().unwrap_or_default());
                    add("path", i.exe_path.clone().unwrap_or_default());
                    add("command", i.cmd.join(" ").chars().take(200).collect());
                    if let Some(a) = self.ir.triage.get(&k.pid).filter(|a| a.score > 0) {
                        add("priority", format!("{} ({}) — {}", a.score, a.level(), a.summary()));
                    }
                } else {
                    add("state", "not running (from recorded events)".into());
                }
            }
            Entity::File(p) => {
                if let Some(x) = self.ir.intel.get(p) {
                    add("signature", format!("{:?} {}", x.sig, x.signer));
                    add("sha256", x.sha256.unwrap_or_default());
                    add("size", crate::process::human_bytes(x.size));
                    if !x.exists {
                        add("exists", "no (deleted?)".into());
                    }
                } else {
                    add("exists", if std::path::Path::new(p).exists() { "yes".into() } else { "no".into() });
                }
                let changes: Vec<&crate::files::watch::FsEvent> = self.ir.fs_events.iter().filter(|f| &f.path == p).collect();
                if let Some(last) = changes.last() {
                    add("changes", format!("{} seen, last {} at {}", changes.len(), last.kind, last.time.format("%H:%M:%S")));
                }
            }
            Entity::Endpoint(ip) => {
                if let Some(r) = self.ir.remotes.iter().find(|r| &r.ip == ip) {
                    add("scope", if r.public { "internet".into() } else { "private / local".into() });
                    add("connects", format!("{} since start, {} open now, first {} last {}", r.connects, r.current, r.first_seen, r.last_seen));
                    if let Some(b) = r.beacon {
                        add("pattern", format!("regular reconnects every ~{b:.0} s"));
                    }
                }
            }
            Entity::Persistence(id) => {
                if let Some(p) = self.persist_items().iter().find(|p| &format!("{}|{}|{}", p.category, p.name, p.location) == id) {
                    add("location", p.location.clone());
                    add("command", p.command.clone());
                    add("written", p.defined.clone().unwrap_or_default());
                    add("flags", p.flags.join("; "));
                }
            }
            Entity::Rule(r) => {
                if let Some(d) = crate::detection::triage::rule(r) {
                    add("rule", format!("{} · {} · confidence {} · {}", d.name, d.severity.label(), d.confidence.label(), d.technique));
                    add("why", d.description.into());
                } else if let Some(s) = self.ir.det.sigma.iter().find(|s| &s.id == r) {
                    add("sigma", format!("{} · {} · {} · {}", s.title, s.level.label(), s.status, s.file));
                    add("why", s.description.clone());
                }
            }
            Entity::Evidence(id) => {
                if let Some(i) = self.ir.case.as_ref().and_then(|c| c.register().into_iter().find(|i| &i.id == id)) {
                    add("file", i.path);
                    add("class", format!("{} · {}", i.class.label(), i.status.label()));
                    add("method", i.method);
                    add("sha256", i.sha256);
                    add("problems", i.problems.join("; "));
                }
            }
            _ => {}
        }
        let key = e.key();
        let events = self.ir.timeline.iter().filter(|t| t.entities().any(|x| x.key() == key)).count();
        v.push(("timeline".into(), format!("{events} event(s) — t shows them")));
        v
    }

    /// Everything directly related to `e`.
    pub fn neighbors(&self, e: &Entity) -> Vec<Neighbor> {
        let mut out: Vec<Neighbor> = Vec::new();
        let mut push = |rel: Rel, entity: Entity, label: String, note: String| {
            if out.iter().filter(|n| n.rel == rel).count() < MAX_PER_REL && !out.iter().any(|n| n.rel == rel && n.entity == entity) {
                out.push(Neighbor { rel, entity, label, note });
            }
        };
        let det_rel = |e: &Entity, push: &mut dyn FnMut(Rel, Entity, String, String)| {
            for d in self.ir.det.store.for_subject(e) {
                let state = if d.suppressed.is_some() { "suppressed" } else if d.active { "active" } else { "past" };
                push(Rel::DetectedBy, Entity::Rule(d.rule_id.clone()), format!("{} {}", d.rule_id, d.rule_name), format!("{} · {state}", d.severity.label()));
            }
        };
        match e {
            Entity::Process(k) => {
                if let Some(n) = self.live_node(k) {
                    let i = &n.info;
                    if let Some(pp) = i.ppid {
                        push(Rel::ChildOf, self.proc_entity(pp), format!("{} ({pp})", self.name_of(pp)), String::new());
                    }
                    for c in &n.children {
                        push(Rel::Spawned, self.proc_entity(*c), format!("{} ({c})", self.name_of(*c)), String::new());
                    }
                    if let Some(exe) = &i.exe_path {
                        push(Rel::Executes, Entity::File(exe.clone()), exe.clone(), String::new());
                    }
                    if let Some(u) = &i.user {
                        push(Rel::RunsAs, Entity::User(u.clone()), u.clone(), String::new());
                    }
                    let mut eps: BTreeMap<(bool, String), Vec<String>> = BTreeMap::new();
                    for c in self.connections.get(&k.pid).into_iter().flatten() {
                        let listen = c.state == crate::network::ConnState::Listen;
                        let (ip, port) = crate::common::filter::split_endpoint(if listen { &c.local } else { &c.remote });
                        if ip != "*" {
                            eps.entry((listen, ip)).or_default().push(format!("{}/{port}", c.protocol));
                        }
                    }
                    for ((listen, ip), ports) in eps {
                        let rel = if listen { Rel::ListensOn } else { Rel::ConnectedTo };
                        push(rel, Entity::Endpoint(ip.clone()), self.entity_label(&Entity::Endpoint(ip)), ports.join(", "));
                    }
                    if let Some(Ok(files)) = self.deep_cache.get(&k.pid).map(|d| &d.info.open_files) {
                        for f in files.iter().filter(|f| f.kind == "REG" && f.name.starts_with(['/', '\\']) || f.name.get(1..3) == Some(":\\")) {
                            push(Rel::Opened, Entity::File(f.name.clone()), f.name.clone(), format!("fd {}", f.fd));
                        }
                    }
                    if let Some(exe) = &i.exe_path {
                        for p in self.persist_items().iter().filter(|p| p.target.as_deref() == Some(exe.as_str())) {
                            let id = format!("{}|{}|{}", p.category, p.name, p.location);
                            push(Rel::LaunchedBy, Entity::Persistence(id.clone()), self.entity_label(&Entity::Persistence(id)), p.location.clone());
                        }
                    }
                } else {
                    for ev in self.events.iter().filter(|ev| ev.pid == k.pid && (k.start == 0 || ev.start == k.start)) {
                        if let Some(exe) = &ev.exe {
                            push(Rel::Executes, Entity::File(exe.clone()), exe.clone(), String::new());
                        }
                        if let Some(pp) = ev.ppid {
                            push(Rel::ChildOf, self.proc_entity(pp), ev.parent.clone(), String::new());
                        }
                    }
                }
                det_rel(e, &mut push);
                if let Some(c) = &self.ir.case {
                    let subj = format!("process:{}:{}", k.pid, k.start);
                    for it in c.register().into_iter().filter(|i| i.subject.as_deref() == Some(subj.as_str())) {
                        push(Rel::CollectedIn, Entity::Evidence(it.id.clone()), format!("{} {}", it.id, it.path), it.class.label().into());
                    }
                }
            }
            Entity::File(p) => {
                for n in self.tree.nodes.values().filter(|n| n.info.exe_path.as_deref() == Some(p.as_str())) {
                    push(Rel::ExecutedBy, self.proc_entity(n.info.pid), format!("{} ({})", n.info.name, n.info.pid), String::new());
                }
                for (pid, d) in &self.deep_cache {
                    if d.info.open_files.as_ref().is_ok_and(|f| f.iter().any(|f| &f.name == p)) {
                        push(Rel::OpenedBy, self.proc_entity(*pid), format!("{} ({pid})", self.name_of(*pid)), String::new());
                    }
                }
                if let Some(Ok(hits)) = self.files.as_ref().map(|f| &f.result) {
                    for h in hits.iter().filter(|h| &h.path == p) {
                        push(Rel::OpenedBy, self.proc_entity(h.pid), format!("{} ({})", h.command, h.pid), format!("fd {}", h.fd));
                    }
                }
                for it in self.persist_items().iter().filter(|it| it.target.as_deref() == Some(p.as_str()) || &it.location == p) {
                    let id = format!("{}|{}|{}", it.category, it.name, it.location);
                    push(Rel::LaunchedBy, Entity::Persistence(id.clone()), self.entity_label(&Entity::Persistence(id)), it.location.clone());
                }
                det_rel(e, &mut push);
            }
            Entity::Endpoint(ip) => {
                for (pid, cs) in &self.connections {
                    for c in cs {
                        let listen = c.state == crate::network::ConnState::Listen;
                        let (rip, port) = crate::common::filter::split_endpoint(if listen { &c.local } else { &c.remote });
                        if &rip == ip {
                            let rel = if listen { Rel::ListensOn } else { Rel::ConnectedFrom };
                            push(rel, self.proc_entity(*pid), format!("{} ({pid})", self.name_of(*pid)), format!("{}/{port} {}", c.protocol, c.state.label()));
                        }
                    }
                }
                for ev in self.ir.net_events.iter().filter(|ev| crate::common::filter::split_endpoint(&ev.conn.remote).0 == *ip) {
                    push(Rel::ConnectedFrom, self.proc_entity(ev.pid), format!("{} ({})", ev.name, ev.pid), format!("{} at {}", ev.kind, ev.time.format("%H:%M:%S")));
                }
                det_rel(e, &mut push);
            }
            Entity::Persistence(id) => {
                if let Some(it) = self.persist_items().iter().find(|it| &format!("{}|{}|{}", it.category, it.name, it.location) == id) {
                    if let Some(t) = &it.target {
                        push(Rel::Launches, Entity::File(t.clone()), t.clone(), it.signature.clone().unwrap_or_default());
                    }
                    push(Rel::Describes, Entity::File(it.location.clone()), it.location.clone(), "definition".into());
                }
            }
            Entity::User(u) => {
                let mut procs: Vec<&crate::process::TreeNode> = self.tree.nodes.values().filter(|n| n.info.user.as_deref() == Some(u.as_str())).collect();
                procs.sort_by_key(|n| std::cmp::Reverse(n.info.risk));
                for n in procs {
                    push(Rel::Runs, self.proc_entity(n.info.pid), format!("{} ({})", n.info.name, n.info.pid), if n.info.risk > 0 { format!("priority {}", n.info.risk) } else { String::new() });
                }
            }
            Entity::Rule(r) => {
                for d in self.ir.det.store.items.iter().filter(|d| &d.rule_id == r) {
                    push(Rel::Detects, d.subject.clone(), d.subject_label.clone(), d.evidence.first().cloned().unwrap_or_default());
                }
            }
            Entity::Evidence(id) => {
                if let Some(it) = self.ir.case.as_ref().and_then(|c| c.register().into_iter().find(|i| &i.id == id)) {
                    if let Some(s) = it.subject.as_deref() {
                        let mut f = s.split(':');
                        if let (Some("process"), Some(pid), Some(start)) = (f.next(), f.next().and_then(|x| x.parse().ok()), f.next().and_then(|x| x.parse().ok())) {
                            let e = Entity::Process(ProcKey { pid, start });
                            push(Rel::Describes, e.clone(), self.entity_label(&e), String::new());
                        } else {
                            push(Rel::Describes, Entity::File(s.to_string()), s.to_string(), String::new());
                        }
                    }
                }
            }
            Entity::Host(_) => {
                for d in self.ir.det.store.items.iter().filter(|d| matches!(d.subject, Entity::Host(_))) {
                    push(Rel::DetectedBy, Entity::Rule(d.rule_id.clone()), format!("{} {}", d.rule_id, d.rule_name), d.subject_label.clone());
                }
            }
        }
        out
    }

    /// The entity behind whatever is selected on the current page.
    pub fn selected_entity(&self) -> Option<Entity> {
        match self.tab {
            // On an app group, start from its most suspicious member.
            Tab::Processes => self
                .selected_pid()
                .or_else(|| self.selected_group().and_then(|g| g.members.iter().copied().max_by_key(|p| self.tree.get(*p).map_or(0, |n| n.info.risk))))
                .map(|p| self.proc_entity(p)),
            Tab::Network if self.ir.net_hosts_view => {
                self.visible_remotes().get(self.ir.host_selected).map(|i| Entity::Endpoint(self.ir.remotes[*i].ip.clone()))
            }
            Tab::Network => self.conn_rows.get(self.conn_selected).map(|r| {
                let (ip, _) = crate::common::filter::split_endpoint(&r.conn.remote);
                if ip == "*" || r.conn.state == crate::network::ConnState::Listen { self.proc_entity(r.pid) } else { Entity::Endpoint(ip) }
            }),
            Tab::Files => self.selected_path().map(Entity::File).or_else(|| self.selected_file_pid().map(|p| self.proc_entity(p))),
            Tab::Persistence => self.selected_persist().map(|p| Entity::Persistence(format!("{}|{}|{}", p.category, p.name, p.location))),
            Tab::Timeline => {
                let e = &self.ir.timeline[*self.visible_timeline().get(self.ir.tl_selected)?];
                e.subject.clone().filter(|s| !matches!(s, Entity::Host(h) if h.is_empty())).or_else(|| e.pid.map(|p| self.proc_entity(p)))
            }
            Tab::Alerts if self.ir.det.focus => self.selected_detection().map(|d| d.subject.clone()),
            Tab::Alerts => self.selected_alert_pid().map(|p| self.proc_entity(p)),
            Tab::Logs if self.ir.artifacts_view => {
                let a = &self.ir.artifacts[*self.visible_artifacts().get(self.ir.art_selected)?];
                Some(Entity::File(a.subject.clone()))
            }
            Tab::Logs => {
                let e = &self.log_entries()[*self.visible_logs().get(self.ir.log_selected)?];
                e.pid.map(|p| self.proc_entity(p))
            }
            _ => self.detail_pid().map(|p| self.proc_entity(p)),
        }
    }

    pub fn open_graph(&mut self) {
        if !self.require("timeline") {
            return;
        }
        if self.ir.timeline_dirty {
            self.rebuild_timeline();
        }
        match self.selected_entity() {
            Some(e) => {
                self.ir.graph = GraphState { stack: vec![e], cursor: 0, offset: 0 };
                self.mode = Mode::Graph;
            }
            None => self.set_status(StatusLevel::Info, "Select a process, address, file, persistence entry or event first".into()),
        }
    }

    pub fn graph_current(&self) -> Option<&Entity> {
        self.ir.graph.stack.last()
    }

    pub fn graph_pivot(&mut self) {
        let Some(cur) = self.graph_current().cloned() else { return };
        if let Some(n) = self.neighbors(&cur).get(self.ir.graph.cursor) {
            self.ir.graph.stack.push(n.entity.clone());
            self.ir.graph.cursor = 0;
            self.ir.graph.offset = 0;
        }
    }

    pub fn graph_back(&mut self) {
        if self.ir.graph.stack.len() > 1 {
            let prev = self.ir.graph.stack.pop();
            let cur = self.graph_current().cloned();
            self.ir.graph.cursor = cur.map(|c| self.neighbors(&c).iter().position(|n| Some(&n.entity) == prev.as_ref()).unwrap_or(0)).unwrap_or(0);
        } else {
            self.mode = Mode::Normal;
        }
    }

    /// Timeline filtered to the current graph entity.
    pub fn graph_timeline(&mut self) {
        let Some(e) = self.graph_current().cloned() else { return };
        self.mode = Mode::Normal;
        self.switch_tab(Tab::Timeline);
        self.query = format!("entity:{}", crate::common::filter::quote(&e.key()));
        self.ir.tl_selected = 0;
        self.rebuild_timeline();
    }

    /// Jump to the page where the current graph entity lives.
    pub fn graph_goto(&mut self) {
        let Some(e) = self.graph_current().cloned() else { return };
        self.mode = Mode::Normal;
        match e {
            Entity::Process(k) if self.tree.get(k.pid).is_some() => self.focus_pid(k.pid),
            Entity::File(p) => self.analyze_file(&p),
            Entity::Endpoint(ip) => {
                self.switch_tab(Tab::Network);
                self.ir.net_hosts_view = true;
                self.query = format!("ip:{ip}");
            }
            Entity::Persistence(id) => {
                self.switch_tab(Tab::Persistence);
                self.query = format!("name:{}", crate::common::filter::quote(id.split('|').nth(1).unwrap_or("")));
            }
            Entity::Rule(r) => {
                self.switch_tab(Tab::Alerts);
                self.ir.det.focus = true;
                self.query = format!("rule:{r}");
            }
            _ => self.set_status(StatusLevel::Info, "Nothing to open for this item".into()),
        }
    }
}
