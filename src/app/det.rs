//! Detection engine glue for `App`: runs the host rules and Sigma rules
//! over live data, applies suppressions, keeps the detection store and
//! drives the Detect page. A child module of `app`.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Local};

use super::*;
use crate::detection::engine::{Detection, Facts};
use crate::files::watch::FsEvent;
use crate::common::model::{Confidence, Entity, ProcKey, Severity};
use crate::detection::sigma;
use crate::detection::triage::RuleHit;

fn sigma_hit(r: &sigma::Rule, ev: &sigma::Event) -> RuleHit {
    RuleHit {
        id: r.id.clone(),
        name: r.title.clone(),
        severity: r.level,
        confidence: r.confidence,
        technique: r.technique(),
        evidence: r.evidence(ev),
        suppressed: None,
    }
}

impl App {
    pub fn proc_key(&self, pid: u32) -> ProcKey {
        ProcKey { pid, start: self.tree.get(pid).map_or(0, |n| n.info.start_time_secs) }
    }

    /// Suppression check for a hit on a live process.
    fn suppression_for(&self, pid: Option<u32>, rule: &str, path_hint: &str) -> Option<String> {
        let list = &self.ir.det.suppressions;
        if list.is_empty() {
            return None;
        }
        let info = pid.and_then(|p| self.tree.get(p)).map(|n| &n.info);
        let path = info.and_then(|i| i.exe_path.as_deref()).unwrap_or(path_hint);
        let cmd = info.map(|i| i.cmd.join(" ")).unwrap_or_default();
        let team = self.ir.intel.get(path).and_then(|e| e.team.or(Some(e.signer).filter(|s| !s.is_empty()))).unwrap_or_default();
        let facts = Facts {
            name: info.map_or("", |i| i.name.as_str()),
            path,
            user: info.and_then(|i| i.user.as_deref()).unwrap_or(""),
            cmd: &cmd,
            team: &team,
        };
        crate::detection::engine::suppressed(list, rule, &facts)
    }

    fn record_detection(&mut self, hit: &RuleHit, subject: Entity, label: String, pid: Option<u32>, engine: &'static str, t: DateTime<Local>) {
        let d = Detection {
            rule_id: hit.id.clone(),
            rule_name: hit.name.clone(),
            engine,
            severity: hit.severity,
            confidence: hit.confidence,
            technique: hit.technique.clone(),
            subject,
            subject_label: label,
            pid,
            evidence: vec![hit.evidence.clone()],
            first_seen: t,
            last_seen: t,
            count: 1,
            suppressed: hit.suppressed.clone(),
            active: true,
        };
        let rec = crate::forensics::store::Rec::Detection {
            rule: d.rule_id.clone(),
            name: d.rule_name.clone(),
            severity: d.severity.label().into(),
            confidence: d.confidence.label().into(),
            technique: d.technique.clone(),
            subject: d.subject_label.clone(),
            pid: d.pid,
            evidence: d.evidence.join(" | "),
        };
        if self.ir.det.store.upsert(d) {
            if let Some(st) = self.ir.store.as_mut() {
                st.write(t, rec);
            }
            self.ir.timeline_dirty = true;
            if hit.suppressed.is_none() && hit.severity >= Severity::Medium {
                self.ir.det.unread += 1;
            }
        }
    }

    pub(super) fn record_detection_pub(&mut self, hit: &RuleHit, subject: Entity, label: String, pid: Option<u32>, engine: &'static str) {
        if !self.module_on("detection") {
            return;
        }
        let mut hit = hit.clone();
        if hit.suppressed.is_none() {
            let hint = if let Entity::File(p) = &subject { p.clone() } else { String::new() };
            hit.suppressed = self.suppression_for(pid, &hit.id, &hint);
        }
        self.record_detection(&hit, subject, label, pid, engine, Local::now());
    }

    fn label(&self, pid: u32) -> String {
        format!("{} ({pid})", self.name_of(pid))
    }

    /// Sigma `process_creation` rules, once per process instance (again
    /// once its executable hash is known, for hash-based rules).
    fn sigma_on_processes(&mut self, intel: &HashMap<String, crate::files::intel::ExeInfo>) {
        if self.ir.det.sigma.is_empty() {
            return;
        }
        let alive: HashSet<ProcKey> = self.tree.nodes.values().map(|n| ProcKey { pid: n.info.pid, start: n.info.start_time_secs }).collect();
        self.ir.det.sigma_seen.retain(|k, _| alive.contains(k));
        self.ir.det.sigma_hits.retain(|pid, (start, _)| alive.contains(&ProcKey { pid: *pid, start: *start }));
        let mut results: Vec<(u32, u64, Vec<RuleHit>)> = Vec::new();
        for (pid, n) in &self.tree.nodes {
            let key = ProcKey { pid: *pid, start: n.info.start_time_secs };
            let exe = n.info.exe_path.as_deref().and_then(|p| intel.get(p));
            let hashed = exe.is_some_and(|e| e.sha256.is_some());
            match self.ir.det.sigma_seen.get(&key) {
                Some(true) => continue,
                Some(false) if !hashed => continue,
                _ => {}
            }
            self.ir.det.sigma_seen.insert(key, hashed);
            if self.is_own_helper(&n.info) {
                continue;
            }
            let parent = n.info.ppid.and_then(|p| self.tree.get(p)).map(|p| &p.info);
            let ev = sigma::map::process(&n.info, parent, exe.and_then(|e| e.sha256.as_deref()), exe.and_then(|e| e.md5.as_deref()));
            let hits: Vec<RuleHit> = sigma::evaluate(&self.ir.det.sigma, &ev).into_iter().map(|r| sigma_hit(r, &ev)).collect();
            if !hits.is_empty() {
                results.push((*pid, key.start, hits));
            }
        }
        let t = Local::now();
        for (pid, start, mut hits) in results {
            for h in hits.iter_mut() {
                h.suppressed = self.suppression_for(Some(pid), &h.id, "");
                self.record_detection(h, Entity::Process(ProcKey { pid, start }), self.label(pid), Some(pid), "sigma", t);
            }
            let entry = self.ir.det.sigma_hits.entry(pid).or_insert((start, Vec::new()));
            for h in hits {
                if !entry.1.iter().any(|x| x.id == h.id) {
                    entry.1.push(h);
                }
            }
        }
    }

    /// Signature checks for new executables, then host rules for every
    /// process (cheap: no I/O, everything comes from caches).
    /// PW-020 needs the environment, which only an inspection reads.
    pub(super) fn check_preload(&mut self, pid: u32, start: u64, info: &crate::process::inspect::DeepInfo) {
        let Ok(env) = &info.environment else { return };
        let (Some(evidence), Some(def)) = (crate::detection::triage::preload_evidence(env), crate::detection::triage::rule("PW-020")) else { return };
        let hit = RuleHit::from_def(def, evidence);
        self.record_detection_pub(&hit, Entity::Process(ProcKey { pid, start }), self.label(pid), Some(pid), "inspection");
    }

    pub(super) fn triage_all(&mut self) {
        let mut lap = crate::common::perf::Lap::new();
        let mut paths: HashSet<&str> = HashSet::new();
        for n in self.tree.nodes.values() {
            if let Some(p) = n.info.exe_path.as_deref() {
                if paths.insert(p) {
                    self.ir.intel.request(p, false);
                }
            }
        }
        let intel = self.ir.intel.snapshot();
        lap.mark("triage: intel");
        self.sigma_on_processes(&intel);
        lap.mark("triage: sigma");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let empty = Vec::new();
        let mut scores: HashMap<u32, crate::detection::triage::Assessment> = HashMap::with_capacity(self.tree.nodes.len());
        let mut host_hits: Vec<(u32, u64, RuleHit)> = Vec::new();
        for (pid, n) in &self.tree.nodes {
            // Our own helper processes (codesign, lsof…) aren't suspects.
            if self.is_own_helper(&n.info) {
                scores.insert(*pid, Default::default());
                continue;
            }
            let parent = n.info.ppid.and_then(|p| self.tree.get(p)).map(|p| &p.info);
            let exe = n.info.exe_path.as_deref().and_then(|p| intel.get(p));
            let mut a = crate::detection::triage::assess(&n.info, parent, self.connections.get(pid).unwrap_or(&empty), exe, now);
            if let Some((ep, iv)) = self.ir.beacons.get(pid) {
                a.add_rule("PW-016", format!("reconnects to {ep} every ~{iv:.0} s"));
            }
            if let Some((_, hits)) = self.ir.det.sigma_hits.get(pid).filter(|(s, _)| *s == n.info.start_time_secs) {
                a.hits.extend(hits.iter().cloned());
            }
            if !self.ir.det.suppressions.is_empty() {
                for h in a.hits.iter_mut() {
                    h.suppressed = self.suppression_for(Some(*pid), &h.id, "");
                }
            }
            a.finish();
            host_hits.extend(a.hits.iter().filter(|h| h.id.starts_with("PW-")).map(|h| (*pid, n.info.start_time_secs, h.clone())));
            scores.insert(*pid, a);
        }
        lap.mark("triage: assess");
        let t = Local::now();
        let mut seen: HashSet<(String, String)> = HashSet::with_capacity(host_hits.len());
        for (pid, start, h) in host_hits {
            let subject = Entity::Process(ProcKey { pid, start });
            seen.insert((h.id.clone(), subject.key()));
            self.record_detection(&h, subject, self.label(pid), Some(pid), "host rule", t);
        }
        self.ir.det.store.settle("host rule", &seen);
        lap.mark("triage: record");
        for (pid, n) in self.tree.nodes.iter_mut() {
            n.info.risk = scores.get(pid).map_or(0, |a| a.score);
            n.info.signed = match n.info.exe_path.as_deref().and_then(|p| intel.get(p)).map(|e| e.sig) {
                Some(crate::files::intel::Sig::Signed) => 'y',
                Some(crate::files::intel::Sig::Unsigned) => 'n',
                Some(crate::files::intel::Sig::Invalid) => '!',
                _ => '?',
            };
        }
        self.ir.triage = scores;
    }

    /// Sigma `network_connection` rules for sockets that just appeared.
    pub(super) fn sigma_on_sockets(&mut self, opened: &[(u32, crate::network::Connection)]) {
        if !self.module_on("detection") {
            return;
        }
        if self.ir.det.sigma.is_empty() || opened.is_empty() {
            return;
        }
        let t = Local::now();
        for (pid, c) in opened {
            let Some(n) = self.tree.get(*pid) else { continue };
            if self.is_own_helper(&n.info) {
                continue;
            }
            let image = n.info.exe_path.clone().unwrap_or_else(|| n.info.name.clone());
            let listening = c.state == crate::network::ConnState::Listen;
            let ev = sigma::map::connection(&image, *pid, c.protocol, &c.local, &c.remote, listening);
            let hits: Vec<RuleHit> = sigma::evaluate(&self.ir.det.sigma, &ev).into_iter().map(|r| sigma_hit(r, &ev)).collect();
            let start = n.info.start_time_secs;
            for mut h in hits {
                h.suppressed = self.suppression_for(Some(*pid), &h.id, "");
                self.record_detection(&h, Entity::Process(ProcKey { pid: *pid, start }), self.label(*pid), Some(*pid), "sigma", t);
                let entry = self.ir.det.sigma_hits.entry(*pid).or_insert((start, Vec::new()));
                if !entry.1.iter().any(|x| x.id == h.id) {
                    entry.1.push(h);
                }
            }
        }
    }

    /// Sigma `file_*` rules for a file-change notification.
    pub(super) fn sigma_on_fs(&mut self, e: &FsEvent) {
        if !self.module_on("detection") {
            return;
        }
        if self.ir.det.sigma.is_empty() {
            return;
        }
        let ev = sigma::map::file(e.kind, &e.path);
        let hits: Vec<RuleHit> = sigma::evaluate(&self.ir.det.sigma, &ev).into_iter().map(|r| sigma_hit(r, &ev)).collect();
        for mut h in hits {
            h.suppressed = self.suppression_for(None, &h.id, &e.path);
            self.record_detection(&h, Entity::File(e.path.clone()), e.path.clone(), None, "sigma", e.time);
        }
    }

    /// Sigma rules over freshly loaded event-log entries.
    pub(super) fn sigma_on_logs(&mut self) {
        if !self.module_on("detection") {
            return;
        }
        if self.ir.det.sigma.is_empty() {
            return;
        }
        let host = self.host_name();
        let mut found: Vec<(RuleHit, Option<u32>, DateTime<Local>)> = Vec::new();
        for e in self.log_entries() {
            if e.source == "procwatch" {
                continue;
            }
            let ev = sigma::map::log_line(&e.source, &e.process, e.pid, &e.level, &e.message, e.event_id);
            for r in sigma::evaluate(&self.ir.det.sigma, &ev) {
                found.push((sigma_hit(r, &ev), e.pid, e.time));
            }
        }
        for (mut h, pid, t) in found {
            let live = pid.filter(|p| self.tree.get(*p).is_some());
            h.suppressed = self.suppression_for(live, &h.id, "");
            let (subject, label) = match live {
                Some(p) => (Entity::Process(self.proc_key(p)), self.label(p)),
                None => (Entity::Host(host.clone()), format!("{host} (event log)")),
            };
            self.record_detection(&h, subject, label, live, "sigma", t);
        }
    }

    /// Run Sigma over externally parsed records (EVTX, artifacts).
    pub(super) fn sigma_on_events(&mut self, events: &[(sigma::Event, DateTime<Local>, String)]) -> usize {
        if !self.module_on("detection") {
            return Default::default();
        }
        let host = self.host_name();
        let found: Vec<(RuleHit, DateTime<Local>, String, String)> = events
            .iter()
            .flat_map(|(ev, t, label)| {
                let image = ev.fields.get("Image").cloned().unwrap_or_default();
                sigma::evaluate(&self.ir.det.sigma, ev).into_iter().map(move |r| (sigma_hit(r, ev), *t, label.clone(), image.clone()))
            })
            .collect();
        let n = found.len();
        for (mut h, t, label, image) in found {
            h.suppressed = self.suppression_for(None, &h.id, &image);
            self.record_detection(&h, Entity::Host(host.clone()), label, None, "sigma", t);
        }
        n
    }

    /// IOC sweep hits become detections, so they share triage and reports.
    pub(super) fn record_ioc_hits(&mut self) {
        let Some(s) = &self.ir.sweep else { return };
        let hits = s.hits.clone();
        let t = s.at;
        for hit in hits {
            let confidence = match hit.kind {
                crate::detection::ioc::Kind::Md5 | crate::detection::ioc::Kind::Sha1 | crate::detection::ioc::Kind::Sha256 => Confidence::High,
                crate::detection::ioc::Kind::Ip | crate::detection::ioc::Kind::Domain | crate::detection::ioc::Kind::Path => Confidence::Medium,
                crate::detection::ioc::Kind::Text => Confidence::Low,
            };
            let rh = RuleHit {
                id: format!("IOC-{}", hit.kind.label().to_uppercase()),
                name: format!("Indicator match: {}", hit.ioc),
                severity: Severity::High,
                confidence,
                technique: String::new(),
                evidence: format!("{} in {}: {}", hit.ioc, hit.source, hit.detail),
                suppressed: None,
            };
            let live = hit.pid.filter(|p| self.tree.get(*p).is_some());
            let (subject, label) = match (live, hit.kind) {
                (Some(p), _) => (Entity::Process(self.proc_key(p)), self.label(p)),
                (None, crate::detection::ioc::Kind::Ip) => (Entity::Endpoint(hit.ioc.clone()), hit.ioc.clone()),
                (None, _) if hit.detail.starts_with('/') || hit.detail.contains(":\\") => (Entity::File(hit.detail.clone()), hit.detail.clone()),
                _ => (Entity::Host(self.host_name()), format!("{} ({})", hit.name, hit.source)),
            };
            self.record_detection(&rh, subject, label, live, "ioc", t);
        }
    }

    /// Scan the executables of every running process with the content
    /// rules (files on disk only).
    pub fn scan_executables(&mut self) {
        if !self.require("detection") {
            return;
        }
        if self.replaying() {
            self.set_status(StatusLevel::Info, "Not available while replaying a recording — this would act on the live system".into());
            return;
        }
        if self.ir.yara_pending {
            return;
        }
        // procwatch carries its own rules as text, so it would match them.
        let me = std::env::current_exe().ok().and_then(|p| std::fs::canonicalize(p).ok());
        let mut paths: Vec<String> = self
            .tree
            .nodes
            .values()
            .filter_map(|n| n.info.exe_path.clone())
            .filter(|p| me.as_ref().is_none_or(|m| std::fs::canonicalize(p).ok().as_ref() != Some(m)))
            .collect();
        paths.sort();
        paths.dedup();
        self.ir.yara_pending = true;
        self.set_status(StatusLevel::Info, format!("Scanning {} executables with content rules…", paths.len()));
        crate::engine::jobs::spawn_yara(self.tx.clone(), paths);
    }

    pub(super) fn record_yara(&mut self, results: Vec<(String, Vec<crate::files::yara::Match>)>) -> usize {
        let t = Local::now();
        let mut n = 0;
        for (path, matches) in results {
            let pids: Vec<u32> = self.tree.nodes.values().filter(|x| x.info.exe_path.as_deref() == Some(path.as_str())).map(|x| x.info.pid).collect();
            for m in matches {
                n += 1;
                let hit = RuleHit {
                    id: format!("YARA:{}", m.rule),
                    name: if m.description.is_empty() { m.rule.clone() } else { m.description.clone() },
                    severity: m.severity,
                    confidence: m.confidence,
                    technique: String::new(),
                    evidence: format!("{path}: {}", m.strings.iter().map(|(id, off, _)| format!("{id}@{off:#x}")).collect::<Vec<_>>().join(" ")),
                    suppressed: None,
                };
                if pids.is_empty() {
                    let mut h = hit.clone();
                    h.suppressed = self.suppression_for(None, &h.id, &path);
                    self.record_detection(&h, Entity::File(path.clone()), path.clone(), None, "yara", t);
                }
                for pid in &pids {
                    let mut h = hit.clone();
                    h.suppressed = self.suppression_for(Some(*pid), &h.id, "");
                    let key = self.proc_key(*pid);
                    self.record_detection(&h, Entity::Process(key), self.label(*pid), Some(*pid), "yara", t);
                    // Counts towards the process's priority like Sigma hits.
                    let entry = self.ir.det.sigma_hits.entry(*pid).or_insert((key.start, Vec::new()));
                    if !entry.1.iter().any(|x| x.id == h.id) {
                        entry.1.push(h);
                    }
                }
            }
        }
        n
    }

    pub fn host_name(&self) -> String {
        sysinfo::System::host_name().unwrap_or_else(|| "this host".into())
    }

    // ── Detect page ────────────────────────────────────────────────────

    pub fn visible_detections(&self) -> Vec<usize> {
        let f = crate::common::filter::Filter::parse(&self.query);
        let mut v: Vec<usize> = self
            .ir
            .det
            .store
            .items
            .iter()
            .enumerate()
            .filter(|(_, d)| self.ir.det.show_suppressed || d.suppressed.is_none())
            .filter(|(_, d)| f.matches(*d))
            .map(|(i, _)| i)
            .collect();
        let items = &self.ir.det.store.items;
        v.sort_by(|a, b| {
            let (x, y) = (&items[*a], &items[*b]);
            y.active
                .cmp(&x.active)
                .then(x.suppressed.is_some().cmp(&y.suppressed.is_some()))
                .then(y.severity.cmp(&x.severity))
                .then(y.confidence.cmp(&x.confidence))
                .then(y.last_seen.cmp(&x.last_seen))
        });
        v
    }

    pub fn selected_detection(&self) -> Option<&Detection> {
        self.visible_detections().get(self.ir.det.selected).map(|i| &self.ir.det.store.items[*i])
    }

    /// Open the suppression dialog for the selected detection, prefilled
    /// with a filter for its executable (or subject).
    pub fn request_suppress(&mut self) {
        let Some(d) = self.selected_detection() else { return };
        let filter = match (&d.subject, d.pid.and_then(|p| self.tree.get(p)).and_then(|n| n.info.exe_path.clone())) {
            (_, Some(path)) => format!("path:{}", crate::common::filter::quote(&path)),
            (Entity::File(p), _) => format!("path:{}", crate::common::filter::quote(p)),
            _ => format!("name:{}", crate::common::filter::quote(d.subject_label.split(" (").next().unwrap_or(""))),
        };
        let rule = d.rule_id.clone();
        self.mode = Mode::Input { purpose: InputPurpose::Suppress { rule }, input: format!("{filter} | "), error: None };
    }

    /// Trust the publisher of the selected detection's program: silences
    /// only weak signals (see `detect::TRUST_RULES`) for everything it signed.
    pub fn request_trust_publisher(&mut self) {
        let Some(d) = self.selected_detection() else { return };
        let exe = d.pid.and_then(|p| self.tree.get(p)).and_then(|n| n.info.exe_path.clone());
        let Some(info) = exe.as_deref().and_then(|e| self.ir.intel.get(e)) else {
            self.set_status(StatusLevel::Info, "No signature information for this program yet".into());
            return;
        };
        if info.sig != crate::files::intel::Sig::Signed {
            self.set_status(StatusLevel::Error, "Only validly signed programs can be trusted by publisher".into());
            return;
        }
        let who = info.team.clone().unwrap_or_else(|| info.signer.clone());
        let filter = format!("team:{}", crate::common::filter::quote(&who));
        let rule = crate::detection::engine::TRUST_RULES.to_string();
        self.mode = Mode::Input { purpose: InputPurpose::Suppress { rule }, input: format!("{filter} | trusted publisher {}", info.signer), error: None };
    }

    pub(super) fn add_suppression(&mut self, rule: String, input: String) {
        let (filter, reason) = match input.split_once('|') {
            Some((f, r)) => (f.trim().to_string(), r.trim().to_string()),
            None => (input.trim().to_string(), String::new()),
        };
        if filter.is_empty() {
            self.mode = Mode::Input {
                purpose: InputPurpose::Suppress { rule },
                input,
                error: Some("A filter is required (e.g. path:/Applications/Tool.app), so the rule stays on for everything else.".into()),
            };
            return;
        }
        if reason.is_empty() {
            self.mode = Mode::Input { purpose: InputPurpose::Suppress { rule }, input, error: Some("Say why, after the |: it goes into the case log.".into()) };
            return;
        }
        let s = crate::detection::engine::Suppression { rule: rule.clone(), filter: filter.clone(), reason: reason.clone() };
        match crate::detection::engine::append(&s) {
            Ok(p) => {
                self.ir.det.suppressions = crate::detection::engine::load();
                // Re-apply to what is already recorded.
                let list = self.ir.det.suppressions.clone();
                for d in self.ir.det.store.items.iter_mut().filter(|d| d.rule_id.eq_ignore_ascii_case(&rule) || rule == "*") {
                    let info = d.pid.and_then(|p| self.tree.get(p)).map(|n| &n.info);
                    let path = info.and_then(|i| i.exe_path.clone()).or_else(|| if let Entity::File(f) = &d.subject { Some(f.clone()) } else { None }).unwrap_or_default();
                    let cmd = info.map(|i| i.cmd.join(" ")).unwrap_or_default();
                    let name = info.map(|i| i.name.clone()).unwrap_or_else(|| d.subject_label.clone());
                    let user = info.and_then(|i| i.user.clone()).unwrap_or_default();
                    let facts = Facts { name: &name, path: &path, user: &user, cmd: &cmd, team: "" };
                    d.suppressed = crate::detection::engine::suppressed(&list, &d.rule_id, &facts);
                }
                self.ir.det.store.generation += 1;
                if let Some(c) = self.ir.case.as_ref() {
                    let _ = c.log("suppression added", &format!("{rule} | {filter} | {reason}"));
                }
                self.set_status(StatusLevel::Success, format!("Suppressed {rule} for {filter} — saved to {}", p.display()));
            }
            Err(e) => self.set_status(StatusLevel::Error, format!("Couldn't save suppression: {e}")),
        }
    }

    pub fn reload_detection_rules(&mut self) {
        self.ir.det.suppressions = crate::detection::engine::load();
        self.ir.det.reload_sigma();
        let msg = format!(
            "Rules reloaded: {} host rules, {} Sigma rules{}, {} suppressions",
            crate::detection::triage::RULES.len(),
            self.ir.det.sigma.len(),
            if self.ir.det.sigma_errors.is_empty() { String::new() } else { format!(" ({} rejected)", self.ir.det.sigma_errors.len()) },
            self.ir.det.suppressions.len()
        );
        self.set_status(StatusLevel::Info, msg);
        self.sigma_on_logs();
    }

    pub fn detection_to_finding(&mut self) {
        if !self.require("case") {
            return;
        }
        let Some(d) = self.selected_detection().cloned() else { return };
        let sev = match d.severity {
            Severity::Critical | Severity::High => "high",
            Severity::Medium => "medium",
            _ => "low",
        };
        let detail = format!(
            "{} · {} · confidence {} · {} · evidence: {}",
            d.rule_id,
            d.subject_label,
            d.confidence.label(),
            if d.technique.is_empty() { "no ATT&CK mapping".into() } else { d.technique.clone() },
            d.evidence.join(" | ")
        );
        let title = d.rule_name.clone();
        let Some(case) = self.ensure_case() else { return };
        let r = case.add_finding(sev, &title, "Detection", &detail);
        self.report_result(r, "Detection recorded as a finding");
    }
}

// ── collection health ──────────────────────────────────────────────────

impl App {
    /// What procwatch can and can't see right now.
    pub fn collection_health(&self) -> Vec<crate::engine::health::Source> {
        use crate::engine::health::{Source, Status};
        let mut v = Vec::new();
        let elevated = crate::engine::health::elevated();
        v.push(Source::new(
            "Privileges",
            if elevated { Status::Available } else { Status::Partial },
            if elevated { "running elevated (root / administrator)" } else { "running as a normal user: other users' process details, some logs and artifacts are hidden" },
        ));
        let total = self.tree.nodes.len();
        let no_path = self.tree.nodes.values().filter(|n| n.info.exe_path.is_none()).count();
        let no_cmd = self.tree.nodes.values().filter(|n| n.info.cmd.is_empty()).count();
        v.push(Source::new(
            "Process metadata",
            if no_path == 0 { Status::Available } else { Status::Partial },
            format!("{total} processes; {no_path} without an executable path, {no_cmd} without a command line (protected or kernel processes)"),
        ));
        let secs = self.ctl.interval_ms.load(Ordering::Relaxed) as f64 / 1000.0;
        v.push(Source::new(
            "Process start/exit events",
            Status::Partial,
            format!("sampled every {secs:.1} s since procwatch started: processes that live shorter than that may never be seen"),
        ));
        let sockets: usize = self.connections.values().map(Vec::len).sum();
        v.push(Source::new(
            "Network connections",
            if sockets == 0 { Status::Missing } else { Status::Partial },
            format!("{sockets} sockets now; sampled, so short connections can be missed; DNS names come from reverse lookups, not captured queries"),
        ));
        let pending = self.ir.intel.pending();
        let intel = self.ir.intel.snapshot();
        let unknown = intel.values().filter(|e| e.sig == crate::files::intel::Sig::Unknown).count();
        v.push(Source::new(
            "Code signatures & hashes",
            if pending == 0 && unknown == 0 { Status::Available } else { Status::Partial },
            format!("{} executables checked, {pending} queued, {unknown} unreadable or unknown", intel.len()),
        ));
        v.push(Source::new(
            "File changes",
            if self.ir.watch_errors.is_empty() { Status::Partial } else { Status::Denied },
            if self.ir.watch_errors.is_empty() {
                let dropped = match crate::files::watch::dropped() {
                    0 => String::new(),
                    n => format!("; {n} events dropped during bursts"),
                };
                format!("{} watched folders; changes elsewhere aren't seen, and events carry no process{dropped}", self.ir.watch_paths.len())
            } else {
                format!("couldn't watch: {}", self.ir.watch_errors.join("; "))
            },
        ));
        v.push(match (self.ir.capture_method, &self.ir.capture_error) {
            (Some(m), _) => Source::new("Process activity", Status::Available, format!("{m}; {} events dropped under load", crate::activity::dropped())),
            (None, Some(e)) => Source::new("Process activity", Status::Denied, e.clone()),
            (None, None) => Source::new("Process activity", Status::NotLoaded, "not capturing: start it on the Activity page"),
        });
        v.push(match (self.ir.traffic_how, &self.ir.traffic_error) {
            (Some(m), _) => Source::new("Per-process traffic", Status::Available, m),
            (None, Some(e)) => Source::new("Per-process traffic", Status::Denied, e.clone()),
            (None, None) => Source::new("Per-process traffic", Status::NotLoaded, "starting"),
        });
        v.push(match &self.ir.persistence {
            None => Source::new("Persistence", Status::NotLoaded, "open the Persistence page to scan"),
            Some(l) if l.pending => Source::new("Persistence", Status::NotLoaded, "scanning…"),
            Some(l) => match &l.result {
                Ok(s) if s.notes.is_empty() => Source::new("Persistence", Status::Available, format!("{} entries", s.items.len())),
                Ok(s) => Source::new("Persistence", Status::Partial, format!("{} entries; {}", s.items.len(), s.notes.join("; "))),
                Err(e) => Source::new("Persistence", Status::Denied, e.clone()),
            },
        });
        v.push(match &self.ir.logs {
            None => Source::new("Event logs", Status::NotLoaded, "open the Logs page to read"),
            Some(l) if l.pending => Source::new("Event logs", Status::NotLoaded, "reading…"),
            Some(l) => match &l.result {
                Err(e) => Source::new("Event logs", Status::Denied, e.clone()),
                Ok(entries) => {
                    let problems: Vec<&str> = entries.iter().filter(|e| e.source == "procwatch").map(|e| e.message.as_str()).collect();
                    let window = format!("last {} min, {} entries", self.ir.log_minutes, entries.len() - problems.len());
                    if problems.is_empty() {
                        Source::new("Event logs", Status::Available, window)
                    } else {
                        Source::new("Event logs", Status::Partial, format!("{window}; {}", problems.join("; ")))
                    }
                }
            },
        });
        v.push(match &self.ir.artifacts_live {
            None => Source::new("Execution artifacts", Status::NotLoaded, "open Logs → x (artifacts) to collect"),
            Some(l) if l.pending => Source::new("Execution artifacts", Status::NotLoaded, "collecting…"),
            Some(l) => {
                let notes = l.result.as_ref().map(|n| n.join("; ")).unwrap_or_default();
                let n = self.ir.artifacts.len();
                if notes.is_empty() {
                    Source::new("Execution artifacts", Status::Available, format!("{n} items"))
                } else {
                    Source::new("Execution artifacts", Status::Partial, format!("{n} items; {notes}"))
                }
            }
        });
        let enrolled = self.ir.deep.enrolled.len();
        let live = self.ir.deep.enrolled.values().filter(|e| e.ended.is_none()).count();
        v.push(Source::new(
            "Deep trace",
            if enrolled > 0 { Status::Available } else { Status::NotLoaded },
            match self.ir.deep.traced {
                true => format!(
                    "{} · {live} live / {enrolled} traced instances · {} lifecycle events{} · modules every 20 s, open files every 3 s",
                    crate::process::deeptrace::method(),
                    self.ir.deep.events.len(),
                    if self.ir.deep.dropped > 0 { format!(", {} older events dropped (buffer full)", self.ir.deep.dropped) } else { String::new() }
                ),
                false => format!("idle — starts automatically for priority ≥ {} or with D on a process", super::deep::AUTO_PRIORITY),
            },
        ));
        v.push(if self.ir.dns_obs.is_empty() {
            Source::new(
                "DNS queries",
                Status::NotUsed,
                "no per-process DNS records: host names come from reverse lookups (Windows: install Sysmon and read logs, or import EVTX with event 22)",
            )
        } else {
            Source::new("DNS queries", Status::Available, format!("{} queries with the querying process (Sysmon 22), matched to connections by answer address", self.ir.dns_obs.len()))
        });
        v.push(match (crate::files::attribution::unavailable_reason(), self.ir.deep.attribution.as_str()) {
            (Some(why), _) => Source::new("File attribution", Status::Partial, format!("file changes carry no process: {why}; deep trace infers it from open-file snapshots")),
            (None, "") => Source::new("File attribution", Status::NotLoaded, "ready — starts with deep trace (macOS fs_usage) / at launch (Linux fanotify)"),
            (None, how) if how.contains("unavailable") => Source::new("File attribution", Status::Denied, how.to_string()),
            (None, how) => Source::new("File attribution", Status::Available, how.to_string()),
        });
        v.push(match (&self.ir.store, &self.ir.replay) {
            (_, Some(r)) => Source::new("Event history", Status::Available, format!("replaying a recording: {r}")),
            (Some(st), None) => Source::new(
                "Event history",
                if st.error.is_some() { Status::Denied } else { Status::Available },
                match &st.error {
                    Some(e) => format!("can't write: {e}"),
                    None => format!("recording to {} ({} MB on disk, kept {} days / {} MB)", st.dir().display(), st.total_bytes() >> 20, crate::forensics::store::MAX_DAYS, crate::forensics::store::MAX_BYTES >> 20),
                },
            ),
            (None, None) => Source::new("Event history", Status::NotUsed, "off (history = off in the settings file): only in-memory buffers, capped"),
        });
        // Sigma rules whose log source no live collector produces.
        let live: &[&str] = &["process_creation", "network_connection", "file_event", "file_change", "file_delete", "file_rename", ""];
        let blind: Vec<String> = self
            .ir
            .det
            .sigma
            .iter()
            .filter(|r| r.logsource.category.as_deref().is_some_and(|c| !live.contains(&c)) && r.logsource.product.as_deref().is_none_or(|p| p == crate::detection::sigma::product()))
            .map(|r| r.logsource.category.clone().unwrap_or_default())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        v.push(Source::new(
            "Detection rules",
            if self.ir.det.sigma_errors.is_empty() && blind.is_empty() { Status::Available } else { Status::Partial },
            format!(
                "{} host rules, {} Sigma rules{}{}; {} suppressions",
                crate::detection::triage::RULES.len(),
                self.ir.det.sigma.len(),
                if self.ir.det.sigma_errors.is_empty() { String::new() } else { format!(", {} rejected", self.ir.det.sigma_errors.len()) },
                if blind.is_empty() { String::new() } else { format!("; live data has no {} events (those rules only apply to imported logs)", blind.join("/")) },
                self.ir.det.suppressions.len()
            ),
        ));
        v.extend(crate::engine::health::platform());
        v
    }
}
