//! Activity capture and per-process traffic: starting, receiving, filtering, saving.

use super::*;

/// Findings kept for the Defense page.
const MAX_THREATS: usize = 5000;
const MAX_INCIDENTS: usize = 200;

impl App {
    pub(crate) fn on_threat(&mut self, t: crate::defense::Threat) {
        use crate::common::model::Severity;
        if t.severity >= Severity::High {
            let alert = crate::detection::rules::Alert { at: t.time, rule: t.rule.to_string(), pid: t.pid.unwrap_or(0), name: t.source.map_or_else(|| "this host".to_string(), |s| s.to_string()), message: t.title.clone() };
            self.add_alerts(vec![alert]);
        }
        self.ir.threats.push_back(t);
        self.ir.threat_seq += 1;
        if self.ir.threats.len() > MAX_THREATS {
            self.ir.threats.pop_front();
        }
        self.ir.timeline_dirty = true;
    }

    pub(crate) fn on_incident(&mut self, i: crate::defense::chain::Incident) {
        self.ir.incidents.retain(|x| x.id != i.id);
        self.ir.incidents.insert(0, i);
        self.ir.incidents.truncate(MAX_INCIDENTS);
    }

    /// Threats matching the filter, newest first, as indexes.
    pub fn visible_threats(&self) -> Vec<usize> {
        let q = self.query.to_lowercase();
        self.ir
            .threats
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, t)| q.is_empty() || t.title.to_lowercase().contains(&q) || t.rule.contains(&q) || t.stage.label() == q || t.severity.label() == q || t.source.is_some_and(|s| s.to_string().contains(&q)))
            .map(|(i, _)| i)
            .collect()
    }

    pub fn selected_threat(&self) -> Option<&crate::defense::Threat> {
        self.visible_threats().get(self.ir.th_selected).and_then(|i| self.ir.threats.get(*i))
    }

    /// Stacks from captured events, where the system can't sample them:
    /// what this process was doing when it last touched a file or a key.
    pub fn captured_stacks(&self, pid: u32) -> Option<Vec<String>> {
        let mut lines = Vec::new();
        for a in self.ir.activity.iter().rev().filter(|a| a.pid == pid).filter(|a| a.stack.is_some()).take(20) {
            lines.push(format!("{} {} {} {}", a.time.format("%H:%M:%S%.3f"), a.class.label(), a.op, a.path));
            lines.extend(a.stack.iter().flat_map(|s| s.iter()).map(|f| format!("    {f}")));
            lines.push(String::new());
        }
        (!lines.is_empty()).then_some(lines)
    }

    /// Ask the activity module to start or stop capturing.
    pub fn toggle_capture(&mut self) {
        use crate::activity::module::{Command, COMMAND};
        let command = if self.ir.capture_method.is_some() { Command::Stop } else { Command::Start };
        if !self.publish_to("activity", COMMAND, command) {
            self.ir.capture_error = Some("the activity module isn't running".into());
            self.set_status(StatusLevel::Error, "Activity capture: the activity module isn't running".into());
        }
    }

    /// For callers waiting on the module to come up.
    pub fn publish_capture_start(&self) -> bool {
        use crate::activity::module::{Command, COMMAND};
        self.publish_to("activity", COMMAND, Command::Start)
    }

    pub(crate) fn on_capture_state(&mut self, state: crate::activity::module::State) {
        match state {
            Ok(Some(m)) => {
                self.ir.capture_method = Some(m);
                self.ir.capture_error = None;
                self.ir.capture_filter = crate::activity::filter::CaptureConfig::load().unwrap_or_default();
                self.set_status(StatusLevel::Success, format!("Capturing activity: {m}"));
            }
            Ok(None) => {
                self.ir.capture_method = None;
                self.set_status(StatusLevel::Info, "Activity capture stopped".into());
            }
            Err(e) => {
                self.ir.capture_method = None;
                self.set_status(StatusLevel::Error, format!("Activity capture: {e}"));
                self.ir.capture_error = Some(e);
            }
        }
    }

    pub fn clear_activity(&mut self) {
        self.ir.ac_base += self.ir.activity.len() as u64;
        self.ir.activity.clear();
        self.ir.ac_view.clear();
        self.ir.ac_selected = 0;
        self.ir.ac_offset = 0;
    }

    /// The filtered view as of the last refresh.
    pub fn visible_activity(&self) -> &[u64] {
        &self.ir.ac_view
    }

    /// An operation by sequence number; None once it has aged out.
    pub fn activity_at(&self, seq: u64) -> Option<&crate::activity::Activity> {
        self.ir.activity.get(usize::try_from(seq.checked_sub(self.ir.ac_base)?).ok()?)
    }

    /// Rebuild the filtered view: at once when the filter changed, otherwise
    /// taking at most about 5% of the UI thread.
    pub fn refresh_activity_view(&mut self) {
        let changed = self.query != self.ir.ac_view_query;
        let due = self.ir.ac_view_at.is_none_or(|(at, cost)| at.elapsed() >= (cost * 20).max(std::time::Duration::from_millis(200)));
        if !changed && !(self.ir.ac_view_dirty && due) {
            return;
        }
        let began = Instant::now();
        let f = Filter::parse(&self.query);
        let base = self.ir.ac_base;
        self.ir.ac_view = self.ir.activity.iter().enumerate().rev().filter(|(_, e)| f.matches(*e)).map(|(i, _)| base + i as u64).collect();
        self.ir.ac_view_query.clone_from(&self.query);
        self.ir.ac_view_dirty = false;
        self.ir.ac_view_at = Some((Instant::now(), began.elapsed()));
    }

    pub(crate) fn on_activity(&mut self, batch: Vec<crate::activity::Activity>) {
        use crate::activity::Class;
        let tree = &self.tree;
        self.ir.activity_names.retain(|pid, _| tree.nodes.contains_key(pid));
        for mut a in batch {
            let name = match self.ir.activity_names.get(&a.pid) {
                Some(n) => n.clone(),
                None => {
                    let n: Arc<str> = Arc::from(self.name_of(a.pid));
                    self.ir.activity_names.insert(a.pid, n.clone());
                    n
                }
            };
            a.name = name;
            // Rules about processes wait until the name is known.
            if self.ir.capture_filter.verdict(a.class, a.op, &a.path, Some(&a.name)) == crate::activity::filter::Verdict::Drop {
                continue;
            }
            // A write to an autostart key, with the process that did it.
            if a.class == Class::Registry && a.op != "delete key" && crate::activity::is_autostart_key(&a.path) {
                if let Some(def) = crate::detection::triage::rule("PW-022") {
                    let hit = crate::detection::triage::RuleHit::from_def(def, format!("{} {}", a.op, a.path));
                    self.record_detection_pub(&hit, Entity::Process(self.proc_key(a.pid)), format!("{} ({})", a.name, a.pid), Some(a.pid), "activity");
                }
            }
            // Traced processes' file changes join the timeline, attributed.
            if a.class == Class::File && self.ir.deep.is_enrolled(a.pid) {
                let kind = match a.op {
                    "create" => Some("created"),
                    "write" | "close after write" => Some("modified"),
                    "delete" => Some("deleted"),
                    "rename" | "rename to" => Some("renamed"),
                    _ => None,
                };
                if let Some(kind) = kind {
                    self.ir_on_msg(WorkerMsg::Fs(FsEvent { time: a.time, kind, path: a.path.clone(), pid: Some(a.pid) }));
                }
            }
            if let Some(out) = self.ir.activity_out.as_mut() {
                out.push(a.clone());
            }
            if self.ir.activity.len() >= MAX_ACTIVITY {
                self.ir.activity.pop_front();
                self.ir.ac_base += 1;
            }
            self.ir.activity.push_back(a);
            self.ir.ac_view_dirty = true;
        }
    }

    pub(crate) fn on_traffic(&mut self, totals: crate::network::traffic::Totals) {
        let now = Instant::now();
        for (pid, (rx, tx)) in totals {
            let e = self.ir.traffic_rates.entry(pid).or_insert(TrafficRate { rx, tx, at: now, rx_rate: 0.0, tx_rate: 0.0 });
            let secs = now.duration_since(e.at).as_secs_f64();
            if secs > 0.0 {
                e.rx_rate = rx.saturating_sub(e.rx) as f64 / secs;
                e.tx_rate = tx.saturating_sub(e.tx) as f64 / secs;
            }
            (e.rx, e.tx, e.at) = (rx, tx, now);
        }
        let tree = &self.tree;
        self.ir.traffic_rates.retain(|pid, _| tree.nodes.contains_key(pid));
    }

    /// New operations as ECS lines, for `--monitor --activity`.
    pub fn take_activity_lines(&mut self) -> Vec<String> {
        let host = sysinfo::System::host_name().unwrap_or_default();
        let items = self.ir.activity_out.as_mut().map(std::mem::take).unwrap_or_default();
        items.iter().map(|a| activity_line(a, &host)).collect()
    }

    /// Top entries of the shown operations: (title, [(count, bytes, name)]).
    pub fn activity_summary(&self) -> Vec<SummaryGroup> {
        const TOP: usize = 8;
        let shown = || self.visible_activity().iter().filter_map(|s| self.activity_at(*s));
        let rank = |key: &dyn Fn(&crate::activity::Activity) -> String| -> Vec<(u64, u64, String)> {
            let mut m: HashMap<String, (u64, u64)> = HashMap::new();
            for a in shown() {
                let e = m.entry(key(a)).or_default();
                e.0 += u64::from(a.count);
                e.1 += a.bytes;
            }
            let mut v: Vec<(u64, u64, String)> = m.into_iter().map(|(k, (c, b))| (c, b, k)).collect();
            v.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)).then(a.2.cmp(&b.2)));
            v.truncate(TOP);
            v
        };
        vec![
            ("Busiest processes", rank(&|a| format!("{} ({})", a.name, a.pid))),
            ("Operations", rank(&|a| format!("{} {}", a.class.label(), a.op))),
            ("Most touched targets", rank(&|a| a.path.clone())),
        ]
    }

    /// The captured operations, as evidence in the case.
    pub fn save_activity(&mut self) {
        if self.ir.activity.is_empty() {
            self.set_status(StatusLevel::Info, "Nothing captured to save".into());
            return;
        }
        let host = sysinfo::System::host_name().unwrap_or_default();
        let text: String = self.ir.activity.iter().map(|a| activity_line(a, &host) + "\n").collect();
        let (n, dropped) = (self.ir.activity.len(), crate::activity::dropped());
        let mut prov = crate::forensics::case::Provenance::live(self.ir.capture_method.unwrap_or("procwatch activity capture"));
        if dropped > 0 {
            prov.problems.push(format!("{dropped} events were dropped during capture"));
        }
        let Some(case) = self.ensure_case() else { return };
        match case.add_text_with("activity.jsonl", &text, prov) {
            Ok((_, item)) => self.set_status(StatusLevel::Success, format!("{n} operations saved as {}", item.id)),
            Err(e) => self.set_status(StatusLevel::Error, format!("Couldn't save activity: {e}")),
        }
    }
}
