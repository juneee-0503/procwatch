//! Persistence scans, logs, artifacts and file analysis.

use super::*;

impl App {
    // ── persistence / logs ─────────────────────────────────────────────

    pub fn scan_persistence(&mut self) {
        if self.replaying() {
            self.set_status(StatusLevel::Info, "Not available while replaying a recording — this would act on the live system".into());
            return;
        }
        self.ir.persist_rescan_at = None;
        self.ir.persist_last_scan = Some(Instant::now());
        if self.ir.persistence.as_ref().is_some_and(|p| p.pending) {
            return;
        }
        let prev = self.ir.persistence.take().map(|p| p.result).unwrap_or(Err(String::new()));
        self.ir.persistence = Some(Loaded { pending: true, fetched: Instant::now(), result: prev });
        crate::engine::jobs::spawn_persistence(self.tx.clone(), self.ir.intel.snapshot());
    }

    /// Compare a fresh scan with the previous one; record what changed.
    /// Returns the number of changes.
    pub(crate) fn persistence_diff(&mut self, items: &[PersistItem]) -> usize {
        let key = |i: &PersistItem| format!("{}|{}|{}", i.category, i.name, i.location);
        let Some(prev) = self.ir.persist_prev.replace(items.to_vec()) else { return 0 };
        let old: HashMap<String, &PersistItem> = prev.iter().map(|i| (key(i), i)).collect();
        let new: HashMap<String, &PersistItem> = items.iter().map(|i| (key(i), i)).collect();
        let now = Local::now();
        let mut changes: Vec<(&'static str, PersistItem)> = Vec::new();
        for (k, i) in &new {
            match old.get(k) {
                None => changes.push(("added", (*i).clone())),
                Some(o) if o.command != i.command || o.target != i.target || o.sha256 != i.sha256 => changes.push(("changed", (*i).clone())),
                _ => {}
            }
        }
        for (k, i) in &old {
            if !new.contains_key(k) {
                changes.push(("removed", (*i).clone()));
            }
        }
        let n = changes.len();
        for (kind, it) in changes {
            // The writer: a deep-traced process that had the definition
            // file open around the change notification.
            let w = self.ir.persist_writers.iter().rev().find(|(p, _, _)| *p == it.location).cloned();
            let writer_key = w.as_ref().and_then(|x| x.2);
            let time = w.as_ref().map(|x| x.1).unwrap_or(now);
            let writer = writer_key.map(|k| format!("{} ({})", self.name_of(k.pid), k.pid));
            let change = PersistChange {
                time,
                kind,
                category: it.category.clone(),
                name: it.name.clone(),
                location: it.location.clone(),
                target: it.target.clone(),
                command: it.command.clone(),
                writer: writer.clone(),
                writer_key,
            };
            if let Some(st) = self.ir.store.as_mut() {
                st.write(time, crate::forensics::store::Rec::Persist { kind: kind.into(), category: it.category.clone(), name: it.name.clone(), location: it.location.clone(), target: it.target.clone(), writer: writer.clone() });
            }
            if kind != "removed" {
                let mut hit = crate::detection::triage::RuleHit::from_def(
                    crate::detection::triage::rule("PW-019").expect("rule"),
                    format!(
                        "{kind}: {} {} → {} · {}{}",
                        it.category,
                        it.name,
                        it.command,
                        writer.as_deref().map(|w| format!("written by {w}")).unwrap_or_else(|| "writer unknown (not deep-traced)".into()),
                        if it.flags.is_empty() { String::new() } else { format!(" · ⚑ {}", it.flags.join("; ")) }
                    ),
                );
                if it.flags.is_empty() && it.signature.as_deref().is_some_and(|s| s.starts_with("valid")) {
                    hit.severity = crate::common::model::Severity::Low;
                }
                let (subject, label, pid) = match writer_key {
                    Some(k) => (Entity::Process(k), format!("{} ({})", self.name_of(k.pid), k.pid), Some(k.pid)),
                    None => (Entity::Persistence(format!("{}|{}|{}", it.category, it.name, it.location)), format!("{}: {}", it.category, it.name), None),
                };
                self.record_detection_pub(&hit, subject, label, pid, "persistence");
            }
            if self.ir.persist_changes.len() >= 1000 {
                self.ir.persist_changes.pop_front();
            }
            self.ir.persist_changes.push_back(change);
        }
        self.ir.persist_writers.clear();
        self.ir.timeline_dirty = true;
        n
    }

    pub fn persist_items(&self) -> &[PersistItem] {
        match self.ir.persistence.as_ref().map(|p| &p.result) {
            Some(Ok(s)) => &s.items,
            _ => &[],
        }
    }

    pub fn visible_persistence(&self) -> Vec<usize> {
        let f = Filter::parse(&self.query);
        self.persist_items().iter().enumerate().filter(|(_, i)| f.matches(*i)).map(|(i, _)| i).collect()
    }

    pub fn selected_persist(&self) -> Option<&PersistItem> {
        let idx = *self.visible_persistence().get(self.ir.persist_selected)?;
        self.persist_items().get(idx)
    }

    pub fn fetch_logs(&mut self) {
        if self.replaying() {
            self.set_status(StatusLevel::Info, "Not available while replaying a recording — this would act on the live system".into());
            return;
        }
        if self.ir.logs.as_ref().is_some_and(|l| l.pending) {
            return;
        }
        let prev = self.ir.logs.take().map(|l| l.result).unwrap_or(Ok(Vec::new()));
        self.ir.logs = Some(Loaded { pending: true, fetched: Instant::now(), result: prev });
        crate::engine::jobs::spawn_logs(self.tx.clone(), self.ir.log_minutes, self.ir.log_scope);
    }

    pub fn log_entries(&self) -> &[logs::Entry] {
        match self.ir.logs.as_ref().map(|l| &l.result) {
            Some(Ok(v)) => v,
            _ => &[],
        }
    }

    pub fn visible_logs(&self) -> Vec<usize> {
        let f = Filter::parse(&self.query);
        self.log_entries().iter().enumerate().filter(|(_, e)| f.matches(*e)).map(|(i, _)| i).collect()
    }

    pub fn cycle_log_window(&mut self) {
        self.ir.log_minutes = match self.ir.log_minutes {
            5 => 15,
            15 => 60,
            60 => 240,
            240 => 1440,
            _ => 5,
        };
        self.fetch_logs();
    }

    pub fn toggle_log_scope(&mut self) {
        self.ir.log_scope = if self.ir.log_scope == Scope::Important { Scope::All } else { Scope::Important };
        self.fetch_logs();
    }

    // ── file changes / analysis ────────────────────────────────────────

    pub fn visible_fs_events(&self) -> Vec<usize> {
        let f = Filter::parse(&self.query);
        // Newest first.
        (0..self.ir.fs_events.len()).rev().filter(|i| f.matches(&self.ir.fs_events[*i])).collect()
    }

    pub fn analyze_file(&mut self, path: &str) {
        let path = path.trim().to_string();
        if path.is_empty() {
            return;
        }
        self.ir.file_report = Some(Loaded {
            pending: true,
            fetched: Instant::now(),
            result: Err(path.clone()),
        });
        self.mode = Mode::FileReport;
        self.ir.report_scroll = 0;
        crate::engine::jobs::spawn_file_report(self.tx.clone(), path);
    }

    /// Path of the item under the cursor on pages that show files.
    pub fn selected_path(&self) -> Option<String> {
        match self.tab {
            Tab::Files if self.ir.files_changes_view => {
                let i = *self.visible_fs_events().get(self.ir.fs_selected)?;
                Some(self.ir.fs_events[i].path.clone())
            }
            Tab::Files => {
                let idx = *self.visible_files().get(self.file_selected)?;
                let h = self.files.as_ref()?.result.as_ref().ok()?.get(idx)?;
                h.path.starts_with('/').then(|| h.path.clone()).or_else(|| (h.path.get(1..3) == Some(":\\")).then(|| h.path.clone()))
            }
            Tab::Persistence => self.selected_persist().and_then(|i| i.target.clone()),
            _ => self.selected_pid().and_then(|p| self.tree.get(p)).and_then(|n| n.info.exe_path.clone()),
        }
    }
}
