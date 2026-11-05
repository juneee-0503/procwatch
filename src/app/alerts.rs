//! Alert rules, call stacks, file lists and the baseline.

use super::*;

impl App {
    /// Send a request to a module; false if it isn't there to receive it.
    pub(crate) fn publish_to<T: std::any::Any + Send + Sync>(&self, module: &str, topic: &'static str, payload: T) -> bool {
        let Some(k) = &self.kernel else { return false };
        if !k.status().iter().any(|s| s.name == module && s.state == crate::kernel::ModuleState::Running) {
            return false;
        }
        k.bus().publish(topic, "app", std::sync::Arc::new(payload));
        true
    }

    /// Turn a module on or off, and remember the choice.
    pub fn toggle_module(&mut self, name: &str) {
        let Some(k) = self.kernel.clone() else { return };
        let enable = k.status().iter().find(|s| s.name == name).is_none_or(|s| s.state == crate::kernel::ModuleState::Disabled || s.state == crate::kernel::ModuleState::Failed);
        k.set_enabled(name, enable);
        if let Err(e) = crate::engine::save_config(&k.config()) {
            self.set_status(StatusLevel::Error, format!("Couldn't save modules.conf: {e}"));
        }
    }

    // ── alerts ─────────────────────────────────────────────────────────

    pub(crate) fn add_alerts(&mut self, fired: Vec<Alert>) {
        if fired.is_empty() {
            return;
        }
        if self.notify {
            let body = match fired.as_slice() {
                [one] => format!("{} ({}): {}", one.name, one.pid, one.message),
                many => format!("{} alerts — first: {} {}", many.len(), many[0].name, many[0].message),
            };
            crate::common::desktop::notify("procwatch alert", &body);
        }
        if self.tab != Tab::Alerts {
            self.unread_alerts += fired.len();
        }
        let first = &fired[0];
        self.set_status(StatusLevel::Error, format!("Alert: {} ({}) — {}", first.name, first.pid, first.message));
        for a in fired {
            if self.alerts.len() >= 1000 {
                self.alerts.pop_back();
            }
            self.alerts.push_front(a);
            if self.alert_selected > 0 {
                self.alert_selected += 1;
            }
        }
    }

    pub fn add_rule(&mut self, text: &str) -> Result<(), String> {
        let rule = Rule::parse(text)?;
        if self.rules.iter().any(|r| r.text == rule.text) {
            return Err("that rule already exists".into());
        }
        self.set_status(StatusLevel::Success, format!("Rule added: alert when {}", rule.describe()));
        self.rules.push(rule);
        self.rule_selected = self.rules.len() - 1;
        self.save_config();
        Ok(())
    }

    pub fn delete_rule(&mut self) {
        if self.rule_selected < self.rules.len() {
            let r = self.rules.remove(self.rule_selected);
            self.engine.rules_changed();
            self.rule_selected = self.rule_selected.min(self.rules.len().saturating_sub(1));
            self.set_status(StatusLevel::Info, format!("Rule removed: {}", r.text));
            self.save_config();
        }
    }

    pub fn toggle_rule(&mut self) {
        if let Some(r) = self.rules.get_mut(self.rule_selected) {
            r.enabled = !r.enabled;
        }
    }

    // ── call stacks / files / alert filtering ─────────────────────────

    /// Sample call stacks of the shown process (takes about a second).
    pub fn request_stack(&mut self, force: bool) -> bool {
        let Some(pid) = self.detail_pid() else { return false };
        if self.stack_pending.is_some() || (!force && self.stacks.contains_key(&pid)) {
            return false;
        }
        let Some(node) = self.tree.get(pid) else { return false };
        self.stack_pending = Some(pid);
        crate::engine::jobs::spawn_stack(self.tx.clone(), pid, node.info.start_time_secs);
        true
    }

    pub fn refresh_files(&mut self) {
        if self.replaying() {
            self.set_status(StatusLevel::Info, "Not available while replaying a recording — this would act on the live system".into());
            return;
        }
        if self.files.as_ref().is_some_and(|f| f.pending) {
            return;
        }
        let previous = self.files.take().map(|f| f.result).unwrap_or(Ok(Vec::new()));
        self.files = Some(FileList { pending: true, fetched: Instant::now(), result: previous });
        crate::engine::jobs::spawn_file_list(self.tx.clone());
    }

    pub fn visible_files(&self) -> Vec<usize> {
        let Some(Ok(hits)) = self.files.as_ref().map(|f| &f.result) else { return Vec::new() };
        let f = Filter::parse(&self.query);
        hits.iter().enumerate().filter(|(_, h)| f.matches(*h)).map(|(i, _)| i).collect()
    }

    pub fn selected_file_pid(&self) -> Option<u32> {
        let idx = *self.visible_files().get(self.file_selected)?;
        self.files.as_ref()?.result.as_ref().ok()?.get(idx).map(|h| h.pid)
    }

    pub fn visible_alerts(&self) -> Vec<usize> {
        let f = Filter::parse(&self.query);
        self.alerts.iter().enumerate().filter(|(_, a)| f.matches(*a)).map(|(i, _)| i).collect()
    }

    pub fn selected_alert_pid(&self) -> Option<u32> {
        let idx = *self.visible_alerts().get(self.alert_selected)?;
        self.alerts.get(idx).map(|a| a.pid)
    }

    // ── baseline ───────────────────────────────────────────────────────

    /// Ask before replacing an existing baseline; save right away otherwise.
    pub fn request_save_baseline(&mut self) {
        if self.baseline.is_some() {
            self.mode = Mode::Confirm { cmd: Cmd::SaveBaseline, targets: Vec::new() };
        } else {
            self.save_baseline();
        }
    }

    pub fn save_baseline(&mut self) {
        self.mode = Mode::Normal;
        if !self.loaded {
            return;
        }
        let Some(path) = baseline::default_path() else {
            self.set_status(StatusLevel::Error, "No settings directory to save the baseline in".into());
            return;
        };
        let base = Baseline::capture(&self.tree, &self.connections);
        match base.save(&path) {
            Ok(()) => {
                self.set_status(
                    StatusLevel::Success,
                    format!("Baseline saved: {} programs, {} listening ports", base.programs.len(), base.listeners.len()),
                );
                self.baseline = Some(base);
                self.changes.clear();
                self.change_selected = 0;
            }
            Err(e) => self.set_status(StatusLevel::Error, format!("Couldn't save baseline: {e}")),
        }
    }

    /// Indices of changes passing the search.
    pub fn visible_changes(&self) -> Vec<usize> {
        let f = Filter::parse(&self.query);
        self.changes
            .iter()
            .enumerate()
            .filter(|(_, c)| f.matches(*c))
            .map(|(i, _)| i)
            .collect()
    }

    /// New programs and ports since the baseline (for the tab badge).
    pub fn new_change_count(&self) -> usize {
        self.changes.iter().filter(|c| matches!(c.kind, ChangeKind::NewProgram | ChangeKind::NewListener)).count()
    }

    /// Jump to a running process behind the selected change.
    pub fn open_change(&mut self) {
        let Some(c) = self.visible_changes().get(self.change_selected).and_then(|i| self.changes.get(*i)).cloned() else { return };
        let pid = self
            .tree
            .nodes
            .values()
            .filter(|n| n.info.name == c.name && (c.user.is_none() || n.info.user == c.user))
            .map(|n| n.info.pid)
            .min();
        match pid {
            Some(pid) => self.focus_pid(pid),
            None => self.set_status(StatusLevel::Info, format!("{} isn't running now", c.name)),
        }
    }
}
