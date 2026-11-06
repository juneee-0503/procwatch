//! The action menu.

use super::*;

impl App {
    // ── action menu ────────────────────────────────────────────────────

    pub fn open_action_menu(&mut self, anchor: (u16, u16)) {
        let targets = self.targets();
        if targets.is_empty() {
            return;
        }
        let single = targets.len() == 1;
        let info = single.then(|| self.tree.get(targets[0]).map(|n| n.info.clone())).flatten();
        let any_stopped = targets.iter().any(|p| {
            self.tree.get(*p).is_some_and(|n| n.info.status == sysinfo::ProcessStatus::Stop)
        });
        let has_children = targets.iter().any(|p| self.tree.get(*p).is_some_and(|n| !n.children.is_empty()));
        let cur_nice = info.as_ref().and_then(|i| i.nice);

        let level = |label: &str, nice: i32| {
            MenuItem::new(label, "", Cmd::Priority(nice)).checked(cur_nice.is_some_and(|n| {
                let lvl = |n: i32| match n {
                    ..=-15 => 0,
                    -14..=-5 => 1,
                    -4..=4 => 2,
                    5..=14 => 3,
                    _ => 4,
                };
                lvl(n) == lvl(nice)
            }))
        };
        let priority = vec![
            level("Very high", -20),
            level("High", -10),
            level("Normal", 0),
            level("Low", 10),
            level("Very low", 19),
        ];
        let signals: Vec<MenuItem> =
            Sig::available().iter().map(|s| MenuItem::new(s.label().trim().to_string(), "", Cmd::Signal(*s))).collect();
        let copy = vec![
            MenuItem::new("PID", "", Cmd::CopyPid),
            MenuItem::new("Name", "", Cmd::CopyName),
            MenuItem::new("Executable path", "", Cmd::CopyPath).enabled(info.as_ref().is_some_and(|i| i.exe_path.is_some())),
            MenuItem::new("Command line", "", Cmd::CopyCommand).enabled(info.as_ref().is_some_and(|i| !i.cmd.is_empty())),
        ];
        let is_tagged = single && self.tagged.contains(&targets[0]);

        let (trace_on, case_on) = (self.module_on("trace"), self.module_on("case"));
        let mut items = vec![
            MenuItem::new("Show details", "i", Cmd::Details).enabled(single),
            MenuItem::new("Trace behavior", "T", Cmd::Trace).enabled(single && trace_on),
            MenuItem::separator(),
            MenuItem::new("End process", "del", Cmd::End),
            MenuItem::new("Force quit", "X", Cmd::ForceQuit),
            MenuItem::new("End process tree", "", Cmd::EndTree).enabled(has_children),
            if any_stopped {
                MenuItem::new("Resume", "", Cmd::Resume)
            } else {
                MenuItem::new("Suspend", "", Cmd::Suspend)
            },
            MenuItem::new("Priority", "▸", Cmd::Sub(priority)),
        ];
        if cfg!(unix) {
            items.push(MenuItem::new("Send signal", "▸", Cmd::Sub(signals)));
        }
        items.extend([
            MenuItem::separator(),
            MenuItem::new("Copy", "▸", Cmd::Sub(copy)).enabled(single),
            MenuItem::new(
                "Investigate",
                "▸",
                Cmd::Sub(vec![
                    MenuItem::new("Investigation workspace", "W", Cmd::Workspace),
                    MenuItem::new(if info.as_ref().is_some_and(|i| self.deep_enrolled(i.pid)) { "Stop deep trace" } else { "Deep trace (event-driven)" }, "D", Cmd::DeepTrace).enabled(trace_on),
                    MenuItem::new("Analyze executable", "", Cmd::AnalyzeExe).enabled(info.as_ref().is_some_and(|i| i.exe_path.is_some())),
                    MenuItem::new("Collect evidence", "", Cmd::CollectEvidence).enabled(case_on),
                    MenuItem::new("Collect evidence + copy executable", "", Cmd::CollectEvidenceWithExe)
                        .enabled(case_on && info.as_ref().is_some_and(|i| i.exe_path.is_some())),
                    MenuItem::new("Record as finding", "m", Cmd::MarkFinding).enabled(case_on),
                    MenuItem::new("Quarantine executable…", "", Cmd::QuarantineExe).enabled(case_on && info.as_ref().is_some_and(|i| i.exe_path.is_some())),
                ]),
            )
            .enabled(single),
            MenuItem::new(reveal_label(), "", Cmd::Reveal).enabled(info.as_ref().is_some_and(|i| i.exe_path.is_some())),
            MenuItem::separator(),
            MenuItem::new("Show only this app", "", Cmd::OnlyThisApp).enabled(single),
            MenuItem::new("Show only this user", "", Cmd::OnlyThisUser).enabled(info.as_ref().is_some_and(|i| i.user.is_some())),
            MenuItem::new(if is_tagged { "Unselect" } else { "Select" }, "space", Cmd::ToggleSelect),
        ]);
        if let Some(row) = self.selected_row().filter(|r| r.expandable && self.tagged.is_empty()) {
            let label = if row.expanded { "Collapse" } else { "Expand" };
            items.insert(1, MenuItem::new(label, "←→", Cmd::Expand));
        }
        let title = self.describe_targets(&targets);
        self.mode = Mode::Menu(vec![MenuLevel::new(title, items, anchor)]);
    }

    pub fn open_sort_menu(&mut self, anchor: (u16, u16)) {
        let arrow = if self.sort_desc { " ↓" } else { " ↑" };
        let items = Col::ALL
            .iter()
            .filter(|c| c.sortable())
            .map(|c| {
                let label = if *c == self.sort { format!("{}{arrow}", c.header()) } else { c.header().to_string() };
                MenuItem::new(label, "", Cmd::SortBy(*c)).checked(*c == self.sort)
            })
            .collect();
        let mut level = MenuLevel::new("Sort by", items, anchor);
        level.cursor = Col::ALL.iter().filter(|c| c.sortable()).position(|c| *c == self.sort).unwrap_or(0);
        self.mode = Mode::Menu(vec![level]);
    }

    /// Run a menu command against the current targets.
    pub fn run_cmd(&mut self, cmd: Cmd) {
        let targets = self.targets();
        self.mode = Mode::Normal;
        let first = targets.first().copied();
        let info = first.and_then(|p| self.tree.get(p)).map(|n| n.info.clone());
        match cmd {
            Cmd::Sub(_) => {}
            Cmd::Details => self.open_details_full(),
            Cmd::SaveBaseline => self.save_baseline(),
            Cmd::AnalyzeExe => {
                if let Some(p) = info.and_then(|i| i.exe_path) {
                    self.analyze_file(&p);
                }
            }
            Cmd::CollectEvidence => {
                if let Some(pid) = first {
                    self.collect_process_evidence(pid, false);
                }
            }
            Cmd::CollectEvidenceWithExe => {
                if let Some(pid) = first {
                    self.collect_process_evidence(pid, true);
                }
            }
            Cmd::MarkFinding => self.mark_finding(),
            Cmd::Workspace => {
                if let Some(pid) = first {
                    let k = self.proc_key(pid);
                    self.open_workspace_for(k);
                }
            }
            Cmd::DeepTrace => {
                if let Some(pid) = first {
                    self.toggle_deep(pid);
                }
            }
            Cmd::QuarantineExe => {
                if let Some(p) = info.and_then(|i| i.exe_path) {
                    self.request_quarantine(p);
                }
            }
            Cmd::Quarantine(p) => self.do_quarantine(&p),
            Cmd::Trace => {
                if let Some(pid) = first {
                    self.start_trace(pid);
                }
            }
            Cmd::End | Cmd::ForceQuit | Cmd::EndTree => {
                if targets.is_empty() {
                    return;
                }
                if self.confirm_end {
                    self.mode = Mode::Confirm { cmd, targets };
                } else {
                    self.execute(cmd, targets);
                }
            }
            Cmd::Suspend => self.run_action(Action::Signal(Sig::Stop), targets),
            Cmd::Resume => self.run_action(Action::Signal(Sig::Cont), targets),
            Cmd::Priority(n) => self.run_action(Action::SetNice(n), targets),
            Cmd::Signal(s) => self.run_action(Action::Signal(s), targets),
            Cmd::CopyPid => self.copy(first.map(|p| p.to_string())),
            Cmd::CopyName => self.copy(info.map(|i| i.name)),
            Cmd::CopyPath => self.copy(info.and_then(|i| i.exe_path)),
            Cmd::CopyCommand => self.copy(info.map(|i| i.cmd.join(" "))),
            Cmd::Reveal => {
                if let Some(path) = info.and_then(|i| i.exe_path) {
                    match crate::common::desktop::reveal(&path) {
                        Ok(()) => self.set_status(StatusLevel::Success, format!("Opened {}", reveal_label().to_lowercase())),
                        Err(e) => self.set_status(StatusLevel::Error, format!("Couldn't open file location: {e}")),
                    }
                }
            }
            Cmd::OnlyThisApp => {
                if let Some(i) = info {
                    self.app_filter = Some(i.app_name());
                    self.tagged.clear();
                    self.rebuild();
                }
            }
            Cmd::OnlyThisUser => {
                if let Some(u) = info.and_then(|i| i.user) {
                    self.user_filter = Some(u);
                    self.tagged.clear();
                    self.rebuild();
                }
            }
            Cmd::ToggleSelect => self.toggle_tag(),
            Cmd::Expand => self.set_expanded(None),
            Cmd::SortBy(c) => self.set_sort(c),
        }
    }

    /// Carry out a confirmed End / Force quit / End tree.
    pub fn execute(&mut self, cmd: Cmd, mut targets: Vec<u32>) {
        self.mode = Mode::Normal;
        match cmd {
            Cmd::End => {
                for p in &targets {
                    self.end_watch.insert(*p, (Instant::now(), self.name_of(*p)));
                }
                self.run_action(Action::Signal(Sig::Term), targets);
            }
            Cmd::ForceQuit => self.run_action(Action::Signal(Sig::Kill), targets),
            Cmd::EndTree => {
                let extra: Vec<u32> = targets.iter().flat_map(|p| self.tree.descendants(*p)).collect();
                targets.extend(extra);
                targets.sort_unstable();
                targets.dedup();
                self.run_action(Action::Signal(Sig::Term), targets);
            }
            _ => {}
        }
        self.tagged.clear();
    }

    pub(crate) fn run_action(&mut self, action: Action, mut pids: Vec<u32>) {
        if self.replaying() {
            self.set_status(StatusLevel::Info, "Not available while replaying a recording — this would act on the live system".into());
            return;
        }
        let me = std::process::id();
        pids.retain(|p| *p != me);
        if pids.is_empty() {
            self.set_status(StatusLevel::Error, "Nothing to do (procwatch won't act on itself)".into());
            return;
        }
        let what = describe(action);
        let desc = self.describe_targets(&pids);
        let targets: Vec<(u32, String, u64)> =
            pids.iter().map(|p| (*p, self.name_of(*p), self.tree.get(*p).map_or(0, |n| n.info.start_time_secs))).collect();
        self.response_begin(action, &targets);
        self.actions_pending += 1;
        self.set_status(StatusLevel::Info, format!("{what}: {desc}"));
        crate::engine::jobs::spawn_action(self.tx.clone(), targets, action);
    }

    /// Delete key / X: end or force quit without opening the menu.
    pub fn quick_end(&mut self, force: bool) {
        self.run_cmd(if force { Cmd::ForceQuit } else { Cmd::End });
    }

    pub(crate) fn copy(&mut self, text: Option<String>) {
        let Some(text) = text else { return };
        match crate::common::desktop::copy_to_clipboard(&text) {
            Ok(dest) => self.set_status(StatusLevel::Success, format!("Copied to {dest}: {}", crate::common::text::truncate(&text, 60))),
            Err(e) => self.set_status(StatusLevel::Error, format!("Copy failed: {e}")),
        }
    }
}
