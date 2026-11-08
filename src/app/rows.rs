//! Building the process rows, views, sorting and selection.

use super::*;

impl App {
    // ── building rows ──────────────────────────────────────────────────

    pub(crate) fn compare(&self, a: &ProcessInfo, b: &ProcessInfo) -> std::cmp::Ordering {
        let ord = self.sort.compare(a, b);
        if self.sort_desc { ord.reverse() } else { ord }
    }

    /// Search uses the shared filter syntax (see `filter.rs`): free text
    /// matches name, PID, path, arguments or user; `port:`/`:8080` match
    /// processes with sockets on that port.
    pub(crate) fn matches(&self, info: &ProcessInfo, f: &Filter) -> bool {
        f.matches(&ProcItem { info, conns: self.connections.get(&info.pid) })
    }

    pub fn filtering(&self) -> bool {
        !self.query.is_empty() || self.user_filter.is_some() || self.app_filter.is_some()
    }

    /// Recompute rows from the tree, view, sort, search and expansion
    /// state, keeping the same row selected.
    pub fn rebuild(&mut self) {
        let q = self.query.trim().to_lowercase();
        let f = Filter::parse(&self.query);
        self.matched.clear();
        let filtering = self.filtering();
        if filtering {
            for (pid, node) in &self.tree.nodes {
                let i = &node.info;
                let user_ok = self.user_filter.as_deref().is_none_or(|u| i.user.as_deref() == Some(u));
                let app_ok = self.app_filter.as_deref().is_none_or(|a| i.app_name() == a);
                if user_ok && app_ok && (f.is_empty() || self.matches(i, &f)) {
                    self.matched.insert(*pid);
                }
            }
        }
        let visible = |pid: &u32| !filtering || self.matched.contains(pid);

        // While the order is held, rows already on screen keep their
        // position; new processes go after them in normal sort order.
        let sig = format!("{:?}|{:?}|{}|{}|{:?}|{:?}", self.view, self.sort, self.sort_desc, q, self.user_filter, self.app_filter);
        let holding = self.order_held() && sig == self.layout_sig;
        self.layout_sig = sig;
        let rank: HashMap<RowKey, usize> =
            if holding { self.rows.iter().enumerate().map(|(i, r)| (r.key.clone(), i)).collect() } else { HashMap::new() };
        let held = |a: &RowKey, b: &RowKey| match (rank.get(a), rank.get(b)) {
            (Some(x), Some(y)) => Some(x.cmp(y)),
            (Some(_), None) => Some(std::cmp::Ordering::Less),
            (None, Some(_)) => Some(std::cmp::Ordering::Greater),
            (None, None) => None,
        };
        let cmp = |a: &ProcessInfo, b: &ProcessInfo| {
            held(&RowKey::Proc(a.pid), &RowKey::Proc(b.pid)).unwrap_or_else(|| self.compare(a, b))
        };

        let mut groups: HashMap<String, Group> = HashMap::new();
        let rows = match self.view {
            ViewMode::Suspicious => {
                let mut pids: Vec<u32> =
                    self.tree.nodes.iter().filter(|(p, n)| n.info.risk > 0 && visible(p)).map(|(p, _)| *p).collect();
                pids.sort_by(|a, b| {
                    let (ia, ib) = (&self.tree.nodes[a].info, &self.tree.nodes[b].info);
                    held(&RowKey::Proc(*a), &RowKey::Proc(*b)).unwrap_or_else(|| ib.risk.cmp(&ia.risk).then_with(|| self.compare(ia, ib)))
                });
                pids.into_iter()
                    .map(|p| Row { key: RowKey::Proc(p), prefix: String::new(), expandable: false, expanded: false, hidden: 0 })
                    .collect()
            }
            ViewMode::List => {
                let mut pids: Vec<u32> = self.tree.nodes.keys().copied().filter(visible).collect();
                pids.sort_by(|a, b| cmp(&self.tree.nodes[a].info, &self.tree.nodes[b].info));
                pids.into_iter()
                    .map(|p| Row { key: RowKey::Proc(p), prefix: String::new(), expandable: false, expanded: false, hidden: 0 })
                    .collect()
            }
            ViewMode::Tree => {
                let keep = filtering.then(|| {
                    // Keep each match's ancestors so the tree stays readable.
                    let mut keep = self.matched.clone();
                    for pid in &self.matched {
                        let mut cur = self.tree.get(*pid).and_then(|n| n.info.ppid);
                        while let Some(p) = cur {
                            if !keep.insert(p) {
                                break;
                            }
                            cur = self.tree.get(p).and_then(|n| n.info.ppid);
                        }
                    }
                    keep
                });
                self.tree
                    .flatten(&cmp, &self.collapsed, keep.as_ref())
                    .into_iter()
                    .map(|r| Row {
                        key: RowKey::Proc(r.pid),
                        prefix: r.prefix,
                        expandable: r.has_children || r.hidden > 0,
                        expanded: r.hidden == 0,
                        hidden: r.hidden,
                    })
                    .collect()
            }
            ViewMode::Apps => {
                for (pid, node) in &self.tree.nodes {
                    if !visible(pid) {
                        continue;
                    }
                    let i = &node.info;
                    let g = groups.entry(i.app_name()).or_insert_with(|| Group { name: i.app_name(), ..Group::default() });
                    g.members.push(*pid);
                    g.cpu += i.cpu_usage_pct;
                    g.mem += i.mem();
                    g.threads += i.threads.unwrap_or(1) as u64;
                    g.disk += i.disk_read_rate + i.disk_write_rate;
                    if g.user.is_none() {
                        g.user = i.user.clone();
                    } else if g.user != i.user {
                        g.user = Some("(several)".into());
                    }
                }
                let mut sorted: Vec<&Group> = groups.values().collect();
                let sort = self.sort;
                let group_key = |g: &Group| {
                    if g.members.len() == 1 { RowKey::Proc(g.members[0]) } else { RowKey::Group(g.name.clone()) }
                };
                sorted.sort_by(|a, b| {
                    if let Some(ord) = held(&group_key(a), &group_key(b)) {
                        return ord;
                    }
                    let ord = match sort {
                        Col::Cpu => a.cpu.total_cmp(&b.cpu),
                        Col::Memory | Col::MemPct => a.mem.cmp(&b.mem),
                        Col::Threads => a.threads.cmp(&b.threads),
                        Col::Disk | Col::DiskRead | Col::DiskWrite | Col::Net => a.disk.total_cmp(&b.disk),
                        _ => b.name.to_lowercase().cmp(&a.name.to_lowercase()),
                    };
                    let ord = if self.sort_desc { ord.reverse() } else { ord };
                    ord.then_with(|| a.name.cmp(&b.name))
                });
                let mut rows = Vec::new();
                for g in sorted {
                    if g.members.len() == 1 {
                        let pid = g.members[0];
                        rows.push(Row { key: RowKey::Proc(pid), prefix: String::new(), expandable: false, expanded: false, hidden: 0 });
                        continue;
                    }
                    let expanded = self.expanded_groups.contains(&g.name) || (filtering && !q.is_empty());
                    rows.push(Row {
                        key: RowKey::Group(g.name.clone()),
                        prefix: String::new(),
                        expandable: true,
                        expanded,
                        hidden: if expanded { 0 } else { g.members.len() },
                    });
                    if expanded {
                        let mut members = g.members.clone();
                        members.sort_by(|a, b| cmp(&self.tree.nodes[a].info, &self.tree.nodes[b].info));
                        let n = members.len();
                        for (i, pid) in members.into_iter().enumerate() {
                            let prefix = if i + 1 == n { "└─ " } else { "├─ " }.to_string();
                            rows.push(Row { key: RowKey::Proc(pid), prefix, expandable: false, expanded: false, hidden: 0 });
                        }
                    }
                }
                rows
            }
        };
        self.rows = rows;
        self.groups = groups;

        // Keep the same row selected; while searching, a selection on a
        // context-only row moves to the first real match.
        let keep_current = !filtering
            || match &self.selected_key {
                Some(RowKey::Proc(p)) => self.matched.contains(p),
                Some(RowKey::Group(_)) => true,
                None => false,
            };
        let found =
            self.selected_key.clone().filter(|_| keep_current).and_then(|k| self.rows.iter().position(|r| r.key == k));
        match found {
            Some(idx) => self.selected = idx,
            None => {
                if filtering {
                    let first = self.rows.iter().position(|r| match &r.key {
                        RowKey::Proc(p) => self.matched.contains(p),
                        RowKey::Group(_) => true,
                    });
                    if let Some(idx) = first {
                        self.selected = idx;
                    }
                }
                self.selected = self.selected.min(self.rows.len().saturating_sub(1));
                let key = self.rows.get(self.selected).map(|r| r.key.clone());
                self.set_selected_key(key);
            }
        }

        self.rebuild_connections();
    }

    pub(crate) fn rebuild_connections(&mut self) {
        let f = Filter::parse(&self.query);
        let mut rows: Vec<ConnRow> = Vec::new();
        for (pid, conns) in &self.connections {
            let name = self.name_of(*pid);
            let user = self.tree.get(*pid).and_then(|n| n.info.user.clone());
            for c in conns {
                let row = ConnRow { pid: *pid, name: name.clone(), user: user.clone(), conn: c.clone() };
                if f.matches(&row) {
                    rows.push(row);
                }
            }
        }
        rows.sort_by(|a, b| {
            a.conn.state.cmp(&b.conn.state).then_with(|| a.name.cmp(&b.name)).then_with(|| a.conn.cmp(&b.conn))
        });
        self.conn_rows = rows;
        self.conn_selected = self.conn_selected.min(self.conn_rows.len().saturating_sub(1));
    }

    pub(crate) fn set_selected_key(&mut self, key: Option<RowKey>) {
        if self.selected_key != key {
            self.selected_key = key;
            self.selection_changed = Instant::now();
            self.pane_scroll = 0;
        }
    }

    pub fn selected_row(&self) -> Option<&Row> {
        self.rows.get(self.selected)
    }

    /// The selected process (None for a group row).
    pub fn selected_pid(&self) -> Option<u32> {
        match self.selected_row()?.key {
            RowKey::Proc(p) if self.tree.nodes.contains_key(&p) => Some(p),
            _ => None,
        }
    }

    pub fn selected_group(&self) -> Option<&Group> {
        match &self.selected_row()?.key {
            RowKey::Group(name) => self.groups.get(name),
            _ => None,
        }
    }

    pub fn select_index(&mut self, idx: usize) {
        if self.rows.is_empty() {
            return;
        }
        self.selected = idx.min(self.rows.len() - 1);
        let key = self.rows.get(self.selected).map(|r| r.key.clone());
        self.set_selected_key(key);
    }

    pub fn move_selection(&mut self, delta: isize) {
        self.hold_order();
        let step = |cur: usize, len: usize| (cur as isize + delta).clamp(0, len.saturating_sub(1) as isize) as usize;
        match self.tab {
            Tab::Processes if !self.rows.is_empty() => self.select_index(step(self.selected, self.rows.len())),
            Tab::Network if self.ir.net_hosts_view => self.ir.host_selected = step(self.ir.host_selected, self.visible_remotes().len()),
            Tab::Network => self.conn_selected = step(self.conn_selected, self.conn_rows.len()),
            Tab::Persistence if self.ir.persist_changes_view => {
                self.change_selected = step(self.change_selected, self.visible_changes().len())
            }
            Tab::Persistence => self.ir.persist_selected = step(self.ir.persist_selected, self.visible_persistence().len()),
            Tab::Activity => self.ir.ac_selected = step(self.ir.ac_selected, self.visible_activity().len()),
            Tab::Defense => self.ir.th_selected = step(self.ir.th_selected, self.visible_threats().len()),
            Tab::Timeline => self.ir.tl_selected = step(self.ir.tl_selected, self.visible_timeline().len()),
            Tab::Logs if self.ir.artifacts_view => self.ir.art_selected = step(self.ir.art_selected, self.visible_artifacts().len()),
            Tab::Logs => self.ir.log_selected = step(self.ir.log_selected, self.visible_logs().len()),
            Tab::Files if self.ir.files_changes_view => self.ir.fs_selected = step(self.ir.fs_selected, self.visible_fs_events().len()),
            Tab::Case if self.ir.case_focus_quarantine => {
                self.ir.quarantine_selected = step(self.ir.quarantine_selected, self.quarantined().len())
            }
            Tab::Case => {
                let n = self.ir.case.as_ref().map_or(0, |c| c.findings.len());
                self.ir.finding_selected = step(self.ir.finding_selected, n);
            }
            Tab::Trace if self.trace_tree => {
                let n = self.trace.as_ref().map_or(0, |t| t.procs.len());
                self.trace_tree_selected = step(self.trace_tree_selected, n);
            }
            Tab::Trace => {
                let n = self.visible_trace().len();
                self.trace_selected = step(self.trace_selected, n);
                // Scrolling up pauses auto-follow; reaching the end resumes it.
                self.trace_follow = self.trace_selected + 1 >= n;
            }
            Tab::Files => self.file_selected = step(self.file_selected, self.visible_files().len()),
            Tab::Alerts if self.ir.det.focus => self.ir.det.selected = step(self.ir.det.selected, self.visible_detections().len()),
            Tab::Alerts if !self.rules_focus => self.alert_selected = step(self.alert_selected, self.visible_alerts().len()),
            Tab::Alerts if self.rules_focus => self.rule_selected = step(self.rule_selected, self.rules.len()),
            _ => {}
        }
    }

    /// Jump to `pid` on the Processes page, clearing filters that hide it.
    pub fn focus_pid(&mut self, pid: u32) {
        if !self.require("process") {
            return;
        }
        if !self.tree.nodes.contains_key(&pid) {
            self.set_status(StatusLevel::Error, format!("Process {pid} is no longer running"));
            return;
        }
        self.tab = Tab::Processes;
        self.mode = Mode::Normal;
        if !self.rows.iter().any(|r| r.key == RowKey::Proc(pid)) {
            self.query.clear();
            self.user_filter = None;
            self.app_filter = None;
            let mut cur = self.tree.get(pid).and_then(|n| n.info.ppid);
            while let Some(p) = cur {
                self.collapsed.remove(&p);
                cur = self.tree.get(p).and_then(|n| n.info.ppid);
            }
            if let Some(n) = self.tree.get(pid) {
                self.expanded_groups.insert(n.info.app_name());
            }
        }
        self.selected_key = Some(RowKey::Proc(pid));
        self.rebuild();
    }

    // ── view / sort / columns / expansion ──────────────────────────────

    pub fn set_view(&mut self, view: ViewMode) {
        self.view = view;
        self.rebuild();
        self.set_status(StatusLevel::Info, format!("View: {}", view.label()));
    }

    pub fn set_sort(&mut self, col: Col) {
        if !col.sortable() {
            return;
        }
        if self.sort == col {
            self.sort_desc = !self.sort_desc;
        } else {
            self.sort = col;
            self.sort_desc = col.default_desc();
        }
        self.rebuild();
    }

    pub fn reverse_sort(&mut self) {
        self.sort_desc = !self.sort_desc;
        self.rebuild();
    }

    pub fn toggle_column(&mut self, col: Col) {
        if col == Col::Name {
            return;
        }
        if let Some(i) = self.columns.iter().position(|c| *c == col) {
            self.columns.remove(i);
        } else {
            let rank = |c: &Col| Col::ALL.iter().position(|x| x == c).unwrap_or(0);
            let at = self.columns.iter().position(|c| rank(c) > rank(&col)).unwrap_or(self.columns.len());
            self.columns.insert(at, col);
        }
    }

    /// Expand (`Some(true)`), collapse (`Some(false)`) or toggle the
    /// selected tree node / app group. Collapsing a leaf jumps to its
    /// parent, like a file browser.
    pub fn set_expanded(&mut self, expand: Option<bool>) {
        let Some(row) = self.selected_row().cloned() else { return };
        match &row.key {
            RowKey::Group(name) => {
                let want = expand.unwrap_or(!row.expanded);
                if want {
                    self.expanded_groups.insert(name.clone());
                } else {
                    self.expanded_groups.remove(name);
                }
            }
            RowKey::Proc(pid) => {
                let want = expand.unwrap_or(!row.expanded);
                if row.expandable && self.view == ViewMode::Tree && want != row.expanded {
                    if want {
                        self.collapsed.remove(pid);
                    } else {
                        self.collapsed.insert(*pid);
                    }
                } else if expand == Some(false) || (!row.expandable && expand.is_none()) {
                    let parent = match self.view {
                        ViewMode::Tree => self.tree.get(*pid).and_then(|n| n.info.ppid).map(RowKey::Proc),
                        ViewMode::Apps if !row.prefix.is_empty() => self.tree.get(*pid).map(|n| RowKey::Group(n.info.app_name())),
                        _ => None,
                    };
                    if let Some(idx) = parent.and_then(|k| self.rows.iter().position(|r| r.key == k)) {
                        self.select_index(idx);
                    }
                    return;
                } else {
                    return;
                }
            }
        }
        self.rebuild();
    }

    // ── selection (multi) ──────────────────────────────────────────────

    pub fn toggle_tag(&mut self) {
        match self.selected_row().map(|r| r.key.clone()) {
            Some(RowKey::Proc(pid)) => {
                if !self.tagged.remove(&pid) {
                    self.tagged.insert(pid);
                }
            }
            Some(RowKey::Group(name)) => {
                let members = self.groups.get(&name).map(|g| g.members.clone()).unwrap_or_default();
                if members.iter().all(|p| self.tagged.contains(p)) {
                    members.iter().for_each(|p| {
                        self.tagged.remove(p);
                    });
                } else {
                    self.tagged.extend(members);
                }
            }
            None => return,
        }
        self.move_selection(1);
    }

    /// Processes an action applies to: the selection set if any, else the
    /// highlighted row (all members for an app group).
    pub fn targets(&self) -> Vec<u32> {
        if self.detail_full {
            return self.selected_pid().into_iter().collect();
        }
        if !self.tagged.is_empty() {
            let mut v: Vec<u32> = self.tagged.iter().copied().collect();
            v.sort_unstable();
            return v;
        }
        match self.selected_row().map(|r| &r.key) {
            Some(RowKey::Proc(p)) if self.tree.nodes.contains_key(p) => vec![*p],
            Some(RowKey::Group(name)) => self.groups.get(name).map(|g| g.members.clone()).unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    pub fn describe_targets(&self, targets: &[u32]) -> String {
        match targets {
            [] => "nothing".into(),
            [one] => format!("{} ({one})", self.name_of(*one)),
            many => {
                let names: HashSet<String> = many.iter().map(|p| self.name_of(*p)).collect();
                if names.len() == 1 {
                    format!("{} processes named {}", many.len(), names.into_iter().next().unwrap_or_default())
                } else {
                    format!("{} processes", many.len())
                }
            }
        }
    }
}
