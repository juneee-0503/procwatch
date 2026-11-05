//! How worker results update the application.

use super::*;

impl App {
    // ── worker messages ────────────────────────────────────────────────

    pub fn on_worker_msg(&mut self, msg: WorkerMsg) {
        match msg {
            WorkerMsg::Snapshot(snap) => {
                self.ctl.snapshot_handled();
                self.on_snapshot(*snap);
            }
            WorkerMsg::Gpu(g) => self.gpu = Some(g),
            WorkerMsg::Metrics(m) => {
                self.metrics = Some(m);
                self.metrics_at = Some(Instant::now());
            }
            WorkerMsg::Services(s) => self.services = Some(s),
            WorkerMsg::Inspected { pid, start_time, info } => {
                self.deep_pending.remove(&pid);
                let mut info = *info;
                // A light refresh shouldn't throw away modules we already have.
                if let Some(old) = self.deep_cache.get(&pid) {
                    if !info.modules_loaded && old.info.modules_loaded && old.start_time == start_time {
                        info.loaded_modules = old.info.loaded_modules.clone();
                        info.modules_loaded = true;
                    }
                }
                self.check_preload(pid, start_time, &info);
                self.deep_cache.insert(pid, DeepEntry { start_time, fetched: Instant::now(), info });
            }
            WorkerMsg::ActionDone { action, results } => {
                self.actions_pending = self.actions_pending.saturating_sub(1);
                let what = describe(action);
                self.response_results(action, &results);
                use crate::process::actions::Outcome;
                let ok = results.iter().filter(|r| r.2 == Outcome::Done).count();
                let gone = results.iter().filter(|r| r.2 == Outcome::AlreadyExited).count();
                let reused: Vec<&(u32, String, Outcome)> = results.iter().filter(|r| matches!(r.2, Outcome::PidReused { .. })).collect();
                let failed: Vec<(u32, String, String)> =
                    results.iter().filter_map(|(p, n, o)| if let Outcome::Failed(e) = o { Some((*p, n.clone(), e.clone())) } else { None }).collect();
                let extra = format!(
                    "{}{}",
                    if gone > 0 { format!(" · {gone} had already exited") } else { String::new() },
                    if reused.is_empty() { String::new() } else { format!(" · {} skipped: PID now belongs to another process", reused.len()) }
                );
                match failed.first() {
                    None if ok == 1 && extra.is_empty() => self.set_status(StatusLevel::Success, format!("{what}: done")),
                    None if reused.is_empty() => self.set_status(StatusLevel::Success, format!("{what}: {ok} processes{extra}")),
                    None => self.set_status(StatusLevel::Error, format!("{what}: {ok} processes{extra}")),
                    Some((pid, name, err)) => {
                        let more = if failed.len() > 1 { format!(" (and {} more)", failed.len() - 1) } else { String::new() };
                        let hint = if err.contains("ermission") || err.contains("denied") {
                            " — needs administrator rights"
                        } else {
                            ""
                        };
                        self.set_status(StatusLevel::Error, format!("{what} failed for {name} ({pid}): {err}{hint}{more}"));
                    }
                }
                self.request_refresh();
            }
            WorkerMsg::Stack { pid, start_time, result } => {
                if self.stack_pending == Some(pid) {
                    self.stack_pending = None;
                }
                self.stacks.insert(pid, StackEntry { start_time, fetched: Instant::now(), result });
            }
            WorkerMsg::FileList(result) => {
                self.files = Some(FileList { pending: false, fetched: Instant::now(), result });
                self.file_selected = self.file_selected.min(self.visible_files().len().saturating_sub(1));
            }
            WorkerMsg::TraceFiles(files) => {
                if let Some(t) = self.trace.as_mut() {
                    t.on_files(files);
                    self.follow_trace();
                }
            }
            msg @ (WorkerMsg::Fs(_)
            | WorkerMsg::Persistence(_)
            | WorkerMsg::Logs(_)
            | WorkerMsg::FileReport(_)
            | WorkerMsg::Artifacts { .. }
            | WorkerMsg::Yara { .. }
            | WorkerMsg::Deep(_)
            | WorkerMsg::Dns { .. }
            | WorkerMsg::Activity(_)
            | WorkerMsg::Traffic(_)
            | WorkerMsg::DeepSnap { .. }
            | WorkerMsg::Memory { .. }
            | WorkerMsg::Evidence(_)) => self.ir_on_msg(msg),
            WorkerMsg::StaticLibs { key, libs } => {
                if self.ir.ws.key == Some(key) {
                    self.ir.ws.static_libs = libs;
                    self.refresh_workspace();
                }
            }
            WorkerMsg::Error(e) => self.set_status(StatusLevel::Error, e),
            WorkerMsg::Found { query, result } => {
                if let Some(f) = self.find.as_mut().filter(|f| f.query == query) {
                    f.pending = false;
                    f.result = result;
                    f.cursor = 0;
                }
            }
        }
    }

    pub(crate) fn on_snapshot(&mut self, snap: crate::engine::messages::Snapshot) {
        let mut lap = crate::common::perf::Lap::new();
        let first = !self.loaded;
        self.seq += 1;
        let old = std::mem::replace(&mut self.tree, snap.tree);
        self.stats = snap.stats;
        self.connections = snap.connections;
        self.last_snapshot = Instant::now();
        self.loaded = true;

        let (started, exited) = if first { (Vec::new(), Vec::new()) } else { self.record_events(&old) };
        lap.mark("snapshot: record events");

        let seq = self.seq;
        let tree = &self.tree;
        self.first_seen.retain(|pid, _| tree.nodes.contains_key(pid));
        self.proc_hist.retain(|pid, h| tree.get(*pid).is_some_and(|n| n.info.start_time_secs == h.start_time));
        for (pid, node) in &tree.nodes {
            self.first_seen.entry(*pid).or_insert(if first { 0 } else { seq });
            let h = self.proc_hist.entry(*pid).or_insert_with(|| ProcHistory {
                start_time: node.info.start_time_secs,
                cpu: VecDeque::with_capacity(HISTORY),
                mem: VecDeque::with_capacity(HISTORY),
                io: VecDeque::with_capacity(HISTORY),
            });
            push(&mut h.cpu, node.info.cpu_usage_pct as f64);
            push(&mut h.mem, node.info.mem() as f64);
            push(&mut h.io, node.info.disk_read_rate + node.info.disk_write_rate);
        }

        // Memory trend from ~30 s of history: the leak detector.
        let interval = self.ctl.interval();
        let min_samples = ((30.0 / interval.as_secs_f64().max(0.25)) as usize).clamp(8, HISTORY);
        for (pid, node) in self.tree.nodes.iter_mut() {
            node.info.mem_growth =
                self.proc_hist.get(pid).and_then(|h| rules::growth_per_min(&h.mem, interval, min_samples));
        }

        for (pid, node) in self.tree.nodes.iter_mut() {
            if let Some(r) = self.ir.traffic_rates.get(pid) {
                node.info.net_rate = r.rx_rate + r.tx_rate;
            }
        }
        lap.mark("snapshot: histories");
        // Alert rules.
        let started_refs: Vec<&ProcessInfo> = started.iter().collect();
        let exited_refs: Vec<&ProcessInfo> = exited.iter().collect();
        let changes = rules::Changes { started: &started_refs, exited: &exited_refs };
        let tree = &self.tree;
        let growth = |pid: u32| tree.get(pid).and_then(|n| n.info.mem_growth);
        let fired = self.engine.evaluate(&self.rules, tree, &self.connections, &changes, &growth);
        self.add_alerts(fired);
        lap.mark("snapshot: alert rules");

        // Baseline comparison.
        if let Some(base) = &self.baseline {
            self.changes = base.diff(&Baseline::capture(&self.tree, &self.connections));
            self.change_selected = self.change_selected.min(self.changes.len().saturating_sub(1));
        }

        // Behavior trace.
        if let Some(t) = self.trace.as_mut() {
            t.on_snapshot(&self.tree, &self.connections);
            if let Ok(mut targets) = self.trace_targets.lock() {
                *targets = if t.is_running() { t.live_pids() } else { Vec::new() };
            }
        }
        self.follow_trace();
        lap.mark("snapshot: baseline and trace");
        self.ir_on_snapshot();
        lap.mark("snapshot: investigation");

        let s = &self.stats;
        let pct = |u: u64, t: u64| if t == 0 { 0.0 } else { u as f64 * 100.0 / t as f64 };
        push(&mut self.sys_hist.cpu, s.cpu_pct as f64);
        self.sys_hist.per_core.resize_with(s.per_core.len(), VecDeque::new);
        for (h, v) in self.sys_hist.per_core.iter_mut().zip(&s.per_core) {
            push(h, *v as f64);
        }
        push(&mut self.sys_hist.mem, pct(s.mem_used, s.mem_total));
        push(&mut self.sys_hist.swap, pct(s.swap_used, s.swap_total));
        push(&mut self.sys_hist.net_rx, s.net_rx_rate);
        push(&mut self.sys_hist.net_tx, s.net_tx_rate);
        push(&mut self.sys_hist.disk_r, s.disk_read_rate);
        push(&mut self.sys_hist.disk_w, s.disk_write_rate);

        // Drop state belonging to processes that exited or whose PID was
        // reused by a different process.
        let tree = &self.tree;
        self.deep_cache.retain(|pid, e| tree.get(*pid).is_some_and(|n| n.info.start_time_secs == e.start_time));
        self.stacks.retain(|pid, e| tree.get(*pid).is_some_and(|n| n.info.start_time_secs == e.start_time));
        self.tagged.retain(|pid| tree.nodes.contains_key(pid));
        self.collapsed.retain(|pid| tree.nodes.contains_key(pid));

        // Politely ended processes that are still around: offer force quit.
        let mut stuck = Vec::new();
        self.end_watch.retain(|pid, (at, name)| {
            if !tree.nodes.contains_key(pid) {
                return false;
            }
            if at.elapsed() >= END_GRACE {
                stuck.push(name.clone());
                return false;
            }
            true
        });
        if let Some(name) = stuck.first() {
            self.set_status(StatusLevel::Error, format!("{name} is still running — press X to force quit"));
        }

        lap.mark("snapshot: housekeeping");
        self.rebuild();
        lap.mark("snapshot: rebuild view");
        drop(old);
        lap.mark("snapshot: free old tree");
    }

    /// Log starts/exits since `old`; returns them for the rule engine.
    pub(crate) fn record_events(&mut self, old: &ProcessTree) -> (Vec<ProcessInfo>, Vec<ProcessInfo>) {
        let now = Local::now();
        let parent_name = |tree: &ProcessTree, ppid: Option<u32>| {
            ppid.and_then(|p| tree.get(p)).map(|n| format!("{} ({})", n.info.name, n.info.pid)).unwrap_or_default()
        };
        // procwatch's own helpers (codesign, lsof, vmmap…) are not activity
        // on the system under investigation.
        let mut started: Vec<&ProcessInfo> = self
            .tree
            .nodes
            .values()
            .filter(|n| !self.is_own_helper(&n.info))
            .filter(|n| old.get(n.info.pid).is_none_or(|o| o.info.start_time_secs != n.info.start_time_secs))
            .map(|n| &n.info)
            .collect();
        started.sort_by_key(|i| i.pid);
        let mut exited: Vec<&ProcessInfo> = old
            .nodes
            .values()
            .filter(|n| !self.is_own_helper(&n.info))
            .filter(|n| self.tree.get(n.info.pid).is_none_or(|c| c.info.start_time_secs != n.info.start_time_secs))
            .map(|n| &n.info)
            .collect();
        exited.sort_by_key(|i| i.pid);
        let owned = (started.iter().map(|i| (*i).clone()).collect(), exited.iter().map(|i| (*i).clone()).collect());

        let mut new_events = Vec::new();
        for i in exited {
            new_events.push(Event {
                at: now,
                kind: EventKind::Exited,
                pid: i.pid,
                name: i.name.clone(),
                parent: parent_name(old, i.ppid),
                user: i.user.clone().unwrap_or_default(),
                // Without a start time the OS reports "since 1970".
                detail: if i.start_time_secs == 0 || i.run_time_secs > 10 * 365 * 86_400 {
                    "lifetime unknown".to_string()
                } else {
                    format!("ran {}", crate::process::human_duration(i.run_time_secs))
                },
                start: i.start_time_secs,
                ppid: i.ppid,
                exe: i.exe_path.clone(),
            });
        }
        for i in started {
            new_events.push(Event {
                at: now,
                kind: EventKind::Started,
                pid: i.pid,
                name: i.name.clone(),
                parent: parent_name(&self.tree, i.ppid),
                user: i.user.clone().unwrap_or_default(),
                detail: i.cmd.join(" "),
                start: i.start_time_secs,
                ppid: i.ppid,
                exe: i.exe_path.clone(),
            });
        }
        if let Some(st) = self.ir.store.as_mut() {
            for e in &new_events {
                let rec = match e.kind {
                    EventKind::Started => crate::forensics::store::Rec::ProcStart(crate::forensics::store::ProcRec {
                        pid: e.pid,
                        ppid: e.ppid,
                        start: e.start,
                        name: e.name.clone(),
                        exe: e.exe.clone(),
                        cmd: e.detail.clone(),
                        user: e.user.clone(),
                    }),
                    EventKind::Exited => crate::forensics::store::Rec::ProcExit { pid: e.pid, start: e.start, name: e.name.clone(), ran: e.detail.clone() },
                };
                st.write(e.at, rec);
            }
        }
        for e in new_events {
            if self.events.len() >= MAX_EVENTS {
                self.events.pop_back();
            }
            self.events.push_front(e);
        }
        owned
    }
}
