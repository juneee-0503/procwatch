//! Merging every source into one timeline.

use super::*;

impl App {
    // ── timeline ───────────────────────────────────────────────────────

    /// Automatic rebuilds run on the UI thread, so they may take at most
    /// about 5% of it however large the timeline grows. Anything the user
    /// asks for directly rebuilds at once.
    pub fn timeline_rebuild_due(&self) -> bool {
        self.ir.timeline_dirty && self.ir.last_rebuild.is_none_or(|(at, cost)| at.elapsed() >= (cost * 20).min(std::time::Duration::from_secs(30)))
    }

    /// Timeline events since `since` not in `seen`, oldest first, as ECS
    /// JSON lines (for `--monitor`).
    pub fn new_ecs_lines(&self, since: DateTime<Local>, seen: &mut HashSet<u64>) -> Vec<String> {
        let host = sysinfo::System::host_name().unwrap_or_default();
        self.ir
            .timeline
            .iter()
            .rev()
            .filter(|e| e.time >= since && seen.insert(e.id))
            .map(|e| {
                let exe = e.links.iter().find_map(|(r, x)| if *r == Rel::Executes { if let Entity::File(p) = x { Some(p.as_str()) } else { None } } else { None });
                let line = ecs_line(e, &host);
                // A hash is asked for once and added as soon as it is known.
                let Some(exe) = exe else { return line };
                self.ir.intel.request(exe, true);
                match self.ir.intel.get(exe).and_then(|i| i.sha256) {
                    Some(h) => {
                        let mut v: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
                        v["process"]["hash"] = json!({ "sha256": h });
                        v.to_string()
                    }
                    None => line,
                }
            })
            .collect()
    }

    /// Forget ids that have left the timeline.
    pub fn retain_seen(&self, seen: &mut HashSet<u64>) {
        let live: HashSet<u64> = self.ir.timeline.iter().map(|e| e.id).collect();
        seen.retain(|id| live.contains(id));
    }

    pub fn rebuild_timeline(&mut self) {
        let began = Instant::now();
        let mut lap = crate::common::perf::Lap::new();
        let mut whole = crate::common::perf::Lap::new();
        // New events arrive at the top; keep the selected event (and its
        // position on screen) where it is instead of letting it drift.
        let anchor = self.visible_timeline().get(self.ir.tl_selected).map(|i| self.ir.timeline[*i].id);
        let mut v: Vec<TimelineItem> = Vec::new();
        let pkey = |pid: u32, start: u64| Entity::Process(ProcKey { pid, start });
        let live_key = |pid: u32| ProcKey { pid, start: self.tree.get(pid).map_or(0, |n| n.info.start_time_secs) };
        // Deep-trace lifecycle events are exact; the sampled start/exit of
        // the same instance would only duplicate them.
        let deep_seen: HashSet<(u32, bool)> = self
            .ir
            .deep
            .events
            .iter()
            .filter(|d| d.kind != crate::process::deeptrace::DtKind::Exec)
            .map(|d| (d.pid, d.kind == crate::process::deeptrace::DtKind::Spawn))
            .collect();
        // Name each traced instance after the program it ended up running
        // (a child is a copy of its parent until it execs).
        let mut final_image: HashMap<u32, (String, Option<String>)> = HashMap::new();
        for d in &self.ir.deep.events {
            if let Some(p) = &d.path {
                if d.kind != crate::process::deeptrace::DtKind::Spawn || !final_image.contains_key(&d.pid) {
                    final_image.insert(d.pid, (p.clone(), d.args.clone()));
                }
            }
        }
        for d in &self.ir.deep.events {
            let image = final_image.get(&d.pid);
            // The invoked name (argv[0]) — hard links like macOS `id` →
            // whoami share an image but are different commands.
            let argv0 = image.and_then(|(_, a)| a.as_deref()).and_then(|a| a.split_whitespace().next()).map(|a| a.rsplit(['/', '\\']).next().unwrap_or(a).to_string());
            let name = argv0
                .or_else(|| image.map(|(p, _)| p.as_str()).or(d.path.as_deref()).and_then(|p| p.rsplit(['/', '\\']).next()).map(str::to_string))
                .unwrap_or_else(|| self.name_of(d.pid));
            let detail = match d.kind {
                crate::process::deeptrace::DtKind::Exit => format!("exited (noticed via {})", d.via),
                crate::process::deeptrace::DtKind::Spawn => {
                    let (p, a) = image.cloned().unwrap_or((String::new(), None));
                    format!("{}{}", a.or(Some(p)).filter(|x| !x.is_empty()).unwrap_or_else(|| "(gone before it could be read)".into()), d.ppid.map(|p| format!(" · parent {p}")).unwrap_or_default())
                }
                _ => format!("{}{}", d.args.clone().or_else(|| d.path.clone()).unwrap_or_else(|| "(gone before it could be read)".into()), d.ppid.map(|p| format!(" · parent {p}")).unwrap_or_default()),
            };
            let key = if d.start > 0 { ProcKey { pid: d.pid, start: d.start } } else { live_key(d.pid) };
            let mut item = TimelineItem::new(d.at, Basis::Event, "deep", d.kind.label(), Some(d.pid), name, detail).about(Entity::Process(key));
            if let Some(p) = &d.path {
                item = item.link(Rel::Executes, Entity::File(p.clone()));
            }
            if let Some(pp) = d.ppid {
                item = item.link(Rel::ChildOf, Entity::Process(live_key(pp)));
            }
            v.push(item);
        }
        for c in &self.ir.deep.changes {
            v.push(
                TimelineItem::new(c.at, Basis::Observed, "deep", c.kind.label(), Some(c.key.pid), self.name_of(c.key.pid), c.path.clone())
                    .about(Entity::Process(c.key))
                    .link(if matches!(c.kind, super::deep::ChangeKind::FileOpen | super::deep::ChangeKind::FileClose) { Rel::Opened } else { Rel::Executes }, Entity::File(c.path.clone())),
            );
        }
        for e in &self.events {
            let started = e.kind == EventKind::Started;
            if deep_seen.contains(&(e.pid, started)) && self.ir.deep.events.iter().any(|d| d.pid == e.pid && (d.start == 0 || d.start.abs_diff(e.start) <= 2)) {
                continue;
            }
            // A start's real time is the OS-reported start time; exits are
            // only known when a refresh no longer finds the process.
            let os_time = chrono::DateTime::from_timestamp(e.start as i64, 0).map(|t| t.with_timezone(&Local));
            let (time, basis) = match os_time {
                Some(t) if started && e.start > 0 => (t, Basis::Event),
                _ => (e.at, Basis::Observed),
            };
            let detail = if e.parent.is_empty() { e.detail.clone() } else { format!("{} · parent {}", e.detail, e.parent) };
            let mut item = TimelineItem::new(time, basis, "process", if started { "started" } else { "exited" }, Some(e.pid), e.name.clone(), detail)
                .about(pkey(e.pid, e.start))
                .seen(e.at);
            if let Some(exe) = &e.exe {
                item = item.link(Rel::Executes, Entity::File(exe.clone()));
            }
            if let Some(pp) = e.ppid {
                item = item.link(Rel::ChildOf, Entity::Process(live_key(pp)));
            }
            if !e.user.is_empty() {
                item = item.link(Rel::RunsAs, Entity::User(e.user.clone()));
            }
            v.push(item);
        }
        for e in &self.ir.net_events {
            let (ip, _) = split_endpoint(if e.kind.contains("listen") { &e.conn.local } else { &e.conn.remote });
            let rel = if e.kind.contains("listen") { Rel::ListensOn } else { Rel::ConnectedTo };
            v.push(
                TimelineItem::new(e.time, Basis::Observed, "network", e.kind, Some(e.pid), e.name.clone(), format!("{} {} → {} {}", e.conn.protocol, e.conn.local, e.conn.remote, e.conn.state.label()))
                    .about(Entity::Process(live_key(e.pid)))
                    .link(rel, Entity::Endpoint(ip)),
            );
        }
        for e in &self.ir.fs_events {
            // The source's own process (fanotify / fs_usage), else a
            // deep-traced process that had the file open.
            let owner = e.pid.map(|p| self.proc_key(p)).or_else(|| self.file_owner_near(&e.path, e.time));
            let mut item = TimelineItem::new(e.time, Basis::Observed, "file", e.kind, owner.map(|k| k.pid), owner.map(|k| self.name_of(k.pid)).unwrap_or_default(), e.path.clone())
                .about(Entity::File(e.path.clone()));
            if let Some(k) = owner {
                item = item.link(Rel::OpenedBy, Entity::Process(k));
            }
            v.push(item);
        }
        for t in &self.ir.threats {
            let item = TimelineItem::new(t.time, Basis::Observed, "defense", t.rule.to_string(), t.pid, t.source.map_or_else(String::new, |s| s.to_string()), t.title.clone());
            v.push(match (t.pid, t.source) {
                (Some(p), _) => item.about(Entity::Process(live_key(p))),
                (None, Some(ip)) => item.about(Entity::Endpoint(ip.to_string())),
                _ => item,
            });
        }
        for a in &self.alerts {
            v.push(TimelineItem::new(a.at, Basis::Observed, "alert", a.rule.clone(), Some(a.pid), a.name.clone(), a.message.clone()).about(Entity::Process(live_key(a.pid))));
        }
        for d in &self.ir.det.store.items {
            if d.suppressed.is_some() {
                continue;
            }
            v.push(
                TimelineItem::new(
                    d.first_seen,
                    Basis::Observed,
                    "detect",
                    format!("{} {}", d.severity.label(), d.rule_id),
                    d.pid,
                    d.subject_label.clone(),
                    format!("{} — {}", d.rule_name, d.evidence.first().cloned().unwrap_or_default()),
                )
                .about(d.subject.clone())
                .link(Rel::DetectedBy, Entity::Rule(d.rule_id.clone())),
            );
        }
        if let Some(t) = &self.trace {
            for e in &t.events {
                v.push(TimelineItem::new(e.at, Basis::Observed, "trace", e.kind.label(), Some(e.pid), e.process.clone(), e.detail.clone()).about(Entity::Process(live_key(e.pid))));
            }
        }
        for e in self.log_entries() {
            let subject = match e.pid {
                Some(p) => Entity::Process(live_key(p)),
                None => Entity::Host(String::new()),
            };
            let kind = match e.event_id {
                Some(id) => format!("{} {id}", e.level),
                None => e.level.clone(),
            };
            v.push(TimelineItem::new(e.time, Basis::Event, "log", kind, e.pid, e.process.clone(), e.message.clone()).about(subject));
        }
        for p in self.persist_items() {
            let Some(t) = p.defined.as_deref().and_then(|t| DateTime::parse_from_rfc3339(t).ok()) else { continue };
            let id = format!("{}|{}|{}", p.category, p.name, p.location);
            let mut item = TimelineItem::new(
                t.with_timezone(&Local),
                Basis::Event,
                "persist",
                "written",
                None,
                p.name.clone(),
                format!("{}: {} → {}{}", p.category, p.location, p.command, if p.flags.is_empty() { String::new() } else { format!(" ⚑ {}", p.flags.join("; ")) }),
            )
            .about(Entity::Persistence(id));
            if let Some(target) = &p.target {
                item = item.link(Rel::Launches, Entity::File(target.clone()));
            }
            v.push(item);
        }
        for c in &self.ir.persist_changes {
            let mut item = TimelineItem::new(
                c.time,
                Basis::Observed,
                "persist",
                c.kind,
                c.writer_key.map(|k| k.pid),
                c.writer.clone().unwrap_or_else(|| c.name.clone()),
                format!("{}: {} → {} ({})", c.category, c.name, c.command, c.location),
            )
            .about(Entity::Persistence(format!("{}|{}|{}", c.category, c.name, c.location)));
            if let Some(t) = &c.target {
                item = item.link(Rel::Launches, Entity::File(t.clone()));
            }
            if let Some(k) = c.writer_key {
                item = item.link(Rel::Changed, Entity::Process(k));
            }
            v.push(item);
        }
        for a in &self.ir.artifacts {
            if let Some(t) = a.time {
                let mut item = TimelineItem::new(t, Basis::Event, "artifact", a.kind, None, a.user.clone().unwrap_or_default(), format!("{} — {}", a.subject, a.detail));
                if a.subject.contains('/') || a.subject.contains('\\') {
                    item = item.about(Entity::File(a.subject.clone()));
                }
                v.push(item);
            }
        }
        if let Some(c) = &self.ir.case {
            for r in c.custody_records() {
                if let Ok(t) = DateTime::parse_from_rfc3339(&r.time) {
                    v.push(TimelineItem::new(t.with_timezone(&Local), Basis::Event, "case", r.action, None, r.examiner, r.detail));
                }
            }
        }
        // Lineage for `tree:PID`: walk parents in the live tree, falling
        // back to parent pids recorded when processes started/exited.
        let mut recorded_parent: HashMap<u32, u32> = HashMap::new();
        for e in &self.events {
            if let Some(ppid) = e.ppid {
                recorded_parent.insert(e.pid, ppid);
            }
        }
        for d in &self.ir.deep.events {
            if let Some(ppid) = d.ppid {
                recorded_parent.entry(d.pid).or_insert(ppid);
            }
        }
        let mut memo: HashMap<u32, Vec<u32>> = HashMap::new();
        for item in v.iter_mut() {
            item.id = event_id(&[item.source, &item.kind, &item.time.timestamp_micros().to_string(), &item.pid.unwrap_or(0).to_string(), &item.detail]);
            let Some(pid) = item.pid else { continue };
            let chain = memo.entry(pid).or_insert_with(|| {
                let mut chain = vec![pid];
                let mut cur = pid;
                while chain.len() < 64 {
                    let parent = self.tree.get(cur).and_then(|n| n.info.ppid).or_else(|| recorded_parent.get(&cur).copied());
                    match parent {
                        Some(p) if !chain.contains(&p) => {
                            chain.push(p);
                            cur = p;
                        }
                        _ => break,
                    }
                }
                chain
            });
            item.lineage = chain.clone();
        }
        if let Some(c) = &self.ir.case {
            let tags: HashMap<&str, &str> = c.bookmarks.iter().map(|b| (b.event.as_str(), b.tag.as_str())).collect();
            for item in v.iter_mut() {
                item.tag = tags.get(short_id(item.id).as_str()).map(|t| t.to_string());
            }
        }
        // Newest first; stable so same-second events keep source order.
        lap.mark("timeline: gather");
        v.sort_by_key(|e| std::cmp::Reverse(e.time));
        lap.mark("timeline: sort");
        let clusters = {
            let evs: Vec<crate::detection::correlate::Ev> = v
                .iter()
                .map(|e| crate::detection::correlate::Ev {
                    time: e.time,
                    id: e.id,
                    source: e.source,
                    kind: &e.kind,
                    pid: e.pid,
                    name: &e.name,
                    detail: &e.detail,
                    lineage: &e.lineage,
                    links: &e.links,
                    subject: e.subject.as_ref(),
                })
                .collect();
            crate::detection::correlate::cluster(&evs)
        };
        for c in &clusters {
            for i in &c.members {
                v[*i].cluster = Some(c.id);
            }
        }
        lap.mark("timeline: cluster");
        let behaviour = if self.ir.det.behavior.is_empty() { Vec::new() } else { crate::detection::behave::evaluate(&self.ir.det.behavior, &behaviour_events(&v)) };
        lap.mark("timeline: behaviour");
        self.ir.timeline = v;
        self.ir.clusters = clusters;
        self.ir.timeline_dirty = false;
        whole.mark("timeline: rebuild total");
        self.ir.last_rebuild = Some((Instant::now(), began.elapsed()));
        let mut recorded = false;
        for m in behaviour {
            let first = m.events.first().cloned().unwrap_or_default();
            if !self.ir.det.behavior_seen.insert((m.rule.clone(), first)) {
                continue;
            }
            let hit = crate::detection::triage::RuleHit {
                id: m.rule.clone(),
                name: m.title.clone(),
                severity: m.level,
                confidence: m.confidence,
                technique: m.technique.clone(),
                evidence: m.evidence.clone(),
                suppressed: None,
            };
            let (subject, label) = match m.pid {
                Some(p) => (Entity::Process(self.proc_key(p)), format!("{} ({p})", self.name_of(p))),
                None => (Entity::Host(String::new()), "this host".into()),
            };
            self.record_detection_pub(&hit, subject, label, m.pid, "behavior");
            recorded = true;
        }
        // New detections appear in the timeline on the next rebuild.
        if recorded {
            self.ir.timeline_dirty = true;
        }
        if let Some(id) = anchor {
            if let Some(pos) = self.visible_timeline().iter().position(|i| self.ir.timeline[*i].id == id) {
                let shift = pos as isize - self.ir.tl_selected as isize;
                self.ir.tl_selected = pos;
                self.ir.tl_offset = (self.ir.tl_offset as isize + shift).max(0) as usize;
            }
        }
    }

    /// Summaries of the correlated activity clusters (for the report and
    /// the cluster view).
    pub fn cluster_summaries(&self) -> Vec<crate::detection::correlate::SummaryBlock> {
        let evs: Vec<crate::detection::correlate::Ev> = self
            .ir
            .timeline
            .iter()
            .map(|e| crate::detection::correlate::Ev {
                time: e.time,
                id: e.id,
                source: e.source,
                kind: &e.kind,
                pid: e.pid,
                name: &e.name,
                detail: &e.detail,
                lineage: &e.lineage,
                links: &e.links,
                subject: e.subject.as_ref(),
            })
            .collect();
        let (evidence, bookmarks) = match &self.ir.case {
            Some(c) => (
                c.register().into_iter().filter_map(|i| i.subject.map(|s| (i.id, s))).collect::<Vec<_>>(),
                self.ir.timeline.iter().filter_map(|e| e.tag.clone().map(|t| (e.id, t))).collect::<Vec<_>>(),
            ),
            None => (Vec::new(), Vec::new()),
        };
        self.ir.clusters.iter().map(|c| crate::detection::correlate::summarize(c, &evs, &evidence, &bookmarks)).collect()
    }

    /// Bookmark the selected timeline event (asks for the phase).
    pub fn request_bookmark(&mut self) {
        if !self.require("case") {
            return;
        }
        let Some(e) = self.visible_timeline().get(self.ir.tl_selected).map(|i| &self.ir.timeline[*i]) else { return };
        let summary = format!("{} {} {} {}", e.source, e.kind, e.name, e.detail).chars().take(160).collect();
        let purpose = InputPurpose::Bookmark { event: short_id(e.id), time: e.time.to_rfc3339(), summary };
        let input = match &e.tag {
            Some(t) => format!("{} ", crate::forensics::case::BOOKMARK_TAGS.iter().position(|x| x == t).map_or(1, |i| i + 1)),
            None => String::new(),
        };
        self.mode = Mode::Input { purpose, input, error: None };
    }

    pub fn remove_bookmark(&mut self) {
        let Some(id) = self.visible_timeline().get(self.ir.tl_selected).map(|i| short_id(self.ir.timeline[*i].id)) else { return };
        if let Some(c) = self.ir.case.as_mut() {
            let r = c.remove_bookmark(&id);
            self.report_result(r, "Bookmark removed");
            self.ir.timeline_dirty = true;
        }
    }

    /// Export the (filtered) timeline as CSV in the Timesketch import
    /// format: message, datetime, timestamp_desc plus extra columns.
    pub fn export_timeline_csv(&mut self) {
        if self.ir.timeline_dirty {
            self.rebuild_timeline();
        }
        let q = |s: &str| crate::common::text::csv_field(s);
        let mut out = String::from("message,datetime,timestamp_desc,timestamp,source,kind,pid,process\n");
        let rows = self.visible_timeline();
        for i in &rows {
            let e = &self.ir.timeline[*i];
            let who = if e.name.is_empty() { String::new() } else { format!("{} ", e.name) };
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                q(&format!("{who}{} {}", e.kind, e.detail)),
                e.time.to_rfc3339(),
                q(&format!("{} {}", e.source, e.kind)),
                e.time.timestamp_micros(),
                e.source,
                q(&e.kind),
                e.pid.map(|p| p.to_string()).unwrap_or_default(),
                q(&e.name)
            ));
        }
        let name = format!("procwatch-timeline-{}.csv", Local::now().format("%Y%m%d-%H%M%S"));
        let result = match self.ir.case.as_ref() {
            Some(c) => c.add_text(&name, &out).map(|p| p.display().to_string()),
            None => crate::common::paths::write_new(std::path::Path::new(&name), &out).map(|_| name.clone()).map_err(anyhow::Error::from),
        };
        match result {
            Ok(p) => self.set_status(StatusLevel::Success, format!("Exported {} events to {p}", rows.len())),
            Err(e) => self.set_status(StatusLevel::Error, format!("Export failed: {e}")),
        }
    }

    pub fn visible_timeline(&self) -> Vec<usize> {
        let f = Filter::parse(&self.query);
        self.ir.timeline.iter().enumerate().filter(|(_, e)| f.matches(*e)).map(|(i, _)| i).collect()
    }
}
