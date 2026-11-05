//! Cases, evidence, reports and quarantine.

use super::*;

impl App {
    // ── cases & evidence ───────────────────────────────────────────────

    /// The open case, creating one in the working directory if needed.
    pub(crate) fn ensure_case(&mut self) -> Option<&mut Case> {
        if self.ir.case.is_none() {
            match Case::create(Path::new(".")) {
                Ok(c) => {
                    let p = std::fs::canonicalize(&c.dir).unwrap_or(c.dir.clone());
                    self.set_status(StatusLevel::Success, format!("Case opened: {}", p.display()));
                    self.ir.case = Some(Case { dir: p, ..c });
                }
                Err(e) => {
                    self.set_status(StatusLevel::Error, format!("Couldn't create case folder: {e}"));
                    return None;
                }
            }
        }
        self.ir.case.as_mut()
    }

    pub fn new_case(&mut self) {
        self.ir.case = None;
        self.ir.verify = None;
        self.ir.isolation = None;
        self.ensure_case();
    }

    pub(crate) fn process_json(&self, pid: u32) -> serde_json::Value {
        let Some(n) = self.tree.get(pid) else { return json!({ "pid": pid, "error": "process not found" }) };
        let i = &n.info;
        let deep = self.deep_cache.get(&pid).map(|e| &e.info);
        json!({
            "pid": i.pid,
            "ppid": i.ppid,
            "name": i.name,
            "user": i.user,
            "exe": i.exe_path,
            "cwd": i.cwd,
            "command_line": i.cmd,
            "status": i.status_label(),
            "start_time_unix": i.start_time_secs,
            "cpu_percent": i.cpu_usage_pct,
            "memory_bytes": i.mem(),
            "virtual_bytes": i.virtual_memory_bytes,
            "threads": i.threads,
            "nice": i.nice,
            "cpu_time_secs": i.cpu_time_secs,
            "disk_read_total": i.disk_read_total,
            "disk_write_total": i.disk_write_total,
            "children": n.children,
            "connections": self.connections.get(&pid).map(|cs| cs.iter().map(|c| json!({
                "proto": c.protocol, "local": c.local, "remote": c.remote, "state": c.state.label()
            })).collect::<Vec<_>>()),
            "signature": deep.map(|d| crate::files::info::signature_text(&d.signature_status)),
            "signature_details": deep.map(|d| &d.signature_details),
            "modules": deep.filter(|d| d.modules_loaded).map(|d| &d.loaded_modules),
            "open_files": deep.and_then(|d| d.open_files.as_ref().ok()).map(|f| f.iter().map(|f| json!({"fd": f.fd, "type": f.kind, "name": f.name})).collect::<Vec<_>>()),
            "environment": deep.and_then(|d| d.environment.as_ref().ok()),
            "threads_detail": deep.and_then(|d| d.threads.as_ref().ok()).map(|t| t.iter().map(|t| json!({"id": t.id, "name": t.name, "state": t.state})).collect::<Vec<_>>()),
            "memory_report": self.ir.memory.get(&pid).map(|(_, r)| r),
            "triage": self.ir.triage.get(&pid),
            "detections": self.ir.det.store.for_subject(&Entity::Process(ProcKey { pid, start: i.start_time_secs })).collect::<Vec<_>>(),
            "executable_intel": i.exe_path.as_deref().and_then(|p| self.ir.intel.get(p)),
            "process_instance": format!("process:{}:{}", pid, i.start_time_secs),
        })
    }

    /// Write a process evidence package (and optionally copy its
    /// executable) into the case. Hashing/copying runs in the background.
    pub fn collect_process_evidence(&mut self, pid: u32, copy_exe: bool) {
        let value = self.process_json(pid);
        let name = self.name_of(pid);
        let exe = self.tree.get(pid).and_then(|n| n.info.exe_path.clone());
        let start = self.tree.get(pid).map_or(0, |n| n.info.start_time_secs);
        // What the package is missing, so nobody mistakes gaps for absence.
        let mut problems: Vec<String> = Vec::new();
        match self.deep_cache.get(&pid).map(|d| &d.info) {
            None => problems.push("details (threads, open files, environment, modules) not loaded: open the process details first".into()),
            Some(d) => {
                for (what, r) in [("threads", d.threads.as_ref().err()), ("open files", d.open_files.as_ref().err()), ("environment", d.environment.as_ref().err())] {
                    if let Some(e) = r {
                        problems.push(format!("{what}: {e}"));
                    }
                }
                if !d.modules_loaded {
                    problems.push("module list not loaded (open the Modules tab)".into());
                }
            }
        }
        if exe.is_none() {
            problems.push("executable path not visible to this account".into());
        }
        if !self.ir.memory.contains_key(&pid) {
            problems.push("memory layout report not generated (Memory tab)".into());
        }
        let Some(case) = self.ensure_case().cloned() else { return };
        let tx = self.tx.clone();
        let _ = std::thread::Builder::new().name("evidence".into()).spawn(move || {
            let result = (|| -> anyhow::Result<String> {
                let mut value = value;
                if let Some(exe) = &exe {
                    if let Ok(h) = crate::files::info::hash_file(Path::new(exe)) {
                        value["exe_hashes"] = json!(h);
                    }
                }
                let prov = crate::forensics::case::Provenance::live("process snapshot (OS process APIs, lsof/vmmap/PowerShell where needed)")
                    .subject(format!("process:{pid}:{start}"))
                    .problems(problems);
                let partial = !prov.problems.is_empty();
                let (file, item) = case.add_text_with(&format!("process-{pid}-{name}.json"), &serde_json::to_string_pretty(&value)?, prov)?;
                let mut msg = format!("Collected {} as {}{}", case.rel(&file), item.id, if partial { " (partial — see evidence register)" } else { "" });
                if copy_exe {
                    if let Some(exe) = exe {
                        let dest = case.add_copy(Path::new(&exe))?;
                        msg += &format!(" and {}", case.rel(&dest));
                    }
                }
                Ok(msg)
            })();
            let _ = tx.send(WorkerMsg::Evidence(result.map_err(|e| e.to_string())));
        });
    }

    /// Snapshot of everything currently known into the case.
    pub fn collect_system(&mut self) {
        if self.replaying() {
            self.set_status(StatusLevel::Info, "Not available while replaying a recording — this would act on the live system".into());
            return;
        }
        if self.ir.timeline_dirty {
            self.rebuild_timeline();
        }
        let processes: Vec<serde_json::Value> = {
            let mut pids: Vec<u32> = self.tree.nodes.keys().copied().collect();
            pids.sort_unstable();
            pids.iter()
                .filter_map(|p| self.tree.get(*p))
                .map(|n| {
                    let i = &n.info;
                    json!({"pid": i.pid, "ppid": i.ppid, "name": i.name, "user": i.user, "exe": i.exe_path,
                           "command_line": i.cmd.join(" "), "start_time_unix": i.start_time_secs,
                           "cpu_percent": i.cpu_usage_pct, "memory_bytes": i.mem(), "threads": i.threads})
                })
                .collect()
        };
        // Evidence ignores whatever filter the UI currently shows.
        let mut conns: Vec<serde_json::Value> = self
            .connections
            .iter()
            .flat_map(|(pid, cs)| {
                let name = self.name_of(*pid);
                cs.iter().map(move |c| {
                    json!({"pid": pid, "process": name, "proto": c.protocol, "local": c.local, "remote": c.remote, "state": c.state.label()})
                })
            })
            .collect();
        conns.sort_by_key(|v| v["pid"].as_u64());
        let timeline: Vec<serde_json::Value> = self
            .ir
            .timeline
            .iter()
            .map(|e| json!({"time": e.time.to_rfc3339(), "source": e.source, "kind": e.kind, "pid": e.pid, "name": e.name, "detail": e.detail}))
            .collect();
        let system = json!({
            "host": sysinfo::System::host_name(),
            "os": sysinfo::System::long_os_version(),
            "kernel": sysinfo::System::kernel_version(),
            "uptime_secs": self.stats.uptime_secs,
            "memory_total": self.stats.mem_total,
            "collected_at": Local::now().to_rfc3339(),
            "dns_resolvers": self.ir.resolvers,
            "reverse_dns": self.ir.resolver.known(),
        });
        let persistence = self.persist_items().to_vec();
        let logs = self.log_entries().to_vec();
        let alerts: Vec<String> = self.alerts.iter().map(|a| format!("{} {} ({}) {}", a.at.to_rfc3339(), a.name, a.pid, a.message)).collect();
        let fs: Vec<FsEvent> = self.ir.fs_events.iter().cloned().collect();
        let health = self.collection_health();
        let gaps = |names: &[&str]| -> Vec<String> {
            health
                .iter()
                .filter(|h| names.contains(&h.name.as_str()) && h.status != crate::engine::health::Status::Available)
                .map(|h| format!("{}: {} — {}", h.name, h.status.label(), h.detail))
                .collect()
        };
        let executables = self.ir.intel.snapshot();
        let detections = self.ir.det.store.items.clone();
        let artifacts = self.ir.artifacts.clone();
        let summaries = self.cluster_summaries();
        if let Some(st) = self.ir.store.as_mut() {
            st.flush();
        }
        let history_dir = self.ir.store.as_ref().map(|s| s.dir().to_path_buf());
        let since = self.ir.watch_start;
        let clusters: Vec<serde_json::Value> = self
            .ir
            .clusters
            .iter()
            .zip(&summaries)
            .map(|(c, s)| json!({"id": c.id, "root_pid": c.root_pid, "start": c.start.to_rfc3339(), "end": c.end.to_rfc3339(), "categories": c.categories, "links": c.links, "summary": s}))
            .collect();
        use crate::forensics::case::Provenance as P;
        let sets: Vec<(&str, String, P)> = vec![
            ("collection-health.json", serde_json::to_string_pretty(&health).unwrap_or_default(), P::live("procwatch self-assessment of data sources")),
            ("system.json", (&system as &dyn erased::Ser).json(), P::live("sysinfo host facts")),
            ("processes.json", (&processes as &dyn erased::Ser).json(), P::live("process table snapshot").problems(gaps(&["Process metadata", "Privileges"]))),
            ("executables.json", (&executables as &dyn erased::Ser).json(), P::live("signature check and hashes of running executables").problems(gaps(&["Code signatures & hashes"]))),
            ("connections.json", (&conns as &dyn erased::Ser).json(), P::live("socket table snapshot").problems(gaps(&["Network connections"]))),
            ("timeline.json", (&timeline as &dyn erased::Ser).json(), P::derived("timeline merged from all sources since procwatch started").problems(gaps(&["Process start/exit events", "Event logs", "Persistence"]))),
            ("clusters.json", (&clusters as &dyn erased::Ser).json(), P::derived("activity correlation (process lineage + path links)")),
            ("detections.json", (&detections as &dyn erased::Ser).json(), P::derived("host rules, Sigma rules and IOC matches").problems(gaps(&["Detection rules"]))),
            ("file-changes.json", (&fs as &dyn erased::Ser).json(), P::live("file system notifications in watched folders").problems(gaps(&["File changes"]))),
            ("alerts.json", (&alerts as &dyn erased::Ser).json(), P::derived("alert rules")),
        ];
        let Some(case) = self.ensure_case() else { return };
        let mut written = 0;
        let mut partial = 0;
        let mut errors = Vec::new();
        for (name, text, prov) in sets {
            let is_partial = !prov.problems.is_empty();
            match case.add_text_with(name, &text, prov) {
                Ok(_) => {
                    written += 1;
                    partial += is_partial as usize;
                }
                Err(e) => errors.push(format!("{name}: {e}")),
            }
        }
        let mut optional = |name: &str, empty: bool, text: String, prov: P, missing: &str| {
            if empty {
                let _ = case.record_failure(name, P { problems: vec![missing.to_string()], ..prov });
            } else {
                match case.add_text_with(name, &text, prov) {
                    Ok(_) => written += 1,
                    Err(e) => errors.push(format!("{name}: {e}")),
                }
            }
        };
        optional("persistence.json", persistence.is_empty(), (&persistence as &dyn erased::Ser).json(), P::live("autostart enumeration").problems(gaps(&["Persistence"])), "persistence not scanned (open the Persistence page)");
        optional("event-log.json", logs.is_empty(), (&logs as &dyn erased::Ser).json(), P::live("system event log query").problems(gaps(&["Event logs"])), "event log not loaded (open the Logs page)");
        // The recorded event history of this session, for --replay.
        if let Some(dir) = history_dir.as_deref() {
            let (lines, _) = crate::forensics::store::read(dir, Some(since), None);
            let text: String = lines
                .into_iter()
                .filter_map(|(t, rec)| serde_json::to_string(&crate::forensics::store::Line { t: t.to_rfc3339_opts(chrono::SecondsFormat::Millis, false), rec }).ok())
                .map(|l| l + "\n")
                .collect();
            optional("events.jsonl", text.is_empty(), text, P::live("procwatch event history for this session (replay with procwatch --replay CASE)"), "no event history recorded (history = off?)");
        }
        optional("artifacts.json", artifacts.is_empty(), (&artifacts as &dyn erased::Ser).json(), P::live("execution artifacts").problems(gaps(&["Execution artifacts"])), "execution artifacts not collected (Logs → x)");
        let note = if partial > 0 { format!(" ({partial} partial — gaps recorded in the evidence register)") } else { String::new() };
        if errors.is_empty() {
            self.set_status(StatusLevel::Success, format!("Collected {written} evidence files{note}"));
        } else {
            self.set_status(StatusLevel::Error, format!("Collection errors: {}", errors.join("; ")));
        }
        self.ir.timeline_dirty = true;
    }

    pub fn seal_evidence(&mut self) {
        let Some(case) = self.ensure_case() else { return };
        match case.seal() {
            Ok(entries) => self.set_status(StatusLevel::Success, format!("Manifest sealed: {} files hashed (SHA-256)", entries.len())),
            Err(e) => self.set_status(StatusLevel::Error, format!("Couldn't seal evidence: {e}")),
        }
    }

    pub fn verify_evidence(&mut self) {
        let Some(case) = self.ir.case.as_ref() else {
            self.set_status(StatusLevel::Error, "No case open".into());
            return;
        };
        match case.verify() {
            Ok(v) => {
                let bad = v.iter().filter(|(_, c)| *c != Check::Ok).count();
                let level = if bad == 0 { StatusLevel::Success } else { StatusLevel::Error };
                self.set_status(level, format!("Verified {} files: {}", v.len(), if bad == 0 { "all intact".into() } else { format!("{bad} problem(s)") }));
                self.ir.verify = Some(v);
            }
            Err(e) => self.set_status(StatusLevel::Error, e.to_string()),
        }
    }

    /// STIX 2.1 bundle + MISP event (indicators from medium+ detections)
    /// and the timeline as ECS JSON lines, into the case.
    pub fn export_standard(&mut self) {
        use crate::forensics::stdexport::{misp_event, stix_bundle, unique, Indicator};
        if self.ir.timeline_dirty {
            self.rebuild_timeline();
        }
        let intel = self.ir.intel.snapshot();
        let mut ind: Vec<Indicator> = Vec::new();
        for d in self.ir.det.store.items.iter().filter(|d| d.suppressed.is_none() && d.severity >= crate::common::model::Severity::Medium) {
            let why = format!("{} {} ({}) on {}", d.rule_id, d.rule_name, d.severity.label(), d.subject_label);
            let exe = d.pid.and_then(|p| self.tree.get(p)).and_then(|n| n.info.exe_path.clone()).or_else(|| if let Entity::File(f) = &d.subject { Some(f.clone()) } else { None });
            if let Some(e) = exe {
                if let Some(h) = intel.get(&e).and_then(|x| x.sha256.clone()) {
                    ind.push(Indicator::Sha256 { value: h, why: why.clone() });
                }
                ind.push(Indicator::Path { value: e, why: why.clone() });
            }
            if let Some(pid) = d.pid {
                for c in self.connections.get(&pid).into_iter().flatten() {
                    let ip = split_endpoint(&c.remote).0;
                    if c.state != ConnState::Listen && ip != "*" && !crate::detection::triage::is_private(&ip) {
                        if let Some((name, _)) = dns::name_for(&self.ir.dns_obs, &ip, Some(pid), Local::now()) {
                            ind.push(Indicator::Domain { value: name, why: why.clone() });
                        }
                        ind.push(Indicator::Ip { value: ip, why: why.clone() });
                    }
                }
            }
            if let Entity::Endpoint(ip) = &d.subject {
                ind.push(Indicator::Ip { value: ip.clone(), why: why.clone() });
            }
        }
        let ind = unique(ind);
        let now = Local::now();
        let host = sysinfo::System::host_name().unwrap_or_default();
        let ecs: String = self
            .ir
            .timeline
            .iter()
            .rev()
            .map(|e| ecs_line(e, &host) + "\n")
            .collect();
        let Some(case) = self.ensure_case() else { return };
        let id = case.id.clone();
        let p = |what: &str| crate::forensics::case::Provenance::derived(what);
        let r = (|| -> anyhow::Result<String> {
            let (_, a) = case.add_text_with("stix-bundle.json", &serde_json::to_string_pretty(&stix_bundle(&id, &ind, now))?, p("STIX 2.1 bundle of indicators from medium+ detections"))?;
            let (_, b) = case.add_text_with("misp-event.json", &serde_json::to_string_pretty(&misp_event(&id, &ind, now))?, p("MISP event with the same indicators"))?;
            let (_, c) = case.add_text_with("timeline-ecs.jsonl", &ecs, p("timeline in Elastic Common Schema field names"))?;
            Ok(format!("{} indicators → {} (STIX), {} (MISP); timeline → {} (ECS)", ind.len(), a.id, b.id, c.id))
        })();
        match r {
            Ok(m) => self.set_status(StatusLevel::Success, m),
            Err(e) => self.set_status(StatusLevel::Error, format!("Export failed: {e}")),
        }
    }

    pub fn export_case_report(&mut self) {
        if self.ir.timeline_dirty {
            self.rebuild_timeline();
        }
        let extras = ReportExtras {
            timeline: self.ir.timeline.iter().take(300).map(|e| {
                let who = match (e.name.is_empty(), e.pid) {
                    (false, Some(p)) => format!("{} ({p}) ", e.name),
                    (false, None) => format!("{} ", e.name),
                    _ => String::new(),
                };
                (e.time.format("%Y-%m-%d %H:%M:%S").to_string(), e.source.to_string(), format!("{} {who}{}", e.kind, e.detail))
            }).collect(),
            persistence: self
                .persist_items()
                .iter()
                .filter(|i| i.suspicious())
                .map(|i| (i.category.clone(), i.name.clone(), i.command.clone(), i.flags.join("; ")))
                .collect(),
            network: {
                let mut by: HashMap<u32, (String, Vec<String>)> = HashMap::new();
                for (pid, cs) in &self.connections {
                    for c in cs.iter().filter(|c| c.state == ConnState::Established) {
                        by.entry(*pid).or_insert_with(|| (self.name_of(*pid), Vec::new())).1.push(c.remote.clone());
                    }
                }
                let mut v: Vec<(String, u32, String)> = by.into_iter().map(|(pid, (n, eps))| (n, pid, eps.join(", "))).collect();
                v.sort();
                v
            },
            alerts: self.alerts.iter().map(|a| format!("{} — {} ({}): {}", a.at.format("%H:%M:%S"), a.name, a.pid, a.message)).collect(),
            detections: {
                let mut v: Vec<&crate::detection::engine::Detection> = self.ir.det.store.items.iter().filter(|d| d.suppressed.is_none()).collect();
                v.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.confidence.cmp(&a.confidence)).then(a.first_seen.cmp(&b.first_seen)));
                v.into_iter()
                    .take(300)
                    .map(|d| crate::forensics::case::DetectionRow {
                        severity: d.severity.label().into(),
                        confidence: d.confidence.label().into(),
                        rule: format!("{} {}", d.rule_id, d.rule_name),
                        technique: d.technique.clone(),
                        subject: d.subject_label.clone(),
                        evidence: d.evidence.join(" | "),
                        first_seen: d.first_seen.format("%Y-%m-%d %H:%M:%S").to_string(),
                        last_seen: d.last_seen.format("%Y-%m-%d %H:%M:%S").to_string(),
                        state: if d.active { "active".into() } else { "past".into() },
                    })
                    .collect()
            },
            summaries: self.cluster_summaries(),
            health: self.collection_health().into_iter().map(|h| (h.name, h.status.label().to_string(), h.detail)).collect(),
        };
        let Some(case) = self.ensure_case() else { return };
        match case.export_report(&extras) {
            Ok(dir) => self.set_status(StatusLevel::Success, format!("Report written: {}/report.md, .json, .html", dir.display())),
            Err(e) => self.set_status(StatusLevel::Error, format!("Report export failed: {e}")),
        }
    }

    /// Open the finding dialog for whatever is selected on this page.
    pub fn mark_finding(&mut self) {
        let (source, title, detail): (&str, String, String) = match self.tab {
            Tab::Processes => {
                let Some(pid) = self.selected_pid() else { return };
                let Some(n) = self.tree.get(pid) else { return };
                let i = &n.info;
                let triage = self.ir.triage.get(&pid).filter(|a| a.score > 0).map(|a| format!(" · risk {} ({})", a.score, a.summary())).unwrap_or_default();
                ("process", format!("Suspicious process {} ({pid})", i.name), format!("{} · user {} · {}{triage}", i.exe_path.clone().unwrap_or_default(), i.user.clone().unwrap_or_default(), i.cmd.join(" ")))
            }
            Tab::Network => {
                let Some(r) = self.conn_rows.get(self.conn_selected) else { return };
                ("network", format!("Connection by {} ({})", r.name, r.pid), format!("{} {} → {} {}", r.conn.protocol, r.conn.local, r.conn.remote, r.conn.state.label()))
            }
            Tab::Persistence => {
                let Some(it) = self.selected_persist() else { return };
                ("persistence", format!("{}: {}", it.category, it.name), format!("{} · {} · {}", it.command, it.location, it.flags.join("; ")))
            }
            Tab::Timeline => {
                let Some(i) = self.visible_timeline().get(self.ir.tl_selected).copied() else { return };
                let e = &self.ir.timeline[i];
                ("timeline", format!("{} {} {}", e.source, e.kind, e.name), format!("{} · {}", e.time.to_rfc3339(), e.detail))
            }
            Tab::Logs => {
                let Some(i) = self.visible_logs().get(self.ir.log_selected).copied() else { return };
                let e = &self.log_entries()[i];
                ("event log", format!("Log entry from {}", e.process), format!("{} · {} · {}", e.time.to_rfc3339(), e.level, e.message))
            }
            Tab::Files => {
                let Some(p) = self.selected_path() else { return };
                ("file", format!("Suspicious file {}", p.rsplit(['/', '\\']).next().unwrap_or(&p)), p)
            }
            Tab::Alerts => {
                let Some(pid) = self.selected_alert_pid() else { return };
                let i = *self.visible_alerts().get(self.alert_selected).unwrap_or(&0);
                let a = &self.alerts[i];
                ("alert", format!("Alert: {} ({pid})", a.name), format!("{} · rule {}", a.message, a.rule))
            }
            _ => return,
        };
        self.mode = Mode::Input { purpose: InputPurpose::Finding { source: source.into(), detail }, input: title, error: None };
    }

    pub fn finding_from_report(&mut self) {
        let Some(Ok(r)) = self.ir.file_report.as_ref().map(|f| &f.result) else { return };
        let detail = format!(
            "{} · {} · sha256 {} · {}",
            r.path,
            r.kind,
            r.hashes.as_ref().map(|h| h.sha256.as_str()).unwrap_or("-"),
            r.signature
        );
        let title = format!("Suspicious file {}", r.path.rsplit(['/', '\\']).next().unwrap_or(&r.path));
        self.mode = Mode::Input { purpose: InputPurpose::Finding { source: "file analysis".into(), detail }, input: title, error: None };
    }

    /// Submit an input dialog.
    pub fn submit_input(&mut self, purpose: InputPurpose, input: String) {
        self.mode = Mode::Normal;
        match purpose {
            InputPurpose::AnalyzePath => self.analyze_file(&input),
            InputPurpose::Note if !input.trim().is_empty() => {
                if let Some(c) = self.ensure_case() {
                    let r = c.add_note(input.trim());
                    self.report_result(r, "Note added");
                }
            }
            InputPurpose::Conclusion => {
                if let Some(c) = self.ensure_case() {
                    let r = c.set_conclusion(input.trim());
                    self.report_result(r, "Conclusion saved");
                }
            }
            InputPurpose::IsolationAllow => {
                let allow = input.trim();
                let allow = (!allow.is_empty()).then_some(allow);
                if let Some(ip) = allow {
                    if ip.parse::<std::net::IpAddr>().is_err() {
                        self.set_status(StatusLevel::Error, format!("'{ip}' is not an IP address"));
                        return;
                    }
                }
                let Some(c) = self.ensure_case() else { return };
                match contain::write_isolation_plan(c, allow) {
                    Ok((iso, res)) => {
                        self.set_status(StatusLevel::Success, format!("Isolation scripts written (not run): {}", iso.display()));
                        self.ir.isolation = Some((iso, res));
                    }
                    Err(e) => self.set_status(StatusLevel::Error, format!("Couldn't write isolation plan: {e}")),
                }
            }
            InputPurpose::IocFile => self.run_sweep(input.trim()),
            InputPurpose::Suppress { rule } => return self.add_suppression(rule, input),
            InputPurpose::ArtifactDir => self.import_artifacts(&input),
            InputPurpose::Bookmark { event, time, summary } => {
                let t = input.trim();
                let (num, note) = t.split_once(char::is_whitespace).map(|(a, b)| (a, b.trim())).unwrap_or((t, ""));
                let tag = num.parse::<usize>().ok().filter(|n| (1..=crate::forensics::case::BOOKMARK_TAGS.len()).contains(n));
                let Some(tag) = tag.map(|n| crate::forensics::case::BOOKMARK_TAGS[n - 1]) else {
                    self.mode = Mode::Input {
                        purpose: InputPurpose::Bookmark { event, time, summary },
                        input,
                        error: Some("Start with a phase number 1–6.".into()),
                    };
                    return;
                };
                let b = crate::forensics::case::Bookmark { event, tag: tag.into(), time, summary, note: note.into(), added: crate::forensics::case::now() };
                if let Some(c) = self.ensure_case() {
                    let r = c.add_bookmark(b);
                    self.report_result(r, &format!("Bookmarked as \"{tag}\""));
                }
            }
            InputPurpose::Finding { source, detail } => {
                let (sev, title) = parse_severity(&input);
                if title.is_empty() {
                    return;
                }
                if let Some(c) = self.ensure_case() {
                    let r = c.add_finding(sev, &title, &source, &detail);
                    self.report_result(r, &format!("Finding recorded ({sev})"));
                }
            }
            _ => {}
        }
        self.ir.timeline_dirty = true;
    }

    pub(crate) fn report_result(&mut self, r: anyhow::Result<()>, ok: &str) {
        match r {
            Ok(()) => self.set_status(StatusLevel::Success, ok.into()),
            Err(e) => self.set_status(StatusLevel::Error, e.to_string()),
        }
    }

    pub fn delete_finding(&mut self) {
        let i = self.ir.finding_selected;
        if let Some(c) = self.ir.case.as_mut() {
            if i < c.findings.len() {
                let f = c.findings.remove(i);
                let _ = c.save();
                let _ = c.log("finding removed", &f.title);
                self.ir.finding_selected = i.min(c.findings.len().saturating_sub(1));
            }
        }
    }

    // ── quarantine ─────────────────────────────────────────────────────

    pub fn request_quarantine(&mut self, path: String) {
        if self.replaying() {
            self.set_status(StatusLevel::Info, "Not available while replaying a recording — this would act on the live system".into());
            return;
        }
        if !Path::new(&path).is_file() {
            self.set_status(StatusLevel::Error, format!("Not a file: {path}"));
            return;
        }
        self.mode = Mode::Confirm { cmd: Cmd::Quarantine(path), targets: Vec::new() };
    }

    pub fn do_quarantine(&mut self, path: &str) {
        self.mode = Mode::Normal;
        let Some(case) = self.ensure_case() else { return };
        match contain::quarantine(case, Path::new(path)) {
            Ok(q) => self.set_status(StatusLevel::Success, format!("Quarantined {} → {}", q.original_path, q.stored_as)),
            Err(e) => self.set_status(StatusLevel::Error, format!("Quarantine failed: {e} (files owned by root need sudo)")),
        }
        self.ir.timeline_dirty = true;
    }

    pub fn quarantined(&self) -> Vec<Quarantined> {
        self.ir.case.as_ref().map(contain::list).unwrap_or_default()
    }

    pub fn restore_selected(&mut self) {
        let list = self.quarantined();
        let Some(q) = list.get(self.ir.quarantine_selected).cloned() else { return };
        if q.restored {
            self.set_status(StatusLevel::Info, "Already restored".into());
            return;
        }
        let Some(case) = self.ir.case.as_ref() else { return };
        match contain::restore(case, &q) {
            Ok(()) => self.set_status(StatusLevel::Success, format!("Restored {}", q.original_path)),
            Err(e) => self.set_status(StatusLevel::Error, format!("Restore failed: {e}")),
        }
    }
}
