//! What happens on each snapshot and tick, and how worker results arrive.

use super::*;

impl App {
    // ── lifecycle hooks ────────────────────────────────────────────────

    pub(crate) fn update_network_intel(&mut self) {
        let now = Local::now();
        let current: HashSet<(u32, Connection)> =
            self.connections.iter().flat_map(|(pid, cs)| cs.iter().map(move |c| (*pid, c.clone()))).collect();
        self.ir.conn_first_seen.retain(|k, _| current.contains(k));
        for k in current {
            self.ir.conn_first_seen.entry(k).or_insert(now);
        }

        // Aggregate by remote IP over current sockets and connect history.
        struct Acc {
            processes: std::collections::BTreeSet<String>,
            ports: std::collections::BTreeSet<String>,
            current: usize,
            connects: Vec<DateTime<Local>>,
            pids: HashSet<u32>,
            first: DateTime<Local>,
            last: DateTime<Local>,
        }
        let mut by: HashMap<String, Acc> = HashMap::new();
        let mut add = |ip: String, port: String, name: String, pid: u32, t: DateTime<Local>, connect: bool, current: bool| {
            let a = by.entry(ip).or_insert_with(|| Acc {
                processes: Default::default(),
                ports: Default::default(),
                current: 0,
                connects: Vec::new(),
                pids: HashSet::new(),
                first: t,
                last: t,
            });
            a.processes.insert(name);
            a.ports.insert(port);
            a.pids.insert(pid);
            a.first = a.first.min(t);
            a.last = a.last.max(t);
            if connect {
                a.connects.push(t);
            }
            if current {
                a.current += 1;
            }
        };
        for ((pid, c), t) in &self.ir.conn_first_seen {
            if c.state == ConnState::Listen || c.remote == "*:*" {
                continue;
            }
            let (ip, port) = split_endpoint(&c.remote);
            add(ip, port, self.name_of(*pid), *pid, *t, false, true);
        }
        for e in self.ir.net_events.iter().filter(|e| e.kind == "connect") {
            let (ip, port) = split_endpoint(&e.conn.remote);
            if ip == "*" {
                continue;
            }
            add(ip, port, e.name.clone(), e.pid, e.time, true, false);
        }
        // Beaconing is judged per (process, address): many programs talking
        // to the same address would otherwise blur each other's rhythm.
        // Keyed by the remote *service* (address + port): an accepted
        // inbound socket has a fresh ephemeral remote port every time and
        // so never forms a series.
        let mut per_pair: HashMap<(u32, String, String), Vec<DateTime<Local>>> = HashMap::new();
        for e in self.ir.net_events.iter().filter(|e| e.kind == "connect") {
            let (ip, port) = split_endpoint(&e.conn.remote);
            if ip != "*" {
                per_pair.entry((e.pid, ip, port)).or_default().push(e.time);
            }
        }
        let mut beacons: HashMap<u32, (String, f64)> = HashMap::new();
        let mut beacon_by_ip: HashMap<String, f64> = HashMap::new();
        for ((pid, ip, port), mut times) in per_pair {
            times.sort();
            if let Some(iv) = beacon_interval(&times) {
                beacons.insert(pid, (format!("{ip}:{port}"), iv));
                beacon_by_ip.insert(ip, iv);
            }
        }
        let mut remotes: Vec<RemoteSummary> = by
            .into_iter()
            .map(|(ip, a)| {
                let beacon = beacon_by_ip.get(&ip).copied();
                let host = self.host_for(&ip, None);
                let public = !matches!(ip.parse::<std::net::IpAddr>(), Ok(addr) if match addr {
                    std::net::IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
                    std::net::IpAddr::V6(v) => v.is_loopback() || (v.segments()[0] & 0xffc0) == 0xfe80 || (v.segments()[0] & 0xfe00) == 0xfc00,
                });
                RemoteSummary {
                    ip,
                    host,
                    public,
                    processes: a.processes.into_iter().collect(),
                    ports: a.ports.into_iter().collect(),
                    current: a.current,
                    connects: a.connects.len(),
                    first_seen: a.first.format("%H:%M:%S").to_string(),
                    last_seen: a.last.format("%H:%M:%S").to_string(),
                    beacon,
                }
            })
            .collect();
        remotes.sort_by(|a, b| b.beacon.is_some().cmp(&a.beacon.is_some()).then(b.public.cmp(&a.public)).then(b.connects.cmp(&a.connects)).then(a.ip.cmp(&b.ip)));
        self.ir.remotes = remotes;
        self.ir.beacons = beacons;
    }

    /// Learn per-executable behaviour and report what's new to a program
    /// with an established profile.
    pub(crate) fn update_profiles(&mut self) {
        if self.ir.profiles.is_none() || self.replaying() {
            return;
        }
        let elapsed = self.ir.last_profile.map(|t| t.elapsed().as_secs());
        if elapsed.is_some_and(|e| e < 5) {
            return;
        }
        self.ir.last_profile = Some(Instant::now());
        let elapsed = elapsed.unwrap_or(0);
        let intel = self.ir.intel.snapshot();
        let now = Local::now();
        let alive: HashSet<ProcKey> = self.tree.nodes.values().map(|n| ProcKey { pid: n.info.pid, start: n.info.start_time_secs }).collect();
        self.ir.profile_runs.retain(|k, _| alive.contains(k));
        let mut found: Vec<(u32, Vec<crate::detection::profile::Novelty>)> = Vec::new();
        let system = |p: &str| {
            let l = p.to_lowercase();
            l.starts_with("/usr/lib") || l.starts_with("/system/") || l.starts_with("/lib") || l.contains("\\windows\\")
        };
        for n in self.tree.nodes.values() {
            let i = &n.info;
            if self.is_own_helper(i) {
                continue;
            }
            let Some(exe) = i.exe_path.as_deref() else { continue };
            let sha = intel.get(exe).and_then(|x| x.sha256.clone());
            let key = match &sha {
                Some(h) => format!("sha:{h}"),
                None => format!("path:{exe}"),
            };
            let pk = ProcKey { pid: i.pid, start: i.start_time_secs };
            let profiles = self.ir.profiles.as_mut().unwrap();
            if self.ir.profile_runs.get(&pk) != Some(&key) {
                profiles.new_run(&key, exe, sha.as_deref(), now);
                self.ir.profile_runs.insert(pk, key.clone());
            }
            let conns = self.connections.get(&i.pid);
            let listen_ports: HashSet<String> =
                conns.into_iter().flatten().filter(|c| c.state == ConnState::Listen).map(|c| split_endpoint(&c.local).1).collect();
            let mut obs = crate::detection::profile::Observation::default();
            for c in conns.into_iter().flatten() {
                if c.state == ConnState::Listen {
                    obs.listens.push(format!("{}/{}", c.protocol, split_endpoint(&c.local).1));
                } else if c.remote != "*:*" && !listen_ports.contains(&split_endpoint(&c.local).1) {
                    obs.destinations.push(c.remote.clone());
                }
            }
            for ch in &n.children {
                if let Some(cn) = self.tree.get(*ch) {
                    obs.children.push(cn.info.exe_path.as_deref().and_then(|p| p.rsplit(['/', '\\']).next()).unwrap_or(&cn.info.name).to_string());
                }
            }
            if let Some(m) = self.ir.deep.snaps.get(&pk).and_then(|s| s.modules.as_ref()) {
                obs.modules.extend(m.iter().filter(|p| !system(p)).cloned());
            }
            let new = profiles.observe(&key, &obs, elapsed, now);
            if !new.is_empty() {
                found.push((i.pid, new));
            }
        }
        for (pid, new) in found {
            let key = self.ir.profile_runs.get(&self.proc_key(pid)).cloned().unwrap_or_default();
            let (runs, since) = self.ir.profiles.as_ref().and_then(|p| p.by_key.get(&key)).map(|p| (p.runs, p.first_seen.get(..10).unwrap_or("").to_string())).unwrap_or_default();
            let what: Vec<String> = new.iter().map(|n| n.describe()).collect();
            let hit = crate::detection::triage::RuleHit::from_def(
                crate::detection::triage::rule("PW-018").expect("rule"),
                format!("first time in {runs} runs since {since}: {}", what.join("; ")),
            );
            self.record_detection_pub(&hit, Entity::Process(self.proc_key(pid)), format!("{} ({pid})", self.name_of(pid)), Some(pid), "baseline");
        }
        if self.ir.last_profile_save.is_none_or(|t| t.elapsed().as_secs() >= 60) {
            self.ir.last_profile_save = Some(Instant::now());
            if let Some(p) = self.ir.profiles.as_mut() {
                let _ = p.save();
            }
        }
    }

    /// Process table into the history every 10 minutes (for replay).
    pub(crate) fn store_snapshot(&mut self) {
        let due = self.ir.last_store_snapshot.is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(600));
        if !due || self.ir.store.is_none() {
            return;
        }
        self.ir.last_store_snapshot = Some(Instant::now());
        let processes: Vec<crate::forensics::store::ProcRec> = self
            .tree
            .nodes
            .values()
            .map(|n| crate::forensics::store::ProcRec {
                pid: n.info.pid,
                ppid: n.info.ppid,
                start: n.info.start_time_secs,
                name: n.info.name.clone(),
                exe: n.info.exe_path.clone(),
                cmd: n.info.cmd.join(" "),
                user: n.info.user.clone().unwrap_or_default(),
            })
            .collect();
        if let Some(st) = self.ir.store.as_mut() {
            st.write(Local::now(), crate::forensics::store::Rec::Snapshot { processes });
            st.flush();
            st.prune();
        }
    }

    pub(crate) fn ir_on_snapshot(&mut self) {
        let mut lap = crate::common::perf::Lap::new();
        self.store_snapshot();
        if let Some(st) = self.ir.store.as_mut() {
            st.flush();
        }
        lap.mark("investigation: store");
        self.update_network_intel();
        lap.mark("investigation: network intel");
        self.triage_all();
        lap.mark("investigation: triage");
        self.response_on_snapshot();
        self.deep_auto_enroll();
        self.deep_tick();
        self.launch_tick();
        lap.mark("investigation: deep trace");
        self.update_profiles();
        lap.mark("investigation: profiles");
        if self.mode == Mode::Workspace {
            self.refresh_workspace();
            lap.mark("investigation: workspace");
        }
        // System-wide socket changes become network events.
        let now: HashSet<(u32, Connection)> =
            self.connections.iter().flat_map(|(pid, cs)| cs.iter().map(move |c| (*pid, c.clone()))).collect();
        if let Some(prev) = self.ir.prev_sockets.take() {
            let t = Local::now();
            let mut opened: Vec<&(u32, Connection)> = now.difference(&prev).collect();
            opened.sort();
            let mut closed: Vec<&(u32, Connection)> = prev.difference(&now).collect();
            closed.sort();
            let fresh: Vec<(u32, Connection)> = opened.iter().map(|(p, c)| (*p, c.clone())).collect();
            self.sigma_on_sockets(&fresh);
            let mut add = Vec::new();
            // Windows has exact events for these; elsewhere this is the source.
            if self.ir.capture_method.is_some() && !cfg!(windows) {
                let batch = opened.iter().filter(|(_, c)| c.state != ConnState::Listen).map(|(pid, c)| crate::activity::Activity::new(*pid, crate::activity::Class::Network, "connect", c.remote.clone()).with_detail(format!("{} from {}", c.protocol, c.local))).collect();
                self.on_activity(batch);
            }
            for (pid, c) in opened {
                let kind = if c.state == ConnState::Listen { "listen" } else { "connect" };
                add.push(NetEvent { time: t, kind, pid: *pid, name: self.name_of(*pid), conn: c.clone() });
            }
            for (pid, c) in closed {
                let kind = if c.state == ConnState::Listen { "unlisten" } else { "close" };
                let name = self.ir.net_events.iter().rev().find(|e| e.pid == *pid).map(|e| e.name.clone()).unwrap_or_else(|| self.name_of(*pid));
                add.push(NetEvent { time: t, kind, pid: *pid, name, conn: c.clone() });
            }
            if let Some(st) = self.ir.store.as_mut() {
                for e in &add {
                    st.write(
                        e.time,
                        crate::forensics::store::Rec::Net {
                            kind: e.kind.into(),
                            pid: e.pid,
                            name: e.name.clone(),
                            proto: e.conn.protocol.into(),
                            local: e.conn.local.clone(),
                            remote: e.conn.remote.clone(),
                            state: e.conn.state.label().into(),
                        },
                    );
                }
            }
            for e in add {
                if self.ir.net_events.len() >= MAX_NET_EVENTS {
                    self.ir.net_events.pop_front();
                }
                self.ir.net_events.push_back(e);
            }
        }
        self.ir.prev_sockets = Some(now);
        lap.mark("investigation: sockets");

        // Ask for reverse names of remote peers (cached, background).
        let remotes: Vec<String> = self
            .connections
            .values()
            .flatten()
            .filter(|c| c.state != ConnState::Listen && c.remote != "*:*")
            .map(|c| split_endpoint(&c.remote).0)
            .collect();
        for ip in remotes {
            self.ir.resolver.name(&ip);
        }
        self.ir.timeline_dirty = true;

        let tree = &self.tree;
        self.ir.memory.retain(|pid, (start, _)| tree.get(*pid).is_some_and(|n| n.info.start_time_secs == *start));
    }

    /// Returns true if the message was an investigation message.
    pub(crate) fn ir_on_msg(&mut self, msg: WorkerMsg) {
        match msg {
            WorkerMsg::Fs(e) => {
                // Our own case folder isn't evidence of anything.
                if self.ir.case.as_ref().is_some_and(|c| Path::new(&e.path).starts_with(&c.dir))
                    || e.path.contains("/procwatch-case-")
                    || e.path.contains("\\procwatch-case-")
                {
                    return;
                }
                if self.ir.fs_events.len() >= MAX_FS_EVENTS {
                    self.ir.fs_events.pop_front();
                }
                self.sigma_on_fs(&e);
                if crate::files::watch::autostart_location(&e.path) && !self.replaying() {
                    let owner = self.file_owner_near(&e.path, e.time);
                    // Attribution looks for the newest write: drop the oldest.
                    if self.ir.persist_writers.len() >= 200 {
                        self.ir.persist_writers.remove(0);
                    }
                    self.ir.persist_writers.push((e.path.clone(), e.time, owner));
                    self.ir.persist_rescan_at = Some(Instant::now() + std::time::Duration::from_secs(3));
                }
                if let Some(st) = self.ir.store.as_mut() {
                    st.write(e.time, crate::forensics::store::Rec::File { kind: e.kind.into(), path: e.path.clone() });
                }
                self.ir.fs_events.push_back(e);
                self.ir.timeline_dirty = true;
            }
            WorkerMsg::Persistence(scan) => {
                let flagged = scan.items.iter().filter(|i| i.suspicious()).count();
                let changes = self.persistence_diff(&scan.items);
                if !self.ir.persist_auto || changes > 0 {
                    self.set_status(
                        if changes > 0 { StatusLevel::Error } else { StatusLevel::Info },
                        format!(
                            "Persistence scan: {} entries, {flagged} flagged for review{}",
                            scan.items.len(),
                            if changes > 0 { format!(" · {changes} added/changed/removed since the last scan — see Detect") } else { String::new() }
                        ),
                    );
                }
                self.ir.persist_auto = false;
                self.ir.persistence = Some(Loaded { pending: false, fetched: Instant::now(), result: Ok(scan) });
            }
            WorkerMsg::Logs(result) => {
                self.ir.logs = Some(Loaded { pending: false, fetched: Instant::now(), result });
                self.ir.log_selected = 0;
                self.sigma_on_logs();
                let found: Vec<dns::DnsObs> = self
                    .log_entries()
                    .iter()
                    .filter(|e| e.event_id == Some(22) && e.source.to_lowercase().contains("sysmon"))
                    .filter_map(|e| dns::from_sysmon_message(e.time, &e.message))
                    .collect();
                self.add_dns_obs(found);
                self.ir.timeline_dirty = true;
            }
            WorkerMsg::Artifacts { from, scan } => {
                let scan = *scan;
                let events: Vec<(crate::detection::sigma::Event, DateTime<Local>, String)> =
                    scan.records.iter().map(|r| (crate::detection::sigma::map::record_event(r), r.time, format!("{} {} on {}", r.channel, r.event_id, r.computer))).collect();
                let hits = self.sigma_on_events(&events);
                let found: Vec<dns::DnsObs> = scan
                    .records
                    .iter()
                    .filter(|r| r.event_id == 22 && crate::detection::sigma::map::service_of(&r.channel) == "sysmon")
                    .filter_map(|r| dns::from_sysmon_fields(r.time, &r.data))
                    .collect();
                self.add_dns_obs(found);
                let msg = format!(
                    "{} artifacts{}{}",
                    scan.items.len(),
                    if scan.records.is_empty() { String::new() } else { format!(", {} event records ({hits} Sigma hits)", scan.records.len()) },
                    if scan.notes.is_empty() { String::new() } else { format!(" · {} note(s)", scan.notes.len()) }
                );
                match from {
                    Some(dir) => {
                        if let Some(c) = &self.ir.case {
                            let _ = c.log("artifacts imported", &format!("{}: {msg}", dir.display()));
                        }
                        self.ir.artifacts_imported.retain(|(d, _, _)| d != &dir);
                        self.ir.artifacts_imported.push((dir.clone(), scan.items, scan.notes));
                        self.set_status(StatusLevel::Success, format!("Imported {}: {msg}", dir.display()));
                    }
                    None => {
                        self.ir.live_artifacts = scan.items;
                        self.ir.artifacts_live = Some(Loaded { pending: false, fetched: Instant::now(), result: Ok(scan.notes) });
                    }
                }
                let mut all = self.ir.live_artifacts.clone();
                for (_, items, _) in &self.ir.artifacts_imported {
                    all.extend(items.iter().cloned());
                }
                crate::host::artifacts::sort_newest_first(&mut all);
                self.ir.artifacts = all;
                self.ir.timeline_dirty = true;
            }
            WorkerMsg::Activity(batch) => self.on_activity(batch),
            WorkerMsg::CaptureState(s) => self.on_capture_state(s),
            WorkerMsg::WatchStatus(s) => {
                self.ir.watch_errors = s.errors;
                if !s.attribution.is_empty() {
                    self.ir.deep.attribution = s.attribution;
                }
            }
            WorkerMsg::TrafficState(s) => match s {
                Ok(how) => self.ir.traffic_how = Some(how),
                Err(e) => self.ir.traffic_error = Some(e),
            },
            WorkerMsg::Traffic(totals) => self.on_traffic(totals),
            WorkerMsg::Dns { resolvers, cache } => {
                self.ir.dns_pending = false;
                self.ir.resolvers = resolvers;
                self.ir.dns_cache = Some(cache);
            }
            WorkerMsg::Deep(evs) => self.deep_on_events(evs),
            WorkerMsg::DeepSnap { pid, start, modules, files } => self.deep_on_snap(pid, start, modules, files),
            WorkerMsg::Yara { results, scanned, failed } => {
                self.ir.yara_pending = false;
                let hits = self.record_yara(results);
                let msg = format!("Content scan: {scanned} executables, {hits} matched{}", if failed.is_empty() { String::new() } else { format!(", {} unreadable", failed.len()) });
                if let Some(c) = &self.ir.case {
                    let _ = c.log("content scan", &msg);
                }
                self.set_status(if hits > 0 { StatusLevel::Error } else { StatusLevel::Success }, msg);
            }
            WorkerMsg::FileReport(r) => {
                self.ir.file_report = Some(Loaded { pending: false, fetched: Instant::now(), result: Ok(*r) });
            }
            WorkerMsg::Memory { pid, report } => {
                if self.ir.memory_pending == Some(pid) {
                    self.ir.memory_pending = None;
                }
                if let Some(n) = self.tree.get(pid) {
                    self.ir.memory.insert(pid, (n.info.start_time_secs, *report));
                }
            }
            WorkerMsg::Evidence(result) => match result {
                Ok(msg) => self.set_status(StatusLevel::Success, msg),
                Err(e) => self.set_status(StatusLevel::Error, format!("Evidence collection failed: {e}")),
            },
            _ => {}
        }
    }

    /// On Windows this runs PowerShell for seconds, so never on this thread.
    pub(crate) fn collect_dns(&mut self) {
        self.ir.dns_asked = true;
        self.ir.dns_pending = true;
        crate::engine::jobs::spawn_dns(self.tx.clone());
    }

    pub(crate) fn ir_on_tick(&mut self) -> bool {
        let mut dirty = false;
        if self.replaying() {
            if self.ir.timeline_dirty && self.tab == Tab::Timeline {
                self.rebuild_timeline();
                return true;
            }
            return false;
        }
        // Live persistence monitoring: a first scan shortly after start,
        // then after changes in autostart folders and every 15 minutes.
        let scanning = self.ir.persistence.as_ref().is_some_and(|p| p.pending);
        let due = match (self.ir.persist_rescan_at, self.ir.persist_last_scan) {
            (Some(at), _) => Instant::now() >= at,
            (None, None) => (Local::now() - self.ir.watch_start).num_seconds() >= 30,
            (None, Some(last)) => last.elapsed() >= std::time::Duration::from_secs(900),
        };
        if due && !scanning && self.tab != Tab::Persistence && self.module_on("persistence") {
            self.ir.persist_auto = true;
            self.scan_persistence();
        }
        if !self.ir.dns_asked && !self.ir.dns_pending && self.module_on("network") {
            self.collect_dns();
        }
        if self.ir.capture_method.is_some() && !self.module_on("activity") {
            self.ir.capture_method = None;
        }
        if !self.tab_on(self.tab) {
            // Its module was switched off.
            if let Some(first) = self.first_tab() {
                self.tab = first;
            }
            return true;
        }
        if self.tab == Tab::Activity {
            self.refresh_activity_view();
        }
        match self.tab {
            Tab::Persistence if self.ir.persistence.is_none() => {
                self.scan_persistence();
                dirty = true;
            }
            Tab::Logs if self.ir.artifacts_view && self.ir.artifacts_live.is_none() => {
                self.collect_artifacts();
                dirty = true;
            }
            Tab::Logs if self.ir.logs.is_none() => {
                self.fetch_logs();
                dirty = true;
            }
            Tab::Timeline if self.timeline_rebuild_due() => {
                self.rebuild_timeline();
                dirty = true;
            }
            Tab::Network if self.ir.net_dns_view && self.ir.dns_cache.is_none() && !self.ir.dns_pending => {
                self.collect_dns();
                dirty = true;
            }
            _ => {}
        }
        // Hash the executable of whatever process is being looked at.
        if let Some(path) = self.detail_pid().and_then(|p| self.tree.get(p)).and_then(|n| n.info.exe_path.clone()) {
            self.ir.intel.request(&path, true);
        }
        // Memory tab: needs the module list first, then the memory report.
        if self.details_visible() && self.pane_tab == PaneTab::Memory {
            if let Some(pid) = self.detail_pid() {
                let modules = self.deep_cache.get(&pid).filter(|e| e.info.modules_loaded).map(|e| e.info.loaded_modules.clone());
                if let Some(modules) = modules {
                    if !self.ir.memory.contains_key(&pid) && self.ir.memory_pending.is_none() {
                        self.ir.memory_pending = Some(pid);
                        crate::engine::jobs::spawn_memory(self.tx.clone(), pid, modules);
                        dirty = true;
                    }
                }
            }
        }
        dirty
    }

    pub fn collect_artifacts(&mut self) {
        if self.replaying() {
            self.set_status(StatusLevel::Info, "Not available while replaying a recording — this would act on the live system".into());
            return;
        }
        if self.ir.artifacts_live.as_ref().is_some_and(|l| l.pending) {
            return;
        }
        self.ir.artifacts_live = Some(Loaded { pending: true, fetched: Instant::now(), result: Ok(Vec::new()) });
        crate::engine::jobs::spawn_artifacts(self.tx.clone(), None);
    }

    pub fn import_artifacts(&mut self, dir: &str) {
        let p = PathBuf::from(dir.trim());
        if !p.is_dir() {
            self.mode = Mode::Input { purpose: InputPurpose::ArtifactDir, input: dir.into(), error: Some("not a folder".into()) };
            return;
        }
        self.set_status(StatusLevel::Info, format!("Reading artifacts in {}…", p.display()));
        crate::engine::jobs::spawn_artifacts(self.tx.clone(), Some(p));
    }

    pub(crate) fn add_dns_obs(&mut self, mut found: Vec<dns::DnsObs>) {
        if found.is_empty() {
            return;
        }
        found.sort_by_key(|o| o.time);
        for o in found {
            let dup = self.ir.dns_obs.iter().rev().take(64).any(|x| x.time == o.time && x.name == o.name && x.pid == o.pid);
            if !dup {
                if self.ir.dns_obs.len() >= 20_000 {
                    self.ir.dns_obs.pop_front();
                }
                self.ir.dns_obs.push_back(o);
            }
        }
        self.ir.dns_obs.make_contiguous().sort_by_key(|o| o.time);
    }

    /// Host name for a remote address: the DNS query that produced it if
    /// recorded, else the reverse lookup (labelled as such).
    pub fn host_for(&self, ip: &str, pid: Option<u32>) -> Option<String> {
        if let Some((name, same)) = dns::name_for(&self.ir.dns_obs, ip, pid, Local::now()) {
            return Some(if same { format!("{name} (queried by this process)") } else { format!("{name} (queried)") });
        }
        self.ir.resolver.cached(ip).map(|h| format!("{h} (reverse lookup)"))
    }

    pub fn visible_remotes(&self) -> Vec<usize> {
        let f = Filter::parse(&self.query);
        self.ir.remotes.iter().enumerate().filter(|(_, r)| f.matches(*r)).map(|(i, _)| i).collect()
    }

    pub fn visible_artifacts(&self) -> Vec<usize> {
        let f = Filter::parse(&self.query);
        self.ir.artifacts.iter().enumerate().filter(|(_, a)| f.matches(*a)).map(|(i, _)| i).collect()
    }

    pub fn ir_busy(&self) -> bool {
        self.ir.artifacts_live.as_ref().is_some_and(|p| p.pending)
            || self.ir.persistence.as_ref().is_some_and(|p| p.pending)
            || self.ir.logs.as_ref().is_some_and(|l| l.pending)
            || self.ir.file_report.as_ref().is_some_and(|f| f.pending)
            || self.ir.memory_pending.is_some()
    }
}
