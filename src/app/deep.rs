//! Process-centric deep trace for `App`: which process instances are
//! enrolled (by the analyst or automatically when they look suspicious),
//! their precise lifecycle events from the watcher, and periodic module and
//! open-file snapshots whose differences become module-load and file
//! events. A child module of `app`.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use serde::Serialize;

use super::*;
use crate::process::deeptrace::{DtEvent, DtKind};
use crate::common::model::ProcKey;

const MAX_EVENTS: usize = 20_000;
const MAX_CHANGES: usize = 50_000;
/// Roots enrolled automatically (each brings its descendants).
const MAX_AUTO_ROOTS: usize = 16;
/// Live enrolled processes snapshotted per refresh at most.
const SNAPS_PER_TICK: usize = 6;
const FILES_EVERY: Duration = Duration::from_secs(3);
const MODULES_EVERY: Duration = Duration::from_secs(20);
/// Priority at which a process is enrolled automatically.
pub const AUTO_PRIORITY: u8 = 45;

#[derive(Debug, Clone, Serialize)]
pub struct Enrolled {
    pub reason: String,
    #[serde(serialize_with = "ser_time")]
    pub since: DateTime<Local>,
    /// The enrolled ancestor this one came in through (itself for roots).
    pub root: ProcKey,
    pub auto: bool,
    pub ended: Option<String>,
}

fn ser_time<S: serde::Serializer>(t: &DateTime<Local>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&t.to_rfc3339())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    ModuleLoad,
    ModuleUnload,
    FileOpen,
    FileClose,
}

impl ChangeKind {
    pub fn label(self) -> &'static str {
        match self {
            ChangeKind::ModuleLoad => "module load",
            ChangeKind::ModuleUnload => "module unload",
            ChangeKind::FileOpen => "file open",
            ChangeKind::FileClose => "file close",
        }
    }
}

/// A difference between two snapshots of one process.
#[derive(Debug, Clone, Serialize)]
pub struct Change {
    #[serde(serialize_with = "ser_time")]
    pub at: DateTime<Local>,
    pub key: ProcKey,
    pub kind: ChangeKind,
    pub path: String,
}

#[derive(Default)]
pub struct Snap {
    pub modules: Option<BTreeSet<String>>,
    pub modules_at: Option<Instant>,
    pub files: Option<BTreeSet<String>>,
    pub files_at: Option<Instant>,
    pub pending: bool,
    pub errors: Vec<String>,
}

#[derive(Default)]
pub struct DeepState {
    /// Tracing has been asked for at least once.
    pub traced: bool,
    pub enrolled: HashMap<ProcKey, Enrolled>,
    pub events: VecDeque<DtEvent>,
    pub changes: VecDeque<Change>,
    pub snaps: HashMap<ProcKey, Snap>,
    /// Enroll suspicious processes without being asked.
    pub auto: bool,
    pub dropped: usize,
    /// macOS: fs_usage restricted to traced pids (root only).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fs_usage: Helper,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fs_usage_pids: Vec<u32>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fs_usage_at: Option<Instant>,
    /// How file operations are attributed to processes right now.
    pub attribution: String,
}

impl DeepState {
    /// Is a live instance of `pid` being traced?
    pub fn is_enrolled(&self, pid: u32) -> bool {
        self.enrolled.iter().any(|(k, e)| k.pid == pid && e.ended.is_none())
    }
}

/// A helper process stopped when procwatch exits.
#[derive(Default)]
pub struct Helper(pub Option<std::process::Child>);

impl Helper {
    pub fn stop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        self.stop();
    }
}

impl App {
    fn trace_request(&mut self, r: crate::process::trace_module::Request) -> bool {
        let sent = self.publish_to("trace", crate::process::trace_module::REQUEST, r);
        self.ir.deep.traced |= sent;
        sent
    }

    /// Enroll a process (and its current descendants) in deep trace.
    pub fn deep_enroll(&mut self, pid: u32, reason: String, auto: bool) {
        if self.replaying() {
            self.set_status(StatusLevel::Info, "Not available while replaying a recording — this would act on the live system".into());
            return;
        }
        let me = std::process::id();
        if pid == me || self.tree.get(pid).is_some_and(|n| self.is_own_helper(&n.info)) {
            return;
        }
        let root = self.proc_key(pid);
        if self.ir.deep.enrolled.contains_key(&root) {
            return;
        }
        let mut pids = vec![pid];
        pids.extend(self.tree.descendants(pid));
        let now = Local::now();
        for p in pids {
            let key = self.proc_key(p);
            let why = if p == pid { reason.clone() } else { format!("descendant of {} ({pid})", self.name_of(pid)) };
            self.ir.deep.enrolled.entry(key).or_insert(Enrolled { reason: why, since: now, root, auto, ended: None });
            self.trace_request(crate::process::trace_module::Request::Watch(p));
        }
        if let Some(c) = &self.ir.case {
            let _ = c.log("deep trace", &format!("{} ({pid}) enrolled: {reason}", self.name_of(pid)));
        }
        if !auto {
            self.set_status(StatusLevel::Success, format!("Deep trace on {} ({pid}) and its descendants", self.name_of(pid)));
        }
    }

    pub fn deep_stop(&mut self, pid: u32) {
        let root = self.proc_key(pid);
        let keys: Vec<ProcKey> = self.ir.deep.enrolled.iter().filter(|(k, e)| **k == root || e.root == root).map(|(k, _)| *k).collect();
        for k in keys {
            self.ir.deep.enrolled.remove(&k);
            self.trace_request(crate::process::trace_module::Request::Unwatch(k.pid));
        }
        self.set_status(StatusLevel::Info, format!("Deep trace stopped for {} ({pid})", self.name_of(pid)));
    }

    /// `--run`: start a program held at its first instruction, attach deep
    /// trace, then let it run. Output goes to a log in the case.
    pub fn launch_and_trace(&mut self, argv: Vec<String>) {
        let Some(case) = self.ensure_case().cloned() else { return };
        let log = case.dir.join("evidence").join(format!("run-{}.log", Local::now().format("%Y%m%d-%H%M%S")));
        let launched = match crate::process::launch::start(&argv, Some(&log)) {
            Ok(l) => l,
            Err(e) => {
                self.set_status(StatusLevel::Error, format!("Couldn't start {}: {e}", argv.join(" ")));
                return;
            }
        };
        let pid = launched.pid;
        let key = ProcKey { pid, start: crate::process::native::start_time(pid).unwrap_or(0) };
        self.ir.launched.insert(pid);
        let (reply, confirmed) = std::sync::mpsc::channel();
        let attached = self.trace_request(crate::process::trace_module::Request::WatchConfirmed(pid, reply)) && confirmed.recv_timeout(std::time::Duration::from_secs(3)).unwrap_or(false);
        self.ir.deep.enrolled.insert(key, Enrolled { reason: "launched by procwatch --run".into(), since: Local::now(), root: key, auto: false, ended: None });
        let sha = crate::files::info::sha256_file(Path::new(&launched.program)).unwrap_or_default();
        let _ = case.log(
            "program launched for analysis",
            &format!("{} (pid {pid}) sha256={sha} · trace attached before start: {attached} · output → {}", argv.join(" "), case.rel(&log)),
        );
        if let Err(e) = crate::process::launch::resume(&launched) {
            self.set_status(StatusLevel::Error, format!("Couldn't resume {}: {e}", launched.program));
            return;
        }
        self.ir.launch_logs.push((pid, log));
        self.request_refresh();
        self.set_status(
            if attached { StatusLevel::Success } else { StatusLevel::Error },
            if attached { format!("Running {} as pid {pid} under deep trace from its first instruction", argv.join(" ")) } else { format!("Running {} as pid {pid} — trace could NOT attach before start", argv.join(" ")) },
        );
        self.open_workspace_for(key);
    }

    /// Reap launched programs that exited; register their output logs.
    pub(super) fn launch_tick(&mut self) {
        let mut done = Vec::new();
        for (pid, log) in &self.ir.launch_logs {
            if let Some(code) = crate::process::launch::reap(*pid) {
                done.push((*pid, log.clone(), code));
            }
        }
        for (pid, log, code) in done {
            self.ir.launch_logs.retain(|(p, _)| *p != pid);
            if let Some(c) = &self.ir.case {
                let prov = crate::forensics::case::Provenance::live("stdout/stderr of the launched program").subject(format!("process:{pid}"));
                let _ = c.register_existing(&log, prov);
                let _ = c.log("launched program exited", &format!("pid {pid} exit status {code}"));
            }
            self.set_status(StatusLevel::Info, format!("Launched program (pid {pid}) exited with status {code}; its descendants are still traced"));
        }
    }

    pub fn toggle_deep(&mut self, pid: u32) {
        if !self.require("trace") {
            return;
        }
        if self.deep_enrolled(pid) {
            self.deep_stop(pid);
        } else {
            self.deep_enroll(pid, "started by analyst".into(), false);
        }
    }

    pub fn deep_enrolled(&self, pid: u32) -> bool {
        self.ir.deep.enrolled.contains_key(&self.proc_key(pid))
    }

    /// Automatic process investigation: enroll processes whose priority
    /// or detections cross the threshold.
    pub(super) fn deep_auto_enroll(&mut self) {
        if !self.ir.deep.auto {
            return;
        }
        let roots = self.ir.deep.enrolled.values().filter(|e| e.auto && e.ended.is_none()).map(|e| e.root).collect::<BTreeSet<_>>().len();
        if roots >= MAX_AUTO_ROOTS {
            return;
        }
        let mut candidates: Vec<(u32, String)> = Vec::new();
        for (pid, a) in &self.ir.triage {
            if a.score >= AUTO_PRIORITY && !self.ir.deep.enrolled.contains_key(&self.proc_key(*pid)) {
                let why = a.active().next().map(|h| format!("auto: priority {} — {} {}", a.score, h.id, h.name)).unwrap_or_default();
                candidates.push((*pid, why));
            }
        }
        candidates.sort_by_key(|(p, _)| std::cmp::Reverse(self.ir.triage.get(p).map_or(0, |a| a.score)));
        for (pid, why) in candidates.into_iter().take(MAX_AUTO_ROOTS - roots) {
            self.deep_enroll(pid, why, true);
        }
    }

    pub(super) fn deep_on_events(&mut self, evs: Vec<DtEvent>) {
        for e in evs {
            match e.kind {
                DtKind::Spawn => {
                    let key = ProcKey { pid: e.pid, start: e.start };
                    let parent = e.ppid.map(|pp| self.proc_key(pp));
                    let root = parent.and_then(|p| self.ir.deep.enrolled.get(&p).map(|x| x.root)).unwrap_or(key);
                    let auto = parent.and_then(|p| self.ir.deep.enrolled.get(&p).map(|x| x.auto)).unwrap_or(false);
                    let pname = e.ppid.map(|pp| self.name_of(pp)).unwrap_or_default();
                    self.ir.deep.enrolled.entry(key).or_insert(Enrolled {
                        reason: format!("child of {pname} ({})", e.ppid.unwrap_or(0)),
                        since: e.at,
                        root,
                        auto,
                        ended: if e.start == 0 { Some("exited before it could be inspected".into()) } else { None },
                    });
                }
                DtKind::Exit => {
                    let at = e.at.format("%H:%M:%S%.3f").to_string();
                    for (k, en) in self.ir.deep.enrolled.iter_mut() {
                        if k.pid == e.pid && en.ended.is_none() {
                            en.ended = Some(format!("exited {at}"));
                        }
                    }
                }
                DtKind::Exec => {}
            }
            if let Some(st) = self.ir.store.as_mut() {
                st.write(
                    e.at,
                    crate::forensics::store::Rec::Deep { kind: e.kind.label().into(), pid: e.pid, ppid: e.ppid, start: e.start, path: e.path.clone(), args: e.args.clone(), via: e.via.into() },
                );
            }
            if self.ir.deep.events.len() >= MAX_EVENTS {
                self.ir.deep.events.pop_front();
                self.ir.deep.dropped += 1;
            }
            self.ir.deep.events.push_back(e);
        }
        self.ir.timeline_dirty = true;
    }

    /// macOS + root: keep fs_usage following the live traced processes.
    fn deep_fs_usage(&mut self) {
        #[cfg(target_os = "macos")]
        {
            if crate::files::attribution::unavailable_reason().is_some() || self.replaying() {
                return;
            }
            let mut pids: Vec<u32> = self.ir.deep.enrolled.iter().filter(|(_, e)| e.ended.is_none()).map(|(k, _)| k.pid).collect();
            pids.sort_unstable();
            pids.truncate(64);
            let recent = self.ir.deep.fs_usage_at.is_some_and(|t| t.elapsed() < Duration::from_secs(5));
            if pids == self.ir.deep.fs_usage_pids || recent {
                return;
            }
            self.ir.deep.fs_usage.stop();
            self.ir.deep.fs_usage = Helper(crate::files::attribution::start_fs_usage(&pids, crate::common::emit::Emit::to(self.tx.clone(), WorkerMsg::Fs)));
            self.ir.deep.attribution = if self.ir.deep.fs_usage.0.is_some() { format!("fs_usage on {} traced processes", pids.len()) } else { String::new() };
            self.ir.deep.fs_usage_pids = pids;
            self.ir.deep.fs_usage_at = Some(Instant::now());
        }
    }

    /// Ask for module / open-file snapshots of live enrolled processes.
    pub(super) fn deep_tick(&mut self) {
        self.deep_fs_usage();
        let now = Instant::now();
        let mut due: Vec<(ProcKey, bool, bool)> = Vec::new();
        for (k, e) in &self.ir.deep.enrolled {
            if e.ended.is_some() || self.tree.get(k.pid).is_none_or(|n| n.info.start_time_secs.abs_diff(k.start) > 2) {
                continue;
            }
            let s = self.ir.deep.snaps.get(k);
            if s.is_some_and(|s| s.pending) {
                continue;
            }
            let files = s.and_then(|s| s.files_at).is_none_or(|t| now - t >= FILES_EVERY);
            let modules = s.and_then(|s| s.modules_at).is_none_or(|t| now - t >= MODULES_EVERY);
            if files || modules {
                due.push((*k, modules, files));
            }
        }
        due.sort_by_key(|(k, m, _)| (!*m, k.pid));
        for (k, modules, files) in due.into_iter().take(SNAPS_PER_TICK) {
            self.ir.deep.snaps.entry(k).or_default().pending = true;
            crate::engine::jobs::spawn_deep_snap(self.tx.clone(), k.pid, k.start, modules, files);
        }
        // Mark instances that disappeared without an exit event (e.g. the
        // watcher was started after they were enrolled and missed it).
        for (k, e) in self.ir.deep.enrolled.iter_mut() {
            if e.ended.is_none() && self.tree.get(k.pid).is_none_or(|n| n.info.start_time_secs.abs_diff(k.start) > 2) && k.start > 0 {
                e.ended = Some("gone (seen at refresh)".into());
            }
        }
    }

    pub(super) fn deep_on_snap(&mut self, pid: u32, start: u64, modules: Option<Result<Vec<String>, String>>, files: Option<Result<Vec<crate::process::inspect::OpenFile>, String>>) {
        let key = ProcKey { pid, start };
        let at = Local::now();
        let mut out: Vec<Change> = Vec::new();
        let snap = self.ir.deep.snaps.entry(key).or_default();
        snap.pending = false;
        if let Some(r) = modules {
            snap.modules_at = Some(Instant::now());
            match r {
                Ok(list) => {
                    let new: BTreeSet<String> = list.into_iter().collect();
                    if let Some(old) = &snap.modules {
                        out.extend(new.difference(old).map(|p| Change { at, key, kind: ChangeKind::ModuleLoad, path: p.clone() }));
                        out.extend(old.difference(&new).map(|p| Change { at, key, kind: ChangeKind::ModuleUnload, path: p.clone() }));
                    }
                    snap.modules = Some(new);
                }
                Err(e) => snap.errors.push(format!("modules: {e}")),
            }
        }
        if let Some(r) = files {
            snap.files_at = Some(Instant::now());
            match r {
                Ok(list) => {
                    let new: BTreeSet<String> =
                        list.into_iter().filter(|f| f.kind == "REG" || f.kind.is_empty()).map(|f| f.name).filter(|n| n.starts_with('/') || n.get(1..3) == Some(":\\")).collect();
                    match &snap.files {
                        Some(old) => {
                            out.extend(new.difference(old).map(|p| Change { at, key, kind: ChangeKind::FileOpen, path: p.clone() }));
                            out.extend(old.difference(&new).map(|p| Change { at, key, kind: ChangeKind::FileClose, path: p.clone() }));
                        }
                        // First look: what it already had open.
                        None => out.extend(new.iter().take(200).map(|p| Change { at, key, kind: ChangeKind::FileOpen, path: p.clone() })),
                    }
                    snap.files = Some(new);
                }
                Err(e) => snap.errors.push(format!("files: {e}")),
            }
        }
        snap.errors.truncate(8);
        if !out.is_empty() {
            for c in out {
                if let Some(st) = self.ir.store.as_mut() {
                    st.write(c.at, crate::forensics::store::Rec::Change { pid: c.key.pid, start: c.key.start, kind: c.kind.label().into(), path: c.path.clone() });
                }
                if self.ir.deep.changes.len() >= MAX_CHANGES {
                    self.ir.deep.changes.pop_front();
                    self.ir.deep.dropped += 1;
                }
                self.ir.deep.changes.push_back(c);
            }
            self.ir.timeline_dirty = true;
        }
    }

    /// Which enrolled process had `path` open around `t` (from snapshots):
    /// attribution for file-change notifications, which carry no process.
    pub fn file_owner_near(&self, path: &str, t: DateTime<Local>) -> Option<ProcKey> {
        let window = chrono::Duration::seconds(5);
        self.ir
            .deep
            .changes
            .iter()
            .rev()
            .find(|c| c.kind == ChangeKind::FileOpen && c.path == path && (c.at - t).abs() <= window)
            .map(|c| c.key)
            .or_else(|| self.ir.deep.snaps.iter().find(|(_, s)| s.files.as_ref().is_some_and(|f| f.contains(path))).map(|(k, _)| *k))
    }
}
