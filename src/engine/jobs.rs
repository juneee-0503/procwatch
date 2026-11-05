//! One-shot background work. Everything that can block runs here, off the
//! UI thread, and reports on the worker channel.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use super::messages::WorkerMsg;
use crate::common::emit::Emit;
use crate::common::panic_text;
use crate::process::actions::{self, Action};
use crate::process::inspect::{self, DeepInfo};

/// Deep trace reporting into the worker channel.
pub fn deep_output(tx: &Sender<WorkerMsg>) -> crate::process::deeptrace::Output {
    crate::process::deeptrace::Output { events: Emit::to(tx.clone(), WorkerMsg::Deep), errors: Emit::to(tx.clone(), WorkerMsg::Error) }
}

/// Run `body` on a named thread; if it panics, report `on_panic(message)`
/// instead of leaving the UI waiting forever for a result.
fn worker<B, P>(name: String, tx: Sender<WorkerMsg>, body: B, on_panic: P)
where
    B: FnOnce() -> WorkerMsg + Send + 'static,
    P: FnOnce(String) -> WorkerMsg + Send + 'static,
{
    let _ = thread::Builder::new().name(name).spawn(move || {
        let msg = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
            Ok(m) => m,
            Err(e) => on_panic(panic_text(&*e)),
        };
        let _ = tx.send(msg);
    });
}

pub fn spawn_inspect(tx: Sender<WorkerMsg>, pid: u32, start_time: u64, exe_path: Option<String>, modules: bool) {
    worker(
        format!("inspect-{pid}"),
        tx,
        move || WorkerMsg::Inspected { pid, start_time, info: Box::new(inspect::inspect(pid, exe_path.as_deref(), modules)) },
        move |e| {
            let mut info = DeepInfo::default();
            info.notes.push(format!("inspection crashed: {e}"));
            WorkerMsg::Inspected { pid, start_time, info: Box::new(info) }
        },
    );
}

/// Targets are (pid, name, start time): the start time is re-checked right
/// before acting so a reused PID is never hit.
pub fn spawn_action(tx: Sender<WorkerMsg>, targets: Vec<(u32, String, u64)>, action: Action) {
    let first = targets.first().map(|(p, n, _)| (*p, n.clone())).unwrap_or_default();
    worker(
        "action".into(),
        tx,
        move || {
            let results = targets.into_iter().map(|(pid, name, start)| (pid, name, actions::apply_checked(pid, start, action))).collect();
            WorkerMsg::ActionDone { action, results }
        },
        move |e| WorkerMsg::ActionDone { action, results: vec![(first.0, first.1, actions::Outcome::Failed(format!("crashed: {e}")))] },
    );
}

pub fn spawn_find(tx: Sender<WorkerMsg>, query: String) {
    let q2 = query.clone();
    worker(
        "find".into(),
        tx,
        move || {
            let result = crate::process::open_files::find_open_file(&query).map_err(|e| e.to_string());
            WorkerMsg::Found { query, result }
        },
        move |e| WorkerMsg::Found { query: q2, result: Err(format!("search crashed: {e}")) },
    );
}

/// Poll open files of the traced processes every couple of seconds until
/// `stop` is set. The target list is shared so the trace can grow as
/// children appear.
pub fn spawn_trace_poller(tx: Sender<WorkerMsg>, targets: Arc<std::sync::Mutex<Vec<u32>>>, stop: Arc<AtomicBool>) {
    const PERIOD: Duration = Duration::from_secs(2);
    const MAX_PIDS: usize = 40;
    let _ = thread::Builder::new().name("trace-files".into()).spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            let started = Instant::now();
            let pids: Vec<u32> = targets.lock().map(|t| t.iter().take(MAX_PIDS).copied().collect()).unwrap_or_default();
            if !pids.is_empty() {
                let files = pids.into_iter().map(|p| (p, inspect::open_files(p))).collect();
                if stop.load(Ordering::Relaxed) || tx.send(WorkerMsg::TraceFiles(files)).is_err() {
                    return;
                }
            }
            while started.elapsed() < PERIOD && !stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(100));
            }
        }
    });
}

pub fn spawn_dns(tx: Sender<WorkerMsg>) {
    worker(
        "dns".into(),
        tx,
        || WorkerMsg::Dns { resolvers: crate::network::dns::resolvers(), cache: crate::network::dns::client_cache() },
        |e| WorkerMsg::Dns { resolvers: Vec::new(), cache: Err(format!("DNS collection crashed: {e}")) },
    );
}

pub fn spawn_static_libs(tx: Sender<WorkerMsg>, key: crate::common::model::ProcKey, exe: String) {
    worker(
        "static-libs".into(),
        tx,
        move || {
            let libs = crate::files::binfmt::analyze(std::path::Path::new(&exe)).ok().map(|d| d.structure.libraries).filter(|l| !l.is_empty());
            WorkerMsg::StaticLibs { key, libs }
        },
        move |_| WorkerMsg::StaticLibs { key, libs: None },
    );
}

pub fn spawn_stack(tx: Sender<WorkerMsg>, pid: u32, start_time: u64) {
    worker(
        format!("stack-{pid}"),
        tx,
        move || WorkerMsg::Stack { pid, start_time, result: inspect::call_stacks(pid) },
        move |e| WorkerMsg::Stack { pid, start_time, result: Err(format!("sampling crashed: {e}")) },
    );
}

pub fn spawn_file_list(tx: Sender<WorkerMsg>) {
    worker(
        "file-list".into(),
        tx,
        || WorkerMsg::FileList(crate::process::open_files::list_open_files().map_err(|e| e.to_string())),
        |e| WorkerMsg::FileList(Err(format!("scan crashed: {e}"))),
    );
}

pub fn spawn_persistence(tx: Sender<WorkerMsg>, known: HashMap<String, crate::files::intel::ExeInfo>) {
    worker(
        "persistence".into(),
        tx,
        move || WorkerMsg::Persistence(crate::host::persistence::scan_with(&known)),
        |e| WorkerMsg::Persistence(crate::host::persistence::Scan { items: Vec::new(), notes: vec![format!("scan crashed: {e}")] }),
    );
}

pub fn spawn_logs(tx: Sender<WorkerMsg>, minutes: u32, scope: crate::host::logs::Scope) {
    worker(
        "logs".into(),
        tx,
        move || WorkerMsg::Logs(crate::host::logs::fetch(minutes, scope)),
        |e| WorkerMsg::Logs(Err(format!("log reader crashed: {e}"))),
    );
}

pub fn spawn_artifacts(tx: Sender<WorkerMsg>, from: Option<std::path::PathBuf>) {
    let f2 = from.clone();
    worker(
        "artifacts".into(),
        tx,
        move || {
            let scan = match &from {
                Some(d) => crate::host::artifacts::collect_dir(d),
                None => crate::host::artifacts::collect_live(),
            };
            WorkerMsg::Artifacts { from, scan: Box::new(scan) }
        },
        move |e| WorkerMsg::Artifacts {
            from: f2,
            scan: Box::new(crate::host::artifacts::Scan { notes: vec![format!("artifact collection crashed: {e}")], ..Default::default() }),
        },
    );
}

pub fn spawn_yara(tx: Sender<WorkerMsg>, paths: Vec<String>) {
    worker(
        "yara".into(),
        tx,
        move || {
            let (rules, _) = crate::files::yara::load(None);
            let (results, failed) = crate::files::yara::scan_files(&rules, &paths);
            WorkerMsg::Yara { results, scanned: paths.len(), failed }
        },
        |e| WorkerMsg::Yara { results: Vec::new(), scanned: 0, failed: vec![format!("scan crashed: {e}")] },
    );
}

pub fn spawn_deep_snap(tx: Sender<WorkerMsg>, pid: u32, start: u64, modules: bool, files: bool) {
    worker(
        format!("deep-{pid}"),
        tx,
        move || WorkerMsg::DeepSnap {
            pid,
            start,
            modules: modules.then(|| crate::process::inspect::modules(pid)),
            files: files.then(|| crate::process::inspect::open_files(pid)),
        },
        move |e| WorkerMsg::DeepSnap { pid, start, modules: None, files: Some(Err(format!("snapshot crashed: {e}"))) },
    );
}

pub fn spawn_file_report(tx: Sender<WorkerMsg>, path: String) {
    let p2 = path.clone();
    worker(
        "file-report".into(),
        tx,
        move || WorkerMsg::FileReport(Box::new(crate::files::info::analyze(&path))),
        move |e| {
            let mut r = crate::files::info::analyze_stub(&p2);
            r.error = Some(format!("analysis crashed: {e}"));
            WorkerMsg::FileReport(Box::new(r))
        },
    );
}

pub fn spawn_memory(tx: Sender<WorkerMsg>, pid: u32, modules: Vec<String>) {
    worker(
        format!("memory-{pid}"),
        tx,
        move || WorkerMsg::Memory { pid, report: Box::new(crate::process::memory::analyze(pid, &modules)) },
        move |e| WorkerMsg::Memory {
            pid,
            report: Box::new(crate::process::memory::Report { notes: vec![format!("analysis crashed: {e}")], ..Default::default() }),
        },
    );
}

