//! Background workers. Everything that can block — process enumeration,
//! socket tables, GPU counters, deep inspection, process actions — runs off
//! the UI thread and reports back over a single channel, so the interface
//! never freezes while a slow system tool (vmmap, PowerShell, lsof) runs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::gpu::{self, GpuSnapshot};
use crate::inspect::{self, DeepInfo};
use crate::network::{self, Connection};
use crate::process::actions::{self, Action};

use crate::process::{ProcessMonitor, ProcessTree, SystemStats};

pub const MIN_INTERVAL_MS: u64 = 250;
pub const MAX_INTERVAL_MS: u64 = 10_000;
const GPU_INTERVAL: Duration = Duration::from_secs(3);

pub struct Snapshot {
    pub tree: ProcessTree,
    pub stats: SystemStats,
    pub connections: HashMap<u32, Vec<Connection>>,
}

pub enum WorkerMsg {
    Snapshot(Box<Snapshot>),
    Gpu(GpuSnapshot),
    Inspected { pid: u32, start_time: u64, info: Box<DeepInfo> },
    /// A file change in a watched folder.
    Fs(crate::fswatch::FsEvent),
    /// Result of a persistence scan.
    Persistence(crate::persistence::Scan),
    /// Event-log query result.
    Logs(Result<Vec<crate::logs::Entry>, String>),
    /// File analysis report.
    FileReport(Box<crate::fileinfo::FileReport>),
    /// YARA scan of executables: (path, matches) plus files that failed.
    Yara { results: Vec<(String, Vec<crate::yara::Match>)>, scanned: usize, failed: Vec<String> },
    /// Execution artifacts; `from` is the imported folder, or None for
    /// the live system.
    Artifacts { from: Option<std::path::PathBuf>, scan: Box<crate::artifacts::Scan> },
    /// Memory layout / abnormal-module report for one process.
    Memory { pid: u32, report: Box<crate::memory::Report> },
    /// Lifecycle events from the deep-trace watcher.
    Deep(Vec<crate::deeptrace::DtEvent>),
    /// Module and open-file snapshot of a deep-traced process.
    DeepSnap { pid: u32, start: u64, modules: Option<Result<Vec<String>, String>>, files: Option<Result<Vec<crate::inspect::OpenFile>, String>> },
    /// A background failure worth telling the user about.
    Error(String),
    /// Outcome of a background evidence collection.
    Evidence(Result<String, String>),
    /// Call stacks sampled for one process.
    Stack { pid: u32, start_time: u64, result: Result<Vec<String>, String> },
    /// System-wide open file listing for the Files page.
    FileList(Result<Vec<crate::os::Hit>, String>),
    /// Open files of the processes being traced.
    TraceFiles(HashMap<u32, Result<Vec<crate::inspect::OpenFile>, String>>),
    /// Configured resolvers and the OS DNS cache.
    Dns { resolvers: Vec<String>, cache: Result<Vec<(String, String)>, String> },
    /// Libraries an executable links against, for an open workspace.
    StaticLibs { key: crate::model::ProcKey, libs: Option<Vec<String>> },
    /// Result of a file/port search across all processes.
    Found { query: String, result: Result<Vec<crate::os::Hit>, String> },
    /// Result of applying one action to a batch of processes.
    /// Per target: (pid, name, outcome).
    ActionDone { action: Action, results: Vec<(u32, String, crate::process::actions::Outcome)> },
}

/// Knobs the UI can turn on the running sampler without a round trip.
pub struct SamplerCtl {
    pub interval_ms: AtomicU64,
    pub paused: AtomicBool,
    pub refresh_now: AtomicBool,
    /// Snapshots sent but not handled yet.
    pub snapshots_queued: AtomicU64,
}

impl SamplerCtl {
    /// The UI handled a snapshot.
    pub fn snapshot_handled(&self) {
        let mut n = self.snapshots_queued.load(Ordering::Relaxed);
        while n > 0 {
            match self.snapshots_queued.compare_exchange_weak(n, n - 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(now) => n = now,
            }
        }
    }

    pub fn interval(&self) -> Duration {
        Duration::from_millis(self.interval_ms.load(Ordering::Relaxed))
    }
}

const MAX_QUEUED_SNAPSHOTS: u64 = 2;

/// What a bounded drain left behind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Drained {
    /// Stopped at the budget with messages still queued.
    pub more: bool,
    pub disconnected: bool,
}

/// Handle queued messages for at most `budget`. An unbounded drain never
/// returns once messages arrive faster than they are handled, which freezes
/// the caller's input, drawing and deadline checks.
pub fn drain_for<T>(rx: &mpsc::Receiver<T>, budget: Duration, mut handle: impl FnMut(T)) -> Drained {
    let start = Instant::now();
    loop {
        match rx.try_recv() {
            Ok(msg) => handle(msg),
            Err(mpsc::TryRecvError::Empty) => return Drained::default(),
            Err(mpsc::TryRecvError::Disconnected) => return Drained { more: false, disconnected: true },
        }
        if start.elapsed() >= budget {
            return Drained { more: true, disconnected: false };
        }
    }
}

pub fn spawn_sampler(tx: Sender<WorkerMsg>, ctl: Arc<SamplerCtl>) -> std::io::Result<()> {
    let gpu_tx = tx.clone();
    thread::Builder::new()
        .name("sampler".into())
        .spawn(move || {
            let mut monitor = ProcessMonitor::new();
            // CPU usage is a delta between two samples; take the first real
            // one shortly after startup instead of a full interval later.
            thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL.max(Duration::from_millis(250)));
            loop {
                let started = Instant::now();
                // A slow UI gets the newest state, not a growing pile of
                // large snapshots.
                if ctl.snapshots_queued.load(Ordering::Relaxed) >= MAX_QUEUED_SNAPSHOTS {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                // A failure in one sample (e.g. an OS API returning
                // something unexpected) must not stop monitoring.
                let sample = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut lap = crate::perf::Lap::new();
                    let (tree, stats) = monitor.snapshot();
                    lap.mark("sampler: processes");
                    let connections = network::connections_by_pid();
                    lap.mark("sampler: connections");
                    Snapshot { tree, stats, connections }
                }));
                let msg = match sample {
                    Ok(snap) => {
                        ctl.snapshots_queued.fetch_add(1, Ordering::Relaxed);
                        WorkerMsg::Snapshot(Box::new(snap))
                    }
                    Err(e) => WorkerMsg::Error(format!("sampling failed: {}", panic_text(&*e))),
                };
                if tx.send(msg).is_err() {
                    return; // UI is gone
                }

                // Sleep in small steps so pause/interval/refresh changes
                // take effect immediately.
                loop {
                    thread::sleep(Duration::from_millis(50));
                    if ctl.refresh_now.swap(false, Ordering::Relaxed) {
                        break;
                    }
                    if !ctl.paused.load(Ordering::Relaxed) && started.elapsed() >= ctl.interval() {
                        break;
                    }
                }
            }
        })?;

    // GPU counters are slow to query on Windows (a PowerShell spawn), so
    // they get their own, slower loop instead of stalling process updates.
    let _ = thread::Builder::new().name("gpu".into()).spawn(move || loop {
        let snap = gpu::system_gpu_usage();
        let available = snap.available;
        if gpu_tx.send(WorkerMsg::Gpu(snap)).is_err() || !available {
            return; // nothing will change on platforms without counters
        }
        thread::sleep(GPU_INTERVAL);
    });
    Ok(())
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

pub fn panic_text(e: &(dyn std::any::Any + Send)) -> String {
    e.downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| e.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".into())
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
            let result = crate::os::find_open_file(&query).map_err(|e| e.to_string());
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
        || WorkerMsg::Dns { resolvers: crate::dns::resolvers(), cache: crate::dns::client_cache() },
        |e| WorkerMsg::Dns { resolvers: Vec::new(), cache: Err(format!("DNS collection crashed: {e}")) },
    );
}

pub fn spawn_static_libs(tx: Sender<WorkerMsg>, key: crate::model::ProcKey, exe: String) {
    worker(
        "static-libs".into(),
        tx,
        move || {
            let libs = crate::binfmt::analyze(std::path::Path::new(&exe)).ok().map(|d| d.structure.libraries).filter(|l| !l.is_empty());
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
        || WorkerMsg::FileList(crate::os::list_open_files().map_err(|e| e.to_string())),
        |e| WorkerMsg::FileList(Err(format!("scan crashed: {e}"))),
    );
}

pub fn spawn_persistence(tx: Sender<WorkerMsg>, known: HashMap<String, crate::intel::ExeInfo>) {
    worker(
        "persistence".into(),
        tx,
        move || WorkerMsg::Persistence(crate::persistence::scan_with(&known)),
        |e| WorkerMsg::Persistence(crate::persistence::Scan { items: Vec::new(), notes: vec![format!("scan crashed: {e}")] }),
    );
}

pub fn spawn_logs(tx: Sender<WorkerMsg>, minutes: u32, scope: crate::logs::Scope) {
    worker(
        "logs".into(),
        tx,
        move || WorkerMsg::Logs(crate::logs::fetch(minutes, scope)),
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
                Some(d) => crate::artifacts::collect_dir(d),
                None => crate::artifacts::collect_live(),
            };
            WorkerMsg::Artifacts { from, scan: Box::new(scan) }
        },
        move |e| WorkerMsg::Artifacts {
            from: f2,
            scan: Box::new(crate::artifacts::Scan { notes: vec![format!("artifact collection crashed: {e}")], ..Default::default() }),
        },
    );
}

pub fn spawn_yara(tx: Sender<WorkerMsg>, paths: Vec<String>) {
    worker(
        "yara".into(),
        tx,
        move || {
            let (rules, _) = crate::yara::load(None);
            let (results, failed) = crate::yara::scan_files(&rules, &paths);
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
            modules: modules.then(|| crate::inspect::modules(pid)),
            files: files.then(|| crate::inspect::open_files(pid)),
        },
        move |e| WorkerMsg::DeepSnap { pid, start, modules: None, files: Some(Err(format!("snapshot crashed: {e}"))) },
    );
}

pub fn spawn_file_report(tx: Sender<WorkerMsg>, path: String) {
    let p2 = path.clone();
    worker(
        "file-report".into(),
        tx,
        move || WorkerMsg::FileReport(Box::new(crate::fileinfo::analyze(&path))),
        move |e| {
            let mut r = crate::fileinfo::analyze_stub(&p2);
            r.error = Some(format!("analysis crashed: {e}"));
            WorkerMsg::FileReport(Box::new(r))
        },
    );
}

pub fn spawn_memory(tx: Sender<WorkerMsg>, pid: u32, modules: Vec<String>) {
    worker(
        format!("memory-{pid}"),
        tx,
        move || WorkerMsg::Memory { pid, report: Box::new(crate::memory::analyze(pid, &modules)) },
        move |e| WorkerMsg::Memory {
            pid,
            report: Box::new(crate::memory::Report { notes: vec![format!("analysis crashed: {e}")], ..Default::default() }),
        },
    );
}

#[cfg(test)]
mod drain_tests {
    use super::*;

    #[test]
    fn drain_returns_while_a_producer_outruns_the_handler() {
        let (tx, rx) = mpsc::channel();
        // Queued up front, so the drain can't see an empty queue first.
        for _ in 0..1000 {
            tx.send(1u8).unwrap();
        }
        let feeding = std::sync::Arc::new(AtomicBool::new(true));
        let f = feeding.clone();
        let feeder = std::thread::spawn(move || {
            while f.load(Ordering::Relaxed) {
                let _ = tx.send(1u8);
            }
        });
        let start = Instant::now();
        let d = drain_for(&rx, Duration::from_millis(20), |_| std::thread::sleep(Duration::from_millis(1)));
        let took = start.elapsed();
        feeding.store(false, Ordering::Relaxed);
        let _ = feeder.join();
        assert!(d.more, "the queue never emptied, so the budget must have ended it");
        assert!(took < Duration::from_secs(2), "took {took:?}");
    }

    #[test]
    fn the_snapshot_count_stops_at_zero() {
        let ctl = SamplerCtl { interval_ms: AtomicU64::new(1000), paused: AtomicBool::new(false), refresh_now: AtomicBool::new(false), snapshots_queued: AtomicU64::new(1) };
        ctl.snapshot_handled();
        ctl.snapshot_handled();
        assert_eq!(ctl.snapshots_queued.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn drain_reports_empty_and_disconnected() {
        let (tx, rx) = mpsc::channel();
        tx.send(1).unwrap();
        let mut n = 0;
        assert_eq!(drain_for(&rx, Duration::from_secs(1), |v: i32| n += v), Drained::default());
        assert_eq!(n, 1);
        drop(tx);
        assert!(drain_for(&rx, Duration::from_secs(1), |_: i32| ()).disconnected);
    }
}
