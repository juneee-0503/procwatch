//! The one channel every background source reports through.

use std::collections::HashMap;

use crate::network::Connection;
use crate::performance::gpu::GpuSnapshot;
use crate::performance::metrics::Metrics;
use crate::performance::services::Service;
use crate::process::actions::Action;
use crate::process::inspect::DeepInfo;
use crate::process::{ProcessTree, SystemStats};

pub struct Snapshot {
    pub tree: ProcessTree,
    pub stats: SystemStats,
    pub connections: HashMap<u32, Vec<Connection>>,
}

pub enum WorkerMsg {
    Snapshot(Box<Snapshot>),
    Gpu(GpuSnapshot),
    /// Scheduling, paging, disks, network errors, sensors.
    Metrics(Box<Metrics>),
    /// System services, or why they couldn't be listed.
    Services(Result<Vec<Service>, String>),
    Inspected { pid: u32, start_time: u64, info: Box<DeepInfo> },
    /// A file change in a watched folder.
    Fs(crate::files::watch::FsEvent),
    /// Result of a persistence scan.
    Persistence(crate::host::persistence::Scan),
    /// Event-log query result.
    Logs(Result<Vec<crate::host::logs::Entry>, String>),
    /// File analysis report.
    FileReport(Box<crate::files::info::FileReport>),
    /// YARA scan of executables: (path, matches) plus files that failed.
    Yara { results: Vec<(String, Vec<crate::files::yara::Match>)>, scanned: usize, failed: Vec<String> },
    /// Execution artifacts; `from` is the imported folder, or None for
    /// the live system.
    Artifacts { from: Option<std::path::PathBuf>, scan: Box<crate::host::artifacts::Scan> },
    /// Memory layout / abnormal-module report for one process.
    Memory { pid: u32, report: Box<crate::process::memory::Report> },
    /// Lifecycle events from the deep-trace watcher.
    Deep(Vec<crate::process::deeptrace::DtEvent>),
    /// Module and open-file snapshot of a deep-traced process.
    DeepSnap { pid: u32, start: u64, modules: Option<Result<Vec<String>, String>>, files: Option<Result<Vec<crate::process::inspect::OpenFile>, String>> },
    /// A background failure worth telling the user about.
    Error(String),
    /// Outcome of a background evidence collection.
    Evidence(Result<String, String>),
    /// Call stacks sampled for one process.
    Stack { pid: u32, start_time: u64, result: Result<Vec<String>, String> },
    /// System-wide open file listing for the Files page.
    FileList(Result<Vec<crate::process::open_files::Hit>, String>),
    /// Open files of the processes being traced.
    TraceFiles(HashMap<u32, Result<Vec<crate::process::inspect::OpenFile>, String>>),
    /// A batch of per-process file, registry and network operations.
    Activity(Vec<crate::activity::Activity>),
    /// Bytes per process since monitoring started.
    Traffic(crate::network::traffic::Totals),
    /// Configured resolvers and the OS DNS cache.
    Dns { resolvers: Vec<String>, cache: Result<Vec<(String, String)>, String> },
    /// Libraries an executable links against, for an open workspace.
    StaticLibs { key: crate::common::model::ProcKey, libs: Option<Vec<String>> },
    /// Result of a file/port search across all processes.
    Found { query: String, result: Result<Vec<crate::process::open_files::Hit>, String> },
    /// Result of applying one action to a batch of processes.
    /// Per target: (pid, name, outcome).
    ActionDone { action: Action, results: Vec<(u32, String, crate::process::actions::Outcome)> },
}

