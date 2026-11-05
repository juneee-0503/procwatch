//! Investigation state and actions for `App`: unified timeline, network
//! events, file changes, persistence, event logs, DNS, memory reports,
//! file analysis, evidence collection, findings, quarantine and reports.
//! A child module of `app`, so it can reach App's private fields.

mod activity;
mod cases;
mod collection;
mod filters;
mod hooks;
mod sweep;
mod timeline;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Local};
use serde_json::json;

use super::*;
use crate::forensics::case::{Case, Check, ReportExtras};
use crate::forensics::contain::{self, Quarantined};
use crate::network::dns;
use crate::files::info::FileReport;
use crate::common::filter::{split_endpoint, Filter, Filterable};
use crate::files::watch::FsEvent;
use crate::host::logs::{self, Scope};
use crate::process::memory;
use crate::common::model::{event_id, short_id, Basis, Entity, ProcKey, Rel};
use crate::network::{ConnState, Connection};
use crate::host::persistence::{Item as PersistItem, Scan};

const MAX_NET_EVENTS: usize = 5000;
const MAX_FS_EVENTS: usize = 5000;
/// Operations kept for the Activity page.
const MAX_ACTIVITY: usize = 200_000;

/// A titled ranking: (title, [(count, bytes, name)]).
pub type SummaryGroup = (&'static str, Vec<(u64, u64, String)>);

#[derive(Debug, Clone, Copy)]
pub struct TrafficRate {
    pub rx: u64,
    pub tx: u64,
    pub at: Instant,
    pub rx_rate: f64,
    pub tx_rate: f64,
}

/// One row of the unified timeline.
#[derive(Debug, Clone)]
pub struct TimelineItem {
    /// Stable id (shown as T-xxxxxxxx), used by bookmarks and summaries.
    pub id: u64,
    /// When it happened — or, for `Basis::Observed`, when procwatch saw it.
    pub time: DateTime<Local>,
    pub basis: Basis,
    /// When procwatch recorded it, if different from `time`.
    pub observed: Option<DateTime<Local>>,
    pub source: &'static str,
    pub kind: String,
    pub pid: Option<u32>,
    pub name: String,
    pub detail: String,
    /// The pid and its known ancestors, for `tree:PID` filtering.
    pub lineage: Vec<u32>,
    /// What the event is about, and what else it involves.
    pub subject: Option<Entity>,
    pub links: Vec<(Rel, Entity)>,
    pub cluster: Option<usize>,
    pub tag: Option<String>,
}

impl TimelineItem {
    fn new(time: DateTime<Local>, basis: Basis, source: &'static str, kind: impl Into<String>, pid: Option<u32>, name: impl Into<String>, detail: impl Into<String>) -> TimelineItem {
        TimelineItem {
            id: 0,
            time,
            basis,
            observed: None,
            source,
            kind: kind.into(),
            pid,
            name: name.into(),
            detail: detail.into(),
            lineage: Vec::new(),
            subject: None,
            links: Vec::new(),
            cluster: None,
            tag: None,
        }
    }
    fn about(mut self, subject: Entity) -> Self {
        self.subject = Some(subject);
        self
    }
    fn link(mut self, rel: Rel, e: Entity) -> Self {
        self.links.push((rel, e));
        self
    }
    fn seen(mut self, at: DateTime<Local>) -> Self {
        if (at - self.time).num_seconds().abs() >= 1 {
            self.observed = Some(at);
        }
        self
    }
    pub fn entities(&self) -> impl Iterator<Item = &Entity> {
        self.subject.iter().chain(self.links.iter().map(|(_, e)| e))
    }
}

#[derive(Debug, Clone)]
pub struct NetEvent {
    pub time: DateTime<Local>,
    pub kind: &'static str,
    pub pid: u32,
    pub name: String,
    pub conn: Connection,
}

pub struct Loaded<T> {
    pub pending: bool,
    pub fetched: Instant,
    pub result: Result<T, String>,
}

/// Everything seen talking to one remote address.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RemoteSummary {
    pub ip: String,
    pub host: Option<String>,
    pub public: bool,
    pub processes: Vec<String>,
    pub ports: Vec<String>,
    pub current: usize,
    pub connects: usize,
    pub first_seen: String,
    pub last_seen: String,
    /// Average seconds between reconnects when they are suspiciously regular.
    pub beacon: Option<f64>,
}

/// Regular reconnects (C2 "beaconing"): at least 4 intervals, each at least
/// 2 s apart on average, with a coefficient of variation ≤ 0.25.
pub fn beacon_interval(times: &[DateTime<Local>]) -> Option<f64> {
    if times.len() < 5 {
        return None;
    }
    let gaps: Vec<f64> = times.windows(2).map(|w| (w[1] - w[0]).num_milliseconds() as f64 / 1000.0).collect();
    let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
    if mean < 2.0 {
        return None;
    }
    let var = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
    (var.sqrt() / mean <= 0.25).then_some(mean)
}

/// What an `Mode::Input` box is collecting.
#[derive(Debug, Clone, PartialEq)]
pub enum InputPurpose {
    Note,
    Conclusion,
    AnalyzePath,
    IsolationAllow,
    IocFile,
    /// Folder of copied artifacts (.pf, .evtx, histories) to import.
    ArtifactDir,
    /// "filter | reason" for suppressing a rule.
    Suppress { rule: String },
    /// "N note" — phase number and optional note for a timeline bookmark.
    Bookmark { event: String, time: String, summary: String },
    /// Title for a finding; source and detail are fixed.
    Finding { source: String, detail: String },
}

impl InputPurpose {
    pub fn title(&self) -> &'static str {
        match self {
            InputPurpose::Note => "Add analyst note",
            InputPurpose::Conclusion => "Investigation conclusion",
            InputPurpose::AnalyzePath => "Analyze file",
            InputPurpose::IsolationAllow => "Network isolation plan",
            InputPurpose::IocFile => "IOC sweep",
            InputPurpose::Suppress { .. } => "Suppress detection",
            InputPurpose::ArtifactDir => "Import artifacts",
            InputPurpose::Bookmark { .. } => "Bookmark event",
            InputPurpose::Finding { .. } => "Record finding",
        }
    }
    pub fn hint(&self) -> &'static str {
        match self {
            InputPurpose::Note => "Free text, saved to the case and the custody log.",
            InputPurpose::Conclusion => "Replaces the current conclusion; goes at the top of the report.",
            InputPurpose::AnalyzePath => "Full path of the file to hash, identify and check.",
            InputPurpose::IocFile => "Indicator file: one hash, IP, domain, path or \"text\" per line (# comments).",
            InputPurpose::Suppress { .. } => "filter | reason   — the rule stays on for everything the filter doesn't match.",
            InputPurpose::ArtifactDir => "Folder with .pf, .evtx, shell history or AppCompatCache files copied from a system.",
            InputPurpose::Bookmark { .. } => {
                "1 initial anomaly · 2 suspicious execution · 3 persistence · 4 network · 5 containment · 6 recovery — then a note"
            }
            InputPurpose::IsolationAllow => {
                "Optional management IP to keep reachable (empty = loopback only). Scripts are written, not run."
            }
            InputPurpose::Finding { .. } => "Start with high: or low: to set severity (default medium).",
        }
    }
}

pub struct Ir {
    pub intel: crate::files::intel::Intel,
    pub triage: HashMap<u32, crate::detection::triage::Assessment>,
    pub det: crate::detection::engine::State,
    pub net_events: VecDeque<NetEvent>,
    /// When each current socket was first seen.
    pub conn_first_seen: HashMap<(u32, Connection), DateTime<Local>>,
    /// Remote-host aggregation for the Network page's "Hosts" view.
    pub remotes: Vec<RemoteSummary>,
    pub net_hosts_view: bool,
    pub host_selected: usize,
    /// pid → (remote ip, interval seconds) for regular reconnect patterns.
    pub beacons: HashMap<u32, (String, f64)>,
    prev_sockets: Option<HashSet<(u32, Connection)>>,
    pub fs_events: VecDeque<FsEvent>,
    _watcher: Option<notify::RecommendedWatcher>,
    pub watch_paths: Vec<String>,
    pub watch_errors: Vec<String>,
    pub persistence: Option<Loaded<Scan>>,
    pub persist_selected: usize,
    /// Live persistence monitoring: last scan's items, when to rescan,
    /// writers seen for changed definition files, and the changes found.
    persist_prev: Option<Vec<PersistItem>>,
    persist_rescan_at: Option<Instant>,
    persist_last_scan: Option<Instant>,
    persist_writers: Vec<(String, DateTime<Local>, Option<ProcKey>)>,
    persist_auto: bool,
    pub persist_changes: VecDeque<PersistChange>,
    pub persist_offset: usize,
    pub persist_changes_view: bool,
    pub logs: Option<Loaded<Vec<logs::Entry>>>,
    pub log_minutes: u32,
    pub log_scope: Scope,
    pub log_selected: usize,
    pub log_offset: usize,
    pub timeline: Vec<TimelineItem>,
    pub timeline_dirty: bool,
    /// When the timeline was last rebuilt, and how long that took.
    last_rebuild: Option<(Instant, std::time::Duration)>,
    pub clusters: Vec<crate::detection::correlate::Cluster>,
    pub cluster_selected: usize,
    pub tl_selected: usize,
    pub tl_offset: usize,
    pub file_report: Option<Loaded<FileReport>>,
    /// Execution artifacts: live ones plus folders imported for offline
    /// analysis (folder → items), with collection notes.
    pub artifacts: Vec<crate::host::artifacts::Artifact>,
    pub artifacts_live: Option<Loaded<Vec<String>>>,
    pub artifacts_imported: Vec<(PathBuf, Vec<crate::host::artifacts::Artifact>, Vec<String>)>,
    pub artifacts_view: bool,
    pub art_selected: usize,
    pub art_offset: usize,
    live_artifacts: Vec<crate::host::artifacts::Artifact>,
    pub report_scroll: usize,
    pub files_changes_view: bool,
    pub fs_selected: usize,
    pub fs_offset: usize,
    pub memory: HashMap<u32, (u64, memory::Report)>,
    pub memory_pending: Option<u32>,
    pub resolver: dns::Resolver,
    pub resolvers: Vec<String>,
    pub dns_cache: Option<Result<Vec<(String, String)>, String>>,
    /// Per-process operations, newest last.
    pub activity: VecDeque<crate::activity::Activity>,
    /// Running capture; None when stopped.
    pub capture: Option<crate::activity::Capture>,
    /// Why the capture couldn't start.
    pub capture_error: Option<String>,
    pub ac_selected: usize,
    pub ac_offset: usize,
    /// Sequence number of the oldest kept operation.
    ac_base: u64,
    /// Filtered view, newest first, as sequence numbers: filtering 200,000
    /// rows can't happen on every draw.
    ac_view: Vec<u64>,
    ac_view_query: String,
    ac_view_dirty: bool,
    ac_view_at: Option<(Instant, std::time::Duration)>,
    /// Names shared by a process's events.
    activity_names: HashMap<u32, Arc<str>>,
    /// Operations for `--monitor` to stream.
    pub activity_out: Option<Vec<crate::activity::Activity>>,
    traffic: Option<crate::network::traffic::Traffic>,
    pub traffic_error: Option<String>,
    traffic_asked: bool,
    /// Per pid: last totals, when, and the rates they gave.
    pub traffic_rates: HashMap<u32, TrafficRate>,
    /// A DNS collection is running.
    dns_pending: bool,
    /// DNS has been collected at least once (evidence needs the resolvers).
    dns_asked: bool,
    pub net_dns_view: bool,
    pub case: Option<Case>,
    pub case_focus_quarantine: bool,
    pub finding_selected: usize,
    pub quarantine_selected: usize,
    pub verify: Option<Vec<(String, Check)>>,
    pub isolation: Option<(PathBuf, PathBuf)>,
    pub sweep: Option<SweepState>,
    pub sweep_selected: usize,
    pub graph: super::graph::GraphState,
    pub yara_pending: bool,
    /// When procwatch started watching (events before are inferred).
    pub watch_start: DateTime<Local>,
    pub state_at: Option<super::state::StateAt>,
    pub response: super::response::ResponseState,
    pub deep: super::deep::DeepState,
    pub ws: super::workspace::WorkspaceState,
    /// Persistent event history (None when off, in tests, or replaying).
    pub store: Option<crate::forensics::store::Writer>,
    last_store_snapshot: Option<Instant>,
    /// Set when showing a recorded session instead of the live system.
    pub replay: Option<String>,
    /// Per-executable behaviour baselines (None when history is off).
    pub profiles: Option<crate::detection::profile::Profiles>,
    profile_runs: HashMap<ProcKey, String>,
    last_profile: Option<Instant>,
    last_profile_save: Option<Instant>,
    pub state_scroll: usize,
    /// Processes started by `--run` (watched although they're our children).
    pub launched: HashSet<u32>,
    pub launch_logs: Vec<(u32, PathBuf)>,
    /// DNS queries with the process that made them (Sysmon 22).
    pub dns_obs: VecDeque<dns::DnsObs>,
}

/// An autostart entry that appeared, changed or disappeared between scans.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PersistChange {
    #[serde(serialize_with = "ser_local")]
    pub time: DateTime<Local>,
    pub kind: &'static str,
    pub category: String,
    pub name: String,
    pub location: String,
    pub target: Option<String>,
    pub command: String,
    pub writer: Option<String>,
    pub writer_key: Option<ProcKey>,
}

fn ser_local<S: serde::Serializer>(t: &DateTime<Local>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&t.to_rfc3339())
}

pub struct SweepState {
    pub file: String,
    pub indicators: usize,
    pub errors: Vec<String>,
    pub hits: Vec<crate::detection::ioc::Hit>,
    /// Executables whose hashes weren't ready yet when the sweep ran.
    pub hashing: usize,
    pub at: DateTime<Local>,
}

impl Ir {
    pub fn new(tx: Sender<WorkerMsg>, watch: &[String]) -> Self {
        let watch_paths = if watch.is_empty() { crate::files::watch::default_paths() } else { watch.to_vec() };
        let (watcher, watch_errors) = crate::files::watch::start(&watch_paths, crate::common::emit::Emit::to(tx, WorkerMsg::Fs));
        Ir {
            intel: crate::files::intel::Intel::new(),
            triage: HashMap::new(),
            det: crate::detection::engine::State::load(None),
            net_events: VecDeque::new(),
            conn_first_seen: HashMap::new(),
            remotes: Vec::new(),
            net_hosts_view: false,
            host_selected: 0,
            beacons: HashMap::new(),
            prev_sockets: None,
            fs_events: VecDeque::new(),
            _watcher: watcher,
            watch_paths,
            watch_errors,
            persistence: None,
            persist_selected: 0,
            persist_prev: None,
            persist_rescan_at: None,
            persist_last_scan: None,
            persist_writers: Vec::new(),
            persist_auto: false,
            persist_changes: VecDeque::new(),
            persist_offset: 0,
            persist_changes_view: false,
            logs: None,
            log_minutes: 15,
            log_scope: Scope::Important,
            log_selected: 0,
            log_offset: 0,
            timeline: Vec::new(),
            timeline_dirty: true,
            last_rebuild: None,
            clusters: Vec::new(),
            cluster_selected: 0,
            tl_selected: 0,
            tl_offset: 0,
            file_report: None,
            artifacts: Vec::new(),
            artifacts_live: None,
            artifacts_imported: Vec::new(),
            artifacts_view: false,
            art_selected: 0,
            art_offset: 0,
            live_artifacts: Vec::new(),
            report_scroll: 0,
            files_changes_view: false,
            fs_selected: 0,
            fs_offset: 0,
            memory: HashMap::new(),
            memory_pending: None,
            resolver: dns::Resolver::new(),
            resolvers: Vec::new(),
            dns_cache: None,
            activity: VecDeque::new(),
            capture: None,
            capture_error: None,
            ac_selected: 0,
            ac_offset: 0,
            ac_base: 0,
            ac_view: Vec::new(),
            ac_view_query: String::new(),
            ac_view_dirty: true,
            ac_view_at: None,
            activity_names: HashMap::new(),
            activity_out: None,
            traffic: None,
            traffic_error: None,
            traffic_asked: false,
            traffic_rates: HashMap::new(),
            dns_pending: false,
            dns_asked: false,
            net_dns_view: false,
            case: None,
            case_focus_quarantine: false,
            finding_selected: 0,
            quarantine_selected: 0,
            verify: None,
            isolation: None,
            sweep: None,
            sweep_selected: 0,
            graph: Default::default(),
            yara_pending: false,
            watch_start: Local::now(),
            state_at: None,
            response: Default::default(),
            deep: super::deep::DeepState { auto: true, ..Default::default() },
            ws: Default::default(),
            store: None,
            last_store_snapshot: None,
            replay: None,
            profiles: None,
            profile_runs: HashMap::new(),
            last_profile: None,
            last_profile_save: None,
            state_scroll: 0,
            launched: HashSet::new(),
            launch_logs: Vec::new(),
            dns_obs: VecDeque::new(),
        }
    }
}

/// The timeline as behaviour-rule events, oldest first.
fn behaviour_events(tl: &[TimelineItem]) -> Vec<crate::detection::behave::Ev> {
    let mut out: Vec<crate::detection::behave::Ev> = Vec::with_capacity(tl.len());
    for e in tl.iter().rev() {
        let kind: &'static str = match (e.source, e.kind.as_str()) {
            ("process", "started") | ("deep", "spawn") | ("deep", "exec") => "process_start",
            ("process", "exited") | ("deep", "exit") => "process_exit",
            ("file", "created" | "modified" | "renamed" | "changed") => "file_write",
            ("deep", "file open") => "file_open",
            ("deep", "module load") => "module_load",
            ("network", "connect") => "net_connect",
            ("network", "listen") => "net_listen",
            ("persist", "added" | "changed" | "written") => "persistence_change",
            ("detect", _) => "detection",
            _ => continue,
        };
        let mut f: std::collections::BTreeMap<&'static str, String> = std::collections::BTreeMap::new();
        if let Some(p) = e.pid {
            f.insert("pid", p.to_string());
        }
        let name = e.name.rsplit(['/', '\\']).next().unwrap_or(&e.name).to_lowercase();
        f.insert("name", name);
        match kind {
            "process_start" => {
                if let Some(img) = e.links.iter().find_map(|(r, x)| if *r == Rel::Executes { if let Entity::File(p) = x { Some(p.clone()) } else { None } } else { None }) {
                    f.insert("image", img);
                }
                f.insert("cmd", e.detail.clone());
            }
            "file_write" | "file_open" | "module_load" => {
                let path = e.entities().find_map(|x| if let Entity::File(p) = x { Some(p.clone()) } else { None }).unwrap_or_else(|| e.detail.clone());
                f.insert("path", path);
            }
            "net_connect" | "net_listen" => {
                let ep = e.detail.split_whitespace().nth(3).unwrap_or("");
                let (ip, port) = split_endpoint(ep);
                f.insert("public", (!crate::detection::triage::is_private(&ip)).to_string());
                f.insert("remote_ip", ip);
                f.insert("remote_port", port);
            }
            "persistence_change" => {
                if let Some(t) = e.links.iter().find_map(|(r, x)| if *r == Rel::Launches { if let Entity::File(p) = x { Some(p.clone()) } else { None } } else { None }) {
                    f.insert("target", t);
                }
            }
            "detection" => {
                f.insert("rule", e.kind.clone());
            }
            _ => {}
        }
        out.push(crate::detection::behave::Ev { time: e.time, id: short_id(e.id), kind, pid: e.pid, lineage: e.lineage.clone(), fields: f });
    }
    out.sort_by_key(|e| e.time);
    out
}

/// One captured operation as an ECS JSON line.
fn activity_line(a: &crate::activity::Activity, host: &str) -> String {
    let id = short_id(event_id(&[&a.time.to_rfc3339(), &a.pid.to_string(), a.op, &a.path]));
    let (file, registry) = match a.class {
        crate::activity::Class::File => (Some(a.path.as_str()), None),
        crate::activity::Class::Registry => (None, Some(a.path.as_str())),
        crate::activity::Class::Network => (None, None),
    };
    let mut v = crate::forensics::stdexport::ecs_event(a.time, &id, a.class.label(), a.op, Some(a.pid), &a.name, &a.path, None, None, file, host);
    if let Some(r) = registry {
        v["registry"] = json!({ "path": r });
    }
    if a.count > 1 {
        v["event"]["count"] = a.count.into();
    }
    if a.bytes > 0 {
        v["procwatch"] = json!({ "bytes": a.bytes });
    }
    v.to_string()
}

/// One timeline row as an ECS JSON line.
fn ecs_line(e: &TimelineItem, host: &str) -> String {
    let exe = e.links.iter().find_map(|(r, x)| if *r == Rel::Executes { if let Entity::File(p) = x { Some(p.as_str()) } else { None } } else { None });
    let path = e.entities().find_map(|x| if let Entity::File(p) = x { Some(p.as_str()) } else { None });
    let ep = e.detail.split_whitespace().nth(3).map(split_endpoint);
    let remote = if e.source == "network" { ep.as_ref().map(|(a, b)| (a.as_str(), b.as_str())) } else { None };
    crate::forensics::stdexport::ecs_event(e.time, &short_id(e.id), e.source, &e.kind, e.pid, &e.name, &e.detail, exe, remote, if e.source == "file" { path } else { None }, host).to_string()
}

fn parse_severity(text: &str) -> (&'static str, String) {
    let t = text.trim();
    for (prefix, sev) in [("high:", "high"), ("critical:", "high"), ("low:", "low"), ("info:", "low"), ("medium:", "medium")] {
        if let Some(rest) = t.strip_prefix(prefix) {
            return (sev, rest.trim().to_string());
        }
    }
    ("medium", t.to_string())
}

/// Tiny helper so differently-typed values share one pretty-printer.
mod erased {
    pub trait Ser {
        fn json(&self) -> String;
    }
    impl<T: serde::Serialize> Ser for T {
        fn json(&self) -> String {
            serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_severity;

    #[test]
    fn severity_prefix() {
        assert_eq!(parse_severity("high: dropper in tmp"), ("high", "dropper in tmp".into()));
        assert_eq!(parse_severity("plain"), ("medium", "plain".into()));
        assert_eq!(parse_severity("low:x"), ("low", "x".into()));
    }
}

#[cfg(test)]
mod beacon_tests {
    use super::beacon_interval;
    use chrono::{Duration, Local};

    #[test]
    fn regular_vs_irregular() {
        let t0 = Local::now();
        let regular: Vec<_> = (0..6).map(|i| t0 + Duration::seconds(30 * i) + Duration::milliseconds((i % 2) * 400)).collect();
        assert!(beacon_interval(&regular).is_some_and(|iv| (iv - 30.0).abs() < 1.0));
        let irregular: Vec<_> = [0, 3, 40, 41, 90, 200].iter().map(|s| t0 + Duration::seconds(*s)).collect();
        assert!(beacon_interval(&irregular).is_none());
        assert!(beacon_interval(&regular[..3]).is_none(), "too few samples");
    }
}

#[cfg(test)]
mod net_tests {
    use crate::network::{ConnState, Connection};

    #[test]
    fn snapshot_message_runs_investigation_hooks() {
        let mut app = crate::app::tests_support::app();
        let c = Connection { protocol: "TCP", local: "127.0.0.1:5".into(), remote: "10.0.0.1:443".into(), state: ConnState::Established };
        let mut conns = std::collections::HashMap::new();
        conns.insert(1, vec![c.clone()]);
        let snap = crate::engine::messages::Snapshot { tree: crate::process::tests::sample(), stats: Default::default(), connections: conns };
        app.on_worker_msg(crate::engine::messages::WorkerMsg::Snapshot(Box::new(snap)));
        assert!(app.ir.conn_first_seen.contains_key(&(1, c)), "snapshot must update network intel");
        assert_eq!(app.ir.triage.len(), app.tree.nodes.len(), "snapshot must triage every process");
    }

    #[test]
    fn first_seen_tracks_current_sockets() {
        let mut app = crate::app::tests_support::app();
        let c = Connection { protocol: "TCP", local: "127.0.0.1:5".into(), remote: "10.0.0.1:443".into(), state: ConnState::Established };
        app.connections.insert(1, vec![c.clone()]);
        app.ir_on_snapshot();
        assert!(app.ir.conn_first_seen.contains_key(&(1, c)), "{:?}", app.ir.conn_first_seen.keys().collect::<Vec<_>>());
    }
}

#[cfg(test)]
mod activity_tests {
    use super::*;
    use crate::activity::{Activity, Class};

    #[test]
    fn operations_are_named_filtered_and_capped_with_autostart_writes_detected() {
        let mut app = crate::app::tests_support::app();
        let pid = *app.tree.nodes.keys().next().unwrap();
        let name = app.name_of(pid);
        app.ir.activity_out = Some(Vec::new());
        app.on_worker_msg(WorkerMsg::Activity(vec![
            Activity::new(pid, Class::File, "write", "/tmp/a").with_bytes(9),
            Activity::new(pid, Class::Registry, "set value", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\evil"),
            Activity::new(pid, Class::Registry, "set value", r"HKLM\SOFTWARE\Vendor\Setting"),
        ]));
        assert_eq!(app.ir.activity.len(), 3);
        assert_eq!(&*app.ir.activity[0].name, name.as_str());
        app.query = "source:registry".into();
        app.refresh_activity_view();
        assert_eq!(app.visible_activity().len(), 2);
        let newest = app.visible_activity()[0];
        assert_eq!(app.activity_at(newest).unwrap().path, r"HKLM\SOFTWARE\Vendor\Setting");
        app.query = "kind:write".into();
        app.refresh_activity_view();
        assert_eq!(app.visible_activity().len(), 1);
        app.query.clear();
        assert_eq!(app.ir.det.store.items.iter().filter(|d| d.rule_id == "PW-022").count(), 1, "only the autostart key");
        app.refresh_activity_view();
        let summary = app.activity_summary();
        assert_eq!(summary[0].1[0].0, 3, "all three by one process");
        assert_eq!(summary[1].1[0].2, "registry set value");
        assert_eq!(summary[2].1.len(), 3);
        let lines = app.take_activity_lines();
        assert_eq!(lines.len(), 3);
        let v: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(v["event"]["category"][0], "registry");
        assert!(v["registry"]["path"].as_str().unwrap().ends_with("evil"));
        assert!(app.take_activity_lines().is_empty());
        app.clear_activity();
        assert!(app.ir.activity.is_empty());
    }

    #[test]
    fn traffic_totals_become_rates_on_processes() {
        let mut app = crate::app::tests_support::app();
        let pid = *app.tree.nodes.keys().next().unwrap();
        app.on_worker_msg(WorkerMsg::Traffic([(pid, (1000, 2000))].into()));
        assert_eq!(app.ir.traffic_rates[&pid].rx_rate, 0.0, "the first total is a baseline");
        std::thread::sleep(std::time::Duration::from_millis(50));
        app.on_worker_msg(WorkerMsg::Traffic([(pid, (2000, 2000))].into()));
        let r = app.ir.traffic_rates[&pid];
        assert!(r.rx_rate > 1000.0 && r.tx_rate == 0.0, "{r:?}");
        app.on_worker_msg(WorkerMsg::Traffic([(pid + 99_999, (1, 1))].into()));
        assert!(!app.ir.traffic_rates.contains_key(&(pid + 99_999)), "gone processes are dropped");
    }
}

#[cfg(test)]
mod persist_tests {
    use super::*;

    fn item(name: &str, cmd: &str) -> PersistItem {
        let mut i = PersistItem::test("Launch agent", name, cmd, &format!("/Users/a/Library/LaunchAgents/{name}.plist"));
        i.target = Some(cmd.to_string());
        i
    }

    #[test]
    fn diff_reports_added_changed_removed_with_writer() {
        let mut app = crate::app::tests_support::app();
        assert_eq!(app.persistence_diff(&[item("a", "/bin/a"), item("b", "/bin/b")]), 0, "first scan is the baseline");
        // A deep-traced process had b's plist open when it changed.
        let writer = ProcKey { pid: 4242, start: 7 };
        app.ir.persist_writers.push(("/Users/a/Library/LaunchAgents/b.plist".into(), Local::now(), Some(writer)));
        let n = app.persistence_diff(&[item("b", "/tmp/evil"), item("c", "/bin/c")]);
        assert_eq!(n, 3);
        let kinds: Vec<&str> = app.ir.persist_changes.iter().map(|c| c.kind).collect();
        assert!(kinds.contains(&"added") && kinds.contains(&"changed") && kinds.contains(&"removed"));
        let changed = app.ir.persist_changes.iter().find(|c| c.kind == "changed").unwrap();
        assert_eq!(changed.writer_key, Some(writer));
        let dets: Vec<&crate::detection::engine::Detection> = app.ir.det.store.items.iter().filter(|d| d.rule_id == "PW-019").collect();
        assert_eq!(dets.len(), 2, "added + changed, not removed");
        assert!(dets.iter().any(|d| d.subject == Entity::Process(writer)));
    }
}
