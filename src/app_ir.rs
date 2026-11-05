//! Investigation state and actions for `App`: unified timeline, network
//! events, file changes, persistence, event logs, DNS, memory reports,
//! file analysis, evidence collection, findings, quarantine and reports.
//! A child module of `app`, so it can reach App's private fields.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Local};
use serde_json::json;

use super::*;
use crate::case::{Case, Check, ReportExtras};
use crate::contain::{self, Quarantined};
use crate::dns;
use crate::fileinfo::FileReport;
use crate::filter::{split_endpoint, Filter, Filterable};
use crate::fswatch::{self, FsEvent};
use crate::logs::{self, Scope};
use crate::memory;
use crate::model::{event_id, short_id, Basis, Entity, ProcKey, Rel};
use crate::network::{ConnState, Connection};
use crate::persistence::{Item as PersistItem, Scan};

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
    pub intel: crate::intel::Intel,
    pub triage: HashMap<u32, crate::triage::Assessment>,
    pub det: crate::detect::State,
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
    pub clusters: Vec<crate::correlate::Cluster>,
    pub cluster_selected: usize,
    pub tl_selected: usize,
    pub tl_offset: usize,
    pub file_report: Option<Loaded<FileReport>>,
    /// Execution artifacts: live ones plus folders imported for offline
    /// analysis (folder → items), with collection notes.
    pub artifacts: Vec<crate::artifacts::Artifact>,
    pub artifacts_live: Option<Loaded<Vec<String>>>,
    pub artifacts_imported: Vec<(PathBuf, Vec<crate::artifacts::Artifact>, Vec<String>)>,
    pub artifacts_view: bool,
    pub art_selected: usize,
    pub art_offset: usize,
    live_artifacts: Vec<crate::artifacts::Artifact>,
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
    traffic: Option<crate::netio::Traffic>,
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
    pub store: Option<crate::store::Writer>,
    last_store_snapshot: Option<Instant>,
    /// Set when showing a recorded session instead of the live system.
    pub replay: Option<String>,
    /// Per-executable behaviour baselines (None when history is off).
    pub profiles: Option<crate::profile::Profiles>,
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
    pub hits: Vec<crate::ioc::Hit>,
    /// Executables whose hashes weren't ready yet when the sweep ran.
    pub hashing: usize,
    pub at: DateTime<Local>,
}

impl Ir {
    pub fn new(tx: Sender<WorkerMsg>, watch: &[String]) -> Self {
        let watch_paths = if watch.is_empty() { fswatch::default_paths() } else { watch.to_vec() };
        let (watcher, watch_errors) = fswatch::start(&watch_paths, crate::common::emit::Emit::to(tx, WorkerMsg::Fs));
        Ir {
            intel: crate::intel::Intel::new(),
            triage: HashMap::new(),
            det: crate::detect::State::load(None),
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

// ── filter support ─────────────────────────────────────────────────────

impl Filterable for TimelineItem {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "pid" => Some(vec![self.pid.map(|p| p.to_string()).unwrap_or_default()]),
            "tree" => Some(self.lineage.iter().map(|p| p.to_string()).collect()),
            "name" => Some(vec![self.name.clone()]),
            "kind" => Some(vec![self.kind.clone()]),
            "source" => Some(vec![self.source.to_string()]),
            "id" => Some(vec![short_id(self.id).to_lowercase()]),
            "basis" => Some(vec![self.basis.label().into()]),
            "cluster" => Some(vec![self.cluster.map(|c| c.to_string()).unwrap_or_default()]),
            "tag" => Some(vec![self.tag.clone().unwrap_or_default()]),
            "entity" => Some(self.entities().map(|e| e.key()).collect()),
            "path" => Some(self.entities().filter_map(|e| if let Entity::File(p) = e { Some(p.clone()) } else { None }).collect()),
            "port" | "ip" => {
                let eps: Vec<String> = self.detail.split_whitespace().filter(|w| w.contains(':')).map(|w| w.to_string()).collect();
                let mut v: Vec<String> = eps.iter().map(|e| if name == "port" { split_endpoint(e).1 } else { split_endpoint(e).0 }).collect();
                if name == "ip" {
                    v.extend(self.entities().filter_map(|e| if let Entity::Endpoint(ip) = e { Some(ip.clone()) } else { None }));
                }
                Some(v)
            }
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {} {}", self.source, self.kind, self.name, self.pid.map(|p| p.to_string()).unwrap_or_default(), self.detail)
    }
}

impl Filterable for RemoteSummary {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "ip" => Some(vec![self.ip.clone()]),
            "name" => Some(self.processes.iter().cloned().chain(self.host.clone()).collect()),
            "port" => Some(self.ports.clone()),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {}", self.ip, self.host.clone().unwrap_or_default(), self.processes.join(" "), self.ports.join(" "))
    }
}

impl Filterable for PersistItem {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "name" => Some(vec![self.name.clone()]),
            "kind" => Some(vec![self.category.clone()]),
            "path" => Some(vec![self.target.clone().unwrap_or_default(), self.location.clone()]),
            "cmd" => Some(vec![self.command.clone()]),
            "user" => Some(vec![self.scope.clone()]),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {} {} {}", self.category, self.name, self.command, self.location, self.detail, self.flags.join(" "))
    }
}

impl Filterable for logs::Entry {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "pid" => Some(vec![self.pid.map(|p| p.to_string()).unwrap_or_default()]),
            "name" => Some(vec![self.process.clone()]),
            "kind" => Some(vec![self.level.clone()]),
            "source" => Some(vec![self.source.clone()]),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {}", self.level, self.process, self.source, self.message)
    }
}

impl Filterable for crate::artifacts::Artifact {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "kind" | "source" => Some(vec![self.kind.into()]),
            "path" | "cmd" => Some(vec![self.subject.clone()]),
            "user" => Some(vec![self.user.clone().unwrap_or_default()]),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {}", self.kind, self.subject, self.detail, self.user.as_deref().unwrap_or(""))
    }
}

impl Ir {
    pub fn traffic_method(&self) -> Option<&'static str> {
        self.traffic.as_ref().map(|t| t.method)
    }
}

impl Filterable for crate::activity::Activity {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "pid" => Some(vec![self.pid.to_string()]),
            "name" => Some(vec![self.name.to_string()]),
            "path" => Some(vec![self.path.clone()]),
            "kind" | "type" => Some(vec![self.op.to_string()]),
            "source" => Some(vec![self.class.label().to_string()]),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {} {} {}", self.pid, self.name, self.class.label(), self.op, self.path, self.detail)
    }
}

impl Filterable for FsEvent {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "kind" => Some(vec![self.kind.to_string()]),
            "path" => Some(vec![self.path.clone()]),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {}", self.kind, self.path)
    }
}

/// The timeline as behaviour-rule events, oldest first.
fn behaviour_events(tl: &[TimelineItem]) -> Vec<crate::behave::Ev> {
    let mut out: Vec<crate::behave::Ev> = Vec::with_capacity(tl.len());
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
                f.insert("public", (!crate::triage::is_private(&ip)).to_string());
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
        out.push(crate::behave::Ev { time: e.time, id: short_id(e.id), kind, pid: e.pid, lineage: e.lineage.clone(), fields: f });
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
    let mut v = crate::stdexport::ecs_event(a.time, &id, a.class.label(), a.op, Some(a.pid), &a.name, &a.path, None, None, file, host);
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
    crate::stdexport::ecs_event(e.time, &short_id(e.id), e.source, &e.kind, e.pid, &e.name, &e.detail, exe, remote, if e.source == "file" { path } else { None }, host).to_string()
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

impl App {
    // ── lifecycle hooks ────────────────────────────────────────────────

    fn update_network_intel(&mut self) {
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
    fn update_profiles(&mut self) {
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
        let mut found: Vec<(u32, Vec<crate::profile::Novelty>)> = Vec::new();
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
            let mut obs = crate::profile::Observation::default();
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
            let hit = crate::triage::RuleHit::from_def(
                crate::triage::rule("PW-018").expect("rule"),
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
    fn store_snapshot(&mut self) {
        let due = self.ir.last_store_snapshot.is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(600));
        if !due || self.ir.store.is_none() {
            return;
        }
        self.ir.last_store_snapshot = Some(Instant::now());
        let processes: Vec<crate::store::ProcRec> = self
            .tree
            .nodes
            .values()
            .map(|n| crate::store::ProcRec {
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
            st.write(Local::now(), crate::store::Rec::Snapshot { processes });
            st.flush();
            st.prune();
        }
    }

    pub(super) fn ir_on_snapshot(&mut self) {
        let mut lap = crate::perf::Lap::new();
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
            if self.ir.capture.is_some() && !cfg!(windows) {
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
                        crate::store::Rec::Net {
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
    pub(super) fn ir_on_msg(&mut self, msg: WorkerMsg) {
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
                if crate::fswatch::autostart_location(&e.path) && !self.replaying() {
                    let owner = self.file_owner_near(&e.path, e.time);
                    // Attribution looks for the newest write: drop the oldest.
                    if self.ir.persist_writers.len() >= 200 {
                        self.ir.persist_writers.remove(0);
                    }
                    self.ir.persist_writers.push((e.path.clone(), e.time, owner));
                    self.ir.persist_rescan_at = Some(Instant::now() + std::time::Duration::from_secs(3));
                }
                if let Some(st) = self.ir.store.as_mut() {
                    st.write(e.time, crate::store::Rec::File { kind: e.kind.into(), path: e.path.clone() });
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
                let events: Vec<(crate::sigma::Event, DateTime<Local>, String)> =
                    scan.records.iter().map(|r| (r.sigma_event(), r.time, format!("{} {} on {}", r.channel, r.event_id, r.computer))).collect();
                let hits = self.sigma_on_events(&events);
                let found: Vec<dns::DnsObs> = scan
                    .records
                    .iter()
                    .filter(|r| r.event_id == 22 && crate::sigma::map::service_of(&r.channel) == "sysmon")
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
                crate::artifacts::sort_newest_first(&mut all);
                self.ir.artifacts = all;
                self.ir.timeline_dirty = true;
            }
            WorkerMsg::Activity(batch) => self.on_activity(batch),
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

    /// Start or stop capturing per-process operations.
    pub fn toggle_capture(&mut self) {
        if self.ir.capture.take().is_some() {
            self.set_status(StatusLevel::Info, "Activity capture stopped".into());
            return;
        }
        match crate::activity::start(crate::common::emit::Emit::to(self.tx.clone(), WorkerMsg::Activity)) {
            Ok(c) => {
                self.ir.capture_error = None;
                self.set_status(StatusLevel::Success, format!("Capturing activity: {}", c.method));
                self.ir.capture = Some(c);
            }
            Err(e) => {
                self.set_status(StatusLevel::Error, format!("Activity capture: {e}"));
                self.ir.capture_error = Some(e);
            }
        }
    }

    pub fn clear_activity(&mut self) {
        self.ir.ac_base += self.ir.activity.len() as u64;
        self.ir.activity.clear();
        self.ir.ac_view.clear();
        self.ir.ac_selected = 0;
        self.ir.ac_offset = 0;
    }

    /// The filtered view as of the last refresh.
    pub fn visible_activity(&self) -> &[u64] {
        &self.ir.ac_view
    }

    /// An operation by sequence number; None once it has aged out.
    pub fn activity_at(&self, seq: u64) -> Option<&crate::activity::Activity> {
        self.ir.activity.get(usize::try_from(seq.checked_sub(self.ir.ac_base)?).ok()?)
    }

    /// Rebuild the filtered view: at once when the filter changed, otherwise
    /// taking at most about 5% of the UI thread.
    pub fn refresh_activity_view(&mut self) {
        let changed = self.query != self.ir.ac_view_query;
        let due = self.ir.ac_view_at.is_none_or(|(at, cost)| at.elapsed() >= (cost * 20).max(std::time::Duration::from_millis(200)));
        if !changed && !(self.ir.ac_view_dirty && due) {
            return;
        }
        let began = Instant::now();
        let f = Filter::parse(&self.query);
        let base = self.ir.ac_base;
        self.ir.ac_view = self.ir.activity.iter().enumerate().rev().filter(|(_, e)| f.matches(*e)).map(|(i, _)| base + i as u64).collect();
        self.ir.ac_view_query.clone_from(&self.query);
        self.ir.ac_view_dirty = false;
        self.ir.ac_view_at = Some((Instant::now(), began.elapsed()));
    }

    fn on_activity(&mut self, batch: Vec<crate::activity::Activity>) {
        use crate::activity::Class;
        let tree = &self.tree;
        self.ir.activity_names.retain(|pid, _| tree.nodes.contains_key(pid));
        for mut a in batch {
            let name = match self.ir.activity_names.get(&a.pid) {
                Some(n) => n.clone(),
                None => {
                    let n: Arc<str> = Arc::from(self.name_of(a.pid));
                    self.ir.activity_names.insert(a.pid, n.clone());
                    n
                }
            };
            a.name = name;
            // A write to an autostart key, with the process that did it.
            if a.class == Class::Registry && a.op != "delete key" && crate::activity::is_autostart_key(&a.path) {
                if let Some(def) = crate::triage::rule("PW-022") {
                    let hit = crate::triage::RuleHit::from_def(def, format!("{} {}", a.op, a.path));
                    self.record_detection_pub(&hit, Entity::Process(self.proc_key(a.pid)), format!("{} ({})", a.name, a.pid), Some(a.pid), "activity");
                }
            }
            // Traced processes' file changes join the timeline, attributed.
            if a.class == Class::File && self.ir.deep.is_enrolled(a.pid) {
                let kind = match a.op {
                    "create" => Some("created"),
                    "write" | "close after write" => Some("modified"),
                    "delete" => Some("deleted"),
                    "rename" | "rename to" => Some("renamed"),
                    _ => None,
                };
                if let Some(kind) = kind {
                    self.ir_on_msg(WorkerMsg::Fs(FsEvent { time: a.time, kind, path: a.path.clone(), pid: Some(a.pid) }));
                }
            }
            if let Some(out) = self.ir.activity_out.as_mut() {
                out.push(a.clone());
            }
            if self.ir.activity.len() >= MAX_ACTIVITY {
                self.ir.activity.pop_front();
                self.ir.ac_base += 1;
            }
            self.ir.activity.push_back(a);
            self.ir.ac_view_dirty = true;
        }
    }

    fn on_traffic(&mut self, totals: crate::netio::Totals) {
        let now = Instant::now();
        for (pid, (rx, tx)) in totals {
            let e = self.ir.traffic_rates.entry(pid).or_insert(TrafficRate { rx, tx, at: now, rx_rate: 0.0, tx_rate: 0.0 });
            let secs = now.duration_since(e.at).as_secs_f64();
            if secs > 0.0 {
                e.rx_rate = rx.saturating_sub(e.rx) as f64 / secs;
                e.tx_rate = tx.saturating_sub(e.tx) as f64 / secs;
            }
            (e.rx, e.tx, e.at) = (rx, tx, now);
        }
        let tree = &self.tree;
        self.ir.traffic_rates.retain(|pid, _| tree.nodes.contains_key(pid));
    }

    /// New operations as ECS lines, for `--monitor --activity`.
    pub fn take_activity_lines(&mut self) -> Vec<String> {
        let host = sysinfo::System::host_name().unwrap_or_default();
        let items = self.ir.activity_out.as_mut().map(std::mem::take).unwrap_or_default();
        items.iter().map(|a| activity_line(a, &host)).collect()
    }

    /// Top entries of the shown operations: (title, [(count, bytes, name)]).
    pub fn activity_summary(&self) -> Vec<SummaryGroup> {
        const TOP: usize = 8;
        let shown = || self.visible_activity().iter().filter_map(|s| self.activity_at(*s));
        let rank = |key: &dyn Fn(&crate::activity::Activity) -> String| -> Vec<(u64, u64, String)> {
            let mut m: HashMap<String, (u64, u64)> = HashMap::new();
            for a in shown() {
                let e = m.entry(key(a)).or_default();
                e.0 += u64::from(a.count);
                e.1 += a.bytes;
            }
            let mut v: Vec<(u64, u64, String)> = m.into_iter().map(|(k, (c, b))| (c, b, k)).collect();
            v.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)).then(a.2.cmp(&b.2)));
            v.truncate(TOP);
            v
        };
        vec![
            ("Busiest processes", rank(&|a| format!("{} ({})", a.name, a.pid))),
            ("Operations", rank(&|a| format!("{} {}", a.class.label(), a.op))),
            ("Most touched targets", rank(&|a| a.path.clone())),
        ]
    }

    /// The captured operations, as evidence in the case.
    pub fn save_activity(&mut self) {
        if self.ir.activity.is_empty() {
            self.set_status(StatusLevel::Info, "Nothing captured to save".into());
            return;
        }
        let host = sysinfo::System::host_name().unwrap_or_default();
        let text: String = self.ir.activity.iter().map(|a| activity_line(a, &host) + "\n").collect();
        let (n, dropped) = (self.ir.activity.len(), crate::activity::dropped());
        let mut prov = crate::case::Provenance::live(self.ir.capture.as_ref().map_or("procwatch activity capture", |c| c.method));
        if dropped > 0 {
            prov.problems.push(format!("{dropped} events were dropped during capture"));
        }
        let Some(case) = self.ensure_case() else { return };
        match case.add_text_with("activity.jsonl", &text, prov) {
            Ok((_, item)) => self.set_status(StatusLevel::Success, format!("{n} operations saved as {}", item.id)),
            Err(e) => self.set_status(StatusLevel::Error, format!("Couldn't save activity: {e}")),
        }
    }

    /// On Windows this runs PowerShell for seconds, so never on this thread.
    fn collect_dns(&mut self) {
        self.ir.dns_asked = true;
        self.ir.dns_pending = true;
        sampler::spawn_dns(self.tx.clone());
    }

    pub(super) fn ir_on_tick(&mut self) -> bool {
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
        if due && !scanning && self.tab != Tab::Persistence {
            self.ir.persist_auto = true;
            self.scan_persistence();
        }
        if !self.ir.dns_asked && !self.ir.dns_pending {
            self.collect_dns();
        }
        if !self.ir.traffic_asked && !cfg!(test) {
            self.ir.traffic_asked = true;
            match crate::netio::start(crate::common::emit::Emit::to(self.tx.clone(), WorkerMsg::Traffic)) {
                Ok(t) => self.ir.traffic = Some(t),
                Err(e) => self.ir.traffic_error = Some(e),
            }
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
                        sampler::spawn_memory(self.tx.clone(), pid, modules);
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
        sampler::spawn_artifacts(self.tx.clone(), None);
    }

    pub fn import_artifacts(&mut self, dir: &str) {
        let p = PathBuf::from(dir.trim());
        if !p.is_dir() {
            self.mode = Mode::Input { purpose: InputPurpose::ArtifactDir, input: dir.into(), error: Some("not a folder".into()) };
            return;
        }
        self.set_status(StatusLevel::Info, format!("Reading artifacts in {}…", p.display()));
        sampler::spawn_artifacts(self.tx.clone(), Some(p));
    }

    fn add_dns_obs(&mut self, mut found: Vec<dns::DnsObs>) {
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

    // ── persistence / logs ─────────────────────────────────────────────

    pub fn scan_persistence(&mut self) {
        if self.replaying() {
            self.set_status(StatusLevel::Info, "Not available while replaying a recording — this would act on the live system".into());
            return;
        }
        self.ir.persist_rescan_at = None;
        self.ir.persist_last_scan = Some(Instant::now());
        if self.ir.persistence.as_ref().is_some_and(|p| p.pending) {
            return;
        }
        let prev = self.ir.persistence.take().map(|p| p.result).unwrap_or(Err(String::new()));
        self.ir.persistence = Some(Loaded { pending: true, fetched: Instant::now(), result: prev });
        sampler::spawn_persistence(self.tx.clone(), self.ir.intel.snapshot());
    }

    /// Compare a fresh scan with the previous one; record what changed.
    /// Returns the number of changes.
    fn persistence_diff(&mut self, items: &[PersistItem]) -> usize {
        let key = |i: &PersistItem| format!("{}|{}|{}", i.category, i.name, i.location);
        let Some(prev) = self.ir.persist_prev.replace(items.to_vec()) else { return 0 };
        let old: HashMap<String, &PersistItem> = prev.iter().map(|i| (key(i), i)).collect();
        let new: HashMap<String, &PersistItem> = items.iter().map(|i| (key(i), i)).collect();
        let now = Local::now();
        let mut changes: Vec<(&'static str, PersistItem)> = Vec::new();
        for (k, i) in &new {
            match old.get(k) {
                None => changes.push(("added", (*i).clone())),
                Some(o) if o.command != i.command || o.target != i.target || o.sha256 != i.sha256 => changes.push(("changed", (*i).clone())),
                _ => {}
            }
        }
        for (k, i) in &old {
            if !new.contains_key(k) {
                changes.push(("removed", (*i).clone()));
            }
        }
        let n = changes.len();
        for (kind, it) in changes {
            // The writer: a deep-traced process that had the definition
            // file open around the change notification.
            let w = self.ir.persist_writers.iter().rev().find(|(p, _, _)| *p == it.location).cloned();
            let writer_key = w.as_ref().and_then(|x| x.2);
            let time = w.as_ref().map(|x| x.1).unwrap_or(now);
            let writer = writer_key.map(|k| format!("{} ({})", self.name_of(k.pid), k.pid));
            let change = PersistChange {
                time,
                kind,
                category: it.category.clone(),
                name: it.name.clone(),
                location: it.location.clone(),
                target: it.target.clone(),
                command: it.command.clone(),
                writer: writer.clone(),
                writer_key,
            };
            if let Some(st) = self.ir.store.as_mut() {
                st.write(time, crate::store::Rec::Persist { kind: kind.into(), category: it.category.clone(), name: it.name.clone(), location: it.location.clone(), target: it.target.clone(), writer: writer.clone() });
            }
            if kind != "removed" {
                let mut hit = crate::triage::RuleHit::from_def(
                    crate::triage::rule("PW-019").expect("rule"),
                    format!(
                        "{kind}: {} {} → {} · {}{}",
                        it.category,
                        it.name,
                        it.command,
                        writer.as_deref().map(|w| format!("written by {w}")).unwrap_or_else(|| "writer unknown (not deep-traced)".into()),
                        if it.flags.is_empty() { String::new() } else { format!(" · ⚑ {}", it.flags.join("; ")) }
                    ),
                );
                if it.flags.is_empty() && it.signature.as_deref().is_some_and(|s| s.starts_with("valid")) {
                    hit.severity = crate::model::Severity::Low;
                }
                let (subject, label, pid) = match writer_key {
                    Some(k) => (Entity::Process(k), format!("{} ({})", self.name_of(k.pid), k.pid), Some(k.pid)),
                    None => (Entity::Persistence(format!("{}|{}|{}", it.category, it.name, it.location)), format!("{}: {}", it.category, it.name), None),
                };
                self.record_detection_pub(&hit, subject, label, pid, "persistence");
            }
            if self.ir.persist_changes.len() >= 1000 {
                self.ir.persist_changes.pop_front();
            }
            self.ir.persist_changes.push_back(change);
        }
        self.ir.persist_writers.clear();
        self.ir.timeline_dirty = true;
        n
    }

    pub fn persist_items(&self) -> &[PersistItem] {
        match self.ir.persistence.as_ref().map(|p| &p.result) {
            Some(Ok(s)) => &s.items,
            _ => &[],
        }
    }

    pub fn visible_persistence(&self) -> Vec<usize> {
        let f = Filter::parse(&self.query);
        self.persist_items().iter().enumerate().filter(|(_, i)| f.matches(*i)).map(|(i, _)| i).collect()
    }

    pub fn selected_persist(&self) -> Option<&PersistItem> {
        let idx = *self.visible_persistence().get(self.ir.persist_selected)?;
        self.persist_items().get(idx)
    }

    pub fn fetch_logs(&mut self) {
        if self.replaying() {
            self.set_status(StatusLevel::Info, "Not available while replaying a recording — this would act on the live system".into());
            return;
        }
        if self.ir.logs.as_ref().is_some_and(|l| l.pending) {
            return;
        }
        let prev = self.ir.logs.take().map(|l| l.result).unwrap_or(Ok(Vec::new()));
        self.ir.logs = Some(Loaded { pending: true, fetched: Instant::now(), result: prev });
        sampler::spawn_logs(self.tx.clone(), self.ir.log_minutes, self.ir.log_scope);
    }

    pub fn log_entries(&self) -> &[logs::Entry] {
        match self.ir.logs.as_ref().map(|l| &l.result) {
            Some(Ok(v)) => v,
            _ => &[],
        }
    }

    pub fn visible_logs(&self) -> Vec<usize> {
        let f = Filter::parse(&self.query);
        self.log_entries().iter().enumerate().filter(|(_, e)| f.matches(*e)).map(|(i, _)| i).collect()
    }

    pub fn cycle_log_window(&mut self) {
        self.ir.log_minutes = match self.ir.log_minutes {
            5 => 15,
            15 => 60,
            60 => 240,
            240 => 1440,
            _ => 5,
        };
        self.fetch_logs();
    }

    pub fn toggle_log_scope(&mut self) {
        self.ir.log_scope = if self.ir.log_scope == Scope::Important { Scope::All } else { Scope::Important };
        self.fetch_logs();
    }

    // ── file changes / analysis ────────────────────────────────────────

    pub fn visible_fs_events(&self) -> Vec<usize> {
        let f = Filter::parse(&self.query);
        // Newest first.
        (0..self.ir.fs_events.len()).rev().filter(|i| f.matches(&self.ir.fs_events[*i])).collect()
    }

    pub fn analyze_file(&mut self, path: &str) {
        let path = path.trim().to_string();
        if path.is_empty() {
            return;
        }
        self.ir.file_report = Some(Loaded {
            pending: true,
            fetched: Instant::now(),
            result: Err(path.clone()),
        });
        self.mode = Mode::FileReport;
        self.ir.report_scroll = 0;
        sampler::spawn_file_report(self.tx.clone(), path);
    }

    /// Path of the item under the cursor on pages that show files.
    pub fn selected_path(&self) -> Option<String> {
        match self.tab {
            Tab::Files if self.ir.files_changes_view => {
                let i = *self.visible_fs_events().get(self.ir.fs_selected)?;
                Some(self.ir.fs_events[i].path.clone())
            }
            Tab::Files => {
                let idx = *self.visible_files().get(self.file_selected)?;
                let h = self.files.as_ref()?.result.as_ref().ok()?.get(idx)?;
                h.path.starts_with('/').then(|| h.path.clone()).or_else(|| (h.path.get(1..3) == Some(":\\")).then(|| h.path.clone()))
            }
            Tab::Persistence => self.selected_persist().and_then(|i| i.target.clone()),
            _ => self.selected_pid().and_then(|p| self.tree.get(p)).and_then(|n| n.info.exe_path.clone()),
        }
    }

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
        let mut lap = crate::perf::Lap::new();
        let mut whole = crate::perf::Lap::new();
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
            .filter(|d| d.kind != crate::deeptrace::DtKind::Exec)
            .map(|d| (d.pid, d.kind == crate::deeptrace::DtKind::Spawn))
            .collect();
        // Name each traced instance after the program it ended up running
        // (a child is a copy of its parent until it execs).
        let mut final_image: HashMap<u32, (String, Option<String>)> = HashMap::new();
        for d in &self.ir.deep.events {
            if let Some(p) = &d.path {
                if d.kind != crate::deeptrace::DtKind::Spawn || !final_image.contains_key(&d.pid) {
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
                crate::deeptrace::DtKind::Exit => format!("exited (noticed via {})", d.via),
                crate::deeptrace::DtKind::Spawn => {
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
            let evs: Vec<crate::correlate::Ev> = v
                .iter()
                .map(|e| crate::correlate::Ev {
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
            crate::correlate::cluster(&evs)
        };
        for c in &clusters {
            for i in &c.members {
                v[*i].cluster = Some(c.id);
            }
        }
        lap.mark("timeline: cluster");
        let behaviour = if self.ir.det.behavior.is_empty() { Vec::new() } else { crate::behave::evaluate(&self.ir.det.behavior, &behaviour_events(&v)) };
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
            let hit = crate::triage::RuleHit {
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
    pub fn cluster_summaries(&self) -> Vec<crate::case::SummaryBlock> {
        let evs: Vec<crate::correlate::Ev> = self
            .ir
            .timeline
            .iter()
            .map(|e| crate::correlate::Ev {
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
        self.ir.clusters.iter().map(|c| crate::correlate::summarize(c, &evs, &evidence, &bookmarks)).collect()
    }

    /// Bookmark the selected timeline event (asks for the phase).
    pub fn request_bookmark(&mut self) {
        let Some(e) = self.visible_timeline().get(self.ir.tl_selected).map(|i| &self.ir.timeline[*i]) else { return };
        let summary = format!("{} {} {} {}", e.source, e.kind, e.name, e.detail).chars().take(160).collect();
        let purpose = InputPurpose::Bookmark { event: short_id(e.id), time: e.time.to_rfc3339(), summary };
        let input = match &e.tag {
            Some(t) => format!("{} ", crate::case::BOOKMARK_TAGS.iter().position(|x| x == t).map_or(1, |i| i + 1)),
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
        let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
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
            None => std::fs::write(&name, &out).map(|_| name.clone()).map_err(anyhow::Error::from),
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

    // ── cases & evidence ───────────────────────────────────────────────

    /// The open case, creating one in the working directory if needed.
    pub(super) fn ensure_case(&mut self) -> Option<&mut Case> {
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

    fn process_json(&self, pid: u32) -> serde_json::Value {
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
            "signature": deep.map(|d| crate::fileinfo::signature_text(&d.signature_status)),
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
                    if let Ok(h) = crate::fileinfo::hash_file(Path::new(exe)) {
                        value["exe_hashes"] = json!(h);
                    }
                }
                let prov = crate::case::Provenance::live("process snapshot (OS process APIs, lsof/vmmap/PowerShell where needed)")
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
                .filter(|h| names.contains(&h.name.as_str()) && h.status != crate::health::Status::Available)
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
        use crate::case::Provenance as P;
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
            let (lines, _) = crate::store::read(dir, Some(since), None);
            let text: String = lines
                .into_iter()
                .filter_map(|(t, rec)| serde_json::to_string(&crate::store::Line { t: t.to_rfc3339_opts(chrono::SecondsFormat::Millis, false), rec }).ok())
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
        use crate::stdexport::{misp_event, stix_bundle, unique, Indicator};
        if self.ir.timeline_dirty {
            self.rebuild_timeline();
        }
        let intel = self.ir.intel.snapshot();
        let mut ind: Vec<Indicator> = Vec::new();
        for d in self.ir.det.store.items.iter().filter(|d| d.suppressed.is_none() && d.severity >= crate::model::Severity::Medium) {
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
                    if c.state != ConnState::Listen && ip != "*" && !crate::triage::is_private(&ip) {
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
        let p = |what: &str| crate::case::Provenance::derived(what);
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
                let mut v: Vec<&crate::detect::Detection> = self.ir.det.store.items.iter().filter(|d| d.suppressed.is_none()).collect();
                v.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.confidence.cmp(&a.confidence)).then(a.first_seen.cmp(&b.first_seen)));
                v.into_iter()
                    .take(300)
                    .map(|d| crate::case::DetectionRow {
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
                let tag = num.parse::<usize>().ok().filter(|n| (1..=crate::case::BOOKMARK_TAGS.len()).contains(n));
                let Some(tag) = tag.map(|n| crate::case::BOOKMARK_TAGS[n - 1]) else {
                    self.mode = Mode::Input {
                        purpose: InputPurpose::Bookmark { event, time, summary },
                        input,
                        error: Some("Start with a phase number 1–6.".into()),
                    };
                    return;
                };
                let b = crate::case::Bookmark { event, tag: tag.into(), time, summary, note: note.into(), added: crate::case::now() };
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

    pub(super) fn report_result(&mut self, r: anyhow::Result<()>, ok: &str) {
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

impl App {
    // ── IOC sweep ──────────────────────────────────────────────────────

    pub fn open_sweep_dialog(&mut self) {
        let default = self
            .ir
            .sweep
            .as_ref()
            .map(|s| s.file.clone())
            .or_else(|| crate::ioc::default_path().map(|p| p.display().to_string()))
            .unwrap_or_default();
        self.mode = Mode::Input { purpose: InputPurpose::IocFile, input: default, error: None };
    }

    /// Everything procwatch can currently see, as sweep observations.
    fn observations(&mut self) -> Vec<crate::ioc::Obs> {
        use crate::ioc::Obs;
        let mut obs = Vec::new();
        for n in self.tree.nodes.values() {
            if let Some(p) = n.info.exe_path.as_deref() {
                self.ir.intel.request(p, true);
            }
        }
        let intel = self.ir.intel.snapshot();
        for n in self.tree.nodes.values() {
            let i = &n.info;
            let e = i.exe_path.as_deref().and_then(|p| intel.get(p));
            obs.push(Obs {
                source: "process",
                pid: Some(i.pid),
                name: i.name.clone(),
                sha256: e.and_then(|e| e.sha256.clone()),
                md5: e.and_then(|e| e.md5.clone()),
                sha1: e.and_then(|e| e.sha1.clone()),
                path: i.exe_path.clone(),
                text: format!("{} {}", i.name, i.cmd.join(" ")),
                ..Default::default()
            });
        }
        for (pid, cs) in &self.connections {
            let name = self.name_of(*pid);
            for c in cs {
                let ip = split_endpoint(&c.remote).0;
                let host = self.ir.resolver.name(&ip);
                obs.push(Obs { source: "network", pid: Some(*pid), name: name.clone(), ip: Some(ip), host, text: format!("{} {}", c.local, c.remote), ..Default::default() });
            }
        }
        for (ip, host) in self.ir.resolver.known() {
            obs.push(Obs { source: "dns", ip: Some(ip), host: Some(host), ..Default::default() });
        }
        if let Some(Ok(cache)) = &self.ir.dns_cache {
            for (name, data) in cache {
                obs.push(Obs { source: "dns cache", host: Some(name.clone()), ip: Some(data.clone()), ..Default::default() });
            }
        }
        for it in self.persist_items() {
            obs.push(Obs {
                source: "persistence",
                name: format!("{}: {}", it.category, it.name),
                sha256: it.sha256.clone(),
                path: it.target.clone(),
                text: format!("{} {}", it.command, it.location),
                ..Default::default()
            });
        }
        if let Some(Ok(files)) = self.files.as_ref().map(|f| &f.result) {
            for h in files {
                obs.push(Obs { source: "open file", pid: Some(h.pid), name: h.command.clone(), path: Some(h.path.clone()), ..Default::default() });
            }
        }
        for e in &self.ir.fs_events {
            obs.push(Obs { source: "file change", path: Some(e.path.clone()), ..Default::default() });
        }
        for e in self.log_entries() {
            obs.push(Obs { source: "event log", pid: e.pid, name: e.process.clone(), text: e.message.clone(), ..Default::default() });
        }
        if let Some(t) = &self.trace {
            for e in &t.events {
                obs.push(Obs { source: "trace", pid: Some(e.pid), name: e.process.clone(), text: e.detail.clone(), ..Default::default() });
            }
        }
        if let Some(Ok(r)) = self.ir.file_report.as_ref().map(|f| &f.result) {
            if let Some(h) = &r.hashes {
                obs.push(Obs {
                    source: "analyzed file",
                    sha256: Some(h.sha256.clone()),
                    md5: Some(h.md5.clone()),
                    sha1: Some(h.sha1.clone()),
                    path: Some(r.path.clone()),
                    text: r.deep.indicators.iter().map(|(_, v)| v.as_str()).collect::<Vec<_>>().join(" "),
                    ..Default::default()
                });
            }
        }
        obs
    }

    pub fn run_sweep(&mut self, file: &str) {
        let file = file.trim().to_string();
        let text = match std::fs::read_to_string(&file) {
            Ok(t) => t,
            Err(e) => {
                self.mode = Mode::Input { purpose: InputPurpose::IocFile, input: file, error: Some(format!("can't read: {e}")) };
                return;
            }
        };
        let (iocs, errors) = crate::ioc::parse(&text);
        if iocs.is_empty() {
            self.mode = Mode::Input { purpose: InputPurpose::IocFile, input: file, error: Some("no usable indicators in that file".into()) };
            return;
        }
        let obs = self.observations();
        let hits = crate::ioc::sweep(&iocs, &obs);
        let hashing = self.ir.intel.pending();
        self.set_status(
            if hits.is_empty() { StatusLevel::Success } else { StatusLevel::Error },
            format!("IOC sweep: {} indicators, {} hits across {} observations", iocs.len(), hits.len(), obs.len()),
        );
        if let Some(c) = &self.ir.case {
            let _ = c.log("ioc sweep", &format!("{file}: {} indicators, {} hits", iocs.len(), hits.len()));
        }
        self.ir.sweep = Some(SweepState { file, indicators: iocs.len(), errors, hits, hashing, at: Local::now() });
        self.record_ioc_hits();
        self.ir.sweep_selected = 0;
        self.mode = Mode::Sweep;
    }

    pub fn rerun_sweep(&mut self) {
        if let Some(f) = self.ir.sweep.as_ref().map(|s| s.file.clone()) {
            self.run_sweep(&f);
        }
    }

    /// Record every sweep hit as a high-severity finding.
    pub fn sweep_to_findings(&mut self) {
        let Some(hits) = self.ir.sweep.as_ref().map(|s| s.hits.clone()) else { return };
        if hits.is_empty() {
            return;
        }
        let Some(case) = self.ensure_case() else { return };
        let mut n = 0;
        for h in &hits {
            let who = match h.pid {
                Some(p) => format!(" in {} ({p})", h.name),
                None if !h.name.is_empty() => format!(" in {}", h.name),
                None => String::new(),
            };
            let title = format!("IOC match: {} {}{who}", h.kind.label(), h.ioc);
            let detail = format!("{} · {}{}", h.source, h.detail, if h.note.is_empty() { String::new() } else { format!(" · {}", h.note) });
            if case.add_finding("high", &title, "ioc sweep", &detail).is_ok() {
                n += 1;
            }
        }
        self.set_status(StatusLevel::Success, format!("Recorded {n} findings from the sweep"));
    }
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
        let snap = crate::sampler::Snapshot { tree: crate::process::tests::sample(), stats: Default::default(), connections: conns };
        app.on_worker_msg(crate::sampler::WorkerMsg::Snapshot(Box::new(snap)));
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
        let dets: Vec<&crate::detect::Detection> = app.ir.det.store.items.iter().filter(|d| d.rule_id == "PW-019").collect();
        assert_eq!(dets.len(), 2, "added + changed, not removed");
        assert!(dets.iter().any(|d| d.subject == Entity::Process(writer)));
    }
}
