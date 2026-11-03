use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::mpsc::Sender;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use ratatui::layout::Rect;

use crate::baseline::{self, Baseline, Change, ChangeKind};
use crate::columns::Col;
use crate::filter::{split_endpoint, Filter, Filterable};
use crate::config::Config;
use crate::gpu::GpuSnapshot;
use crate::inspect::DeepInfo;
use crate::network::Connection;
use crate::os::{self, Hit};
use crate::process::actions::{Action, Sig};
use crate::process::{ProcessInfo, ProcessTree, SystemStats};
use crate::rules::{self, Alert, Rule};
use crate::trace::{Category, Trace};
use crate::sampler::{self, SamplerCtl, WorkerMsg, MAX_INTERVAL_MS, MIN_INTERVAL_MS};

/// Wait this long after the selection stops moving before shelling out for
/// details, so holding ↓ doesn't spawn one inspection per row.
const INSPECT_DEBOUNCE: Duration = Duration::from_millis(300);
const MAX_INFLIGHT_INSPECTIONS: usize = 2;
const STATUS_TTL: Duration = Duration::from_secs(6);
/// Samples kept for history graphs (≈ 4.5 min at the default 1.5 s).
pub const HISTORY: usize = 180;
/// Refreshes during which a newly started process stays highlighted.
const NEW_HIGHLIGHT_SAMPLES: u64 = 3;
/// How long a politely ended process gets before we suggest force quit.
const END_GRACE: Duration = Duration::from_secs(3);
const MAX_EVENTS: usize = 2000;
/// After the user moves the selection, rows keep their order this long so
/// the list doesn't reshuffle under the cursor (values still update).
const ORDER_HOLD: Duration = Duration::from_secs(4);

#[path = "app_ir.rs"]
mod ir;
#[path = "app_detect.rs"]
mod det;
#[path = "app_graph.rs"]
pub mod graph;
#[path = "app_state.rs"]
pub mod state;
#[path = "app_response.rs"]
mod response;
#[path = "app_deep.rs"]
pub mod deep;
#[path = "app_workspace.rs"]
pub mod workspace;
#[path = "app_replay.rs"]
mod replay;
pub use ir::{InputPurpose, RemoteSummary};

// ── enums ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Processes,
    Performance,
    Network,
    Files,
    Persistence,
    Timeline,
    Logs,
    Trace,
    Alerts,
    Case,
}

impl Tab {
    pub const ALL: [Tab; 10] = [
        Tab::Processes,
        Tab::Performance,
        Tab::Network,
        Tab::Files,
        Tab::Persistence,
        Tab::Timeline,
        Tab::Logs,
        Tab::Trace,
        Tab::Alerts,
        Tab::Case,
    ];
    pub fn title(self) -> &'static str {
        match self {
            Tab::Processes => "Processes",
            Tab::Performance => "Performance",
            Tab::Network => "Network",
            Tab::Files => "Files",
            Tab::Persistence => "Persistence",
            Tab::Timeline => "Timeline",
            Tab::Logs => "Logs",
            Tab::Trace => "Trace",
            Tab::Alerts => "Detect",
            Tab::Case => "Case",
        }
    }

    /// Compact label for narrow terminals.
    pub fn short(self) -> &'static str {
        match self {
            Tab::Processes => "Procs",
            Tab::Performance => "Perf",
            Tab::Network => "Net",
            Tab::Files => "Files",
            Tab::Persistence => "Persist",
            Tab::Timeline => "Time",
            Tab::Logs => "Logs",
            Tab::Trace => "Trace",
            Tab::Alerts => "Detect",
            Tab::Case => "Case",
        }
    }

    /// Key that jumps to this page: 1–9, then 0.
    pub fn key(self) -> char {
        let i = Self::ALL.iter().position(|t| *t == self).unwrap_or(0);
        if i == 9 { '0' } else { char::from(b'1' + i as u8) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    List,
    Tree,
    Apps,
    /// Only processes with a triage score, riskiest first.
    Suspicious,
}

impl ViewMode {
    pub fn label(self) -> &'static str {
        match self {
            ViewMode::List => "All processes",
            ViewMode::Tree => "Process tree",
            ViewMode::Apps => "Grouped by app",
            ViewMode::Suspicious => "Suspicious only",
        }
    }
    pub fn key(self) -> &'static str {
        match self {
            ViewMode::List => "list",
            ViewMode::Tree => "tree",
            ViewMode::Apps => "apps",
            ViewMode::Suspicious => "suspicious",
        }
    }
    pub fn from_key(k: &str) -> Option<Self> {
        [ViewMode::List, ViewMode::Tree, ViewMode::Apps, ViewMode::Suspicious].into_iter().find(|v| v.key() == k.trim())
    }
    pub fn next(self) -> Self {
        match self {
            ViewMode::List => ViewMode::Tree,
            ViewMode::Tree => ViewMode::Apps,
            ViewMode::Apps => ViewMode::Suspicious,
            ViewMode::Suspicious => ViewMode::List,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneTab {
    Overview,
    Relations,
    Performance,
    Threads,
    Stack,
    Files,
    Network,
    Modules,
    Memory,
    Environment,
}

impl PaneTab {
    pub const ALL: [PaneTab; 10] = [
        PaneTab::Overview,
        PaneTab::Relations,
        PaneTab::Performance,
        PaneTab::Threads,
        PaneTab::Stack,
        PaneTab::Files,
        PaneTab::Network,
        PaneTab::Modules,
        PaneTab::Memory,
        PaneTab::Environment,
    ];
    pub fn title(self) -> &'static str {
        match self {
            PaneTab::Overview => "Overview",
            PaneTab::Relations => "Relations",
            PaneTab::Performance => "Performance",
            PaneTab::Threads => "Threads",
            PaneTab::Stack => "Stack",
            PaneTab::Files => "Handles",
            PaneTab::Network => "Network",
            PaneTab::Modules => "Modules",
            PaneTab::Memory => "Memory",
            PaneTab::Environment => "Environment",
        }
    }
    fn index(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
    pub fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }
    pub fn prev(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
    /// Tabs whose data comes from a (slow) inspection.
    pub fn needs_inspection(self) -> bool {
        matches!(self, PaneTab::Overview | PaneTab::Threads | PaneTab::Files | PaneTab::Modules | PaneTab::Memory | PaneTab::Environment)
    }
}

// ── rows ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RowKey {
    Proc(u32),
    Group(String),
}

#[derive(Debug, Clone)]
pub struct Row {
    pub key: RowKey,
    /// Tree guide (`│  ├─ `) or group indent.
    pub prefix: String,
    pub expandable: bool,
    pub expanded: bool,
    /// Descendants hidden under a collapsed tree node.
    pub hidden: usize,
}

/// Aggregate of all processes belonging to one app (Apps view).
#[derive(Debug, Clone, Default)]
pub struct Group {
    pub name: String,
    pub members: Vec<u32>,
    pub cpu: f32,
    pub mem: u64,
    pub threads: u64,
    pub disk: f64,
    pub user: Option<String>,
}

// ── menus & dialogs ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Cmd {
    Details,
    Trace,
    SaveBaseline,
    End,
    ForceQuit,
    EndTree,
    Suspend,
    Resume,
    Priority(i32),
    Signal(Sig),
    CopyPid,
    CopyName,
    CopyPath,
    CopyCommand,
    Reveal,
    OnlyThisApp,
    OnlyThisUser,
    ToggleSelect,
    Expand,
    SortBy(Col),
    Sub(Vec<MenuItem>),
    CollectEvidence,
    CollectEvidenceWithExe,
    AnalyzeExe,
    QuarantineExe,
    MarkFinding,
    Workspace,
    DeepTrace,
    /// Confirmed file quarantine of this path.
    Quarantine(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct MenuItem {
    pub label: String,
    /// Key that does the same thing directly, shown at the right.
    pub shortcut: &'static str,
    pub cmd: Cmd,
    pub enabled: bool,
    pub checked: bool,
}

impl MenuItem {
    pub fn new(label: impl Into<String>, shortcut: &'static str, cmd: Cmd) -> Self {
        Self { label: label.into(), shortcut, cmd, enabled: true, checked: false }
    }
    pub fn enabled(mut self, on: bool) -> Self {
        self.enabled = on;
        self
    }
    pub fn checked(mut self, on: bool) -> Self {
        self.checked = on;
        self
    }
    pub fn is_separator(&self) -> bool {
        self.label.is_empty()
    }
    pub fn separator() -> Self {
        Self { label: String::new(), shortcut: "", cmd: Cmd::Details, enabled: false, checked: false }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MenuLevel {
    pub title: String,
    pub items: Vec<MenuItem>,
    pub cursor: usize,
    /// Screen position the menu opens at (top-left).
    pub anchor: (u16, u16),
}

impl MenuLevel {
    pub fn new(title: impl Into<String>, items: Vec<MenuItem>, anchor: (u16, u16)) -> Self {
        let cursor = items.iter().position(|i| i.enabled && !i.is_separator()).unwrap_or(0);
        Self { title: title.into(), items, cursor, anchor }
    }
    pub fn step(&mut self, delta: isize) {
        let n = self.items.len() as isize;
        if n == 0 {
            return;
        }
        let mut i = self.cursor as isize;
        for _ in 0..n {
            i = (i + delta).rem_euclid(n);
            let it = &self.items[i as usize];
            if it.enabled && !it.is_separator() {
                self.cursor = i as usize;
                return;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Mode {
    Normal,
    Search,
    Menu(Vec<MenuLevel>),
    Confirm { cmd: Cmd, targets: Vec<u32> },
    Options { cursor: usize },
    Find { input: String },
    RuleInput { input: String, error: Option<String> },
    Input { purpose: InputPurpose, input: String, error: Option<String> },
    /// File analysis report overlay.
    FileReport,
    /// Investigation graph around one entity.
    Graph,
    /// Correlated activity clusters (from the timeline).
    Clusters,
    /// What data sources are available.
    Health,
    /// Reconstructed system state at one moment.
    StateAt,
    /// Process Investigation Workspace.
    Workspace,
    /// IOC sweep results overlay.
    Sweep,
    Help,
}

/// Entries of the Options screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionItem {
    Interval,
    View,
    DetailsPane,
    ConfirmEnd,
    HighlightNew,
    Notify,
    Column(Col),
}

impl OptionItem {
    pub fn all() -> Vec<OptionItem> {
        let mut v = vec![
            OptionItem::Interval,
            OptionItem::View,
            OptionItem::DetailsPane,
            OptionItem::ConfirmEnd,
            OptionItem::HighlightNew,
            OptionItem::Notify,
        ];
        v.extend(Col::ALL.iter().filter(|c| **c != Col::Name).map(|c| OptionItem::Column(*c)));
        v
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusLevel {
    Info,
    Success,
    Error,
}

pub struct Status {
    pub text: String,
    pub level: StatusLevel,
    pub at: Instant,
}

// ── other state ────────────────────────────────────────────────────────

/// Screen regions from the last frame, for mouse hit-testing.
#[derive(Default)]
pub struct HitAreas {
    pub tabs: Vec<(Rect, Tab)>,
    pub search: Rect,
    pub view_toggle: Rect,
    pub list_header: Vec<(Rect, Col)>,
    pub list_rows: Rect,
    pub pane_tabs: Vec<(Rect, PaneTab)>,
    pub pane_body: Rect,
    pub menus: Vec<Rect>,
    pub find_rows: Rect,
}

pub struct DeepEntry {
    pub start_time: u64,
    pub fetched: Instant,
    pub info: DeepInfo,
}

pub struct ProcHistory {
    pub start_time: u64,
    pub cpu: VecDeque<f64>,
    pub mem: VecDeque<f64>,
    pub io: VecDeque<f64>,
}

#[derive(Default)]
pub struct SysHistory {
    pub cpu: VecDeque<f64>,
    pub per_core: Vec<VecDeque<f64>>,
    pub mem: VecDeque<f64>,
    pub swap: VecDeque<f64>,
    pub net_rx: VecDeque<f64>,
    pub net_tx: VecDeque<f64>,
    pub disk_r: VecDeque<f64>,
    pub disk_w: VecDeque<f64>,
}

fn push(buf: &mut VecDeque<f64>, v: f64) {
    if buf.len() >= HISTORY {
        buf.pop_front();
    }
    buf.push_back(if v.is_finite() { v } else { 0.0 });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Started,
    Exited,
}

/// One entry of the Activity log.
pub struct Event {
    pub at: DateTime<Local>,
    pub kind: EventKind,
    pub pid: u32,
    pub name: String,
    pub parent: String,
    pub user: String,
    /// Lifetime for exits, command line for starts.
    pub detail: String,
    /// Process start time (OS-reported), so the event names one process
    /// instance even after its PID is reused.
    pub start: u64,
    pub ppid: Option<u32>,
    pub exe: Option<String>,
}

/// One line of the system-wide connections table.
pub struct ConnRow {
    pub pid: u32,
    pub name: String,
    pub user: Option<String>,
    pub conn: Connection,
}

pub struct StackEntry {
    pub start_time: u64,
    pub fetched: Instant,
    pub result: Result<Vec<String>, String>,
}

pub struct FileList {
    pub pending: bool,
    pub fetched: Instant,
    pub result: Result<Vec<Hit>, String>,
}

pub struct FindState {
    pub query: String,
    pub pending: bool,
    pub result: Result<Vec<Hit>, String>,
    pub cursor: usize,
}

pub struct App {
    // Data from the sampler.
    pub tree: ProcessTree,
    pub stats: SystemStats,
    pub connections: HashMap<u32, Vec<Connection>>,
    pub gpu: Option<GpuSnapshot>,
    pub loaded: bool,
    pub last_snapshot: Instant,
    seq: u64,
    first_seen: HashMap<u32, u64>,
    pub proc_hist: HashMap<u32, ProcHistory>,
    pub sys_hist: SysHistory,
    pub events: VecDeque<Event>,

    // Process list.
    pub tab: Tab,
    pub rows: Vec<Row>,
    pub groups: HashMap<String, Group>,
    pub selected: usize,
    selected_key: Option<RowKey>,
    selection_changed: Instant,
    pub offset: usize,
    pub columns: Vec<Col>,
    pub sort: Col,
    pub sort_desc: bool,
    pub view: ViewMode,
    pub highlight_new: bool,
    pub confirm_end: bool,
    pub collapsed: HashSet<u32>,
    pub expanded_groups: HashSet<String>,
    pub tagged: HashSet<u32>,
    pub query: String,
    /// Processes matching the search (others shown are tree context).
    pub matched: HashSet<u32>,
    pub user_filter: Option<String>,
    pub app_filter: Option<String>,

    // Other pages.
    pub conn_rows: Vec<ConnRow>,
    pub conn_selected: usize,
    pub conn_offset: usize,
    pub find: Option<FindState>,

    // Alerts.
    pub rules: Vec<Rule>,
    engine: rules::Engine,
    pub alerts: VecDeque<Alert>,
    pub unread_alerts: usize,
    pub alert_selected: usize,
    pub alert_offset: usize,
    pub rule_selected: usize,
    /// Alerts page: keyboard focus on the rule list instead of alerts.
    pub rules_focus: bool,
    pub notify: bool,

    // Call stacks (sampled on demand) and the system-wide file list.
    pub stacks: HashMap<u32, StackEntry>,
    pub stack_pending: Option<u32>,
    pub files: Option<FileList>,
    pub file_selected: usize,
    pub file_offset: usize,

    /// Investigation state (timeline, persistence, logs, case…).
    pub ir: ir::Ir,

    // Baseline comparison.
    pub baseline: Option<Baseline>,
    pub changes: Vec<Change>,
    pub change_selected: usize,
    pub change_offset: usize,

    // Behavior trace.
    pub trace: Option<Trace>,
    trace_targets: Arc<Mutex<Vec<u32>>>,
    trace_stop: Arc<AtomicBool>,
    pub trace_filter: Category,
    pub trace_selected: usize,
    pub trace_offset: usize,
    /// Keep the newest trace event selected as events arrive.
    pub trace_follow: bool,

    // Details.
    pub pane_visible: bool,
    pub detail_full: bool,
    pub pane_tab: PaneTab,
    pub pane_scroll: usize,
    pub deep_cache: HashMap<u32, DeepEntry>,
    pub deep_pending: HashSet<u32>,
    pub actions_pending: usize,
    end_watch: HashMap<u32, (Instant, String)>,

    pub mode: Mode,
    pub status: Option<Status>,
    pub ctl: Arc<SamplerCtl>,
    tx: Sender<WorkerMsg>,
    pub hit: HitAreas,
    pub tick: u64,
    last_click: Option<(Instant, u16)>,
    pub should_quit: bool,
    /// Manual freeze of the row order (`z`); values keep updating.
    pub order_frozen: bool,
    hold_until: Option<Instant>,
    /// View/sort/filter signature of the last rebuild; a change here always
    /// re-sorts, even while the order is held.
    layout_sig: String,
}

impl App {
    pub fn new(tx: Sender<WorkerMsg>, ctl: Arc<SamplerCtl>, cfg: Config) -> Self {
        ctl.interval_ms.store(cfg.interval_ms, Ordering::Relaxed);
        Self {
            tree: ProcessTree::default(),
            stats: SystemStats::default(),
            connections: HashMap::new(),
            gpu: None,
            loaded: false,
            last_snapshot: Instant::now(),
            seq: 0,
            first_seen: HashMap::new(),
            proc_hist: HashMap::new(),
            sys_hist: SysHistory::default(),
            events: VecDeque::new(),
            tab: Tab::Processes,
            rows: Vec::new(),
            groups: HashMap::new(),
            selected: 0,
            selected_key: None,
            selection_changed: Instant::now(),
            offset: 0,
            columns: cfg.columns,
            sort: cfg.sort,
            sort_desc: cfg.sort_desc,
            view: cfg.view,
            highlight_new: cfg.highlight_new,
            confirm_end: cfg.confirm_end,
            collapsed: HashSet::new(),
            expanded_groups: HashSet::new(),
            tagged: HashSet::new(),
            query: String::new(),
            matched: HashSet::new(),
            user_filter: None,
            app_filter: None,
            conn_rows: Vec::new(),
            conn_selected: 0,
            conn_offset: 0,
            find: None,
            rules: cfg.rules.iter().filter_map(|r| Rule::parse(r).ok()).collect(),
            engine: rules::Engine::default(),
            alerts: VecDeque::new(),
            unread_alerts: 0,
            alert_selected: 0,
            alert_offset: 0,
            rule_selected: 0,
            rules_focus: false,
            notify: cfg.notify,
            stacks: HashMap::new(),
            stack_pending: None,
            files: None,
            file_selected: 0,
            file_offset: 0,
            ir: {
                let mut ir = ir::Ir::new(tx.clone(), &cfg.watch);
                if cfg.history && !cfg!(test) {
                    ir.profiles = Some(crate::profile::Profiles::load());
                    ir.store = crate::store::default_dir().map(crate::store::Writer::open);
                    if let Some(s) = ir.store.as_mut() {
                        s.write(chrono::Local::now(), crate::store::Rec::Session {
                            host: sysinfo::System::host_name().unwrap_or_default(),
                            version: env!("CARGO_PKG_VERSION").into(),
                            note: "session started".into(),
                        });
                    }
                }
                ir
            },
            baseline: baseline::default_path().and_then(|p| Baseline::load(&p).ok()),
            changes: Vec::new(),
            change_selected: 0,
            change_offset: 0,
            trace: None,
            trace_targets: Arc::new(Mutex::new(Vec::new())),
            trace_stop: Arc::new(AtomicBool::new(true)),
            trace_filter: Category::All,
            trace_selected: 0,
            trace_offset: 0,
            trace_follow: true,
            pane_visible: cfg.details_pane,
            detail_full: false,
            pane_tab: PaneTab::Overview,
            pane_scroll: 0,
            deep_cache: HashMap::new(),
            deep_pending: HashSet::new(),
            actions_pending: 0,
            end_watch: HashMap::new(),
            mode: Mode::Normal,
            status: None,
            ctl,
            tx,
            hit: HitAreas::default(),
            tick: 0,
            last_click: None,
            should_quit: false,
            order_frozen: false,
            hold_until: None,
            layout_sig: String::new(),
        }
    }

    pub fn config(&self) -> Config {
        Config {
            columns: self.columns.clone(),
            sort: self.sort,
            sort_desc: self.sort_desc,
            view: self.view,
            interval_ms: self.ctl.interval_ms.load(Ordering::Relaxed),
            highlight_new: self.highlight_new,
            details_pane: self.pane_visible,
            confirm_end: self.confirm_end,
            notify: self.notify,
            rules: self.rules.iter().map(|r| r.text.clone()).collect(),
            watch: self.ir.watch_paths.clone(),
            // Not changed from the UI; keep what the file says (a replay
            // session runs with history off and must not save that).
            history: Config::load().history,
        }
    }

    pub fn save_config(&mut self) {
        if let Err(e) = self.config().save() {
            self.set_status(StatusLevel::Error, format!("Couldn't save settings: {e}"));
        }
    }

    /// Change page, clearing the per-page search and badges.
    pub fn switch_tab(&mut self, tab: Tab) {
        self.tab = tab;
        if tab == Tab::Alerts {
            self.unread_alerts = 0;
            self.ir.det.unread = 0;
        }
    }

    pub fn name_of(&self, pid: u32) -> String {
        if let Some(n) = self.tree.get(pid) {
            return n.info.name.clone();
        }
        // Exited: the name it was recorded under.
        self.events
            .iter()
            .find(|e| e.pid == pid)
            .map(|e| e.name.clone())
            .or_else(|| {
                self.ir.deep.events.iter().rev().filter(|e| e.pid == pid).find_map(|e| {
                    e.args.as_deref().and_then(|a| a.split_whitespace().next()).or(e.path.as_deref()).map(|p| p.rsplit(['/', '\\']).next().unwrap_or(p).to_string())
                })
            })
            .unwrap_or_else(|| format!("pid {pid}"))
    }

    // ── worker messages ────────────────────────────────────────────────

    pub fn on_worker_msg(&mut self, msg: WorkerMsg) {
        match msg {
            WorkerMsg::Snapshot(snap) => self.on_snapshot(*snap),
            WorkerMsg::Gpu(g) => self.gpu = Some(g),
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
            | WorkerMsg::DeepSnap { .. }
            | WorkerMsg::Memory { .. }
            | WorkerMsg::Evidence(_)) => self.ir_on_msg(msg),
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

    fn on_snapshot(&mut self, snap: sampler::Snapshot) {
        let first = !self.loaded;
        self.seq += 1;
        let old = std::mem::replace(&mut self.tree, snap.tree);
        self.stats = snap.stats;
        self.connections = snap.connections;
        self.last_snapshot = Instant::now();
        self.loaded = true;

        let (started, exited) = if first { (Vec::new(), Vec::new()) } else { self.record_events(&old) };

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

        // Alert rules.
        let started_refs: Vec<&ProcessInfo> = started.iter().collect();
        let exited_refs: Vec<&ProcessInfo> = exited.iter().collect();
        let changes = rules::Changes { started: &started_refs, exited: &exited_refs };
        let tree = &self.tree;
        let growth = |pid: u32| tree.get(pid).and_then(|n| n.info.mem_growth);
        let fired = self.engine.evaluate(&self.rules, tree, &self.connections, &changes, &growth);
        self.add_alerts(fired);

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
        self.ir_on_snapshot();

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

        self.rebuild();
    }

    /// Log starts/exits since `old`; returns them for the rule engine.
    fn record_events(&mut self, old: &ProcessTree) -> (Vec<ProcessInfo>, Vec<ProcessInfo>) {
        let now = Local::now();
        let parent_name = |tree: &ProcessTree, ppid: Option<u32>| {
            ppid.and_then(|p| tree.get(p)).map(|n| format!("{} ({})", n.info.name, n.info.pid)).unwrap_or_default()
        };
        // procwatch's own helpers (codesign, lsof, vmmap…) are not activity
        // on the system under investigation.
        let me = Some(std::process::id());
        let mut started: Vec<&ProcessInfo> = self
            .tree
            .nodes
            .values()
            .filter(|n| n.info.ppid != me)
            .filter(|n| old.get(n.info.pid).is_none_or(|o| o.info.start_time_secs != n.info.start_time_secs))
            .map(|n| &n.info)
            .collect();
        started.sort_by_key(|i| i.pid);
        let mut exited: Vec<&ProcessInfo> = old
            .nodes
            .values()
            .filter(|n| n.info.ppid != me)
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
                    EventKind::Started => crate::store::Rec::ProcStart(crate::store::ProcRec {
                        pid: e.pid,
                        ppid: e.ppid,
                        start: e.start,
                        name: e.name.clone(),
                        exe: e.exe.clone(),
                        cmd: e.detail.clone(),
                        user: e.user.clone(),
                    }),
                    EventKind::Exited => crate::store::Rec::ProcExit { pid: e.pid, start: e.start, name: e.name.clone(), ran: e.detail.clone() },
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

    // ── alerts ─────────────────────────────────────────────────────────

    fn add_alerts(&mut self, fired: Vec<Alert>) {
        if fired.is_empty() {
            return;
        }
        if self.notify {
            let body = match fired.as_slice() {
                [one] => format!("{} ({}): {}", one.name, one.pid, one.message),
                many => format!("{} alerts — first: {} {}", many.len(), many[0].name, many[0].message),
            };
            os::notify("procwatch alert", &body);
        }
        if self.tab != Tab::Alerts {
            self.unread_alerts += fired.len();
        }
        let first = &fired[0];
        self.set_status(StatusLevel::Error, format!("Alert: {} ({}) — {}", first.name, first.pid, first.message));
        for a in fired {
            if self.alerts.len() >= 1000 {
                self.alerts.pop_back();
            }
            self.alerts.push_front(a);
            if self.alert_selected > 0 {
                self.alert_selected += 1;
            }
        }
    }

    pub fn add_rule(&mut self, text: &str) -> Result<(), String> {
        let rule = Rule::parse(text)?;
        if self.rules.iter().any(|r| r.text == rule.text) {
            return Err("that rule already exists".into());
        }
        self.set_status(StatusLevel::Success, format!("Rule added: alert when {}", rule.describe()));
        self.rules.push(rule);
        self.rule_selected = self.rules.len() - 1;
        self.save_config();
        Ok(())
    }

    pub fn delete_rule(&mut self) {
        if self.rule_selected < self.rules.len() {
            let r = self.rules.remove(self.rule_selected);
            self.rule_selected = self.rule_selected.min(self.rules.len().saturating_sub(1));
            self.set_status(StatusLevel::Info, format!("Rule removed: {}", r.text));
            self.save_config();
        }
    }

    pub fn toggle_rule(&mut self) {
        if let Some(r) = self.rules.get_mut(self.rule_selected) {
            r.enabled = !r.enabled;
        }
    }

    // ── call stacks / files / alert filtering ─────────────────────────

    /// Sample call stacks of the shown process (takes about a second).
    pub fn request_stack(&mut self, force: bool) -> bool {
        let Some(pid) = self.detail_pid() else { return false };
        if self.stack_pending.is_some() || (!force && self.stacks.contains_key(&pid)) {
            return false;
        }
        let Some(node) = self.tree.get(pid) else { return false };
        self.stack_pending = Some(pid);
        sampler::spawn_stack(self.tx.clone(), pid, node.info.start_time_secs);
        true
    }

    pub fn refresh_files(&mut self) {
        if self.replaying() {
            self.set_status(StatusLevel::Info, "Not available while replaying a recording — this would act on the live system".into());
            return;
        }
        if self.files.as_ref().is_some_and(|f| f.pending) {
            return;
        }
        let previous = self.files.take().map(|f| f.result).unwrap_or(Ok(Vec::new()));
        self.files = Some(FileList { pending: true, fetched: Instant::now(), result: previous });
        sampler::spawn_file_list(self.tx.clone());
    }

    pub fn visible_files(&self) -> Vec<usize> {
        let Some(Ok(hits)) = self.files.as_ref().map(|f| &f.result) else { return Vec::new() };
        let f = Filter::parse(&self.query);
        hits.iter().enumerate().filter(|(_, h)| f.matches(*h)).map(|(i, _)| i).collect()
    }

    pub fn selected_file_pid(&self) -> Option<u32> {
        let idx = *self.visible_files().get(self.file_selected)?;
        self.files.as_ref()?.result.as_ref().ok()?.get(idx).map(|h| h.pid)
    }

    pub fn visible_alerts(&self) -> Vec<usize> {
        let f = Filter::parse(&self.query);
        self.alerts.iter().enumerate().filter(|(_, a)| f.matches(*a)).map(|(i, _)| i).collect()
    }

    pub fn selected_alert_pid(&self) -> Option<u32> {
        let idx = *self.visible_alerts().get(self.alert_selected)?;
        self.alerts.get(idx).map(|a| a.pid)
    }

    // ── baseline ───────────────────────────────────────────────────────

    /// Ask before replacing an existing baseline; save right away otherwise.
    pub fn request_save_baseline(&mut self) {
        if self.baseline.is_some() {
            self.mode = Mode::Confirm { cmd: Cmd::SaveBaseline, targets: Vec::new() };
        } else {
            self.save_baseline();
        }
    }

    pub fn save_baseline(&mut self) {
        self.mode = Mode::Normal;
        if !self.loaded {
            return;
        }
        let Some(path) = baseline::default_path() else {
            self.set_status(StatusLevel::Error, "No settings directory to save the baseline in".into());
            return;
        };
        let base = Baseline::capture(&self.tree, &self.connections);
        match base.save(&path) {
            Ok(()) => {
                self.set_status(
                    StatusLevel::Success,
                    format!("Baseline saved: {} programs, {} listening ports", base.programs.len(), base.listeners.len()),
                );
                self.baseline = Some(base);
                self.changes.clear();
                self.change_selected = 0;
            }
            Err(e) => self.set_status(StatusLevel::Error, format!("Couldn't save baseline: {e}")),
        }
    }

    /// Indices of changes passing the search.
    pub fn visible_changes(&self) -> Vec<usize> {
        let f = Filter::parse(&self.query);
        self.changes
            .iter()
            .enumerate()
            .filter(|(_, c)| f.matches(*c))
            .map(|(i, _)| i)
            .collect()
    }

    /// New programs and ports since the baseline (for the tab badge).
    pub fn new_change_count(&self) -> usize {
        self.changes.iter().filter(|c| matches!(c.kind, ChangeKind::NewProgram | ChangeKind::NewListener)).count()
    }

    /// Jump to a running process behind the selected change.
    pub fn open_change(&mut self) {
        let Some(c) = self.visible_changes().get(self.change_selected).and_then(|i| self.changes.get(*i)).cloned() else { return };
        let pid = self
            .tree
            .nodes
            .values()
            .filter(|n| n.info.name == c.name && (c.user.is_none() || n.info.user == c.user))
            .map(|n| n.info.pid)
            .min();
        match pid {
            Some(pid) => self.focus_pid(pid),
            None => self.set_status(StatusLevel::Info, format!("{} isn't running now", c.name)),
        }
    }

    // ── behavior trace ─────────────────────────────────────────────────

    pub fn start_trace(&mut self, pid: u32) {
        if self.replaying() {
            self.set_status(StatusLevel::Info, "Not available while replaying a recording — this would act on the live system".into());
            return;
        }
        if pid == std::process::id() {
            self.set_status(StatusLevel::Error, "procwatch can't trace itself".into());
            return;
        }
        self.stop_trace();
        let Some(t) = Trace::new(pid, &self.tree, &self.connections) else {
            self.set_status(StatusLevel::Error, format!("Process {pid} is no longer running"));
            return;
        };
        if let Ok(mut targets) = self.trace_targets.lock() {
            *targets = t.live_pids();
        }
        let stop = Arc::new(AtomicBool::new(false));
        self.trace_stop = stop.clone();
        sampler::spawn_trace_poller(self.tx.clone(), self.trace_targets.clone(), stop);
        self.set_status(StatusLevel::Success, format!("Tracing {} ({pid}) and its child processes", t.root_name));
        self.trace = Some(t);
        // A leftover search from the Processes page would hide events.
        self.query.clear();
        self.rebuild();
        self.trace_selected = 0;
        self.trace_offset = 0;
        self.trace_follow = true;
        self.tab = Tab::Trace;
        self.detail_full = false;
    }

    pub fn stop_trace(&mut self) {
        self.trace_stop.store(true, Ordering::Relaxed);
        let mut stopped = None;
        if let Some(t) = self.trace.as_mut() {
            if t.is_running() {
                t.stop();
                stopped = Some(t.elapsed().as_secs_f64());
            }
        }
        if let Some(secs) = stopped {
            self.set_status(StatusLevel::Info, format!("Trace stopped after {secs:.0}s — press e to export a report"));
        }
    }

    pub fn export_trace(&mut self) {
        let Some(t) = self.trace.as_ref() else { return };
        match t.export() {
            Ok(base) => self.set_status(StatusLevel::Success, format!("Report saved: {base}.md and {base}.json")),
            Err(e) => self.set_status(StatusLevel::Error, format!("Couldn't save report: {e}")),
        }
    }

    /// Indices of trace events passing the category filter and search.
    pub fn visible_trace(&self) -> Vec<usize> {
        let Some(t) = self.trace.as_ref() else { return Vec::new() };
        let f = Filter::parse(&self.query);
        t.events
            .iter()
            .enumerate()
            .filter(|(_, e)| self.trace_filter.matches(e.kind))
            .filter(|(_, e)| f.matches(*e))
            .map(|(i, _)| i)
            .collect()
    }

    fn follow_trace(&mut self) {
        if self.trace_follow {
            self.trace_selected = self.visible_trace().len().saturating_sub(1);
        }
    }

    pub fn is_new(&self, pid: u32) -> bool {
        self.highlight_new
            && self.first_seen.get(&pid).is_some_and(|s| *s > 0 && self.seq.saturating_sub(*s) < NEW_HIGHLIGHT_SAMPLES)
    }

    /// Periodic housekeeping between frames. Returns true if anything
    /// visible changed and a redraw is needed.
    pub fn on_tick(&mut self) -> bool {
        self.tick = self.tick.wrapping_add(1);
        let mut dirty = self.is_busy();
        if self.status.as_ref().is_some_and(|s| s.at.elapsed() > STATUS_TTL) {
            self.status = None;
            dirty = true;
        }
        if self.details_visible() && self.pane_tab.needs_inspection() && self.selection_changed.elapsed() >= INSPECT_DEBOUNCE
        {
            dirty |= self.request_deep_info(false);
        }
        if self.details_visible() && self.pane_tab == PaneTab::Stack && self.selection_changed.elapsed() >= INSPECT_DEBOUNCE {
            dirty |= self.request_stack(false);
        }
        if self.tab == Tab::Files && self.files.is_none() {
            self.refresh_files();
            dirty = true;
        }
        dirty |= self.ir_on_tick();
        if self.hold_until.is_some_and(|t| Instant::now() >= t) {
            // Hold expired: catch up with the real sort order.
            self.hold_until = None;
            self.rebuild();
            dirty = true;
        }
        dirty
    }

    /// Whether rows currently keep their previous order.
    pub fn order_held(&self) -> bool {
        self.order_frozen || self.hold_until.is_some_and(|t| Instant::now() < t)
    }

    pub fn hold_order_now(&mut self) {
        self.hold_order();
    }

    fn hold_order(&mut self) {
        if self.tab == Tab::Processes {
            self.hold_until = Some(Instant::now() + ORDER_HOLD);
        }
    }

    pub fn toggle_freeze(&mut self) {
        self.order_frozen = !self.order_frozen;
        self.hold_until = None;
        if !self.order_frozen {
            self.rebuild();
        }
        self.set_status(
            StatusLevel::Info,
            if self.order_frozen {
                "List order frozen — values still update; press z to unfreeze"
            } else {
                "List order follows the sort again"
            }
            .into(),
        );
    }

    pub fn is_busy(&self) -> bool {
        !self.loaded
            || self.actions_pending > 0
            || self.find.as_ref().is_some_and(|f| f.pending)
            || self.detail_pid().is_some_and(|p| self.deep_pending.contains(&p))
            || self.ir_busy()
    }

    pub fn is_stale(&self) -> bool {
        self.loaded
            && !self.ctl.paused.load(Ordering::Relaxed)
            && self.last_snapshot.elapsed() > self.ctl.interval() * 3 + Duration::from_secs(2)
    }

    // ── building rows ──────────────────────────────────────────────────

    fn compare(&self, a: &ProcessInfo, b: &ProcessInfo) -> std::cmp::Ordering {
        let ord = self.sort.compare(a, b);
        if self.sort_desc { ord.reverse() } else { ord }
    }

    /// Search uses the shared filter syntax (see `filter.rs`): free text
    /// matches name, PID, path, arguments or user; `port:`/`:8080` match
    /// processes with sockets on that port.
    fn matches(&self, info: &ProcessInfo, f: &Filter) -> bool {
        f.matches(&ProcItem { info, conns: self.connections.get(&info.pid) })
    }

    pub fn filtering(&self) -> bool {
        !self.query.is_empty() || self.user_filter.is_some() || self.app_filter.is_some()
    }

    /// Recompute rows from the tree, view, sort, search and expansion
    /// state, keeping the same row selected.
    pub fn rebuild(&mut self) {
        let q = self.query.trim().to_lowercase();
        let f = Filter::parse(&self.query);
        self.matched.clear();
        let filtering = self.filtering();
        if filtering {
            for (pid, node) in &self.tree.nodes {
                let i = &node.info;
                let user_ok = self.user_filter.as_deref().is_none_or(|u| i.user.as_deref() == Some(u));
                let app_ok = self.app_filter.as_deref().is_none_or(|a| i.app_name() == a);
                if user_ok && app_ok && (f.is_empty() || self.matches(i, &f)) {
                    self.matched.insert(*pid);
                }
            }
        }
        let visible = |pid: &u32| !filtering || self.matched.contains(pid);

        // While the order is held, rows already on screen keep their
        // position; new processes go after them in normal sort order.
        let sig = format!("{:?}|{:?}|{}|{}|{:?}|{:?}", self.view, self.sort, self.sort_desc, q, self.user_filter, self.app_filter);
        let holding = self.order_held() && sig == self.layout_sig;
        self.layout_sig = sig;
        let rank: HashMap<RowKey, usize> =
            if holding { self.rows.iter().enumerate().map(|(i, r)| (r.key.clone(), i)).collect() } else { HashMap::new() };
        let held = |a: &RowKey, b: &RowKey| match (rank.get(a), rank.get(b)) {
            (Some(x), Some(y)) => Some(x.cmp(y)),
            (Some(_), None) => Some(std::cmp::Ordering::Less),
            (None, Some(_)) => Some(std::cmp::Ordering::Greater),
            (None, None) => None,
        };
        let cmp = |a: &ProcessInfo, b: &ProcessInfo| {
            held(&RowKey::Proc(a.pid), &RowKey::Proc(b.pid)).unwrap_or_else(|| self.compare(a, b))
        };

        let mut groups: HashMap<String, Group> = HashMap::new();
        let rows = match self.view {
            ViewMode::Suspicious => {
                let mut pids: Vec<u32> =
                    self.tree.nodes.iter().filter(|(p, n)| n.info.risk > 0 && visible(p)).map(|(p, _)| *p).collect();
                pids.sort_by(|a, b| {
                    let (ia, ib) = (&self.tree.nodes[a].info, &self.tree.nodes[b].info);
                    held(&RowKey::Proc(*a), &RowKey::Proc(*b)).unwrap_or_else(|| ib.risk.cmp(&ia.risk).then_with(|| self.compare(ia, ib)))
                });
                pids.into_iter()
                    .map(|p| Row { key: RowKey::Proc(p), prefix: String::new(), expandable: false, expanded: false, hidden: 0 })
                    .collect()
            }
            ViewMode::List => {
                let mut pids: Vec<u32> = self.tree.nodes.keys().copied().filter(visible).collect();
                pids.sort_by(|a, b| cmp(&self.tree.nodes[a].info, &self.tree.nodes[b].info));
                pids.into_iter()
                    .map(|p| Row { key: RowKey::Proc(p), prefix: String::new(), expandable: false, expanded: false, hidden: 0 })
                    .collect()
            }
            ViewMode::Tree => {
                let keep = filtering.then(|| {
                    // Keep each match's ancestors so the tree stays readable.
                    let mut keep = self.matched.clone();
                    for pid in &self.matched {
                        let mut cur = self.tree.get(*pid).and_then(|n| n.info.ppid);
                        while let Some(p) = cur {
                            if !keep.insert(p) {
                                break;
                            }
                            cur = self.tree.get(p).and_then(|n| n.info.ppid);
                        }
                    }
                    keep
                });
                self.tree
                    .flatten(&cmp, &self.collapsed, keep.as_ref())
                    .into_iter()
                    .map(|r| Row {
                        key: RowKey::Proc(r.pid),
                        prefix: r.prefix,
                        expandable: r.has_children || r.hidden > 0,
                        expanded: r.hidden == 0,
                        hidden: r.hidden,
                    })
                    .collect()
            }
            ViewMode::Apps => {
                for (pid, node) in &self.tree.nodes {
                    if !visible(pid) {
                        continue;
                    }
                    let i = &node.info;
                    let g = groups.entry(i.app_name()).or_insert_with(|| Group { name: i.app_name(), ..Group::default() });
                    g.members.push(*pid);
                    g.cpu += i.cpu_usage_pct;
                    g.mem += i.mem();
                    g.threads += i.threads.unwrap_or(1) as u64;
                    g.disk += i.disk_read_rate + i.disk_write_rate;
                    if g.user.is_none() {
                        g.user = i.user.clone();
                    } else if g.user != i.user {
                        g.user = Some("(several)".into());
                    }
                }
                let mut sorted: Vec<&Group> = groups.values().collect();
                let sort = self.sort;
                let group_key = |g: &Group| {
                    if g.members.len() == 1 { RowKey::Proc(g.members[0]) } else { RowKey::Group(g.name.clone()) }
                };
                sorted.sort_by(|a, b| {
                    if let Some(ord) = held(&group_key(a), &group_key(b)) {
                        return ord;
                    }
                    let ord = match sort {
                        Col::Cpu => a.cpu.total_cmp(&b.cpu),
                        Col::Memory | Col::MemPct => a.mem.cmp(&b.mem),
                        Col::Threads => a.threads.cmp(&b.threads),
                        Col::Disk | Col::DiskRead | Col::DiskWrite => a.disk.total_cmp(&b.disk),
                        _ => b.name.to_lowercase().cmp(&a.name.to_lowercase()),
                    };
                    let ord = if self.sort_desc { ord.reverse() } else { ord };
                    ord.then_with(|| a.name.cmp(&b.name))
                });
                let mut rows = Vec::new();
                for g in sorted {
                    if g.members.len() == 1 {
                        let pid = g.members[0];
                        rows.push(Row { key: RowKey::Proc(pid), prefix: String::new(), expandable: false, expanded: false, hidden: 0 });
                        continue;
                    }
                    let expanded = self.expanded_groups.contains(&g.name) || (filtering && !q.is_empty());
                    rows.push(Row {
                        key: RowKey::Group(g.name.clone()),
                        prefix: String::new(),
                        expandable: true,
                        expanded,
                        hidden: if expanded { 0 } else { g.members.len() },
                    });
                    if expanded {
                        let mut members = g.members.clone();
                        members.sort_by(|a, b| cmp(&self.tree.nodes[a].info, &self.tree.nodes[b].info));
                        let n = members.len();
                        for (i, pid) in members.into_iter().enumerate() {
                            let prefix = if i + 1 == n { "└─ " } else { "├─ " }.to_string();
                            rows.push(Row { key: RowKey::Proc(pid), prefix, expandable: false, expanded: false, hidden: 0 });
                        }
                    }
                }
                rows
            }
        };
        self.rows = rows;
        self.groups = groups;

        // Keep the same row selected; while searching, a selection on a
        // context-only row moves to the first real match.
        let keep_current = !filtering
            || match &self.selected_key {
                Some(RowKey::Proc(p)) => self.matched.contains(p),
                Some(RowKey::Group(_)) => true,
                None => false,
            };
        let found =
            self.selected_key.clone().filter(|_| keep_current).and_then(|k| self.rows.iter().position(|r| r.key == k));
        match found {
            Some(idx) => self.selected = idx,
            None => {
                if filtering {
                    let first = self.rows.iter().position(|r| match &r.key {
                        RowKey::Proc(p) => self.matched.contains(p),
                        RowKey::Group(_) => true,
                    });
                    if let Some(idx) = first {
                        self.selected = idx;
                    }
                }
                self.selected = self.selected.min(self.rows.len().saturating_sub(1));
                let key = self.rows.get(self.selected).map(|r| r.key.clone());
                self.set_selected_key(key);
            }
        }

        self.rebuild_connections();
    }

    fn rebuild_connections(&mut self) {
        let f = Filter::parse(&self.query);
        let mut rows: Vec<ConnRow> = Vec::new();
        for (pid, conns) in &self.connections {
            let name = self.name_of(*pid);
            let user = self.tree.get(*pid).and_then(|n| n.info.user.clone());
            for c in conns {
                let row = ConnRow { pid: *pid, name: name.clone(), user: user.clone(), conn: c.clone() };
                if f.matches(&row) {
                    rows.push(row);
                }
            }
        }
        rows.sort_by(|a, b| {
            a.conn.state.cmp(&b.conn.state).then_with(|| a.name.cmp(&b.name)).then_with(|| a.conn.cmp(&b.conn))
        });
        self.conn_rows = rows;
        self.conn_selected = self.conn_selected.min(self.conn_rows.len().saturating_sub(1));
    }

    fn set_selected_key(&mut self, key: Option<RowKey>) {
        if self.selected_key != key {
            self.selected_key = key;
            self.selection_changed = Instant::now();
            self.pane_scroll = 0;
        }
    }

    pub fn selected_row(&self) -> Option<&Row> {
        self.rows.get(self.selected)
    }

    /// The selected process (None for a group row).
    pub fn selected_pid(&self) -> Option<u32> {
        match self.selected_row()?.key {
            RowKey::Proc(p) if self.tree.nodes.contains_key(&p) => Some(p),
            _ => None,
        }
    }

    pub fn selected_group(&self) -> Option<&Group> {
        match &self.selected_row()?.key {
            RowKey::Group(name) => self.groups.get(name),
            _ => None,
        }
    }

    pub fn select_index(&mut self, idx: usize) {
        if self.rows.is_empty() {
            return;
        }
        self.selected = idx.min(self.rows.len() - 1);
        let key = self.rows.get(self.selected).map(|r| r.key.clone());
        self.set_selected_key(key);
    }

    pub fn move_selection(&mut self, delta: isize) {
        self.hold_order();
        let step = |cur: usize, len: usize| (cur as isize + delta).clamp(0, len.saturating_sub(1) as isize) as usize;
        match self.tab {
            Tab::Processes if !self.rows.is_empty() => self.select_index(step(self.selected, self.rows.len())),
            Tab::Network if self.ir.net_hosts_view => self.ir.host_selected = step(self.ir.host_selected, self.visible_remotes().len()),
            Tab::Network => self.conn_selected = step(self.conn_selected, self.conn_rows.len()),
            Tab::Persistence if self.ir.persist_changes_view => {
                self.change_selected = step(self.change_selected, self.visible_changes().len())
            }
            Tab::Persistence => self.ir.persist_selected = step(self.ir.persist_selected, self.visible_persistence().len()),
            Tab::Timeline => self.ir.tl_selected = step(self.ir.tl_selected, self.visible_timeline().len()),
            Tab::Logs if self.ir.artifacts_view => self.ir.art_selected = step(self.ir.art_selected, self.visible_artifacts().len()),
            Tab::Logs => self.ir.log_selected = step(self.ir.log_selected, self.visible_logs().len()),
            Tab::Files if self.ir.files_changes_view => self.ir.fs_selected = step(self.ir.fs_selected, self.visible_fs_events().len()),
            Tab::Case if self.ir.case_focus_quarantine => {
                self.ir.quarantine_selected = step(self.ir.quarantine_selected, self.quarantined().len())
            }
            Tab::Case => {
                let n = self.ir.case.as_ref().map_or(0, |c| c.findings.len());
                self.ir.finding_selected = step(self.ir.finding_selected, n);
            }
            Tab::Trace => {
                let n = self.visible_trace().len();
                self.trace_selected = step(self.trace_selected, n);
                // Scrolling up pauses auto-follow; reaching the end resumes it.
                self.trace_follow = self.trace_selected + 1 >= n;
            }
            Tab::Files => self.file_selected = step(self.file_selected, self.visible_files().len()),
            Tab::Alerts if self.ir.det.focus => self.ir.det.selected = step(self.ir.det.selected, self.visible_detections().len()),
            Tab::Alerts if !self.rules_focus => self.alert_selected = step(self.alert_selected, self.visible_alerts().len()),
            Tab::Alerts if self.rules_focus => self.rule_selected = step(self.rule_selected, self.rules.len()),
            _ => {}
        }
    }

    /// Jump to `pid` on the Processes page, clearing filters that hide it.
    pub fn focus_pid(&mut self, pid: u32) {
        if !self.tree.nodes.contains_key(&pid) {
            self.set_status(StatusLevel::Error, format!("Process {pid} is no longer running"));
            return;
        }
        self.tab = Tab::Processes;
        self.mode = Mode::Normal;
        if !self.rows.iter().any(|r| r.key == RowKey::Proc(pid)) {
            self.query.clear();
            self.user_filter = None;
            self.app_filter = None;
            let mut cur = self.tree.get(pid).and_then(|n| n.info.ppid);
            while let Some(p) = cur {
                self.collapsed.remove(&p);
                cur = self.tree.get(p).and_then(|n| n.info.ppid);
            }
            if let Some(n) = self.tree.get(pid) {
                self.expanded_groups.insert(n.info.app_name());
            }
        }
        self.selected_key = Some(RowKey::Proc(pid));
        self.rebuild();
    }

    // ── view / sort / columns / expansion ──────────────────────────────

    pub fn set_view(&mut self, view: ViewMode) {
        self.view = view;
        self.rebuild();
        self.set_status(StatusLevel::Info, format!("View: {}", view.label()));
    }

    pub fn set_sort(&mut self, col: Col) {
        if !col.sortable() {
            return;
        }
        if self.sort == col {
            self.sort_desc = !self.sort_desc;
        } else {
            self.sort = col;
            self.sort_desc = col.default_desc();
        }
        self.rebuild();
    }

    pub fn reverse_sort(&mut self) {
        self.sort_desc = !self.sort_desc;
        self.rebuild();
    }

    pub fn toggle_column(&mut self, col: Col) {
        if col == Col::Name {
            return;
        }
        if let Some(i) = self.columns.iter().position(|c| *c == col) {
            self.columns.remove(i);
        } else {
            let rank = |c: &Col| Col::ALL.iter().position(|x| x == c).unwrap_or(0);
            let at = self.columns.iter().position(|c| rank(c) > rank(&col)).unwrap_or(self.columns.len());
            self.columns.insert(at, col);
        }
    }

    /// Expand (`Some(true)`), collapse (`Some(false)`) or toggle the
    /// selected tree node / app group. Collapsing a leaf jumps to its
    /// parent, like a file browser.
    pub fn set_expanded(&mut self, expand: Option<bool>) {
        let Some(row) = self.selected_row().cloned() else { return };
        match &row.key {
            RowKey::Group(name) => {
                let want = expand.unwrap_or(!row.expanded);
                if want {
                    self.expanded_groups.insert(name.clone());
                } else {
                    self.expanded_groups.remove(name);
                }
            }
            RowKey::Proc(pid) => {
                let want = expand.unwrap_or(!row.expanded);
                if row.expandable && self.view == ViewMode::Tree && want != row.expanded {
                    if want {
                        self.collapsed.remove(pid);
                    } else {
                        self.collapsed.insert(*pid);
                    }
                } else if expand == Some(false) || (!row.expandable && expand.is_none()) {
                    let parent = match self.view {
                        ViewMode::Tree => self.tree.get(*pid).and_then(|n| n.info.ppid).map(RowKey::Proc),
                        ViewMode::Apps if !row.prefix.is_empty() => self.tree.get(*pid).map(|n| RowKey::Group(n.info.app_name())),
                        _ => None,
                    };
                    if let Some(idx) = parent.and_then(|k| self.rows.iter().position(|r| r.key == k)) {
                        self.select_index(idx);
                    }
                    return;
                } else {
                    return;
                }
            }
        }
        self.rebuild();
    }

    // ── selection (multi) ──────────────────────────────────────────────

    pub fn toggle_tag(&mut self) {
        match self.selected_row().map(|r| r.key.clone()) {
            Some(RowKey::Proc(pid)) => {
                if !self.tagged.remove(&pid) {
                    self.tagged.insert(pid);
                }
            }
            Some(RowKey::Group(name)) => {
                let members = self.groups.get(&name).map(|g| g.members.clone()).unwrap_or_default();
                if members.iter().all(|p| self.tagged.contains(p)) {
                    members.iter().for_each(|p| {
                        self.tagged.remove(p);
                    });
                } else {
                    self.tagged.extend(members);
                }
            }
            None => return,
        }
        self.move_selection(1);
    }

    /// Processes an action applies to: the selection set if any, else the
    /// highlighted row (all members for an app group).
    pub fn targets(&self) -> Vec<u32> {
        if self.detail_full {
            return self.selected_pid().into_iter().collect();
        }
        if !self.tagged.is_empty() {
            let mut v: Vec<u32> = self.tagged.iter().copied().collect();
            v.sort_unstable();
            return v;
        }
        match self.selected_row().map(|r| &r.key) {
            Some(RowKey::Proc(p)) if self.tree.nodes.contains_key(p) => vec![*p],
            Some(RowKey::Group(name)) => self.groups.get(name).map(|g| g.members.clone()).unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    pub fn describe_targets(&self, targets: &[u32]) -> String {
        match targets {
            [] => "nothing".into(),
            [one] => format!("{} ({one})", self.name_of(*one)),
            many => {
                let names: HashSet<String> = many.iter().map(|p| self.name_of(*p)).collect();
                if names.len() == 1 {
                    format!("{} processes named {}", many.len(), names.into_iter().next().unwrap_or_default())
                } else {
                    format!("{} processes", many.len())
                }
            }
        }
    }

    // ── action menu ────────────────────────────────────────────────────

    pub fn open_action_menu(&mut self, anchor: (u16, u16)) {
        let targets = self.targets();
        if targets.is_empty() {
            return;
        }
        let single = targets.len() == 1;
        let info = single.then(|| self.tree.get(targets[0]).map(|n| n.info.clone())).flatten();
        let any_stopped = targets.iter().any(|p| {
            self.tree.get(*p).is_some_and(|n| n.info.status == sysinfo::ProcessStatus::Stop)
        });
        let has_children = targets.iter().any(|p| self.tree.get(*p).is_some_and(|n| !n.children.is_empty()));
        let cur_nice = info.as_ref().and_then(|i| i.nice);

        let level = |label: &str, nice: i32| {
            MenuItem::new(label, "", Cmd::Priority(nice)).checked(cur_nice.is_some_and(|n| {
                let lvl = |n: i32| match n {
                    ..=-15 => 0,
                    -14..=-5 => 1,
                    -4..=4 => 2,
                    5..=14 => 3,
                    _ => 4,
                };
                lvl(n) == lvl(nice)
            }))
        };
        let priority = vec![
            level("Very high", -20),
            level("High", -10),
            level("Normal", 0),
            level("Low", 10),
            level("Very low", 19),
        ];
        let signals: Vec<MenuItem> =
            Sig::available().iter().map(|s| MenuItem::new(s.label().trim().to_string(), "", Cmd::Signal(*s))).collect();
        let copy = vec![
            MenuItem::new("PID", "", Cmd::CopyPid),
            MenuItem::new("Name", "", Cmd::CopyName),
            MenuItem::new("Executable path", "", Cmd::CopyPath).enabled(info.as_ref().is_some_and(|i| i.exe_path.is_some())),
            MenuItem::new("Command line", "", Cmd::CopyCommand).enabled(info.as_ref().is_some_and(|i| !i.cmd.is_empty())),
        ];
        let is_tagged = single && self.tagged.contains(&targets[0]);

        let mut items = vec![
            MenuItem::new("Show details", "i", Cmd::Details).enabled(single),
            MenuItem::new("Trace behavior", "T", Cmd::Trace).enabled(single),
            MenuItem::separator(),
            MenuItem::new("End process", "del", Cmd::End),
            MenuItem::new("Force quit", "X", Cmd::ForceQuit),
            MenuItem::new("End process tree", "", Cmd::EndTree).enabled(has_children),
            if any_stopped {
                MenuItem::new("Resume", "", Cmd::Resume)
            } else {
                MenuItem::new("Suspend", "", Cmd::Suspend)
            },
            MenuItem::new("Priority", "▸", Cmd::Sub(priority)),
        ];
        if cfg!(unix) {
            items.push(MenuItem::new("Send signal", "▸", Cmd::Sub(signals)));
        }
        items.extend([
            MenuItem::separator(),
            MenuItem::new("Copy", "▸", Cmd::Sub(copy)).enabled(single),
            MenuItem::new(
                "Investigate",
                "▸",
                Cmd::Sub(vec![
                    MenuItem::new("Investigation workspace", "W", Cmd::Workspace),
                    MenuItem::new(if info.as_ref().is_some_and(|i| self.deep_enrolled(i.pid)) { "Stop deep trace" } else { "Deep trace (event-driven)" }, "D", Cmd::DeepTrace),
                    MenuItem::new("Analyze executable", "", Cmd::AnalyzeExe).enabled(info.as_ref().is_some_and(|i| i.exe_path.is_some())),
                    MenuItem::new("Collect evidence", "", Cmd::CollectEvidence),
                    MenuItem::new("Collect evidence + copy executable", "", Cmd::CollectEvidenceWithExe)
                        .enabled(info.as_ref().is_some_and(|i| i.exe_path.is_some())),
                    MenuItem::new("Record as finding", "m", Cmd::MarkFinding),
                    MenuItem::new("Quarantine executable…", "", Cmd::QuarantineExe).enabled(info.as_ref().is_some_and(|i| i.exe_path.is_some())),
                ]),
            )
            .enabled(single),
            MenuItem::new(reveal_label(), "", Cmd::Reveal).enabled(info.as_ref().is_some_and(|i| i.exe_path.is_some())),
            MenuItem::separator(),
            MenuItem::new("Show only this app", "", Cmd::OnlyThisApp).enabled(single),
            MenuItem::new("Show only this user", "", Cmd::OnlyThisUser).enabled(info.as_ref().is_some_and(|i| i.user.is_some())),
            MenuItem::new(if is_tagged { "Unselect" } else { "Select" }, "space", Cmd::ToggleSelect),
        ]);
        if let Some(row) = self.selected_row().filter(|r| r.expandable && self.tagged.is_empty()) {
            let label = if row.expanded { "Collapse" } else { "Expand" };
            items.insert(1, MenuItem::new(label, "←→", Cmd::Expand));
        }
        let title = self.describe_targets(&targets);
        self.mode = Mode::Menu(vec![MenuLevel::new(title, items, anchor)]);
    }

    pub fn open_sort_menu(&mut self, anchor: (u16, u16)) {
        let arrow = if self.sort_desc { " ↓" } else { " ↑" };
        let items = Col::ALL
            .iter()
            .filter(|c| c.sortable())
            .map(|c| {
                let label = if *c == self.sort { format!("{}{arrow}", c.header()) } else { c.header().to_string() };
                MenuItem::new(label, "", Cmd::SortBy(*c)).checked(*c == self.sort)
            })
            .collect();
        let mut level = MenuLevel::new("Sort by", items, anchor);
        level.cursor = Col::ALL.iter().filter(|c| c.sortable()).position(|c| *c == self.sort).unwrap_or(0);
        self.mode = Mode::Menu(vec![level]);
    }

    /// Run a menu command against the current targets.
    pub fn run_cmd(&mut self, cmd: Cmd) {
        let targets = self.targets();
        self.mode = Mode::Normal;
        let first = targets.first().copied();
        let info = first.and_then(|p| self.tree.get(p)).map(|n| n.info.clone());
        match cmd {
            Cmd::Sub(_) => {}
            Cmd::Details => self.open_details_full(),
            Cmd::SaveBaseline => self.save_baseline(),
            Cmd::AnalyzeExe => {
                if let Some(p) = info.and_then(|i| i.exe_path) {
                    self.analyze_file(&p);
                }
            }
            Cmd::CollectEvidence => {
                if let Some(pid) = first {
                    self.collect_process_evidence(pid, false);
                }
            }
            Cmd::CollectEvidenceWithExe => {
                if let Some(pid) = first {
                    self.collect_process_evidence(pid, true);
                }
            }
            Cmd::MarkFinding => self.mark_finding(),
            Cmd::Workspace => {
                if let Some(pid) = first {
                    let k = self.proc_key(pid);
                    self.open_workspace_for(k);
                }
            }
            Cmd::DeepTrace => {
                if let Some(pid) = first {
                    self.toggle_deep(pid);
                }
            }
            Cmd::QuarantineExe => {
                if let Some(p) = info.and_then(|i| i.exe_path) {
                    self.request_quarantine(p);
                }
            }
            Cmd::Quarantine(p) => self.do_quarantine(&p),
            Cmd::Trace => {
                if let Some(pid) = first {
                    self.start_trace(pid);
                }
            }
            Cmd::End | Cmd::ForceQuit | Cmd::EndTree => {
                if targets.is_empty() {
                    return;
                }
                if self.confirm_end {
                    self.mode = Mode::Confirm { cmd, targets };
                } else {
                    self.execute(cmd, targets);
                }
            }
            Cmd::Suspend => self.run_action(Action::Signal(Sig::Stop), targets),
            Cmd::Resume => self.run_action(Action::Signal(Sig::Cont), targets),
            Cmd::Priority(n) => self.run_action(Action::SetNice(n), targets),
            Cmd::Signal(s) => self.run_action(Action::Signal(s), targets),
            Cmd::CopyPid => self.copy(first.map(|p| p.to_string())),
            Cmd::CopyName => self.copy(info.map(|i| i.name)),
            Cmd::CopyPath => self.copy(info.and_then(|i| i.exe_path)),
            Cmd::CopyCommand => self.copy(info.map(|i| i.cmd.join(" "))),
            Cmd::Reveal => {
                if let Some(path) = info.and_then(|i| i.exe_path) {
                    match os::reveal(&path) {
                        Ok(()) => self.set_status(StatusLevel::Success, format!("Opened {}", reveal_label().to_lowercase())),
                        Err(e) => self.set_status(StatusLevel::Error, format!("Couldn't open file location: {e}")),
                    }
                }
            }
            Cmd::OnlyThisApp => {
                if let Some(i) = info {
                    self.app_filter = Some(i.app_name());
                    self.tagged.clear();
                    self.rebuild();
                }
            }
            Cmd::OnlyThisUser => {
                if let Some(u) = info.and_then(|i| i.user) {
                    self.user_filter = Some(u);
                    self.tagged.clear();
                    self.rebuild();
                }
            }
            Cmd::ToggleSelect => self.toggle_tag(),
            Cmd::Expand => self.set_expanded(None),
            Cmd::SortBy(c) => self.set_sort(c),
        }
    }

    /// Carry out a confirmed End / Force quit / End tree.
    pub fn execute(&mut self, cmd: Cmd, mut targets: Vec<u32>) {
        self.mode = Mode::Normal;
        match cmd {
            Cmd::End => {
                for p in &targets {
                    self.end_watch.insert(*p, (Instant::now(), self.name_of(*p)));
                }
                self.run_action(Action::Signal(Sig::Term), targets);
            }
            Cmd::ForceQuit => self.run_action(Action::Signal(Sig::Kill), targets),
            Cmd::EndTree => {
                let extra: Vec<u32> = targets.iter().flat_map(|p| self.tree.descendants(*p)).collect();
                targets.extend(extra);
                targets.sort_unstable();
                targets.dedup();
                self.run_action(Action::Signal(Sig::Term), targets);
            }
            _ => {}
        }
        self.tagged.clear();
    }

    fn run_action(&mut self, action: Action, mut pids: Vec<u32>) {
        if self.replaying() {
            self.set_status(StatusLevel::Info, "Not available while replaying a recording — this would act on the live system".into());
            return;
        }
        let me = std::process::id();
        pids.retain(|p| *p != me);
        if pids.is_empty() {
            self.set_status(StatusLevel::Error, "Nothing to do (procwatch won't act on itself)".into());
            return;
        }
        let what = describe(action);
        let desc = self.describe_targets(&pids);
        let targets: Vec<(u32, String, u64)> =
            pids.iter().map(|p| (*p, self.name_of(*p), self.tree.get(*p).map_or(0, |n| n.info.start_time_secs))).collect();
        self.response_begin(action, &targets);
        self.actions_pending += 1;
        self.set_status(StatusLevel::Info, format!("{what}: {desc}"));
        sampler::spawn_action(self.tx.clone(), targets, action);
    }

    /// Delete key / X: end or force quit without opening the menu.
    pub fn quick_end(&mut self, force: bool) {
        self.run_cmd(if force { Cmd::ForceQuit } else { Cmd::End });
    }

    fn copy(&mut self, text: Option<String>) {
        let Some(text) = text else { return };
        match os::copy_to_clipboard(&text) {
            Ok(dest) => self.set_status(StatusLevel::Success, format!("Copied to {dest}: {}", crate::ui::truncate(&text, 60))),
            Err(e) => self.set_status(StatusLevel::Error, format!("Copy failed: {e}")),
        }
    }

    // ── search / filters ───────────────────────────────────────────────

    pub fn clear_filters(&mut self) -> bool {
        let had = self.filtering();
        self.query.clear();
        self.user_filter = None;
        self.app_filter = None;
        if had {
            self.rebuild();
        }
        had
    }

    // ── find (file / port) ─────────────────────────────────────────────

    pub fn start_find(&mut self, input: &str) {
        let q = input.trim().trim_start_matches(':').to_string();
        if q.is_empty() {
            return;
        }
        self.mode = Mode::Normal;
        if let Ok(port) = q.parse::<u16>() {
            let needle = format!(":{port}");
            let mut hits = Vec::new();
            for (pid, conns) in &self.connections {
                for c in conns {
                    if c.local.ends_with(&needle) || c.remote.ends_with(&needle) {
                        hits.push(Hit {
                            pid: *pid,
                            kind: c.protocol.to_string(),
                            command: self.name_of(*pid),
                            fd: format!("{} {}", c.protocol, c.state.label()),
                            path: format!("{} → {}", c.local, c.remote),
                        });
                    }
                }
            }
            hits.sort_by(|a, b| a.command.cmp(&b.command).then(a.pid.cmp(&b.pid)));
            self.find = Some(FindState { query: format!("port {port}"), pending: false, result: Ok(hits), cursor: 0 });
        } else {
            self.find = Some(FindState { query: q.clone(), pending: true, result: Ok(Vec::new()), cursor: 0 });
            sampler::spawn_find(self.tx.clone(), q);
        }
    }

    // ── details ────────────────────────────────────────────────────────

    pub fn details_visible(&self) -> bool {
        self.tab == Tab::Processes && (self.pane_visible || self.detail_full)
    }

    /// Process whose details are being shown.
    pub fn detail_pid(&self) -> Option<u32> {
        if self.details_visible() { self.selected_pid() } else { None }
    }

    pub fn open_details_full(&mut self) {
        if self.selected_pid().is_some() {
            self.tab = Tab::Processes;
            self.detail_full = true;
            self.pane_scroll = 0;
            self.selection_changed = Instant::now() - INSPECT_DEBOUNCE;
        }
    }

    pub fn set_pane_tab(&mut self, tab: PaneTab) {
        if self.pane_tab != tab {
            self.pane_tab = tab;
            self.pane_scroll = 0;
        }
    }

    pub fn scroll_pane(&mut self, delta: isize) {
        self.pane_scroll = (self.pane_scroll as isize + delta).max(0) as usize;
    }

    pub fn deep_entry(&self) -> Option<&DeepEntry> {
        self.deep_cache.get(&self.detail_pid()?)
    }

    /// Kick off a background inspection of the shown process if we don't
    /// already have (or aren't already fetching) what the tab needs.
    pub fn request_deep_info(&mut self, force: bool) -> bool {
        let Some(pid) = self.detail_pid() else { return false };
        if self.deep_pending.contains(&pid) || self.deep_pending.len() >= MAX_INFLIGHT_INSPECTIONS {
            return false;
        }
        let want_modules = matches!(self.pane_tab, PaneTab::Modules | PaneTab::Memory);
        if !force {
            if let Some(e) = self.deep_cache.get(&pid) {
                if !want_modules || e.info.modules_loaded {
                    return false;
                }
            }
        }
        let Some(node) = self.tree.get(pid) else { return false };
        self.deep_pending.insert(pid);
        sampler::spawn_inspect(self.tx.clone(), pid, node.info.start_time_secs, node.info.exe_path.clone(), want_modules);
        true
    }

    // ── sampler control ────────────────────────────────────────────────

    pub fn request_refresh(&self) {
        self.ctl.refresh_now.store(true, Ordering::Relaxed);
    }

    pub fn toggle_pause(&mut self) {
        let paused = !self.ctl.paused.load(Ordering::Relaxed);
        self.ctl.paused.store(paused, Ordering::Relaxed);
        self.set_status(StatusLevel::Info, if paused { "Paused — press p to resume" } else { "Live updates resumed" }.into());
    }

    pub fn adjust_interval(&mut self, faster: bool) {
        let cur = self.ctl.interval_ms.load(Ordering::Relaxed);
        let step = if cur <= 1000 { 250 } else { 500 };
        let next = if faster { cur.saturating_sub(step) } else { cur + step };
        self.ctl.interval_ms.store(next.clamp(MIN_INTERVAL_MS, MAX_INTERVAL_MS), Ordering::Relaxed);
    }

    pub fn set_status(&mut self, level: StatusLevel, text: String) {
        self.status = Some(Status { text, level, at: Instant::now() });
    }

    /// True for a second click on the same row within the double-click
    /// window.
    pub fn register_click(&mut self, row: u16) -> bool {
        let now = Instant::now();
        let double = self.last_click.is_some_and(|(t, r)| r == row && now.duration_since(t) < Duration::from_millis(400));
        self.last_click = if double { None } else { Some((now, row)) };
        double
    }
}

pub fn describe(action: Action) -> String {
    match action {
        Action::Signal(Sig::Term) => "End process".into(),
        Action::Signal(Sig::Kill) => "Force quit".into(),
        Action::Signal(Sig::Stop) => "Suspend".into(),
        Action::Signal(Sig::Cont) => "Resume".into(),
        Action::Signal(s) => format!("Send {}", s.label().trim()),
        Action::SetNice(n) => format!("Set priority to {}", priority_name(n)),
    }
}

pub fn priority_name(nice: i32) -> &'static str {
    match nice {
        ..=-15 => "very high",
        -14..=-5 => "high",
        -4..=4 => "normal",
        5..=14 => "low",
        _ => "very low",
    }
}

pub fn reveal_label() -> &'static str {
    if cfg!(target_os = "macos") {
        "Reveal in Finder"
    } else if cfg!(windows) {
        "Open file location"
    } else {
        "Open containing folder"
    }
}


// ── filter support ─────────────────────────────────────────────────────

fn one(v: impl ToString) -> Option<Vec<String>> {
    Some(vec![v.to_string()])
}

fn endpoint_fields(name: &str, eps: &[&str]) -> Option<Vec<String>> {
    match name {
        "port" => Some(eps.iter().map(|e| split_endpoint(e).1).collect()),
        "ip" => Some(eps.iter().map(|e| split_endpoint(e).0).collect()),
        _ => None,
    }
}

/// A process together with its sockets, for searching.
struct ProcItem<'a> {
    info: &'a ProcessInfo,
    conns: Option<&'a Vec<Connection>>,
}

impl Filterable for ProcItem<'_> {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        let i = self.info;
        let conns = self.conns.map(|c| c.as_slice()).unwrap_or(&[]);
        match name {
            "pid" => one(i.pid),
            "ppid" => one(i.ppid.map(|p| p.to_string()).unwrap_or_default()),
            "name" => one(&i.name),
            "user" => one(i.user.clone().unwrap_or_default()),
            "path" => one(i.exe_path.clone().unwrap_or_default()),
            "cmd" => one(i.cmd.join(" ")),
            "state" => Some(conns.iter().map(|c| c.state.label().to_string()).collect()),
            "proto" => Some(conns.iter().map(|c| c.protocol.to_string()).collect()),
            "port" | "ip" => {
                let eps: Vec<&str> = conns.iter().flat_map(|c| [c.local.as_str(), c.remote.as_str()]).collect();
                endpoint_fields(name, &eps)
            }
            _ => None,
        }
    }
    fn text(&self) -> String {
        let i = self.info;
        format!("{} {} {} {} {}", i.name, i.pid, i.exe_path.as_deref().unwrap_or(""), i.args(), i.user.as_deref().unwrap_or(""))
    }
}

impl Filterable for ConnRow {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "pid" => one(self.pid),
            "name" => one(&self.name),
            "user" => one(self.user.clone().unwrap_or_default()),
            "state" => one(self.conn.state.label()),
            "proto" => one(self.conn.protocol),
            "port" | "ip" => endpoint_fields(name, &[&self.conn.local, &self.conn.remote]),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {} {} {}", self.name, self.pid, self.conn.protocol, self.conn.local, self.conn.remote, self.conn.state.label())
    }
}

impl Filterable for Event {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "pid" => one(self.pid),
            "name" => one(&self.name),
            "user" => one(&self.user),
            "kind" => one(match self.kind {
                EventKind::Started => "started",
                EventKind::Exited => "exited",
            }),
            "cmd" => one(&self.detail),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {} {}", self.name, self.pid, self.user, self.parent, self.detail)
    }
}

impl Filterable for crate::trace::Event {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        use crate::trace::Kind;
        let file = matches!(self.kind, Kind::FileOpen | Kind::FileClose);
        match name {
            "pid" => one(self.pid),
            "name" => one(&self.process),
            "kind" => Some(vec![self.kind.label().to_string(), format!("{:?}", self.kind)]),
            "path" if file => one(&self.detail),
            "path" => one(""),
            // Endpoints appear in the detail text of network events.
            "port" | "ip" => {
                let eps: Vec<&str> = self.detail.split_whitespace().filter(|w| w.contains(':') && !w.ends_with(':')).collect();
                endpoint_fields(name, &eps)
            }
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {}", self.process, self.pid, self.kind.label(), self.detail)
    }
}

impl Filterable for Change {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "name" => one(&self.name),
            "user" => one(self.user.clone().unwrap_or_default()),
            "kind" => one(self.kind.label()),
            "path" => one(&self.detail),
            "port" | "ip" => {
                let eps: Vec<&str> = self.detail.split_whitespace().filter(|w| w.contains(':')).collect();
                endpoint_fields(name, &eps)
            }
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {}", self.kind.label(), self.name, self.user.as_deref().unwrap_or(""), self.detail)
    }
}

impl Filterable for Alert {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "pid" => one(self.pid),
            "name" => one(&self.name),
            "rule" => one(&self.rule),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {}", self.name, self.pid, self.message, self.rule)
    }
}

impl Filterable for Hit {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "pid" => one(self.pid),
            "name" => one(&self.command),
            "fd" => one(&self.fd),
            "type" => one(&self.kind),
            "path" => one(&self.path),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {} {}", self.command, self.pid, self.fd, self.kind, self.path)
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    pub fn app() -> super::App {
        super::tests::app()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64};

    pub(super) fn app() -> App {
        let (tx, _rx) = std::sync::mpsc::channel();
        let ctl = Arc::new(SamplerCtl {
            interval_ms: AtomicU64::new(1500),
            paused: AtomicBool::new(false),
            refresh_now: AtomicBool::new(false),
        });
        let mut app = App::new(tx, ctl, Config { view: ViewMode::List, sort: Col::Cpu, sort_desc: true, ..Config::default() });
        app.tree = crate::process::tests::sample();
        app.rebuild();
        app
    }

    fn order(app: &App) -> Vec<RowKey> {
        app.rows.iter().map(|r| r.key.clone()).collect()
    }

    fn set_cpu(app: &mut App, pid: u32, cpu: f32) {
        app.tree.nodes.get_mut(&pid).unwrap().info.cpu_usage_pct = cpu;
    }

    #[test]
    fn order_holds_while_browsing_then_catches_up() {
        let mut a = app();
        let before = order(&a);
        assert_eq!(before[0], RowKey::Proc(6)); // highest CPU first
        a.move_selection(1);
        let selected = a.selected_pid();

        // Values change so the real sort would put pid 1 on top.
        set_cpu(&mut a, 1, 99.0);
        a.rebuild();
        assert_eq!(order(&a), before, "rows must not move while browsing");
        assert_eq!(a.selected_pid(), selected);

        a.hold_until = None;
        a.rebuild();
        assert_eq!(order(&a)[0], RowKey::Proc(1));
        assert_eq!(a.selected_pid(), selected, "selection follows the process");
    }

    #[test]
    fn sort_change_ignores_hold_and_freeze_persists() {
        let mut a = app();
        a.toggle_freeze();
        let before = order(&a);
        set_cpu(&mut a, 1, 99.0);
        a.rebuild();
        assert_eq!(order(&a), before);
        a.set_sort(Col::Pid);
        assert_eq!(order(&a)[0], RowKey::Proc(1), "explicit re-sort always applies");
    }
}
