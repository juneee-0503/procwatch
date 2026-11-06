use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::mpsc::Sender;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use ratatui::layout::Rect;

use crate::forensics::baseline::{self, Baseline, Change, ChangeKind};
use crate::app::columns::Col;
use crate::common::filter::{split_endpoint, Filter, Filterable};
use crate::app::config::Config;
use crate::performance::gpu::GpuSnapshot;
use crate::process::inspect::DeepInfo;
use crate::network::Connection;
use crate::process::open_files::Hit;
use crate::process::actions::{Action, Sig};
use crate::process::{ProcessInfo, ProcessTree, SystemStats};
use crate::detection::rules::{self, Alert, Rule};
use crate::process::trace::{Category, Trace};
use crate::common::pacing::{SamplerCtl, MAX_INTERVAL_MS, MIN_INTERVAL_MS};
use crate::engine::messages::{WorkerMsg};

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

mod alerts;
pub mod board;
pub mod boot;
pub mod settings;
pub mod columns;
pub mod config;
pub mod deep;
mod det;
pub mod export;
pub mod graph;
mod ir;
mod menu;
mod messages;
pub mod palette;
mod replay;
mod response;
mod rows;
pub mod state;
mod tracing;
pub mod workspace;
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
    Activity,
    Defense,
}

impl Tab {
    pub const ALL: [Tab; 12] = [
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
        Tab::Activity,
        Tab::Defense,
    ];
    /// The module behind this page: without it there is nothing to show.
    pub fn module(self) -> &'static str {
        match self {
            Tab::Processes => "process",
            Tab::Performance => "performance",
            Tab::Network => "network",
            Tab::Files => "files",
            Tab::Persistence => "persistence",
            Tab::Timeline => "timeline",
            Tab::Logs => "logs",
            Tab::Trace => "trace",
            Tab::Alerts => "detection",
            Tab::Case => "case",
            Tab::Activity => "activity",
            Tab::Defense => "defense",
        }
    }

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
            Tab::Activity => "Activity",
            Tab::Defense => "Defense",
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
            Tab::Activity => "Act",
            Tab::Defense => "Def",
        }
    }

    /// Key that jumps to this page: 1–9, 0, then `.
    pub fn key(self) -> char {
        match Self::ALL.iter().position(|t| *t == self).unwrap_or(0) {
            9 => '0',
            10 => '`',
            11 => '~',
            i => char::from(b'1' + i as u8),
        }
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
    /// Confirm running a program for analysis (`--run`).
    LaunchConfirm(Vec<String>),
    /// Most active processes, targets and operations in the capture.
    ActivitySummary,
    /// One captured operation in full, with its call stack.
    ActivityDetail,
    /// One finding, and the attack it belongs to.
    ThreatDetail,
    /// Alarms now and lately.
    Alarms { cursor: usize },
    /// Everything that can be configured.
    Settings { cursor: usize },
    /// Modules: what runs, what each supports here, turning them on and off.
    Modules { cursor: usize },
    /// Command palette (`:` or ctrl+k).
    Palette { input: String, cursor: usize },
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
    /// The kernel, when modules are running (not in replay or tests).
    pub kernel: Option<crate::kernel::Kernel>,
    /// Where the session has got to, before monitoring starts.
    pub boot: boot::Boot,
    pub board: board::Board,
    /// When this session began, for anything that flashes.
    pub started: std::time::Instant,
    pub settings: crate::defense::config::DefenseConfig,
    pub kernel_config: crate::kernel::KernelConfig,
    pub metrics: Option<Box<crate::performance::metrics::Metrics>>,
    pub metrics_at: Option<Instant>,
    pub services: Option<Result<Vec<crate::performance::services::Service>, String>>,
    /// Performance page: 0 charts, 1 system metrics, 2 services and critical processes.
    pub perf_view: u8,
    pub perf_scroll: usize,
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

/// The folders to watch: the configured ones, or the defaults.
pub fn watch_paths(cfg: &Config) -> Vec<String> {
    if cfg.watch.is_empty() {
        crate::files::watch::default_paths()
    } else {
        cfg.watch.clone()
    }
}

impl App {
    pub fn new(tx: Sender<WorkerMsg>, ctl: Arc<SamplerCtl>, cfg: Config) -> Self {
        let settings = crate::defense::config::DefenseConfig::load().unwrap_or_default();
        ctl.interval_ms.store(cfg.interval_ms, Ordering::Relaxed);
        Self {
            tree: ProcessTree::default(),
            stats: SystemStats::default(),
            connections: HashMap::new(),
            gpu: None,
            kernel: None,
            boot: boot::Boot::default(),
            board: board::Board::from(&settings.alarm),
            started: std::time::Instant::now(),
            settings,
            kernel_config: crate::engine::load_config(),
            metrics: None,
            metrics_at: None,
            services: None,
            perf_view: 0,
            perf_scroll: 0,
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
                let mut ir = ir::Ir::new(&cfg.watch);
                if cfg.history && !cfg!(test) {
                    ir.profiles = Some(crate::detection::profile::Profiles::load());
                    ir.store = crate::common::paths::data_dir().map(crate::forensics::store::Writer::open);
                    if let Some(s) = ir.store.as_mut() {
                        s.write(chrono::Local::now(), crate::forensics::store::Rec::Session {
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
    /// Whether a module was chosen. With no kernel (a replay, a test) every
    /// page has something to show.
    pub fn module_on(&self, name: &str) -> bool {
        self.kernel.as_ref().is_none_or(|k| k.wanted(name))
    }

    pub fn tab_on(&self, tab: Tab) -> bool {
        self.ir.replay.is_some() || self.module_on(tab.module())
    }

    /// The first page that has something to show.
    pub fn first_tab(&self) -> Option<Tab> {
        Tab::ALL.into_iter().find(|t| self.tab_on(*t))
    }

    pub fn switch_tab(&mut self, tab: Tab) {
        if !self.tab_on(tab) {
            self.set_status(StatusLevel::Info, format!("The {} module isn't loaded. Press M to load it.", tab.module()));
            return;
        }
        self.tab = tab;
        if tab == Tab::Alerts {
            self.unread_alerts = 0;
            self.ir.det.unread = 0;
        }
    }

    /// procwatch itself and the helpers it runs (codesign, lsof, vmmap…)
    /// are not activity on the system under investigation — except
    /// programs started for analysis with `--run`.
    pub fn is_own_helper(&self, i: &ProcessInfo) -> bool {
        let me = std::process::id();
        i.pid == me || (i.ppid == Some(me) && !self.ir.launched.contains(&i.pid))
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
            crate::engine::jobs::spawn_find(self.tx.clone(), q);
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
        crate::engine::jobs::spawn_inspect(self.tx.clone(), pid, node.info.start_time_secs, node.info.exe_path.clone(), want_modules);
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

impl Filterable for crate::process::trace::Event {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        use crate::process::trace::Kind;
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

    #[test]
    fn every_page_and_overlay_draws_at_any_terminal_size() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut a = app();
        let modes = [Mode::Normal, Mode::Help, Mode::Graph, Mode::Clusters, Mode::Health, Mode::StateAt, Mode::Sweep, Mode::ActivitySummary, Mode::ActivityDetail, Mode::ThreatDetail, Mode::Alarms { cursor: 0 }, Mode::Settings { cursor: 0 }, Mode::Modules { cursor: 0 }, Mode::FileReport, Mode::Workspace, Mode::Palette { input: "x".into(), cursor: 0 }];
        for (w, h) in [(1, 1), (2, 2), (5, 3), (10, 4), (20, 5), (33, 9), (40, 10), (80, 24), (200, 60)] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            for tab in Tab::ALL {
                a.tab = tab;
                for m in &modes {
                    a.mode = m.clone();
                    term.draw(|f| crate::ui::draw(f, &mut a)).unwrap();
                }
            }
        }
    }

    #[test]
    fn every_start_up_screen_draws_at_any_size() {
        use crate::app::boot::{BootPhase, Choice};
        use ratatui::{backend::TestBackend, Terminal};
        let mut a = app();
        a.boot.choices = vec![Choice { name: "process", description: "x", support: "supported".into(), chosen: true }];
        a.boot.log.push((false, "Storage: FAILED: no".into()));
        a.boot.done = 1;
        a.boot.total = 3;
        for (w, h) in [(1, 1), (5, 3), (20, 5), (40, 10), (80, 24), (200, 60)] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            for phase in [BootPhase::SelfTest, BootPhase::Standby, BootPhase::Select, BootPhase::Loading, BootPhase::Verify, BootPhase::Halted] {
                a.boot.phase = phase;
                term.draw(|f| crate::ui::draw(f, &mut a)).unwrap();
            }
        }
    }

    /// Every module that can be chosen, with the page it opens: a page
    /// with no module could not be left out of a session.
    #[test]
    fn only_chosen_modules_have_pages() {
        let (tx, _rx) = std::sync::mpsc::channel();
        let ctl = Arc::new(SamplerCtl { interval_ms: AtomicU64::new(1500), paused: AtomicBool::new(false), refresh_now: AtomicBool::new(false), snapshots_queued: Default::default() });
        let kernel = crate::engine::boot(tx, ctl, Vec::new());
        let names: Vec<&str> = kernel.status().iter().map(|m| m.name).collect();
        assert!(Tab::ALL.iter().all(|t| names.contains(&t.module())), "{names:?}");
        let mut a = app();
        a.kernel = Some(kernel.clone());
        assert_eq!(a.first_tab(), None, "nothing is loaded in standby");
        kernel.activate(&["network".to_string(), "defense".to_string()]);
        let on: Vec<Tab> = Tab::ALL.into_iter().filter(|t| a.tab_on(*t)).collect();
        assert_eq!(on, [Tab::Network, Tab::Defense]);
        assert_eq!(a.first_tab(), Some(Tab::Network));
        a.tab = Tab::Network;
        a.switch_tab(Tab::Case);
        assert_eq!(a.tab, Tab::Network, "a page that wasn't chosen can't be opened");
        assert!(a.ensure_case().is_none(), "nor can its work start");
        kernel.shutdown();
    }

    pub(super) fn app() -> App {
        let (tx, _rx) = std::sync::mpsc::channel();
        let ctl = Arc::new(SamplerCtl {
            interval_ms: AtomicU64::new(1500),
            paused: AtomicBool::new(false),
            refresh_now: AtomicBool::new(false), snapshots_queued: Default::default(),
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
