//! Behavior trace: follow one process and every descendant it spawns, and
//! record what they do over time — child processes, network connections,
//! listening ports, files opened and closed, CPU and memory spikes — as a
//! timeline plus a summary, exportable as a Markdown or JSON report.
//!
//! This is observation by sampling (each refresh for processes and
//! sockets, every couple of seconds for files), the same data the rest of
//! procwatch shows. Very short-lived activity between samples can be
//! missed; the report says so.
//!
//! When deep trace is available the trace is also fed the watcher's
//! lifecycle events (kqueue / 20 ms procfs / 100 ms ToolHelp). That is what
//! makes it a process-tree monitor rather than a parent-pid walk: a child
//! that forks a grandchild and exits before the next refresh (the classic
//! double-fork daemon) is adopted from the spawn event, and a member that
//! is re-parented away from the tree stays a member and is reported as an
//! escape. Members are identified by PID *and* start time, so a recycled
//! PID never joins the tree.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use serde::Serialize;

use crate::process::inspect::OpenFile;
use crate::network::{ConnState, Connection};
use crate::process::deeptrace::{DtEvent, DtKind};
use crate::process::{human_bytes, ProcessInfo, ProcessTree};

const MAX_EVENTS: usize = 50_000;
const CPU_SPIKE_PCT: f32 = 80.0;
/// Memory growth (since the trace started) worth an event, per process.
const MEM_STEP: u64 = 100 << 20;
/// Spawns within `BURST_WINDOW` seconds that make a burst (fork bomb,
/// brute-force loop, worm fan-out).
const BURST_COUNT: usize = 30;
const BURST_WINDOW: f64 = 10.0;
/// How long a member known only from a spawn event may be missing from
/// snapshots before it counts as gone.
const ADOPT_GRACE: f64 = 10.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Kind {
    ProcessStart,
    ProcessExit,
    Connect,
    Disconnect,
    Listen,
    StopListen,
    FileOpen,
    FileClose,
    CpuSpike,
    MemoryGrowth,
    /// The process replaced its image.
    Exec,
    /// A member left the tree's parent chain (re-parented, daemonized).
    Escape,
    /// A member runs as a different user than its parent.
    Privilege,
    /// Many processes started in a short time.
    Burst,
    Note,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::ProcessStart => "spawn",
            Kind::ProcessExit => "exit",
            Kind::Connect => "connect",
            Kind::Disconnect => "close",
            Kind::Listen => "listen",
            Kind::StopListen => "unlisten",
            Kind::FileOpen => "open",
            Kind::FileClose => "close",
            Kind::CpuSpike => "cpu",
            Kind::MemoryGrowth => "memory",
            Kind::Exec => "exec",
            Kind::Escape => "escape",
            Kind::Privilege => "user",
            Kind::Burst => "burst",
            Kind::Note => "note",
        }
    }

    pub fn category(self) -> Category {
        match self {
            Kind::ProcessStart | Kind::ProcessExit | Kind::Exec | Kind::Escape | Kind::Privilege | Kind::Burst => Category::Process,
            Kind::Connect | Kind::Disconnect | Kind::Listen | Kind::StopListen => Category::Network,
            Kind::FileOpen | Kind::FileClose => Category::File,
            Kind::CpuSpike | Kind::MemoryGrowth => Category::Resource,
            Kind::Note => Category::All,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    All,
    Process,
    Network,
    File,
    Resource,
}

impl Category {
    pub const CYCLE: [Category; 5] = [Category::All, Category::Process, Category::Network, Category::File, Category::Resource];
    pub fn label(self) -> &'static str {
        match self {
            Category::All => "All",
            Category::Process => "Processes",
            Category::Network => "Network",
            Category::File => "Files",
            Category::Resource => "Resources",
        }
    }
    pub fn next(self) -> Self {
        let i = Self::CYCLE.iter().position(|c| *c == self).unwrap_or(0);
        Self::CYCLE[(i + 1) % Self::CYCLE.len()]
    }
    pub fn matches(self, k: Kind) -> bool {
        self == Category::All || k.category() == self || k == Kind::Note
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    #[serde(serialize_with = "ser_time")]
    pub at: DateTime<Local>,
    /// Seconds since the trace started.
    pub offset: f64,
    pub kind: Kind,
    pub pid: u32,
    pub process: String,
    pub detail: String,
}

fn ser_time<S: serde::Serializer>(t: &DateTime<Local>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&t.to_rfc3339())
}

/// Per-process facts gathered during the trace.
#[derive(Debug, Clone, Serialize)]
pub struct Tracked {
    pub pid: u32,
    /// Parent when it joined the trace (the lineage parent; it stays even
    /// after the process is re-parented).
    pub ppid: Option<u32>,
    /// Start time (s since the epoch, 0 = unknown): with the PID, the
    /// process's identity.
    pub start: u64,
    /// Left the tree's parent chain while running.
    pub escaped: bool,
    /// How it was first seen: "snapshot" or the deep-trace method.
    pub seen_by: &'static str,
    pub name: String,
    pub exe: Option<String>,
    pub command: String,
    pub user: Option<String>,
    pub first_seen: f64,
    pub exited_at: Option<f64>,
    pub peak_cpu: f32,
    pub peak_mem: u64,
    #[serde(skip)]
    start_mem: u64,
    #[serde(skip)]
    mem_reported: u64,
    #[serde(skip)]
    spiking: bool,
    #[serde(skip)]
    user_checked: bool,
}

/// A member's state at the last refresh.
#[derive(Debug, Clone, Copy, Default)]
pub struct Live {
    pub cpu: f32,
    pub mem: u64,
    pub threads: u32,
    pub ppid: Option<u32>,
}

/// One row of the lineage tree, depth first.
#[derive(Debug, Clone, Serialize)]
pub struct Lineage {
    pub pid: u32,
    pub depth: usize,
    /// Members in this subtree (itself included), alive or not.
    pub subtree: usize,
    pub subtree_alive: usize,
    pub subtree_cpu: f32,
    pub subtree_mem: u64,
}

/// Whole-tree figures.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct TreeStats {
    pub alive: usize,
    pub exited: usize,
    pub escaped: usize,
    pub max_depth: usize,
    pub cpu: f32,
    pub mem: u64,
    pub threads: u32,
    pub peak_alive: usize,
    /// Most spawns seen within `BURST_WINDOW`.
    pub peak_spawn_rate: usize,
}

pub struct Trace {
    pub root: u32,
    pub root_name: String,
    pub started: Instant,
    pub started_at: DateTime<Local>,
    pub stopped: Option<Instant>,
    pub events: Vec<Event>,
    pub procs: BTreeMap<u32, Tracked>,
    pub dropped: usize,
    conns: HashSet<(u32, Connection)>,
    files: HashMap<u32, HashSet<String>>,
    files_seeded: HashSet<u32>,
    pub remote_hosts: BTreeMap<String, usize>,
    pub listen_ports: BTreeSet<String>,
    pub files_touched: BTreeSet<String>,
    pub file_errors: Option<String>,
    /// Poll failures waiting for confirmation that the process is still
    /// alive (a process exiting mid-poll isn't a permission problem).
    pending_file_errors: HashMap<u32, String>,
    cpu_time_start: f64,
    pub cpu_time_used: f64,
    /// Members known from spawn events but not yet in a snapshot.
    adopted: HashMap<u32, u64>,
    spawns: VecDeque<f64>,
    burst: bool,
    pub live: HashMap<u32, Live>,
    pub peak_alive: usize,
    pub peak_spawn_rate: usize,
    root_gone_noted: bool,
    /// The trace enrolled the root in deep trace itself (and so ends it).
    pub deep: bool,
    /// Lifecycle events came from the deep-trace watcher.
    pub deep_via: Option<&'static str>,
    /// procwatch itself: never a member, nor are its helpers (tracing an
    /// ancestor of procwatch would otherwise record its own lsof calls).
    skip: u32,
}

/// Same process? Start times of 0 are unknown and match anything; the
/// sources round differently, so allow one second.
fn same_start(a: u64, b: u64) -> bool {
    a == 0 || b == 0 || a.abs_diff(b) <= 1
}

impl Trace {
    /// Start tracing `root`. What's already running/open is the baseline
    /// and isn't reported as events (it's listed in the summary instead).
    pub fn new(root: u32, tree: &ProcessTree, conns: &HashMap<u32, Vec<Connection>>) -> Option<Self> {
        let node = tree.get(root)?;
        let mut t = Self {
            root,
            root_name: node.info.name.clone(),
            started: Instant::now(),
            started_at: Local::now(),
            stopped: None,
            events: Vec::new(),
            procs: BTreeMap::new(),
            dropped: 0,
            conns: HashSet::new(),
            files: HashMap::new(),
            files_seeded: HashSet::new(),
            remote_hosts: BTreeMap::new(),
            listen_ports: BTreeSet::new(),
            files_touched: BTreeSet::new(),
            file_errors: None,
            pending_file_errors: HashMap::new(),
            cpu_time_start: 0.0,
            cpu_time_used: 0.0,
            adopted: HashMap::new(),
            spawns: VecDeque::new(),
            burst: false,
            live: HashMap::new(),
            peak_alive: 0,
            peak_spawn_rate: 0,
            root_gone_noted: false,
            deep: false,
            deep_via: None,
            skip: std::process::id(),
        };
        let pids = t.family(tree);
        for pid in &pids {
            if let Some(n) = tree.get(*pid) {
                t.track(&n.info, 0.0);
                if let Some(p) = t.procs.get_mut(pid) {
                    // The baseline's users are not news.
                    p.user_checked = true;
                }
                t.cpu_time_start += n.info.cpu_time_secs.unwrap_or(0.0);
            }
            for c in conns.get(pid).into_iter().flatten() {
                t.conns.insert((*pid, c.clone()));
                t.note_conn(c);
            }
        }
        let n = pids.len();
        t.push(Kind::Note, root, &t.root_name.clone(), format!("trace started — {n} process(es) in the tree"));
        Some(t)
    }

    pub fn is_running(&self) -> bool {
        self.stopped.is_none()
    }

    pub fn elapsed(&self) -> Duration {
        self.stopped.unwrap_or_else(Instant::now).duration_since(self.started)
    }

    fn offset(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    pub fn stop(&mut self) {
        if self.stopped.is_none() {
            let name = self.root_name.clone();
            self.push(Kind::Note, self.root, &name, "trace stopped".into());
            self.stopped = Some(Instant::now());
        }
    }

    /// PIDs the trace follows: the root and all live descendants, plus
    /// every live member already known — tracked or adopted from a spawn
    /// event — and their descendants, so re-parented and double-forked
    /// members stay followed after their parent exits. A PID whose start
    /// time no longer matches is a different process and is left out.
    pub fn family(&self, tree: &ProcessTree) -> Vec<u32> {
        let mut set: BTreeSet<u32> = BTreeSet::new();
        let alive = |pid: u32, start: u64| tree.get(pid).is_some_and(|n| same_start(start, n.info.start_time_secs));
        let root_start = self.procs.get(&self.root).map_or(0, |p| p.start);
        if alive(self.root, root_start) {
            set.insert(self.root);
            set.extend(tree.descendants(self.root));
        }
        let known: Vec<(u32, u64)> = self
            .procs
            .values()
            .filter(|p| p.exited_at.is_none())
            .map(|p| (p.pid, p.start))
            .chain(self.adopted.iter().map(|(p, s)| (*p, *s)))
            .collect();
        for (pid, start) in known {
            if alive(pid, start) && set.insert(pid) {
                set.extend(tree.descendants(pid));
            }
        }
        if set.remove(&self.skip) {
            for d in tree.descendants(self.skip) {
                set.remove(&d);
            }
        }
        set.into_iter().collect()
    }

    /// Live PIDs whose open files should be polled.
    pub fn live_pids(&self) -> Vec<u32> {
        self.procs.values().filter(|p| p.exited_at.is_none()).map(|p| p.pid).collect()
    }

    fn track(&mut self, info: &ProcessInfo, at: f64) {
        self.procs.entry(info.pid).or_insert_with(|| Tracked {
            pid: info.pid,
            ppid: info.ppid,
            start: info.start_time_secs,
            escaped: false,
            seen_by: "snapshot",
            name: info.name.clone(),
            exe: info.exe_path.clone(),
            command: info.cmd.join(" "),
            user: info.user.clone(),
            first_seen: at,
            exited_at: None,
            peak_cpu: info.cpu_usage_pct,
            peak_mem: info.mem(),
            start_mem: info.mem(),
            mem_reported: info.mem(),
            spiking: false,
            user_checked: false,
        });
    }

    /// Count a spawn towards the burst detector.
    fn spawned(&mut self, at: f64, pid: u32) {
        self.spawns.push_back(at);
        while self.spawns.front().is_some_and(|t| *t < at - BURST_WINDOW) {
            self.spawns.pop_front();
        }
        let n = self.spawns.len();
        self.peak_spawn_rate = self.peak_spawn_rate.max(n);
        if n >= BURST_COUNT && !self.burst {
            self.burst = true;
            let name = self.name(pid);
            self.push(Kind::Burst, pid, &name, format!("{n} processes started in the tree within {BURST_WINDOW:.0} s — fork bomb, brute-force loop or fan-out"));
        } else if n < BURST_COUNT / 2 {
            self.burst = false;
        }
    }

    /// Fold in lifecycle events from the deep-trace watcher. Spawns whose
    /// parent is a live member join the tree at once, even if they (or
    /// their parent) are gone before the next refresh.
    pub fn on_deep(&mut self, evs: &[DtEvent]) {
        if !self.is_running() {
            return;
        }
        for e in evs {
            let at = self.offset();
            let member = |t: &Self, pid: u32| t.procs.get(&pid).is_some_and(|p| p.exited_at.is_none()) || t.adopted.contains_key(&pid);
            match e.kind {
                DtKind::Spawn => {
                    let Some(pp) = e.ppid.filter(|pp| *pp != self.skip && e.pid != self.skip && member(self, *pp)) else { continue };
                    if self.procs.get(&e.pid).is_some_and(|p| p.exited_at.is_none()) {
                        continue;
                    }
                    self.deep_via = Some(e.via);
                    self.adopted.insert(e.pid, e.start);
                    let path = e.path.clone().unwrap_or_default();
                    let base = path.rsplit(['/', '\\']).next().filter(|b| !b.is_empty()).map(str::to_string);
                    let mut info = ProcessInfo::bare(e.pid, Some(pp), base.unwrap_or_else(|| e.pid.to_string()));
                    info.exe_path = e.path.clone();
                    info.start_time_secs = e.start;
                    info.cmd = e.args.iter().cloned().collect();
                    // A recycled PID: the old instance is over.
                    self.procs.remove(&e.pid);
                    self.track(&info, at);
                    if let Some(p) = self.procs.get_mut(&e.pid) {
                        p.seen_by = e.via;
                    }
                    let cmd = e.args.clone().or(e.path.clone()).unwrap_or_default();
                    let detail = format!("started by {} ({pp}): {cmd} · seen by {}", self.name(pp), e.via);
                    let name = self.name(e.pid);
                    self.push(Kind::ProcessStart, e.pid, &name, detail);
                    self.spawned(at, e.pid);
                    if e.start == 0 {
                        // Gone before it could be read; nothing more will come.
                        self.adopted.remove(&e.pid);
                        if let Some(p) = self.procs.get_mut(&e.pid) {
                            p.exited_at = Some(at);
                        }
                    }
                }
                DtKind::Exec => {
                    let Some(p) = self.procs.get_mut(&e.pid).filter(|p| p.exited_at.is_none()) else { continue };
                    let path = e.path.clone().unwrap_or_default();
                    if path.is_empty() || p.exe.as_deref() == Some(path.as_str()) {
                        continue;
                    }
                    let was = p.exe.replace(path.clone()).unwrap_or_else(|| p.name.clone());
                    if let Some(a) = &e.args {
                        p.command = a.clone();
                    }
                    if let Some(b) = path.rsplit(['/', '\\']).next().filter(|b| !b.is_empty()) {
                        p.name = b.to_string();
                    }
                    let name = p.name.clone();
                    let now = e.args.clone().filter(|a| !a.is_empty()).unwrap_or(path);
                    self.push(Kind::Exec, e.pid, &name, format!("{was} → {now}"));
                }
                DtKind::Exit => {
                    let Some(p) = self.procs.get_mut(&e.pid).filter(|p| p.exited_at.is_none() && same_start(p.start, e.start)) else { continue };
                    p.exited_at = Some(at);
                    let lifetime = at - p.first_seen;
                    let name = p.name.clone();
                    self.adopted.remove(&e.pid);
                    self.files.remove(&e.pid);
                    self.push(Kind::ProcessExit, e.pid, &name, format!("exited after {lifetime:.3}s in trace · seen by {}", e.via));
                }
            }
        }
    }

    /// The trace's members as a lineage tree (parents as they were when
    /// each member joined), depth first, with per-subtree figures.
    pub fn lineage(&self) -> Vec<Lineage> {
        let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for p in self.procs.values() {
            if p.pid == self.root {
                continue;
            }
            let parent = p.ppid.filter(|pp| *pp != p.pid && self.procs.contains_key(pp)).unwrap_or(self.root);
            children.entry(parent).or_default().push(p.pid);
        }
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        self.walk(self.root, 0, &children, &mut seen, &mut out);
        // Anything unreachable (a parent cycle) still gets a row.
        for pid in self.procs.keys() {
            if !seen.contains(pid) {
                self.walk(*pid, 1, &children, &mut seen, &mut out);
            }
        }
        out
    }

    fn walk(&self, pid: u32, depth: usize, children: &BTreeMap<u32, Vec<u32>>, seen: &mut HashSet<u32>, out: &mut Vec<Lineage>) -> (usize, usize, f32, u64) {
        if !self.procs.contains_key(&pid) || !seen.insert(pid) {
            return (0, 0, 0.0, 0);
        }
        let at = out.len();
        out.push(Lineage { pid, depth, subtree: 0, subtree_alive: 0, subtree_cpu: 0.0, subtree_mem: 0 });
        let alive = self.procs.get(&pid).is_some_and(|p| p.exited_at.is_none());
        let live = if alive { self.live.get(&pid).copied().unwrap_or_default() } else { Live::default() };
        let mut sum = (1, usize::from(alive), live.cpu, live.mem);
        for c in children.get(&pid).into_iter().flatten() {
            let (n, a, cpu, mem) = self.walk(*c, depth + 1, children, seen, out);
            sum = (sum.0 + n, sum.1 + a, sum.2 + cpu, sum.3 + mem);
        }
        if let Some(row) = out.get_mut(at) {
            (row.subtree, row.subtree_alive, row.subtree_cpu, row.subtree_mem) = sum;
        }
        sum
    }

    pub fn stats(&self) -> TreeStats {
        let mut s = TreeStats { peak_alive: self.peak_alive, peak_spawn_rate: self.peak_spawn_rate, ..TreeStats::default() };
        for p in self.procs.values() {
            if p.exited_at.is_none() {
                s.alive += 1;
                let l = self.live.get(&p.pid).copied().unwrap_or_default();
                s.cpu += l.cpu;
                s.mem += l.mem;
                s.threads += l.threads;
            } else {
                s.exited += 1;
            }
            s.escaped += usize::from(p.escaped);
        }
        s.max_depth = self.lineage().iter().map(|l| l.depth).max().unwrap_or(0);
        s
    }

    fn push(&mut self, kind: Kind, pid: u32, process: &str, detail: String) {
        if self.events.len() >= MAX_EVENTS {
            self.dropped += 1;
            return;
        }
        let offset = self.offset();
        self.events.push(Event { at: Local::now(), offset, kind, pid, process: process.to_string(), detail });
    }

    fn note_conn(&mut self, c: &Connection) {
        if c.state == ConnState::Listen {
            self.listen_ports.insert(format!("{} {}", c.protocol, c.local));
        } else if c.remote != "*:*" {
            let host = c.remote.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| c.remote.clone());
            *self.remote_hosts.entry(host).or_default() += 1;
        }
    }

    fn name(&self, pid: u32) -> String {
        self.procs.get(&pid).map(|p| p.name.clone()).unwrap_or_else(|| pid.to_string())
    }

    /// Fold in a new process/socket snapshot.
    pub fn on_snapshot(&mut self, tree: &ProcessTree, conns: &HashMap<u32, Vec<Connection>>) {
        if !self.is_running() {
            return;
        }
        let at = self.offset();
        let family = self.family(tree);
        let family_set: HashSet<u32> = family.iter().copied().collect();

        // New processes (children spawned during the trace).
        for pid in &family {
            if self.procs.contains_key(pid) {
                continue;
            }
            let Some(n) = tree.get(*pid) else { continue };
            let info = n.info.clone();
            self.track(&info, at);
            let parent = info.ppid.map(|p| format!(" by {} ({p})", self.name(p))).unwrap_or_default();
            let cmd = if info.cmd.is_empty() { info.name.clone() } else { info.cmd.join(" ") };
            self.push(Kind::ProcessStart, *pid, &info.name, format!("started{parent}: {cmd}"));
            self.spawned(at, *pid);
        }
        for pid in &family {
            self.adopted.remove(pid);
        }

        // Identity and lineage: fill in what spawn events couldn't know,
        // flag user changes and members that left the parent chain.
        let mut lineage_events = Vec::new();
        for pid in &family {
            let Some(n) = tree.get(*pid) else { continue };
            let lineage_parent = self.procs.get(pid).and_then(|p| p.ppid);
            let parent_user = lineage_parent.and_then(|pp| self.procs.get(&pp)).and_then(|pp| pp.user.clone());
            let parent_name = lineage_parent.map(|pp| self.name(pp)).unwrap_or_default();
            let now_parent = n.info.ppid.map(|pp| (pp, tree.get(pp).map(|x| x.info.name.clone()).unwrap_or_else(|| pp.to_string())));
            let root = self.root;
            let Some(p) = self.procs.get_mut(pid) else { continue };
            if p.user.is_none() {
                p.user = n.info.user.clone();
            }
            if p.start == 0 {
                p.start = n.info.start_time_secs;
            }
            if !p.user_checked && p.user.is_some() {
                p.user_checked = true;
                if let (Some(u), Some(pu)) = (&p.user, &parent_user) {
                    if u != pu {
                        lineage_events.push((Kind::Privilege, *pid, p.name.clone(), format!("runs as {u} — its parent ran as {pu}")));
                    }
                }
            }
            if *pid != root && !p.escaped {
                if let Some((pp, pname)) = now_parent.filter(|(pp, _)| !family_set.contains(pp)) {
                    p.escaped = true;
                    let from = if parent_name.is_empty() { String::new() } else { format!(" of {parent_name}") };
                    lineage_events.push((
                        Kind::Escape,
                        *pid,
                        p.name.clone(),
                        format!("left the tree{from}: now a child of {pname} ({pp}) — re-parented (double-fork, daemon or parent exit); still followed"),
                    ));
                }
            }
        }
        for (k, pid, name, detail) in lineage_events {
            self.push(k, pid, &name, detail);
        }

        // Exits.
        let gone: Vec<u32> = self
            .procs
            .values()
            .filter(|p| p.exited_at.is_none() && !family_set.contains(&p.pid))
            // Seen by a spawn event after this snapshot was taken: give the
            // next refreshes a chance to show it.
            .filter(|p| !(self.adopted.contains_key(&p.pid) && at - p.first_seen < ADOPT_GRACE))
            .map(|p| p.pid)
            .collect();
        for pid in &gone {
            self.adopted.remove(pid);
        }
        for pid in gone {
            let name = self.name(pid);
            let lifetime = self.procs.get(&pid).map(|p| at - p.first_seen).unwrap_or(0.0);
            if let Some(p) = self.procs.get_mut(&pid) {
                p.exited_at = Some(at);
            }
            self.files.remove(&pid);
            self.push(Kind::ProcessExit, pid, &name, format!("exited after {lifetime:.1}s in trace"));
        }

        // Resource peaks and spikes.
        let mut cpu_total = 0.0;
        let mut resource_events = Vec::new();
        self.live.clear();
        for pid in &family {
            let Some(n) = tree.get(*pid) else { continue };
            let i = &n.info;
            self.live.insert(*pid, Live { cpu: i.cpu_usage_pct, mem: i.mem(), threads: i.threads.unwrap_or(1), ppid: i.ppid });
            cpu_total += i.cpu_time_secs.unwrap_or(0.0);
            let Some(p) = self.procs.get_mut(pid) else { continue };
            p.peak_cpu = p.peak_cpu.max(i.cpu_usage_pct);
            p.peak_mem = p.peak_mem.max(i.mem());
            if i.cpu_usage_pct >= CPU_SPIKE_PCT && !p.spiking {
                p.spiking = true;
                resource_events.push((Kind::CpuSpike, *pid, p.name.clone(), format!("CPU at {:.0}%", i.cpu_usage_pct)));
            } else if i.cpu_usage_pct < CPU_SPIKE_PCT / 2.0 {
                p.spiking = false;
            }
            if i.mem() >= p.mem_reported + MEM_STEP {
                p.mem_reported = i.mem();
                resource_events.push((
                    Kind::MemoryGrowth,
                    *pid,
                    p.name.clone(),
                    format!("memory {} (was {} at start)", human_bytes(i.mem()), human_bytes(p.start_mem)),
                ));
            }
        }
        for (k, pid, name, detail) in resource_events {
            self.push(k, pid, &name, detail);
        }
        self.cpu_time_used = self.cpu_time_used.max(cpu_total - self.cpu_time_start);

        // Socket changes.
        let current: HashSet<(u32, Connection)> = family
            .iter()
            .flat_map(|pid| conns.get(pid).into_iter().flatten().map(move |c| (*pid, c.clone())))
            .collect();
        let mut opened: Vec<&(u32, Connection)> = current.difference(&self.conns).collect();
        opened.sort();
        let mut closed: Vec<(u32, Connection)> = self.conns.difference(&current).cloned().collect();
        closed.sort();
        let opened: Vec<(u32, Connection)> = opened.into_iter().cloned().collect();
        for (pid, c) in &opened {
            let name = self.name(*pid);
            self.note_conn(c);
            match c.state {
                ConnState::Listen => self.push(Kind::Listen, *pid, &name, format!("{} listening on {}", c.protocol, c.local)),
                _ if c.protocol == "UDP" => self.push(Kind::Connect, *pid, &name, format!("UDP socket {}", c.local)),
                _ => self.push(Kind::Connect, *pid, &name, format!("{} {} → {} ({})", c.protocol, c.local, c.remote, c.state.label())),
            }
        }
        for (pid, c) in &closed {
            // Only report closes for processes still alive; an exit already
            // says everything about its sockets.
            if !family_set.contains(pid) {
                continue;
            }
            let name = self.name(*pid);
            match c.state {
                ConnState::Listen => self.push(Kind::StopListen, *pid, &name, format!("stopped listening on {}", c.local)),
                _ => self.push(Kind::Disconnect, *pid, &name, format!("{} {} → {}", c.protocol, c.local, c.remote)),
            }
        }
        self.conns = current;

        for (pid, e) in std::mem::take(&mut self.pending_file_errors) {
            if family_set.contains(&pid) {
                self.file_errors.get_or_insert(e);
            }
        }

        let alive = self.procs.values().filter(|p| p.exited_at.is_none()).count();
        self.peak_alive = self.peak_alive.max(alive);
        if !self.root_gone_noted && self.procs.get(&self.root).is_some_and(|p| p.exited_at.is_some()) && alive > 0 {
            self.root_gone_noted = true;
            let name = self.root_name.clone();
            self.push(Kind::Note, self.root, &name, format!("root exited; {alive} member(s) of its tree still running and still followed"));
        }

        // Nothing left to watch: finish on our own.
        if self.adopted.is_empty() && self.procs.values().all(|p| p.exited_at.is_some()) {
            let name = self.root_name.clone();
            self.push(Kind::Note, self.root, &name, "all traced processes have exited".into());
            self.stop();
        }
    }

    /// Fold in a poll of open files for the traced processes.
    pub fn on_files(&mut self, files: HashMap<u32, Result<Vec<OpenFile>, String>>) {
        if !self.is_running() {
            return;
        }
        for (pid, result) in files {
            if self.procs.get(&pid).is_none_or(|p| p.exited_at.is_some()) {
                continue;
            }
            let list = match result {
                Ok(l) => l,
                Err(e) => {
                    self.pending_file_errors.insert(pid, e);
                    continue;
                }
            };
            // Regular files and directories only; sockets come from the
            // socket table, and pipes/devices are mostly noise.
            let now: HashSet<String> = list
                .into_iter()
                .filter(|f| matches!(f.kind.as_str(), "REG" | "DIR" | "File") && !f.name.is_empty() && f.fd != "txt")
                .map(|f| f.name)
                .collect();
            let name = self.name(pid);
            if self.files_seeded.insert(pid) && self.procs.get(&pid).is_some_and(|p| p.first_seen == 0.0) {
                // First poll of a process that existed before the trace:
                // that's its baseline, not activity.
                self.files_touched.extend(now.iter().cloned());
                self.files.insert(pid, now);
                continue;
            }
            let before = self.files.remove(&pid).unwrap_or_default();
            let mut opened: Vec<&String> = now.difference(&before).collect();
            opened.sort();
            let mut closed: Vec<&String> = before.difference(&now).collect();
            closed.sort();
            for f in opened {
                self.files_touched.insert(f.clone());
                self.push(Kind::FileOpen, pid, &name, f.clone());
            }
            for f in closed {
                self.push(Kind::FileClose, pid, &name, f.clone());
            }
            self.files.insert(pid, now);
        }
    }

    pub fn count(&self, k: Kind) -> usize {
        self.events.iter().filter(|e| e.kind == k).count()
    }

    /// Directories with the most touched files, most first.
    pub fn top_dirs(&self, n: usize) -> Vec<(String, usize)> {
        let mut dirs: HashMap<String, usize> = HashMap::new();
        for f in &self.files_touched {
            let dir = f.rsplit_once(['/', '\\']).map(|(d, _)| d).filter(|d| !d.is_empty()).unwrap_or("/");
            *dirs.entry(dir.to_string()).or_default() += 1;
        }
        let mut v: Vec<(String, usize)> = dirs.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    pub fn top_hosts(&self, n: usize) -> Vec<(String, usize)> {
        let mut v: Vec<(String, usize)> = self.remote_hosts.iter().map(|(h, c)| (h.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    // ── reports ────────────────────────────────────────────────────────

    pub fn to_markdown(&self) -> String {
        let mut s = String::new();
        let secs = self.elapsed().as_secs_f64();
        s.push_str(&format!("# Behavior trace: {} ({})\n\n", self.root_name, self.root));
        s.push_str(&format!("- Started: {}\n- Duration: {secs:.1} s\n", self.started_at.format("%Y-%m-%d %H:%M:%S %Z")));
        s.push_str(&format!("- Processes observed: {}\n", self.procs.len()));
        s.push_str(&format!("- Events: {}{}\n", self.events.len(), if self.dropped > 0 { format!(" ({} dropped)", self.dropped) } else { String::new() }));
        s.push_str(&format!("- CPU time used by the tree: {:.1} s\n\n", self.cpu_time_used));
        match self.deep_via {
            Some(via) => s.push_str(&format!("> Process lifecycle from deep trace ({via}); sockets every refresh, open files every ~2 s.\n\n")),
            None => {
                s.push_str("> Sampled observation: process and socket state every refresh, open files every ~2 s. ");
                s.push_str("Activity shorter than the sampling interval may not appear.\n\n");
            }
        }
        let st = self.stats();
        s.push_str(&format!(
            "## Process tree\n\n- Members: {} ({} running, {} exited), peak {} running at once\n- Deepest level: {}\n- Escaped the parent chain: {}\n- Most spawns within {BURST_WINDOW:.0} s: {}\n\n```\n",
            self.procs.len(),
            st.alive,
            st.exited,
            st.peak_alive,
            st.max_depth,
            st.escaped,
            st.peak_spawn_rate
        ));
        for l in self.lineage() {
            let Some(p) = self.procs.get(&l.pid) else { continue };
            let state = match (p.exited_at, p.escaped) {
                (Some(x), _) => format!("exited +{x:.1}s"),
                (None, true) => "running, escaped".into(),
                (None, false) => "running".into(),
            };
            s.push_str(&format!("{}{} ({}) [{state}] {}\n", "  ".repeat(l.depth), p.name.replace('`', "'"), p.pid, p.user.as_deref().unwrap_or("")));
        }
        s.push_str("```\n\n");

        s.push_str("## Processes\n\n| PID | Parent | Name | First seen | Exited | Peak CPU | Peak memory | Command |\n|---|---|---|---|---|---|---|---|\n");
        for p in self.procs.values() {
            s.push_str(&format!(
                "| {} | {} | {} | +{:.1}s | {} | {:.0}% | {} | `{}` |\n",
                p.pid,
                p.ppid.map(|x| x.to_string()).unwrap_or_default(),
                md(&p.name),
                p.first_seen,
                p.exited_at.map(|x| format!("+{x:.1}s")).unwrap_or_else(|| "running".into()),
                p.peak_cpu,
                human_bytes(p.peak_mem),
                md(&p.command).replace('`', "'"),
            ));
        }
        s.push_str("\n## Network\n\n");
        if self.remote_hosts.is_empty() && self.listen_ports.is_empty() {
            s.push_str("No network activity observed.\n");
        }
        for (h, n) in self.top_hosts(usize::MAX) {
            s.push_str(&format!("- remote {h} — {n} connection(s)\n"));
        }
        for l in &self.listen_ports {
            s.push_str(&format!("- listening {l}\n"));
        }
        s.push_str(&format!("\n## Files ({} distinct)\n\n", self.files_touched.len()));
        if let Some(e) = &self.file_errors {
            s.push_str(&format!("Some open-file polls failed: {e}\n\n"));
        }
        for (d, n) in self.top_dirs(20) {
            s.push_str(&format!("- {d} — {n} file(s)\n"));
        }
        s.push_str("\n## Timeline\n\n| Time | +s | Event | PID | Process | Detail |\n|---|---|---|---|---|---|\n");
        for e in &self.events {
            s.push_str(&format!(
                "| {} | {:.1} | {} | {} | {} | {} |\n",
                e.at.format("%H:%M:%S"),
                e.offset,
                e.kind.label(),
                e.pid,
                md(&e.process),
                md(&e.detail)
            ));
        }
        s
    }

    pub fn to_json(&self) -> String {
        #[derive(Serialize)]
        struct Report<'a> {
            root_pid: u32,
            root_name: &'a str,
            started: String,
            duration_secs: f64,
            cpu_time_used_secs: f64,
            processes: Vec<&'a Tracked>,
            tree: TreeStats,
            lineage: Vec<Lineage>,
            lifecycle_source: &'a str,
            remote_hosts: &'a BTreeMap<String, usize>,
            listening: &'a BTreeSet<String>,
            files_touched: &'a BTreeSet<String>,
            events: &'a [Event],
            events_dropped: usize,
        }
        let r = Report {
            root_pid: self.root,
            root_name: &self.root_name,
            started: self.started_at.to_rfc3339(),
            duration_secs: self.elapsed().as_secs_f64(),
            cpu_time_used_secs: self.cpu_time_used,
            processes: self.procs.values().collect(),
            tree: self.stats(),
            lineage: self.lineage(),
            lifecycle_source: self.deep_via.unwrap_or("snapshot"),
            remote_hosts: &self.remote_hosts,
            listening: &self.listen_ports,
            files_touched: &self.files_touched,
            events: &self.events,
            events_dropped: self.dropped,
        };
        serde_json::to_string_pretty(&r).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }

    /// Write `.md` and `.json` reports to the working directory.
    pub fn export(&self) -> anyhow::Result<String> {
        let safe: String = self.root_name.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
        let base = format!("procwatch-trace-{safe}-{}", self.started_at.format("%Y%m%d-%H%M%S"));
        crate::common::paths::write_new(std::path::Path::new(&format!("{base}.md")), &self.to_markdown())?;
        crate::common::paths::write_new(std::path::Path::new(&format!("{base}.json")), &self.to_json())?;
        Ok(base)
    }
}

fn md(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::tests::{info, sample};
    use crate::process::TreeNode;

    fn conn(local: &str, remote: &str, state: ConnState) -> Connection {
        Connection { protocol: "TCP", local: local.into(), remote: remote.into(), state }
    }

    #[test]
    fn records_children_sockets_and_files() {
        let mut tree = sample();
        let mut conns: HashMap<u32, Vec<Connection>> = HashMap::new();
        conns.insert(2, vec![conn("*:80", "*:*", ConnState::Listen)]);
        let mut t = Trace::new(2, &tree, &conns).unwrap();
        assert_eq!(t.procs.len(), 2); // pid 2 and its child 4
        assert!(t.listen_ports.contains("TCP *:80"));

        // A new child of 4 appears and connects out; pid 4 exits.
        tree.nodes.insert(7, TreeNode { info: info(7, Some(2)), children: vec![] });
        tree.nodes.get_mut(&2).unwrap().children = vec![7];
        tree.nodes.remove(&4);
        conns.insert(7, vec![conn("10.0.0.2:5000", "93.184.216.34:443", ConnState::Established)]);
        t.on_snapshot(&tree, &conns);
        assert_eq!(t.count(Kind::ProcessStart), 1);
        assert_eq!(t.count(Kind::ProcessExit), 1);
        assert_eq!(t.count(Kind::Connect), 1);
        assert_eq!(t.top_hosts(5)[0].0, "93.184.216.34");

        // Files: baseline for pre-existing pid 2, then a new open.
        let f = |n: &str| OpenFile { fd: "3".into(), kind: "REG".into(), name: n.into() };
        t.on_files([(2, Ok(vec![f("/etc/hosts")]))].into());
        assert_eq!(t.count(Kind::FileOpen), 0);
        t.on_files([(2, Ok(vec![f("/etc/hosts"), f("/tmp/x.log")]))].into());
        assert_eq!(t.count(Kind::FileOpen), 1);
        t.on_files([(2, Ok(vec![]))].into());
        assert_eq!(t.count(Kind::FileClose), 2);

        t.stop();
        let md = t.to_markdown();
        assert!(md.contains("Behavior trace") && md.contains("/tmp/x.log"));
        assert!(t.to_json().contains("\"root_pid\": 2"));
    }

    fn ev(kind: DtKind, pid: u32, ppid: Option<u32>, start: u64, path: &str) -> DtEvent {
        DtEvent { at: Local::now(), kind, pid, ppid, start, path: Some(path.into()), args: None, via: "kqueue" }
    }

    fn node(tree: &mut ProcessTree, pid: u32, ppid: u32, start: u64) {
        let mut i = info(pid, Some(ppid));
        i.start_time_secs = start;
        tree.nodes.insert(pid, TreeNode { info: i, children: vec![] });
        if let Some(p) = tree.nodes.get_mut(&ppid) {
            p.children.push(pid);
        }
    }

    /// The double-fork: 2 starts 10, 10 starts 11 and exits, 11 is
    /// re-parented to init — all between two refreshes.
    #[test]
    fn double_forked_daemon_stays_in_the_tree() {
        let mut tree = sample();
        let mut t = Trace::new(2, &tree, &HashMap::new()).unwrap();
        t.on_deep(&[
            ev(DtKind::Spawn, 10, Some(2), 100, "/bin/sh"),
            ev(DtKind::Spawn, 11, Some(10), 100, "/tmp/.x/miner"),
            ev(DtKind::Exit, 10, None, 100, ""),
        ]);
        assert!(t.procs.contains_key(&11) && t.procs[&10].exited_at.is_some());
        node(&mut tree, 11, 1, 100);
        t.on_snapshot(&tree, &HashMap::new());
        assert!(t.family(&tree).contains(&11), "re-parented daemon dropped");
        assert_eq!(t.count(Kind::ProcessStart), 2);
        assert_eq!(t.count(Kind::Escape), 1);
        assert!(t.procs[&11].escaped);
        // Its own children are members too.
        node(&mut tree, 12, 11, 101);
        t.on_snapshot(&tree, &HashMap::new());
        assert!(t.procs.contains_key(&12));
        // Lineage keeps the original parent chain: 2 → 10 → 11 → 12.
        let l = t.lineage();
        let depth = |pid| l.iter().find(|r| r.pid == pid).map(|r| r.depth);
        assert_eq!((depth(2), depth(10), depth(11), depth(12)), (Some(0), Some(2 - 1), Some(2), Some(3)));
        assert_eq!(l[0].subtree, t.procs.len());
        assert_eq!(t.stats().escaped, 1);
        assert!(t.to_markdown().contains("## Process tree"));
    }

    /// A member known only from a spawn event isn't declared gone by a
    /// snapshot taken just before it started.
    #[test]
    fn spawn_seen_before_the_snapshot_is_not_an_exit() {
        let tree = sample();
        let mut t = Trace::new(2, &tree, &HashMap::new()).unwrap();
        t.on_deep(&[ev(DtKind::Spawn, 20, Some(2), 100, "/bin/true")]);
        t.on_snapshot(&tree, &HashMap::new());
        assert!(t.procs[&20].exited_at.is_none());
        assert_eq!(t.count(Kind::ProcessExit), 0);
    }

    /// A recycled PID with a different start time is someone else.
    #[test]
    fn recycled_pid_is_not_a_member() {
        let mut tree = sample();
        tree.nodes.get_mut(&4).unwrap().info.start_time_secs = 50;
        let mut t = Trace::new(2, &tree, &HashMap::new()).unwrap();
        tree.nodes.remove(&4);
        tree.nodes.get_mut(&2).unwrap().children.clear();
        t.on_snapshot(&tree, &HashMap::new());
        assert!(t.procs[&4].exited_at.is_some());
        // pid 4 comes back as an unrelated process under init.
        node(&mut tree, 4, 1, 900);
        t.on_snapshot(&tree, &HashMap::new());
        assert!(!t.family(&tree).contains(&4));
    }

    #[test]
    fn user_change_exec_and_burst_are_reported() {
        let mut tree = sample();
        tree.nodes.get_mut(&2).unwrap().info.user = Some("alice".into());
        let mut t = Trace::new(2, &tree, &HashMap::new()).unwrap();
        node(&mut tree, 30, 2, 100);
        tree.nodes.get_mut(&30).unwrap().info.user = Some("root".into());
        t.on_snapshot(&tree, &HashMap::new());
        assert_eq!(t.count(Kind::Privilege), 1);
        t.on_deep(&[ev(DtKind::Exec, 30, Some(2), 100, "/usr/bin/curl")]);
        assert_eq!(t.count(Kind::Exec), 1);
        assert_eq!(t.procs[&30].name, "curl");
        let burst: Vec<DtEvent> = (100..100 + BURST_COUNT as u32).map(|p| ev(DtKind::Spawn, p, Some(30), 100, "/bin/sh")).collect();
        t.on_deep(&burst);
        assert_eq!(t.count(Kind::Burst), 1, "one burst, not one per spawn");
        assert!(t.stats().peak_spawn_rate >= BURST_COUNT);
    }

    /// procwatch and its helpers never join a trace of its ancestor.
    #[test]
    fn procwatch_is_not_its_own_subject() {
        let mut tree = sample();
        let me = std::process::id();
        node(&mut tree, me, 2, 0);
        node(&mut tree, me + 1, me, 0);
        let mut t = Trace::new(2, &tree, &HashMap::new()).unwrap();
        assert!(!t.procs.contains_key(&me) && !t.procs.contains_key(&(me + 1)));
        t.on_deep(&[ev(DtKind::Spawn, me + 2, Some(me), 100, "/usr/sbin/lsof")]);
        assert!(!t.procs.contains_key(&(me + 2)));
    }

    /// Spawns from outside the tree are ignored.
    #[test]
    fn foreign_spawns_are_not_adopted() {
        let tree = sample();
        let mut t = Trace::new(2, &tree, &HashMap::new()).unwrap();
        t.on_deep(&[ev(DtKind::Spawn, 40, Some(3), 100, "/bin/sh")]);
        assert!(!t.procs.contains_key(&40));
    }
}
