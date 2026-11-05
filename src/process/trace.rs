//! Behavior trace: follow one process and every descendant it spawns, and
//! record what they do over time — child processes, network connections,
//! listening ports, files opened and closed, CPU and memory spikes — as a
//! timeline plus a summary, exportable as a Markdown or JSON report.
//!
//! This is observation by sampling (each refresh for processes and
//! sockets, every couple of seconds for files), the same data the rest of
//! procwatch shows. Very short-lived activity between samples can be
//! missed; the report says so.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use serde::Serialize;

use crate::process::inspect::OpenFile;
use crate::network::{ConnState, Connection};
use crate::process::{human_bytes, ProcessInfo, ProcessTree};

const MAX_EVENTS: usize = 50_000;
const CPU_SPIKE_PCT: f32 = 80.0;
/// Memory growth (since the trace started) worth an event, per process.
const MEM_STEP: u64 = 100 << 20;

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
            Kind::Note => "note",
        }
    }

    pub fn category(self) -> Category {
        match self {
            Kind::ProcessStart | Kind::ProcessExit => Category::Process,
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
    pub ppid: Option<u32>,
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
        };
        let pids = t.family(tree);
        for pid in &pids {
            if let Some(n) = tree.get(*pid) {
                t.track(&n.info, 0.0);
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
    /// anything already tracked that is still alive (re-parented children
    /// stay followed after their parent exits).
    pub fn family(&self, tree: &ProcessTree) -> Vec<u32> {
        let mut set: BTreeSet<u32> = BTreeSet::new();
        if tree.nodes.contains_key(&self.root) {
            set.insert(self.root);
            set.extend(tree.descendants(self.root));
        }
        for pid in self.procs.keys() {
            if self.procs[pid].exited_at.is_none() && tree.nodes.contains_key(pid) {
                set.insert(*pid);
                set.extend(tree.descendants(*pid));
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
        });
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
        }

        // Exits.
        let gone: Vec<u32> = self
            .procs
            .values()
            .filter(|p| p.exited_at.is_none() && !family_set.contains(&p.pid))
            .map(|p| p.pid)
            .collect();
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
        for pid in &family {
            let Some(n) = tree.get(*pid) else { continue };
            let i = &n.info;
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

        // Nothing left to watch: finish on our own.
        if self.procs.values().all(|p| p.exited_at.is_some()) {
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
                .filter(|f| matches!(f.kind.as_str(), "REG" | "DIR") && !f.name.is_empty() && f.fd != "txt")
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
        s.push_str("> Sampled observation: process and socket state every refresh, open files every ~2 s. ");
        s.push_str("Activity shorter than the sampling interval may not appear.\n\n");

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
        std::fs::write(format!("{base}.md"), self.to_markdown())?;
        std::fs::write(format!("{base}.json"), self.to_json())?;
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
}
