//! Cross-platform process snapshot + parent/child tree construction.
//! Backed by the `sysinfo` crate, which abstracts Windows/macOS/Linux
//! process enumeration behind one API, plus `native` for the scheduler
//! fields it lacks.

pub mod actions;
pub mod native;

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use sysinfo::{
    Networks, Pid, ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, System, Uid, UpdateKind, Users,
};

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe_path: Option<String>,
    pub cwd: Option<String>,
    pub cmd: Vec<String>,
    pub cpu_usage_pct: f32,
    pub memory_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub status: ProcessStatus,
    pub start_time_secs: u64,
    pub run_time_secs: u64,
    pub user: Option<String>,
    pub threads: Option<u32>,
    pub nice: Option<i32>,
    pub priority: Option<i32>,
    pub cpu_time_secs: Option<f64>,
    /// Bytes per second over the last sampling interval.
    pub disk_read_rate: f64,
    pub disk_write_rate: f64,
    pub disk_read_total: u64,
    pub disk_write_total: u64,
    pub footprint: Option<u64>,
    /// Memory trend in bytes per minute (filled in by the app from history).
    pub mem_growth: Option<f64>,
    /// Triage score 0–100 (filled in by the app).
    pub risk: u8,
    /// Signature state of the executable: 'y' signed, 'n' unsigned,
    /// '!' invalid, '?' unknown / not checked yet (filled in by the app).
    pub signed: char,
}

impl ProcessInfo {
    /// A process known only from recorded data (offline analysis).
    pub fn bare(pid: u32, ppid: Option<u32>, name: String) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name,
            exe_path: None,
            cwd: None,
            cmd: vec![],
            cpu_usage_pct: 0.0,
            memory_bytes: 0,
            virtual_memory_bytes: 0,
            status: ProcessStatus::Unknown(0),
            start_time_secs: 0,
            run_time_secs: 0,
            user: None,
            threads: None,
            nice: None,
            priority: None,
            cpu_time_secs: None,
            disk_read_rate: 0.0,
            disk_write_rate: 0.0,
            disk_read_total: 0,
            disk_write_total: 0,
            footprint: None,
            mem_growth: None,
            risk: 0,
            signed: '?',
        }
    }

    /// The memory figure to show: physical footprint where the OS has it
    /// (macOS, matching Activity Monitor), resident set size otherwise.
    pub fn mem(&self) -> u64 {
        self.footprint.unwrap_or(self.memory_bytes)
    }

    /// Friendly priority level derived from the nice value.
    pub fn priority_label(&self) -> &'static str {
        match self.nice {
            Some(n) if n <= -15 => "Very high",
            Some(n) if n <= -5 => "High",
            Some(n) if n < 5 => "Normal",
            Some(n) if n < 15 => "Low",
            Some(_) => "Very low",
            None => "-",
        }
    }

    /// App grouping key: the outermost `.app` bundle on macOS (so helper
    /// processes group under their app), else the process name.
    pub fn app_name(&self) -> String {
        if let Some(path) = &self.exe_path {
            if let Some(i) = path.find(".app/") {
                let bundle = &path[..i];
                if let Some(name) = bundle.rsplit('/').next() {
                    return name.to_string();
                }
            }
        }
        self.name.clone()
    }

    pub fn status_label(&self) -> &'static str {
        match self.status {
            ProcessStatus::Run => "running",
            ProcessStatus::Sleep => "sleeping",
            ProcessStatus::Idle => "idle",
            ProcessStatus::Zombie => "zombie",
            ProcessStatus::Stop => "stopped",
            ProcessStatus::Dead => "dead",
            ProcessStatus::Tracing => "traced",
            ProcessStatus::UninterruptibleDiskSleep => "disk sleep",
            _ => "unknown",
        }
    }

    /// One-letter state as in `ps`/`top`.
    pub fn state_char(&self) -> char {
        match self.status {
            ProcessStatus::Run => 'R',
            ProcessStatus::Sleep => 'S',
            ProcessStatus::Idle => 'I',
            ProcessStatus::Zombie => 'Z',
            ProcessStatus::Stop => 'T',
            ProcessStatus::Tracing => 't',
            ProcessStatus::Dead => 'X',
            ProcessStatus::UninterruptibleDiskSleep => 'D',
            _ => '?',
        }
    }

    /// Arguments after argv[0], joined.
    pub fn args(&self) -> String {
        self.cmd.iter().skip(1).map(String::as_str).collect::<Vec<_>>().join(" ")
    }
}

#[derive(Debug, Clone)]
pub struct TreeNode {
    pub info: ProcessInfo,
    pub children: Vec<u32>, // child PIDs, ascending
}

#[derive(Debug, Default)]
pub struct ProcessTree {
    pub nodes: HashMap<u32, TreeNode>,
    pub roots: Vec<u32>,
}

/// One display row produced by [`ProcessTree::flatten`].
#[derive(Debug, Clone)]
pub struct FlatRow {
    pub pid: u32,
    /// Pre-rendered tree guide (`│  ├─ `); empty in flat mode.
    pub prefix: String,
    pub has_children: bool,
    /// Number of descendants hidden because this node is collapsed.
    pub hidden: usize,
}

#[derive(Debug, Clone, Default)]
pub struct IfaceStats {
    pub name: String,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub rx_total: u64,
    pub tx_total: u64,
}

/// Global system figures captured alongside the process list.
#[derive(Debug, Clone, Default)]
pub struct SystemStats {
    pub cpu_pct: f32,
    pub per_core: Vec<f32>,
    pub mem_used: u64,
    pub mem_total: u64,
    pub swap_used: u64,
    pub swap_total: u64,
    pub load_avg: [f64; 3],
    pub uptime_secs: u64,
    pub tasks: usize,
    pub threads: u64,
    pub running: usize,
    pub net_rx_rate: f64,
    pub net_tx_rate: f64,
    pub disk_read_rate: f64,
    pub disk_write_rate: f64,
    pub interfaces: Vec<IfaceStats>,
}

pub struct ProcessMonitor {
    sys: System,
    users: Users,
    networks: Networks,
    user_names: HashMap<Uid, String>,
    last_refresh: Instant,
}

impl ProcessMonitor {
    pub fn new() -> Self {
        let mut sys = System::new();
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        sys.refresh_processes_specifics(ProcessesToUpdate::All, Self::refresh_kind());
        Self {
            sys,
            users: Users::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
            user_names: HashMap::new(),
            last_refresh: Instant::now(),
        }
    }

    /// Only what we actually display. Static fields (exe, cwd, cmd, user)
    /// are read once per process instead of every tick, which is most of
    /// the cost of a naive `refresh_all()`.
    fn refresh_kind() -> ProcessRefreshKind {
        ProcessRefreshKind::new()
            .with_cpu()
            .with_memory()
            .with_disk_usage()
            .with_exe(UpdateKind::OnlyIfNotSet)
            .with_cmd(UpdateKind::OnlyIfNotSet)
            .with_cwd(UpdateKind::OnlyIfNotSet)
            .with_user(UpdateKind::OnlyIfNotSet)
    }

    fn user_name(&mut self, uid: &Uid) -> String {
        if let Some(name) = self.user_names.get(uid) {
            return name.clone();
        }
        let name = self
            .users
            .get_user_by_id(uid)
            .map(|u| u.name().to_string())
            .unwrap_or_else(|| format!("{uid:?}").trim_matches('"').to_string());
        self.user_names.insert(uid.clone(), name.clone());
        name
    }

    /// Re-scan all processes and rebuild the parent/child tree.
    pub fn snapshot(&mut self) -> (ProcessTree, SystemStats) {
        let mut lap = crate::perf::Lap::new();
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        lap.mark("sampler: cpu and memory");
        self.sys.refresh_processes_specifics(ProcessesToUpdate::All, Self::refresh_kind());
        lap.mark("sampler: process list");
        self.networks.refresh();
        lap.mark("sampler: network stats");
        let elapsed = self.last_refresh.elapsed().as_secs_f64().max(0.001);
        self.last_refresh = Instant::now();

        // Skip Linux threads; they share the parent's resources and would
        // only clutter the tree.
        let pids: Vec<u32> = self
            .sys
            .processes()
            .iter()
            .filter(|(_, p)| p.thread_kind().is_none())
            .map(|(pid, _)| pid.as_u32())
            .collect();
        let native = native::collect(&pids);
        lap.mark("sampler: native details");

        let mut nodes: HashMap<u32, TreeNode> = HashMap::with_capacity(pids.len());
        let (mut disk_r, mut disk_w, mut threads, mut running) = (0f64, 0f64, 0u64, 0usize);

        for &pid_u32 in &pids {
            let Some(uid) = self.sys.process(Pid::from_u32(pid_u32)).map(|p| p.user_id().cloned()) else {
                continue;
            };
            let user = uid.map(|u| self.user_name(&u));
            let Some(proc_) = self.sys.process(Pid::from_u32(pid_u32)) else { continue };
            let ppid_u32 = proc_.parent().map(|p: Pid| p.as_u32()).filter(|p| *p != pid_u32);
            let n = native.get(&pid_u32).copied().unwrap_or_default();
            let du = proc_.disk_usage();
            let cpu = proc_.cpu_usage();

            let info = ProcessInfo {
                pid: pid_u32,
                ppid: ppid_u32,
                name: proc_.name().to_string_lossy().into_owned(),
                exe_path: proc_.exe().map(|p| p.display().to_string()),
                cwd: proc_.cwd().map(|p| p.display().to_string()),
                cmd: proc_.cmd().iter().map(|s| s.to_string_lossy().into_owned()).collect(),
                cpu_usage_pct: if cpu.is_finite() { cpu.max(0.0) } else { 0.0 },
                memory_bytes: proc_.memory(),
                virtual_memory_bytes: proc_.virtual_memory(),
                status: proc_.status(),
                start_time_secs: proc_.start_time(),
                run_time_secs: proc_.run_time(),
                user,
                threads: n.threads,
                nice: n.nice,
                priority: n.priority,
                cpu_time_secs: n.cpu_time,
                disk_read_rate: du.read_bytes as f64 / elapsed,
                disk_write_rate: du.written_bytes as f64 / elapsed,
                disk_read_total: du.total_read_bytes,
                disk_write_total: du.total_written_bytes,
                footprint: n.footprint,
                mem_growth: None,
                risk: 0,
                signed: '?',
            };
            disk_r += info.disk_read_rate;
            disk_w += info.disk_write_rate;
            threads += info.threads.unwrap_or(1) as u64;
            running += usize::from(info.status == ProcessStatus::Run);

            nodes.insert(pid_u32, TreeNode { info, children: Vec::new() });
        }

        // Link children to parents. A process whose parent is not in the
        // current snapshot (already exited, or PID 0) becomes a root.
        let links: Vec<(u32, Option<u32>)> = nodes.iter().map(|(pid, n)| (*pid, n.info.ppid)).collect();
        let mut roots = Vec::new();
        for (pid, ppid) in links {
            match ppid.and_then(|p| nodes.get_mut(&p)) {
                Some(parent) => parent.children.push(pid),
                None => roots.push(pid),
            }
        }
        roots.sort_unstable();
        for node in nodes.values_mut() {
            node.children.sort_unstable();
        }

        let mut interfaces: Vec<IfaceStats> = self
            .networks
            .list()
            .iter()
            .map(|(name, d)| IfaceStats {
                name: name.clone(),
                rx_rate: d.received() as f64 / elapsed,
                tx_rate: d.transmitted() as f64 / elapsed,
                rx_total: d.total_received(),
                tx_total: d.total_transmitted(),
            })
            .filter(|i| i.rx_total > 0 || i.tx_total > 0)
            .collect();
        interfaces.sort_by(|a, b| b.rx_total.cmp(&a.rx_total).then_with(|| a.name.cmp(&b.name)));

        let load = System::load_average();
        let stats = SystemStats {
            cpu_pct: self.sys.global_cpu_usage(),
            per_core: self.sys.cpus().iter().map(|c| c.cpu_usage()).collect(),
            mem_used: self.sys.used_memory(),
            mem_total: self.sys.total_memory(),
            swap_used: self.sys.used_swap(),
            swap_total: self.sys.total_swap(),
            load_avg: [load.one, load.five, load.fifteen],
            uptime_secs: System::uptime(),
            tasks: nodes.len(),
            threads,
            running,
            net_rx_rate: interfaces.iter().map(|i| i.rx_rate).sum(),
            net_tx_rate: interfaces.iter().map(|i| i.tx_rate).sum(),
            disk_read_rate: disk_r,
            disk_write_rate: disk_w,
            interfaces,
        };

        (ProcessTree { nodes, roots }, stats)
    }
}

impl ProcessTree {
    pub fn get(&self, pid: u32) -> Option<&TreeNode> {
        self.nodes.get(&pid)
    }

    /// All descendants of `pid` (not including it), depth-first.
    pub fn descendants(&self, pid: u32) -> Vec<u32> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut stack: Vec<u32> = self.get(pid).map(|n| n.children.clone()).unwrap_or_default();
        while let Some(p) = stack.pop() {
            if p == pid || !seen.insert(p) {
                continue;
            }
            out.push(p);
            if let Some(n) = self.get(p) {
                stack.extend(n.children.iter().copied());
            }
        }
        out
    }

    /// Depth-first display order with tree guides. Siblings are ordered by
    /// `cmp` (so "tree + sort by CPU" works like htop), `collapsed` nodes
    /// hide their subtree, and `keep` (when filtering) restricts the rows.
    ///
    /// Iterative (no recursion depth limit) and cycle-safe: PID reuse can
    /// briefly produce parent loops, and nodes trapped in such a loop are
    /// promoted to roots instead of silently disappearing.
    pub fn flatten(
        &self,
        cmp: &dyn Fn(&ProcessInfo, &ProcessInfo) -> Ordering,
        collapsed: &HashSet<u32>,
        keep: Option<&HashSet<u32>>,
    ) -> Vec<FlatRow> {
        let kept = |p: &u32| keep.is_none_or(|k| k.contains(p));
        let sorted = |pids: &[u32]| -> Vec<u32> {
            let mut v: Vec<u32> = pids.iter().copied().filter(|p| kept(p) && self.nodes.contains_key(p)).collect();
            v.sort_by(|a, b| cmp(&self.nodes[a].info, &self.nodes[b].info));
            v
        };

        let mut out = Vec::with_capacity(self.nodes.len());
        let mut visited: HashSet<u32> = HashSet::with_capacity(self.nodes.len());
        let mut roots = sorted(&self.roots);
        let mut i = 0;
        loop {
            while i < roots.len() {
                let root = roots[i];
                i += 1;
                self.walk(root, &sorted, collapsed, &mut visited, &mut out);
            }
            // Nodes caught in a parent cycle are unreachable from any root.
            let orphan = self.nodes.keys().copied().filter(|p| kept(p) && !visited.contains(p)).min();
            match orphan {
                Some(p) => roots.push(p),
                None => break,
            }
        }
        out
    }

    fn walk(
        &self,
        root: u32,
        sorted: &dyn Fn(&[u32]) -> Vec<u32>,
        collapsed: &HashSet<u32>,
        visited: &mut HashSet<u32>,
        out: &mut Vec<FlatRow>,
    ) {
        // (pid, depth, is_last, guide columns of ancestors)
        let mut stack: Vec<(u32, usize, bool, String)> = vec![(root, 0, true, String::new())];
        while let Some((pid, depth, is_last, guides)) = stack.pop() {
            if !visited.insert(pid) {
                continue;
            }
            let Some(node) = self.nodes.get(&pid) else { continue };
            let children: Vec<u32> = sorted(&node.children).into_iter().filter(|c| !visited.contains(c)).collect();
            let prefix = if depth == 0 {
                String::new()
            } else {
                format!("{guides}{}", if is_last { "└─ " } else { "├─ " })
            };
            let is_collapsed = collapsed.contains(&pid) && !children.is_empty();
            let hidden = if is_collapsed {
                let d = self.descendants(pid);
                let n = d.len();
                // Mark the subtree visited so it isn't promoted as orphans.
                visited.extend(d);
                n
            } else {
                0
            };
            out.push(FlatRow { pid, prefix, has_children: !children.is_empty(), hidden });
            if is_collapsed {
                continue;
            }
            let child_guides = if depth == 0 {
                String::new()
            } else {
                format!("{guides}{}", if is_last { "   " } else { "│  " })
            };
            for (i, child) in children.iter().enumerate().rev() {
                stack.push((*child, depth + 1, i == children.len() - 1, child_guides.clone()));
            }
        }
    }
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit_idx = 0;
    while value >= 1024.0 && unit_idx < UNITS.len() - 1 {
        value /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{bytes} B")
    } else if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit_idx])
    } else {
        format!("{value:.1} {}", UNITS[unit_idx])
    }
}

pub fn human_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1.0 {
        "0".to_string()
    } else {
        format!("{}/s", human_bytes(bytes_per_sec as u64))
    }
}

/// "5 min", "3 h", "2 days" — coarse elapsed time for humans.
pub fn ago(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs} s"),
        60..=3599 => format!("{} min", secs / 60),
        3600..=86_399 => format!("{} h", secs / 3600),
        _ => format!("{} days", secs / 86_400),
    }
}

/// `3d 04:05:06` / `04:05:06`.
pub fn human_duration(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, (secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    if d > 0 {
        format!("{d}d {h:02}:{m:02}:{s:02}")
    } else {
        format!("{h:02}:{m:02}:{s:02}")
    }
}

/// CPU time like top's TIME+: `12:34.56`, or `5h12:03` past an hour.
pub fn cpu_time(secs: f64) -> String {
    let secs = if secs.is_finite() { secs.max(0.0) } else { 0.0 };
    let total = secs as u64;
    let (h, m, s) = (total / 3600, (total / 60) % 60, total % 60);
    if h > 0 {
        format!("{h}h{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}.{:02}", (secs.fract() * 100.0) as u64)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn info(pid: u32, ppid: Option<u32>) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: format!("p{pid}"),
            exe_path: None,
            cwd: None,
            cmd: vec![],
            cpu_usage_pct: pid as f32,
            memory_bytes: 0,
            virtual_memory_bytes: 0,
            status: ProcessStatus::Run,
            start_time_secs: 0,
            run_time_secs: 0,
            user: None,
            threads: None,
            nice: None,
            priority: None,
            cpu_time_secs: None,
            disk_read_rate: 0.0,
            disk_write_rate: 0.0,
            disk_read_total: 0,
            disk_write_total: 0,
            footprint: None,
            mem_growth: None,
            risk: 0,
            signed: '?',
        }
    }

    pub fn sample() -> ProcessTree {
        let mut nodes = HashMap::new();
        for (pid, ppid, children) in [
            (1, None, vec![2, 3]),
            (2, Some(1), vec![4]),
            (3, Some(1), vec![]),
            (4, Some(2), vec![]),
            (5, Some(6), vec![6]),
            (6, Some(5), vec![5]),
        ] {
            nodes.insert(pid, TreeNode { info: info(pid, ppid), children });
        }
        ProcessTree { nodes, roots: vec![1] }
    }

    #[test]
    fn flatten_handles_cycles_and_orders_depth_first() {
        let tree = sample();
        let by_pid = |a: &ProcessInfo, b: &ProcessInfo| a.pid.cmp(&b.pid);
        let rows = tree.flatten(&by_pid, &HashSet::new(), None);
        let order: Vec<u32> = rows.iter().map(|r| r.pid).collect();
        assert_eq!(order, vec![1, 2, 4, 3, 5, 6]);
        assert_eq!(rows[1].prefix, "├─ ");
        assert_eq!(rows[2].prefix, "│  └─ ");
        assert_eq!(rows[3].prefix, "└─ ");
    }

    #[test]
    fn flatten_sorts_siblings_and_collapses() {
        let tree = sample();
        let by_cpu_desc = |a: &ProcessInfo, b: &ProcessInfo| b.cpu_usage_pct.total_cmp(&a.cpu_usage_pct);
        let collapsed: HashSet<u32> = [2].into();
        let rows = tree.flatten(&by_cpu_desc, &collapsed, None);
        let order: Vec<u32> = rows.iter().map(|r| r.pid).collect();
        assert_eq!(&order[..3], &[1, 3, 2]);
        assert_eq!(rows[2].hidden, 1);
        assert!(!order.contains(&4));
    }

    #[test]
    fn formats() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(300 * 1024 * 1024), "300 MB");
        assert_eq!(human_duration(90_061), "1d 01:01:01");
        assert_eq!(cpu_time(75.5), "1:15.50");
        assert_eq!(cpu_time(3725.0), "1h02:05");
    }
}
