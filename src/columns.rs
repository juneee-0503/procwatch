//! Process-table columns: header text, width, alignment, sort order.

use std::cmp::Ordering;

use crate::process::ProcessInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Col {
    Name,
    Risk,
    Signed,
    Pid,
    Ppid,
    User,
    Status,
    Cpu,
    Trend,
    Memory,
    MemTrend,
    MemPct,
    Virtual,
    Threads,
    Disk,
    DiskRead,
    DiskWrite,
    Net,
    CpuTime,
    Started,
    Priority,
    Command,
}

impl Col {
    pub const ALL: [Col; 22] = [
        Col::Name,
        Col::Risk,
        Col::Signed,
        Col::Pid,
        Col::Ppid,
        Col::User,
        Col::Status,
        Col::Cpu,
        Col::Trend,
        Col::Memory,
        Col::MemTrend,
        Col::MemPct,
        Col::Virtual,
        Col::Threads,
        Col::Disk,
        Col::DiskRead,
        Col::DiskWrite,
        Col::Net,
        Col::CpuTime,
        Col::Started,
        Col::Priority,
        Col::Command,
    ];

    pub const DEFAULT: [Col; 10] =
        [Col::Name, Col::Risk, Col::Signed, Col::Pid, Col::User, Col::Cpu, Col::Memory, Col::Threads, Col::Disk, Col::CpuTime];

    pub fn header(self) -> &'static str {
        match self {
            Col::Name => "Name",
            Col::Risk => "Risk",
            Col::Signed => "Signed",
            Col::Pid => "PID",
            Col::Ppid => "Parent",
            Col::User => "User",
            Col::Status => "Status",
            Col::Cpu => "CPU",
            Col::Trend => "CPU history",
            Col::Memory => "Memory",
            Col::MemTrend => "Mem trend",
            Col::MemPct => "Mem %",
            Col::Virtual => "Virtual",
            Col::Threads => "Threads",
            Col::Disk => "Disk",
            Col::DiskRead => "Disk read",
            Col::DiskWrite => "Disk write",
            Col::Net => "Network",
            Col::CpuTime => "CPU time",
            Col::Started => "Started",
            Col::Priority => "Priority",
            Col::Command => "Command line",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Col::Name => "Process name (tree / app grouping)",
            Col::Risk => "Triage score 0–100 with reasons in the details pane",
            Col::Signed => "Code signature of the executable",
            Col::Pid => "Process ID",
            Col::Ppid => "Parent process ID",
            Col::User => "Account the process runs as",
            Col::Status => "Running, sleeping, stopped, zombie…",
            Col::Cpu => "CPU usage, 100% = one full core",
            Col::Trend => "Recent CPU usage as a mini graph",
            Col::Memory => "Memory in use (footprint on macOS, resident elsewhere)",
            Col::MemTrend => "How fast memory is growing (spots leaks)",
            Col::MemPct => "Memory as a share of installed RAM",
            Col::Virtual => "Virtual address space size",
            Col::Threads => "Number of threads",
            Col::Disk => "Disk read + write rate",
            Col::DiskRead => "Disk read rate",
            Col::DiskWrite => "Disk write rate",
            Col::Net => "Network bytes per second, in plus out",
            Col::CpuTime => "Total CPU time used since start",
            Col::Started => "When the process started",
            Col::Priority => "Scheduling priority (from nice value)",
            Col::Command => "Full command line",
        }
    }

    /// Fixed width in cells; 0 = takes the remaining space.
    pub fn width(self) -> u16 {
        match self {
            Col::Name | Col::Command => 0,
            Col::Risk => 5,
            Col::Signed => 7,
            Col::Pid | Col::Ppid => 7,
            Col::User => 10,
            Col::Status => 8,
            Col::Cpu => 6,
            Col::Trend => 12,
            Col::Memory | Col::Virtual => 9,
            Col::MemTrend => 12,
            Col::MemPct => 6,
            Col::Threads => 7,
            Col::Disk | Col::DiskRead | Col::DiskWrite | Col::Net => 10,
            Col::CpuTime => 9,
            Col::Started => 8,
            Col::Priority => 9,
        }
    }

    pub fn right_aligned(self) -> bool {
        !matches!(self, Col::Name | Col::User | Col::Status | Col::Command | Col::Started | Col::Priority | Col::Trend | Col::Signed)
    }

    /// Whether sorting by this column makes sense.
    pub fn sortable(self) -> bool {
        !matches!(self, Col::Trend | Col::Command)
    }

    /// Stable identifier used in the config file.
    pub fn key(self) -> &'static str {
        match self {
            Col::Name => "name",
            Col::Risk => "risk",
            Col::Signed => "signed",
            Col::Pid => "pid",
            Col::Ppid => "ppid",
            Col::User => "user",
            Col::Status => "status",
            Col::Cpu => "cpu",
            Col::Trend => "trend",
            Col::Memory => "memory",
            Col::MemTrend => "mem_trend",
            Col::MemPct => "mem_pct",
            Col::Virtual => "virtual",
            Col::Threads => "threads",
            Col::Disk => "disk",
            Col::DiskRead => "disk_read",
            Col::DiskWrite => "disk_write",
            Col::Net => "net",
            Col::CpuTime => "cpu_time",
            Col::Started => "started",
            Col::Priority => "priority",
            Col::Command => "command",
        }
    }

    pub fn from_key(key: &str) -> Option<Col> {
        Col::ALL.into_iter().find(|c| c.key() == key.trim())
    }

    /// Big numbers first for resource columns, alphabetical otherwise.
    pub fn default_desc(self) -> bool {
        matches!(
            self,
            Col::Cpu
                | Col::Risk
                | Col::Memory
                | Col::MemTrend
                | Col::MemPct
                | Col::Virtual
                | Col::Threads
                | Col::Disk
                | Col::DiskRead
                | Col::DiskWrite
                | Col::Net
                | Col::CpuTime
                | Col::Started
                | Col::Priority
        )
    }

    pub fn compare(self, a: &ProcessInfo, b: &ProcessInfo) -> Ordering {
        fn opt<T: PartialOrd>(a: Option<T>, b: Option<T>) -> Ordering {
            match (a, b) {
                (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(Ordering::Equal),
                (Some(_), None) => Ordering::Greater,
                (None, Some(_)) => Ordering::Less,
                (None, None) => Ordering::Equal,
            }
        }
        let ord = match self {
            Col::Name | Col::Command | Col::Trend => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            Col::Pid => a.pid.cmp(&b.pid),
            Col::Risk => a.risk.cmp(&b.risk),
            Col::Signed => a.signed.cmp(&b.signed),
            Col::Ppid => a.ppid.cmp(&b.ppid),
            Col::User => a.user.cmp(&b.user),
            Col::Status => a.status_label().cmp(b.status_label()),
            Col::Cpu => a.cpu_usage_pct.total_cmp(&b.cpu_usage_pct),
            Col::Memory | Col::MemPct => a.mem().cmp(&b.mem()),
            Col::MemTrend => opt(a.mem_growth, b.mem_growth),
            Col::Virtual => a.virtual_memory_bytes.cmp(&b.virtual_memory_bytes),
            Col::Threads => opt(a.threads, b.threads),
            Col::Disk => (a.disk_read_rate + a.disk_write_rate).total_cmp(&(b.disk_read_rate + b.disk_write_rate)),
            Col::DiskRead => a.disk_read_rate.total_cmp(&b.disk_read_rate),
            Col::DiskWrite => a.disk_write_rate.total_cmp(&b.disk_write_rate),
            Col::Net => a.net_rate.total_cmp(&b.net_rate),
            Col::CpuTime => opt(a.cpu_time_secs, b.cpu_time_secs),
            Col::Started => a.start_time_secs.cmp(&b.start_time_secs),
            // Higher priority = lower nice.
            Col::Priority => opt(b.nice, a.nice),
        };
        ord.then_with(|| a.pid.cmp(&b.pid))
    }
}
