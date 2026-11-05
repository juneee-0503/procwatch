//! The process module: the process table, on the UI's schedule.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{ProcessMonitor, ProcessTree, SystemStats};
use crate::common::pacing::{SamplerCtl, MAX_QUEUED_SNAPSHOTS};
use crate::kernel::{Capability, Context, Exclusive, Module};

pub const SNAPSHOT: &str = "process.snapshot";
pub type Table = Exclusive<(ProcessTree, SystemStats)>;

pub struct ProcessModule {
    ctl: Arc<SamplerCtl>,
    monitor: Option<ProcessMonitor>,
    last: Option<Instant>,
}

impl ProcessModule {
    pub fn new(ctl: Arc<SamplerCtl>) -> Self {
        ProcessModule { ctl, monitor: None, last: None }
    }
}

impl Module for ProcessModule {
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::yes("process table"), Capability::yes("cpu, memory, disk per process"), Capability::yes("system totals")]
    }

    fn start(&mut self, _ctx: &Context) -> Result<(), String> {
        self.monitor = Some(ProcessMonitor::new());
        // CPU usage is a delta: take the first real sample soon, not a full
        // interval later.
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL.max(Duration::from_millis(250)));
        Ok(())
    }

    /// Short, so pause and interval changes take effect at once.
    fn interval(&self) -> Option<Duration> {
        Some(Duration::from_millis(50))
    }

    fn watchdog(&self) -> Duration {
        Duration::from_secs(60)
    }

    fn tick(&mut self, ctx: &Context) {
        let refresh = self.ctl.refresh_now.swap(false, Ordering::Relaxed);
        let due = self.last.is_none_or(|t| !self.ctl.paused.load(Ordering::Relaxed) && t.elapsed() >= self.ctl.interval());
        // A slow UI gets the newest state, not a growing pile of snapshots.
        if !(refresh || due) || self.ctl.snapshots_queued.load(Ordering::Relaxed) >= MAX_QUEUED_SNAPSHOTS {
            return;
        }
        let Some(monitor) = self.monitor.as_mut() else { return };
        self.last = Some(Instant::now());
        let mut lap = crate::common::perf::Lap::new();
        let table = monitor.snapshot();
        lap.mark("sampler: processes");
        self.ctl.snapshots_queued.fetch_add(1, Ordering::Relaxed);
        ctx.publish(SNAPSHOT, Table::new(table));
    }
}
