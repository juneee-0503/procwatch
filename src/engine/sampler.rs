//! Background workers. Everything that can block — process enumeration,
//! socket tables, GPU counters, deep inspection, process actions — runs off
//! the UI thread and reports back over a single channel, so the interface
//! never freezes while a slow system tool (vmmap, PowerShell, lsof) runs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use super::messages::{Snapshot, WorkerMsg};
use crate::common::panic_text;
use crate::network::{self, Connection};
use crate::performance::gpu;
use crate::process::ProcessMonitor;

pub const MIN_INTERVAL_MS: u64 = 250;
pub const MAX_INTERVAL_MS: u64 = 10_000;
const GPU_INTERVAL: Duration = Duration::from_secs(3);

/// Knobs the UI can turn on the running sampler without a round trip.
pub struct SamplerCtl {
    pub interval_ms: AtomicU64,
    pub paused: AtomicBool,
    pub refresh_now: AtomicBool,
    /// Snapshots sent but not handled yet.
    pub snapshots_queued: AtomicU64,
}

impl SamplerCtl {
    /// The UI handled a snapshot.
    pub fn snapshot_handled(&self) {
        let mut n = self.snapshots_queued.load(Ordering::Relaxed);
        while n > 0 {
            match self.snapshots_queued.compare_exchange_weak(n, n - 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(now) => n = now,
            }
        }
    }

    pub fn interval(&self) -> Duration {
        Duration::from_millis(self.interval_ms.load(Ordering::Relaxed))
    }
}

const MAX_QUEUED_SNAPSHOTS: u64 = 2;

/// What a bounded drain left behind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Drained {
    /// Stopped at the budget with messages still queued.
    pub more: bool,
    pub disconnected: bool,
}

/// Handle queued messages for at most `budget`. An unbounded drain never
/// returns once messages arrive faster than they are handled, which freezes
/// the caller's input, drawing and deadline checks.
pub fn drain_for<T>(rx: &mpsc::Receiver<T>, budget: Duration, mut handle: impl FnMut(T)) -> Drained {
    let start = Instant::now();
    loop {
        match rx.try_recv() {
            Ok(msg) => handle(msg),
            Err(mpsc::TryRecvError::Empty) => return Drained::default(),
            Err(mpsc::TryRecvError::Disconnected) => return Drained { more: false, disconnected: true },
        }
        if start.elapsed() >= budget {
            return Drained { more: true, disconnected: false };
        }
    }
}

pub fn spawn_sampler(tx: Sender<WorkerMsg>, ctl: Arc<SamplerCtl>) -> std::io::Result<()> {
    let gpu_tx = tx.clone();
    thread::Builder::new()
        .name("sampler".into())
        .spawn(move || {
            let mut monitor = ProcessMonitor::new();
            // CPU usage is a delta between two samples; take the first real
            // one shortly after startup instead of a full interval later.
            thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL.max(Duration::from_millis(250)));
            let mut last_connections: HashMap<u32, Vec<Connection>> = HashMap::new();
            let mut socket_failures = 0u32;
            loop {
                let started = Instant::now();
                // A slow UI gets the newest state, not a growing pile of
                // large snapshots.
                if ctl.snapshots_queued.load(Ordering::Relaxed) >= MAX_QUEUED_SNAPSHOTS {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                // A failure in one sample (e.g. an OS API returning
                // something unexpected) must not stop monitoring.
                let sample = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut lap = crate::common::perf::Lap::new();
                    let (tree, stats) = monitor.snapshot();
                    lap.mark("sampler: processes");
                    let connections = match network::try_connections() {
                        Some(c) => {
                            socket_failures = 0;
                            last_connections.clone_from(&c);
                            c
                        }
                        None => {
                            socket_failures += 1;
                            if socket_failures == 1 {
                                let _ = tx.send(WorkerMsg::Error("couldn't read the socket table; showing the last known connections".into()));
                            }
                            last_connections.clone()
                        }
                    };
                    lap.mark("sampler: connections");
                    Snapshot { tree, stats, connections }
                }));
                let msg = match sample {
                    Ok(snap) => {
                        ctl.snapshots_queued.fetch_add(1, Ordering::Relaxed);
                        WorkerMsg::Snapshot(Box::new(snap))
                    }
                    Err(e) => WorkerMsg::Error(format!("sampling failed: {}", panic_text(&*e))),
                };
                if tx.send(msg).is_err() {
                    return; // UI is gone
                }

                // Sleep in small steps so pause/interval/refresh changes
                // take effect immediately.
                loop {
                    thread::sleep(Duration::from_millis(50));
                    if ctl.refresh_now.swap(false, Ordering::Relaxed) {
                        break;
                    }
                    if !ctl.paused.load(Ordering::Relaxed) && started.elapsed() >= ctl.interval() {
                        break;
                    }
                }
            }
        })?;

    // GPU counters are slow to query on Windows (a PowerShell spawn), so
    // they get their own, slower loop instead of stalling process updates.
    let _ = thread::Builder::new().name("gpu".into()).spawn(move || loop {
        let snap = gpu::system_gpu_usage();
        let available = snap.available;
        if gpu_tx.send(WorkerMsg::Gpu(snap)).is_err() || !available {
            return; // nothing will change on platforms without counters
        }
        thread::sleep(GPU_INTERVAL);
    });
    Ok(())
}

#[cfg(test)]
mod drain_tests {
    use super::*;

    #[test]
    fn drain_returns_while_a_producer_outruns_the_handler() {
        let (tx, rx) = mpsc::channel();
        // Queued up front, so the drain can't see an empty queue first.
        for _ in 0..1000 {
            tx.send(1u8).unwrap();
        }
        let feeding = std::sync::Arc::new(AtomicBool::new(true));
        let f = feeding.clone();
        let feeder = std::thread::spawn(move || {
            while f.load(Ordering::Relaxed) {
                let _ = tx.send(1u8);
            }
        });
        let start = Instant::now();
        let d = drain_for(&rx, Duration::from_millis(20), |_| std::thread::sleep(Duration::from_millis(1)));
        let took = start.elapsed();
        feeding.store(false, Ordering::Relaxed);
        let _ = feeder.join();
        assert!(d.more, "the queue never emptied, so the budget must have ended it");
        assert!(took < Duration::from_secs(2), "took {took:?}");
    }

    #[test]
    fn the_snapshot_count_stops_at_zero() {
        let ctl = SamplerCtl { interval_ms: AtomicU64::new(1000), paused: AtomicBool::new(false), refresh_now: AtomicBool::new(false), snapshots_queued: AtomicU64::new(1) };
        ctl.snapshot_handled();
        ctl.snapshot_handled();
        assert_eq!(ctl.snapshots_queued.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn drain_reports_empty_and_disconnected() {
        let (tx, rx) = mpsc::channel();
        tx.send(1).unwrap();
        let mut n = 0;
        assert_eq!(drain_for(&rx, Duration::from_secs(1), |v: i32| n += v), Drained::default());
        assert_eq!(n, 1);
        drop(tx);
        assert!(drain_for(&rx, Duration::from_secs(1), |_: i32| ()).disconnected);
    }
}
