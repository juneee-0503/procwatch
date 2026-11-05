//! Shared pacing: how fast the UI wants data, and how it takes data without
//! starving itself.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const MIN_INTERVAL_MS: u64 = 250;
pub const MAX_INTERVAL_MS: u64 = 10_000;
/// Knobs the UI can turn on the running sampler without a round trip.
#[derive(Default)]
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

pub const MAX_QUEUED_SNAPSHOTS: u64 = 2;

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
