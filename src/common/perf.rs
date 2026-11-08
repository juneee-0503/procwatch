//! Named timings for finding slow work: off (one relaxed atomic load per
//! mark) unless `--soak` turns them on.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static ON: AtomicBool = AtomicBool::new(false);
/// Count, total and longest time per name.
static TIMES: Mutex<BTreeMap<&'static str, (u64, Duration, Duration)>> = Mutex::new(BTreeMap::new());

pub fn enable() {
    ON.store(true, Ordering::Relaxed);
}

pub fn record(name: &'static str, took: Duration) {
    if !ON.load(Ordering::Relaxed) {
        return;
    }
    if let Ok(mut t) = TIMES.lock() {
        let e = t.entry(name).or_default();
        e.0 += 1;
        e.1 += took;
        e.2 = e.2.max(took);
    }
}

/// Times consecutive sections of a function.
pub struct Lap(Option<Instant>);

impl Lap {
    pub fn new() -> Self {
        Lap(ON.load(Ordering::Relaxed).then(Instant::now))
    }
    /// Record the time since the last mark under `name`.
    pub fn mark(&mut self, name: &'static str) {
        if let Some(t) = self.0.as_mut() {
            record(name, t.elapsed());
            *t = Instant::now();
        }
    }
}

/// Total recorded under names starting with `prefix`.
pub fn total(prefix: &str) -> Duration {
    TIMES.lock().map(|t| t.iter().filter(|(k, _)| k.starts_with(prefix)).map(|(_, v)| v.1).sum()).unwrap_or_default()
}

/// The `limit` names with the longest single run, slowest first.
pub fn report(limit: usize) -> Vec<String> {
    let Ok(t) = TIMES.lock() else { return Vec::new() };
    let mut rows: Vec<_> = t.iter().collect();
    rows.sort_by_key(|(_, v)| std::cmp::Reverse(v.2));
    rows.iter()
        .take(limit)
        .map(|(name, (n, total, max))| format!("  {name:<30} {n:>6} ×  {:>8.2} s total  {:>9.1} ms longest", total.as_secs_f64(), max.as_secs_f64() * 1000.0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn laps_are_recorded_once_enabled() {
        enable();
        let mut l = Lap::new();
        l.mark("perf-test: section");
        assert!(report(1000).iter().any(|r| r.contains("perf-test: section")));
    }
}
