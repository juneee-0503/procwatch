//! The unified data model. Whatever a platform calls something and whatever
//! unit it reports, by the time a value is on the bus it has one name, one
//! unit and one kind of timestamp, so alerting doesn't care about platforms.
//! `dictionary` lists every metric and how its meaning varies.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Instant, SystemTime};

use serde::Serialize;

/// Bus topic carrying `Vec<Sample>`.
pub const SAMPLES: &str = "kernel.samples";

/// Most series one metric may have. Labels can come from anything, and a
/// label per short-lived process would otherwise grow without end.
pub const MAX_SERIES_PER_METRIC: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Bytes,
    BytesPerSecond,
    PerSecond,
    Percent,
    Count,
    Milliseconds,
    Celsius,
    Watts,
}

/// Which machine and which run a value came from. Everything carries it,
/// so a central station can be added without changing any data structure.
#[derive(Debug, Clone, Serialize)]
pub struct Identity {
    pub host: Arc<str>,
    /// New on every start, which tells a restart from a replay.
    pub instance: Arc<str>,
}

static HOST: OnceLock<String> = OnceLock::new();

/// Name this machine. The kernel has no way to ask, and none should be
/// added: it is told, once, at start.
pub fn set_host(name: String) {
    let _ = HOST.set(name);
}

pub fn identity() -> &'static Identity {
    static ID: OnceLock<Identity> = OnceLock::new();
    ID.get_or_init(|| {
        let host = HOST.get().cloned().unwrap_or_else(|| "unknown".to_string());
        let nanos = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        Identity { host: host.into(), instance: format!("{:x}-{:x}", std::process::id(), nanos).into() }
    })
}

/// One measurement. Names are dotted and platform-neutral: `cpu.run_queue`,
/// `disk.queue_depth`. What a thing belongs to goes in labels: `device=sda`.
#[derive(Debug, Clone, Serialize)]
pub struct Sample {
    pub metric: &'static str,
    pub value: f64,
    pub unit: Unit,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<(&'static str, String)>,
    #[serde(serialize_with = "ser_time")]
    pub at: SystemTime,
    pub host: Arc<str>,
}

fn ser_time<S: serde::Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_f64(t.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0))
}

impl Sample {
    pub fn new(metric: &'static str, value: f64, unit: Unit) -> Sample {
        Sample { metric, value, unit, labels: Vec::new(), at: SystemTime::now(), host: identity().host.clone() }
    }

    pub fn label(mut self, key: &'static str, value: impl Into<String>) -> Sample {
        self.labels.push((key, value.into()));
        self
    }
}

/// Turns a running total into a rate. A total that falls means the counter
/// was reset or wrapped: that reading has no rate, or it would look like one
/// enormous spike and raise a false alarm.
#[derive(Default)]
pub struct CounterRate {
    last: HashMap<String, (f64, Instant)>,
}

impl CounterRate {
    pub fn update(&mut self, key: &str, total: f64, now: Instant) -> Option<f64> {
        if self.last.len() >= MAX_SERIES_PER_METRIC && !self.last.contains_key(key) {
            self.last.clear();
        }
        let before = self.last.insert(key.to_string(), (total, now))?;
        let secs = now.checked_duration_since(before.1)?.as_secs_f64();
        (secs > 0.0 && total >= before.0).then(|| (total - before.0) / secs)
    }
}

/// Keeps a metric's series within the limit, retiring the least recently
/// seen, and counts what it turned away.
#[derive(Default)]
pub struct SeriesLimit {
    seen: HashMap<&'static str, HashMap<String, Instant>>,
    pub evicted: u64,
}

impl SeriesLimit {
    /// Note a series; returns the one retired to make room, if any.
    pub fn admit(&mut self, metric: &'static str, series: &str, now: Instant) -> Option<String> {
        let set = self.seen.entry(metric).or_default();
        let mut gone = None;
        if set.len() >= MAX_SERIES_PER_METRIC && !set.contains_key(series) {
            gone = set.iter().min_by_key(|(_, t)| **t).map(|(k, _)| k.clone());
            if let Some(k) = &gone {
                set.remove(k);
                self.evicted += 1;
            }
        }
        set.insert(series.to_string(), now);
        gone
    }

    #[cfg(test)]
    pub fn series(&self, metric: &str) -> usize {
        self.seen.get(metric).map_or(0, HashMap::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_counter_reset_is_not_a_spike() {
        let (mut r, t) = (CounterRate::default(), Instant::now());
        assert_eq!(r.update("a", 1000.0, t), None, "the first reading has no rate");
        assert_eq!(r.update("a", 3000.0, t + Duration::from_secs(2)), Some(1000.0));
        assert_eq!(r.update("a", 10.0, t + Duration::from_secs(4)), None, "reset");
        assert_eq!(r.update("a", 110.0, t + Duration::from_secs(5)), Some(100.0));
    }

    #[test]
    fn series_stay_within_the_limit() {
        let (mut s, t) = (SeriesLimit::default(), Instant::now());
        for i in 0..MAX_SERIES_PER_METRIC + 50 {
            s.admit("proc.cpu", &format!("pid={i}"), t + Duration::from_millis(i as u64));
        }
        assert_eq!(s.series("proc.cpu"), MAX_SERIES_PER_METRIC);
        assert_eq!(s.evicted, 50);
    }

    #[test]
    fn identity_is_stable_within_a_run() {
        assert!(Arc::ptr_eq(&identity().instance, &identity().instance));
        assert_eq!(Sample::new("x", 1.0, Unit::Count).host, identity().host);
    }
}
