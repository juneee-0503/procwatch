//! Learning what normal looks like for each hour of the week, so "busy"
//! means busier than this machine usually is at this time, without anyone
//! setting a threshold. Monday 03:00 and Monday 15:00 are different baselines.

use std::collections::BTreeMap;

use chrono::{DateTime, Datelike, Local, Timelike};
use serde::{Deserialize, Serialize};

use super::{Stage, Threat};
use crate::common::model::Severity;

/// Readings an hour needs before it's trusted.
const MIN_SAMPLES: u64 = 120;
/// Standard deviations away that counts as abnormal.
const DEVIATIONS: f64 = 6.0;
/// Deviation counted as at least this share of the mean, so a metric that
/// never moves doesn't alarm on the first small step.
const MIN_SPREAD: f64 = 0.25;
/// Consecutive abnormal readings before speaking.
const SUSTAINED: u32 = 12;

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
struct Hour {
    n: u64,
    mean: f64,
    m2: f64,
}

impl Hour {
    fn add(&mut self, v: f64) {
        self.n += 1;
        let d = v - self.mean;
        self.mean += d / self.n as f64;
        self.m2 += d * (v - self.mean);
    }

    fn spread(&self) -> f64 {
        (self.m2 / (self.n.max(2) - 1) as f64).sqrt().max(self.mean.abs() * MIN_SPREAD)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Baseline {
    metrics: BTreeMap<String, Vec<Hour>>,
    #[serde(skip)]
    streak: BTreeMap<String, u32>,
}

fn hour_of_week(t: DateTime<Local>) -> usize {
    t.weekday().num_days_from_monday() as usize * 24 + t.hour() as usize
}

impl Baseline {
    /// How many hours of the week can be judged, of 168.
    pub fn coverage(&self) -> usize {
        self.metrics.values().map(|h| h.iter().filter(|x| x.n >= MIN_SAMPLES).count()).max().unwrap_or(0)
    }

    /// A reading. Abnormal ones are kept out of what is learned, or a long
    /// attack would slowly become normal.
    pub fn feed(&mut self, metric: &str, value: f64, now: DateTime<Local>) -> Option<Threat> {
        if !value.is_finite() || value < 0.0 {
            return None;
        }
        let hours = self.metrics.entry(metric.to_string()).or_insert_with(|| vec![Hour::default(); 168]);
        let h = hours.get_mut(hour_of_week(now))?;
        let high = h.n >= MIN_SAMPLES && value > h.mean + DEVIATIONS * h.spread();
        if !high {
            h.add(value);
            self.streak.remove(metric);
            return None;
        }
        let (mean, n) = (h.mean, self.streak.entry(metric.to_string()).or_default());
        *n += 1;
        (*n == SUSTAINED).then(|| {
            Threat::new(now, "unusual-load", Severity::Medium, Stage::Impact, format!("{metric} is {value:.0}, usually about {mean:.0} at this hour")).with_evidence(format!("sustained for {SUSTAINED} readings"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn monday(hour: u32) -> DateTime<Local> {
        Local.with_ymd_and_hms(2026, 11, 2, hour, 0, 0).unwrap()
    }

    fn trained(b: &mut Baseline, at: DateTime<Local>, around: f64) {
        for i in 0..200 {
            assert!(b.feed("net.rx", around + f64::from(i % 10), at).is_none());
        }
    }

    #[test]
    fn says_nothing_until_it_has_learned() {
        let mut b = Baseline::default();
        for _ in 0..100 {
            assert!(b.feed("net.rx", 1e12, monday(3)).is_none());
        }
        assert_eq!(b.coverage(), 0);
    }

    #[test]
    fn a_sustained_jump_is_reported_once() {
        let mut b = Baseline::default();
        trained(&mut b, monday(3), 1000.0);
        assert_eq!(b.coverage(), 1);
        let hits: Vec<_> = (0..40).filter_map(|_| b.feed("net.rx", 50_000.0, monday(3))).collect();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].title.contains("usually about 100"), "{}", hits[0].title);
    }

    #[test]
    fn a_blip_is_not_an_attack_and_busy_hours_are_their_own_normal() {
        let mut b = Baseline::default();
        trained(&mut b, monday(3), 1000.0);
        trained(&mut b, monday(15), 50_000.0);
        for _ in 0..3 {
            assert!(b.feed("net.rx", 50_000.0, monday(3)).is_none());
        }
        assert!(b.feed("net.rx", 1000.0, monday(3)).is_none());
        assert!((0..40).all(|_| b.feed("net.rx", 50_000.0, monday(15)).is_none()));
    }

    #[test]
    fn an_attack_does_not_teach_itself_as_normal() {
        let mut b = Baseline::default();
        trained(&mut b, monday(3), 1000.0);
        for _ in 0..10_000 {
            b.feed("net.rx", 50_000.0, monday(3));
        }
        let mean = b.metrics["net.rx"][hour_of_week(monday(3))].mean;
        assert!(mean < 2000.0, "{mean}");
    }

    #[test]
    fn survives_saving() {
        let mut b = Baseline::default();
        trained(&mut b, monday(3), 1000.0);
        let back: Baseline = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        assert_eq!(back.coverage(), 1);
    }
}
