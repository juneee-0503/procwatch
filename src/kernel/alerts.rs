//! Alerting on normalised metrics, in the kernel because it needs nothing
//! but the data model. A rule reads the same on every platform:
//!
//! ```text
//! cpu.run_queue > 8 for 30s
//! disk.queue_depth{device=sda} >= 32
//! memory.available < 500000000
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::model::Sample;

/// Bus topic carrying `Alert`.
pub const ALERTS: &str = "kernel.alert";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Gt,
    Ge,
    Lt,
    Le,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub text: String,
    metric: String,
    label: Option<(String, String)>,
    op: Op,
    limit: f64,
    hold: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub rule: String,
    pub metric: String,
    pub value: f64,
    pub labels: String,
    /// False when the condition cleared.
    pub firing: bool,
}

impl Rule {
    pub fn parse(text: &str) -> Result<Rule, String> {
        let text = text.trim();
        let (cond, hold) = match text.rsplit_once(" for ") {
            Some((c, h)) => {
                let secs = h.trim().strip_suffix('s').and_then(|v| v.parse::<u64>().ok()).ok_or_else(|| format!("bad duration '{h}': use e.g. 30s"))?;
                (c, Duration::from_secs(secs))
            }
            None => (text, Duration::ZERO),
        };
        let mut f = cond.split_whitespace();
        let (Some(target), Some(op), Some(limit), None) = (f.next(), f.next(), f.next(), f.next()) else {
            return Err(format!("expected 'metric > value [for Ns]': {text}"));
        };
        let op = match op {
            ">" => Op::Gt,
            ">=" => Op::Ge,
            "<" => Op::Lt,
            "<=" => Op::Le,
            o => return Err(format!("unknown comparison '{o}'")),
        };
        let limit: f64 = limit.parse().map_err(|_| format!("'{limit}' isn't a number"))?;
        if !limit.is_finite() {
            return Err("the limit must be a number".into());
        }
        let (metric, label) = match target.split_once('{') {
            Some((m, rest)) => {
                let pair = rest.strip_suffix('}').and_then(|p| p.split_once('=')).ok_or_else(|| format!("bad label in '{target}'"))?;
                (m, Some((pair.0.to_string(), pair.1.to_string())))
            }
            None => (target, None),
        };
        Ok(Rule { text: text.to_string(), metric: metric.to_string(), label, op, limit, hold })
    }

    fn applies(&self, s: &Sample) -> bool {
        s.metric == self.metric && self.label.as_ref().is_none_or(|(k, v)| s.labels.iter().any(|(a, b)| a == k && b == v))
    }

    fn holds(&self, v: f64) -> bool {
        match self.op {
            Op::Gt => v > self.limit,
            Op::Ge => v >= self.limit,
            Op::Lt => v < self.limit,
            Op::Le => v <= self.limit,
        }
    }
}

/// Fires once when a condition has held long enough, and once when it clears.
#[derive(Default)]
pub struct Engine {
    rules: Vec<Rule>,
    /// Per rule and label set: when it began, and whether it has fired.
    active: HashMap<(usize, String), (Instant, bool)>,
}

impl Engine {
    pub fn new(rules: Vec<Rule>) -> Engine {
        Engine { rules, active: HashMap::new() }
    }

    pub fn feed(&mut self, samples: &[Sample], now: Instant) -> Vec<Alert> {
        let mut out = Vec::new();
        for s in samples {
            let labels = s.labels.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(",");
            for (i, r) in self.rules.iter().enumerate().filter(|(_, r)| r.applies(s)) {
                let key = (i, labels.clone());
                let alert = |firing| Alert { rule: r.text.clone(), metric: s.metric.to_string(), value: s.value, labels: labels.clone(), firing };
                if r.holds(s.value) {
                    let e = self.active.entry(key).or_insert((now, false));
                    if !e.1 && now.duration_since(e.0) >= r.hold {
                        e.1 = true;
                        out.push(alert(true));
                    }
                } else if self.active.remove(&key).is_some_and(|(_, fired)| fired) {
                    out.push(alert(false));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::model::Unit;

    #[test]
    fn rules_parse_or_explain() {
        assert!(Rule::parse("cpu.run_queue > 8 for 30s").is_ok());
        assert!(Rule::parse("disk.queue_depth{device=sda} >= 32").is_ok());
        for bad in ["cpu.x", "cpu.x ~ 1", "cpu.x > y", "cpu.x > 1 for soon", "a{b > 1", "cpu.x > NaN"] {
            assert!(Rule::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn fires_after_holding_and_once_per_episode() {
        let mut e = Engine::new(vec![Rule::parse("cpu.run_queue > 8 for 10s").unwrap()]);
        let t = Instant::now();
        let s = |v| [Sample::new("cpu.run_queue", v, Unit::Count)];
        assert!(e.feed(&s(9.0), t).is_empty(), "not long enough yet");
        assert!(e.feed(&s(9.0), t + Duration::from_secs(5)).is_empty());
        assert_eq!(e.feed(&s(9.0), t + Duration::from_secs(10)).len(), 1);
        assert!(e.feed(&s(9.0), t + Duration::from_secs(11)).is_empty(), "fires once");
        let cleared = e.feed(&s(1.0), t + Duration::from_secs(12));
        assert!(!cleared[0].firing);
        assert!(e.feed(&s(9.0), t + Duration::from_secs(13)).is_empty(), "the hold starts over");
    }

    #[test]
    fn a_blip_that_never_fired_clears_silently() {
        let mut e = Engine::new(vec![Rule::parse("x > 1 for 10s").unwrap()]);
        let t = Instant::now();
        e.feed(&[Sample::new("x", 2.0, Unit::Count)], t);
        assert!(e.feed(&[Sample::new("x", 0.0, Unit::Count)], t).is_empty());
    }

    #[test]
    fn labels_separate_and_select() {
        let mut e = Engine::new(vec![Rule::parse("q{device=sda} > 1").unwrap(), Rule::parse("q > 100").unwrap()]);
        let t = Instant::now();
        let a = Sample::new("q", 5.0, Unit::Count).label("device", "sda");
        let b = Sample::new("q", 5.0, Unit::Count).label("device", "sdb");
        assert_eq!(e.feed(&[a, b.clone()], t).len(), 1);
        let hi = Sample::new("q", 500.0, Unit::Count).label("device", "sdb");
        assert_eq!(e.feed(&[hi], t)[0].labels, "device=sdb");
    }
}
