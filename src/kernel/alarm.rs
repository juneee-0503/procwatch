//! The alarm engine: data → judgement → state. Alarms have a lifecycle, and
//! an event exists only when the state changes:
//!
//! ```text
//! normal → observing → firing → acknowledged → recovered → normal
//! ```
//!
//! `observing` filters spikes: a condition must last before it counts.
//! Recovery uses a looser threshold than firing (hysteresis), so a value
//! hovering at the limit can't flap. All durations use the monotonic clock,
//! so changing the system time can't fire or clear anything.
//!
//! Better late than false. Everything here serves that.
//!
//! ```text
//! cpu.usage > 90 clear 80 for 30s clearfor 60s priority high
//! disk.queue_depth{device=sda} >= 32 priority medium
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use super::model::{identity, Sample};

/// How long a condition must hold, unless a rule says otherwise.
pub const DEFAULT_HOLD: Duration = Duration::from_secs(15);
pub const DEFAULT_CLEAR_HOLD: Duration = Duration::from_secs(30);
/// Recovery threshold when a rule names none, as a share of the limit.
const DEFAULT_HYSTERESIS: f64 = 0.1;
/// A metric alarm whose metric stopped arriving can never recover on its
/// own: after this long it ends, because nothing supports it any more.
const STALE: Duration = Duration::from_secs(120);
/// An acknowledged alarm from an event has no metric to clear it. It ends
/// after this, so the same thing happening again alarms again.
const ACK_HOLD: Duration = Duration::from_secs(600);
/// Most alarm instances tracked. Labels can be many; alarms must stay few.
const MAX_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    Low,
    Medium,
    High,
}

impl Priority {
    pub fn label(self) -> &'static str {
        match self {
            Priority::Low => "low",
            Priority::Medium => "medium",
            Priority::High => "high",
        }
    }

    pub fn parse(s: &str) -> Option<Priority> {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Some(Priority::Low),
            "medium" | "med" => Some(Priority::Medium),
            "high" => Some(Priority::High),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Firing,
    Acknowledged,
    Recovered,
}

/// A change in an alarm's state. Never dropped: see `Hub`.
#[derive(Debug, Clone, Serialize)]
pub struct AlarmEvent {
    /// One alarm, across its whole life.
    pub key: String,
    pub host: Arc<str>,
    pub instance: Arc<str>,
    pub rule: String,
    pub title: String,
    pub priority: Priority,
    pub phase: Phase,
    /// Where it came from, such as a metric name: suppression matches on it.
    pub source: String,
    pub detail: String,
    pub value: Option<f64>,
    #[serde(with = "wall")]
    pub at: SystemTime,
}

mod wall {
    use std::time::SystemTime;

    pub fn serialize<S: serde::Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_f64(t.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0))
    }
}

impl AlarmEvent {
    pub fn new(key: impl Into<String>, rule: impl Into<String>, title: impl Into<String>, priority: Priority, source: impl Into<String>) -> AlarmEvent {
        let id = identity();
        // Titles can quote what an attacker typed, and they reach a terminal.
        let title: String = title.into().chars().map(|c| if c.is_control() { '\u{fffd}' } else { c }).collect();
        AlarmEvent { key: key.into(), host: id.host.clone(), instance: id.instance.clone(), rule: rule.into(), title, priority, phase: Phase::Firing, source: source.into(), detail: String::new(), value: None, at: SystemTime::now() }
    }

    pub fn detail(mut self, text: impl Into<String>) -> AlarmEvent {
        self.detail = text.into();
        self
    }
}

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
    pub metric: String,
    label: Option<(String, String)>,
    op: Op,
    pub limit: f64,
    pub clear: f64,
    pub hold: Duration,
    pub clear_hold: Duration,
    pub priority: Priority,
}

fn seconds(text: &str) -> Result<Duration, String> {
    text.strip_suffix('s').and_then(|v| v.parse::<u64>().ok()).map(Duration::from_secs).ok_or_else(|| format!("'{text}' isn't a time such as 30s"))
}

impl Rule {
    pub fn parse(text: &str) -> Result<Rule, String> {
        let text = text.trim();
        let words: Vec<&str> = text.split_whitespace().collect();
        let [target, op, limit, options @ ..] = words.as_slice() else {
            return Err(format!("expected 'metric > value': {text}"));
        };
        let op = match *op {
            ">" => Op::Gt,
            ">=" => Op::Ge,
            "<" => Op::Lt,
            "<=" => Op::Le,
            o => return Err(format!("unknown comparison '{o}'")),
        };
        let number = |v: &str| v.parse::<f64>().ok().filter(|n| n.is_finite()).ok_or_else(|| format!("'{v}' isn't a number"));
        let limit = number(limit)?;
        let (metric, label) = match target.split_once('{') {
            Some((m, rest)) => {
                let pair = rest.strip_suffix('}').and_then(|p| p.split_once('=')).ok_or_else(|| format!("expected metric{{key=value}}: {target}"))?;
                (m, Some((pair.0.to_string(), pair.1.to_string())))
            }
            None => (*target, None),
        };
        let above = matches!(op, Op::Gt | Op::Ge);
        let margin = limit.abs() * DEFAULT_HYSTERESIS;
        let mut rule = Rule {
            text: text.to_string(),
            metric: metric.to_string(),
            label,
            op,
            limit,
            clear: if above { limit - margin } else { limit + margin },
            hold: DEFAULT_HOLD,
            clear_hold: DEFAULT_CLEAR_HOLD,
            priority: Priority::Medium,
        };
        let mut rest = options.iter();
        while let Some(word) = rest.next() {
            let value = rest.next().ok_or_else(|| format!("'{word}' needs a value"))?;
            match *word {
                "for" => rule.hold = seconds(value)?,
                "clearfor" => rule.clear_hold = seconds(value)?,
                "clear" => rule.clear = number(value)?,
                "priority" => rule.priority = Priority::parse(value).ok_or_else(|| format!("unknown priority '{value}'"))?,
                other => return Err(format!("unknown option '{other}'")),
            }
        }
        // Recovery must be easier than firing, or it could never settle.
        if (above && rule.clear > rule.limit) || (!above && rule.clear < rule.limit) {
            return Err(format!("the clear value {} is on the wrong side of the limit {}", rule.clear, rule.limit));
        }
        Ok(rule)
    }

    fn applies(&self, s: &Sample) -> bool {
        s.metric == self.metric && self.label.as_ref().is_none_or(|(k, v)| s.labels.iter().any(|(a, b)| a == k && b == v))
    }

    fn abnormal(&self, v: f64) -> bool {
        match self.op {
            Op::Gt => v > self.limit,
            Op::Ge => v >= self.limit,
            Op::Lt => v < self.limit,
            Op::Le => v <= self.limit,
        }
    }

    /// True only well past the limit: the band between is hysteresis.
    fn recovered(&self, v: f64) -> bool {
        match self.op {
            Op::Gt | Op::Ge => v <= self.clear,
            Op::Lt | Op::Le => v >= self.clear,
        }
    }
}

/// The rules procwatch ships with. Each can be changed in Settings.
pub const DEFAULT_RULES: &[&str] = &[
    "cpu.usage > 90 clear 80 for 60s clearfor 60s priority medium",
    "memory.used_percent > 90 clear 85 for 60s clearfor 60s priority medium",
    "memory.used_percent > 97 clear 92 for 30s clearfor 60s priority high",
    "disk.used_percent > 90 clear 85 for 60s clearfor 300s priority medium",
    "disk.used_percent > 97 clear 93 for 30s clearfor 300s priority high",
    "net.tcp_opens > 500 clear 300 for 30s clearfor 60s priority medium",
    "kernel.cpu > 25 clear 15 for 60s clearfor 60s priority low",
];

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum State {
    Observing,
    Firing,
    Acknowledged,
}

struct Entry {
    state: State,
    rule: Option<usize>,
    /// When the condition began, or when it began to clear.
    since: Instant,
    clearing: Option<Instant>,
    event: AlarmEvent,
    /// Alarms raised from events have no metric to clear them.
    expires: Option<Instant>,
    /// When the metric last reported.
    seen: Instant,
}

/// Evaluates rules and holds every alarm that is not normal.
#[derive(Default)]
pub struct Engine {
    rules: Vec<Rule>,
    entries: HashMap<String, Entry>,
    pub overflow: u64,
}

impl Engine {
    pub fn new(rules: Vec<Rule>) -> Engine {
        Engine { rules, entries: HashMap::new(), overflow: 0 }
    }

    pub fn firing(&self) -> usize {
        self.entries.values().filter(|e| e.state != State::Observing).count()
    }

    pub fn set_rules(&mut self, rules: Vec<Rule>) {
        // Numbers point into the old list, and conditions may mean something
        // new: metric alarms start over.
        self.entries.retain(|_, e| e.rule.is_none());
        self.rules = rules;
    }

    pub fn feed(&mut self, samples: &[Sample], now: Instant) -> Vec<AlarmEvent> {
        let mut out = Vec::new();
        for s in samples {
            let labels = s.labels.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(",");
            for i in 0..self.rules.len() {
                if self.rules.get(i).is_some_and(|r| r.applies(s)) {
                    out.extend(self.judge(i, &labels, s, now));
                }
            }
        }
        out
    }

    fn judge(&mut self, i: usize, labels: &str, s: &Sample, now: Instant) -> Option<AlarmEvent> {
        let rule = self.rules.get(i)?;
        let key = format!("{}|{labels}", rule.text);
        let abnormal = rule.abnormal(s.value);
        let recovered = rule.recovered(s.value);
        if !self.entries.contains_key(&key) {
            if !abnormal {
                return None;
            }
            if self.entries.len() >= MAX_ENTRIES {
                self.overflow += 1;
                return None;
            }
            let shown = if labels.is_empty() { s.metric.to_string() } else { format!("{}{{{labels}}}", s.metric) };
            let title = format!("{shown} is {:.1}", s.value);
            let event = AlarmEvent::new(key.clone(), rule.text.clone(), title, rule.priority, s.metric);
            self.entries.insert(key.clone(), Entry { state: State::Observing, rule: Some(i), since: now, clearing: None, event, expires: None, seen: now });
        }
        let (hold, clear_hold) = (rule.hold, rule.clear_hold);
        let e = self.entries.get_mut(&key)?;
        e.seen = now;
        e.event.value = Some(s.value);
        match e.state {
            State::Observing if !abnormal => {
                self.entries.remove(&key);
                None
            }
            State::Observing => {
                if now.duration_since(e.since) < hold {
                    return None;
                }
                e.state = State::Firing;
                e.event.phase = Phase::Firing;
                e.event.at = SystemTime::now();
                Some(e.event.clone())
            }
            State::Firing | State::Acknowledged => {
                if !recovered {
                    e.clearing = None;
                    return None;
                }
                let began = *e.clearing.get_or_insert(now);
                if now.duration_since(began) < clear_hold {
                    return None;
                }
                let mut done = self.entries.remove(&key)?.event;
                done.phase = Phase::Recovered;
                done.at = SystemTime::now();
                Some(done)
            }
        }
    }

    /// An alarm from an event, not a metric. `lasts` is how long it stays
    /// without being acknowledged; None holds it until someone does.
    pub fn raise(&mut self, event: AlarmEvent, lasts: Option<Duration>, now: Instant) -> Option<AlarmEvent> {
        let expires = lasts.map(|d| now + d);
        if let Some(e) = self.entries.get_mut(&event.key) {
            e.expires = expires;
            // The same alarm only speaks again if it got worse.
            if event.priority <= e.event.priority {
                return None;
            }
            e.event.priority = event.priority;
            e.event.title = event.title;
            e.event.detail = event.detail;
            e.event.at = SystemTime::now();
            e.state = State::Firing;
            e.event.phase = Phase::Firing;
            return Some(e.event.clone());
        }
        if self.entries.len() >= MAX_ENTRIES {
            self.overflow += 1;
        }
        let out = event.clone();
        self.entries.insert(event.key.clone(), Entry { state: State::Firing, rule: None, since: now, clearing: None, event, expires, seen: now });
        Some(out)
    }

    pub fn clear(&mut self, key: &str) -> Option<AlarmEvent> {
        let mut e = self.entries.remove(key)?;
        if e.state == State::Observing {
            return None;
        }
        e.event.phase = Phase::Recovered;
        e.event.at = SystemTime::now();
        Some(e.event)
    }

    pub fn acknowledge(&mut self, key: &str, now: Instant) -> Option<AlarmEvent> {
        let e = self.entries.get_mut(key)?;
        if e.state != State::Firing {
            return None;
        }
        // The kernel itself ends the alarms about modules, when they return.
        if e.rule.is_none() && e.event.source != "kernel.module" {
            e.expires = Some(now + ACK_HOLD);
        }
        e.state = State::Acknowledged;
        e.event.phase = Phase::Acknowledged;
        e.event.at = SystemTime::now();
        Some(e.event.clone())
    }

    /// Alarms whose time is up.
    pub fn expire(&mut self, now: Instant) -> Vec<AlarmEvent> {
        let stale = |e: &Entry| e.rule.is_some() && now.duration_since(e.seen) >= STALE;
        let due: Vec<String> = self.entries.iter().filter(|(_, e)| e.expires.is_some_and(|t| now >= t) || stale(e)).map(|(k, _)| k.clone()).collect();
        due.iter().filter_map(|k| self.clear(k)).collect()
    }
}

/// Counters for watching the alarm system itself.
#[derive(Default, Debug)]
pub struct AlarmStats {
    pub firing: AtomicU64,
    pub eval_us: AtomicU64,
    pub notify_failed: AtomicU64,
    pub notified: AtomicU64,
    pub events: AtomicU64,
}

/// What can be asked of the engine.
pub enum Input {
    Raise { event: AlarmEvent, lasts: Option<Duration> },
    Clear(String),
    Acknowledge(String),
    SetRules(Vec<Rule>),
}

/// The alarm channel, separate from the bus. Samples may be lost under
/// pressure; alarm events may not. Queues here are unbounded, which is safe
/// because the engine only speaks when a state changes and states are few.
#[derive(Clone, Default)]
pub struct Hub {
    inner: Arc<HubInner>,
}

#[derive(Default)]
struct HubInner {
    subscribers: Mutex<Vec<Sender<AlarmEvent>>>,
    input: Mutex<Option<Sender<Input>>>,
    stats: AlarmStats,
}

impl Hub {
    pub fn subscribe(&self) -> Receiver<AlarmEvent> {
        let (tx, rx) = channel();
        if let Ok(mut s) = self.inner.subscribers.lock() {
            s.push(tx);
        }
        rx
    }

    pub fn publish(&self, e: AlarmEvent) {
        self.inner.stats.events.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut s) = self.inner.subscribers.lock() {
            s.retain(|tx| tx.send(e.clone()).is_ok());
        }
    }

    pub(super) fn connect(&self, tx: Sender<Input>) {
        if let Ok(mut i) = self.inner.input.lock() {
            *i = Some(tx);
        }
    }

    pub fn send(&self, input: Input) {
        if let Ok(i) = self.inner.input.lock() {
            if let Some(tx) = i.as_ref() {
                let _ = tx.send(input);
            }
        }
    }

    pub fn stats(&self) -> &AlarmStats {
        &self.inner.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::model::Unit;

    fn s(v: f64) -> [Sample; 1] {
        [Sample::new("cpu.usage", v, Unit::Percent)]
    }

    const RULE: &str = "cpu.usage > 90 clear 80 for 10s clearfor 5s priority high";

    fn phases(e: Vec<AlarmEvent>) -> Vec<Phase> {
        e.into_iter().map(|x| x.phase).collect()
    }

    #[test]
    fn rules_parse_or_explain() {
        let r = Rule::parse(RULE).unwrap();
        assert_eq!((r.limit, r.clear, r.priority), (90.0, 80.0, Priority::High));
        assert_eq!((r.hold, r.clear_hold), (Duration::from_secs(10), Duration::from_secs(5)));
        let d = Rule::parse("memory.available < 1000").unwrap();
        assert_eq!((d.clear, d.hold, d.priority), (1100.0, DEFAULT_HOLD, Priority::Medium));
        assert!(Rule::parse("disk.queue_depth{device=sda} >= 32").is_ok());
        for bad in ["cpu.x", "cpu.x ~ 1", "cpu.x > y", "cpu.x > 1 for soon", "a{b > 1", "cpu.x > NaN", "x > 1 clear 2", "x < 1 clear 0", "x > 1 priority urgent", "x > 1 for", "x > 1 color 2"] {
            assert!(Rule::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn every_default_rule_parses() {
        for r in DEFAULT_RULES {
            let rule = Rule::parse(r).unwrap();
            assert!(crate::kernel::dictionary::lookup(&rule.metric).is_some(), "{r}");
        }
    }

    #[test]
    fn the_whole_lifecycle_produces_one_event_per_change() {
        let mut e = Engine::new(vec![Rule::parse(RULE).unwrap()]);
        let t = Instant::now();
        let at = |secs| t + Duration::from_secs(secs);
        assert!(e.feed(&s(95.0), at(0)).is_empty(), "observing");
        assert_eq!(e.firing(), 0);
        assert!(e.feed(&s(95.0), at(5)).is_empty());
        assert_eq!(phases(e.feed(&s(95.0), at(10))), [Phase::Firing]);
        assert!(e.feed(&s(95.0), at(11)).is_empty(), "no event while nothing changes");
        let key = e.entries.keys().next().unwrap().clone();
        assert_eq!(e.acknowledge(&key, at(11)).unwrap().phase, Phase::Acknowledged);
        assert!(e.acknowledge(&key, at(11)).is_none());
        assert!(e.feed(&s(70.0), at(12)).is_empty(), "clearing must last too");
        assert_eq!(phases(e.feed(&s(70.0), at(17))), [Phase::Recovered]);
        assert_eq!(e.entries.len(), 0, "back to normal");
    }

    #[test]
    fn a_spike_never_fires() {
        let mut e = Engine::new(vec![Rule::parse(RULE).unwrap()]);
        let t = Instant::now();
        assert!(e.feed(&s(99.0), t).is_empty());
        assert!(e.feed(&s(50.0), t + Duration::from_secs(1)).is_empty());
        assert!(e.feed(&s(99.0), t + Duration::from_secs(20)).is_empty(), "the wait starts over");
    }

    #[test]
    fn hovering_at_the_limit_does_not_flap() {
        let mut e = Engine::new(vec![Rule::parse(RULE).unwrap()]);
        let t = Instant::now();
        e.feed(&s(95.0), t);
        assert_eq!(e.feed(&s(95.0), t + Duration::from_secs(10)).len(), 1);
        // Below the limit, above the clear value, for a long time.
        for i in 0..1000 {
            let v = if i % 2 == 0 { 85.0 } else { 91.0 };
            assert!(e.feed(&s(v), t + Duration::from_secs(11 + i)).is_empty());
        }
        assert_eq!(e.firing(), 1);
    }

    #[test]
    fn dipping_below_clear_briefly_does_not_recover() {
        let mut e = Engine::new(vec![Rule::parse(RULE).unwrap()]);
        let t = Instant::now();
        e.feed(&s(95.0), t);
        e.feed(&s(95.0), t + Duration::from_secs(10));
        assert!(e.feed(&s(70.0), t + Duration::from_secs(11)).is_empty());
        assert!(e.feed(&s(85.0), t + Duration::from_secs(14)).is_empty());
        assert!(e.feed(&s(70.0), t + Duration::from_secs(17)).is_empty(), "the clearing clock restarted");
        assert_eq!(e.firing(), 1);
    }

    #[test]
    fn labels_separate_and_select() {
        let mut e = Engine::new(vec![Rule::parse("q{device=sda} > 1 for 0s").unwrap(), Rule::parse("q > 1000 for 0s").unwrap()]);
        let t = Instant::now();
        let a = Sample::new("q", 5.0, Unit::Count).label("device", "sda");
        let b = Sample::new("q", 5.0, Unit::Count).label("device", "sdb");
        assert_eq!(e.feed(&[a, b], t).len(), 1);
        let hi = Sample::new("q", 5000.0, Unit::Count).label("device", "sdb");
        assert!(e.feed(&[hi], t)[0].title.contains("device=sdb"));
    }

    #[test]
    fn raised_alarms_speak_again_only_when_worse() {
        let mut e = Engine::default();
        let t = Instant::now();
        let ev = |p| AlarmEvent::new("k", "r", "x", p, "defense");
        assert!(e.raise(ev(Priority::Medium), None, t).is_some());
        assert!(e.raise(ev(Priority::Medium), None, t).is_none());
        assert!(e.raise(ev(Priority::Low), None, t).is_none());
        assert_eq!(e.raise(ev(Priority::High), None, t).unwrap().priority, Priority::High);
        e.acknowledge("k", t);
        assert_eq!(e.clear("k").unwrap().phase, Phase::Recovered);
    }

    #[test]
    fn raised_alarms_can_expire() {
        let mut e = Engine::default();
        let t = Instant::now();
        e.raise(AlarmEvent::new("k", "r", "x", Priority::Low, "s"), Some(Duration::from_secs(60)), t);
        assert!(e.expire(t + Duration::from_secs(59)).is_empty());
        assert_eq!(phases(e.expire(t + Duration::from_secs(60))), [Phase::Recovered]);
    }

    /// The same attack repeated must alarm again, even after an old one was
    /// acknowledged.
    #[test]
    fn an_acknowledged_event_alarm_ends_so_the_next_can_fire() {
        let mut e = Engine::default();
        let t = Instant::now();
        let ev = || AlarmEvent::new("k", "r", "x", Priority::High, "defense");
        e.raise(ev(), None, t);
        e.acknowledge("k", t);
        assert!(e.expire(t + ACK_HOLD - Duration::from_secs(1)).is_empty());
        assert_eq!(phases(e.expire(t + ACK_HOLD)), [Phase::Recovered]);
        assert!(e.raise(ev(), None, t + ACK_HOLD).is_some(), "it can fire again");
        e.raise(AlarmEvent::new("m", "module-lost", "x", Priority::High, "kernel.module"), None, t);
        e.acknowledge("m", t);
        assert!(e.expire(t + ACK_HOLD * 10).is_empty() , "a module stays lost until it returns");
    }

    /// A module unloaded while its metric was alarming: no sample will ever
    /// clear it, and a lamp must not stay on for ever about nothing.
    #[test]
    fn a_metric_that_stops_reporting_ends_its_alarm() {
        let mut e = Engine::new(vec![Rule::parse(RULE).unwrap()]);
        let t = Instant::now();
        e.feed(&s(95.0), t);
        assert_eq!(e.feed(&s(95.0), t + Duration::from_secs(10)).len(), 1);
        assert!(e.expire(t + Duration::from_secs(100)).is_empty());
        assert_eq!(phases(e.expire(t + Duration::from_secs(10) + STALE)), [Phase::Recovered]);
        assert_eq!(e.firing(), 0);
    }

    #[test]
    fn titles_cannot_carry_terminal_escapes() {
        let e = AlarmEvent::new("k", "r", "bad\x1b]0;owned\x07name\n", Priority::Low, "s");
        assert!(!e.title.chars().any(char::is_control), "{:?}", e.title);
    }

    #[test]
    fn alarms_reach_every_subscriber_however_many() {
        let hub = Hub::default();
        let (a, b) = (hub.subscribe(), hub.subscribe());
        for i in 0..100_000 {
            hub.publish(AlarmEvent::new(i.to_string(), "r", "t", Priority::Low, "s"));
        }
        assert_eq!(a.try_iter().count(), 100_000, "nothing is dropped");
        drop(a);
        hub.publish(AlarmEvent::new("x", "r", "t", Priority::Low, "s"));
        assert_eq!(b.try_iter().count(), 100_001);
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Whatever the data does, every alarm goes firing → recovered,
            /// never twice in a row, and nothing happens between the
            /// limits that hysteresis keeps apart.
            #[test]
            fn events_alternate(values in proptest::collection::vec((0.0f64..120.0, 0u64..40), 1..200)) {
                let mut e = Engine::new(vec![Rule::parse("cpu.usage > 90 clear 80 for 10s clearfor 5s").unwrap()]);
                let mut t = Instant::now();
                let mut firing = false;
                for (v, step) in values {
                    t += Duration::from_secs(step);
                    for ev in e.feed(&s(v), t) {
                        match ev.phase {
                            Phase::Firing => {
                                prop_assert!(!firing);
                                prop_assert!(v > 90.0);
                                firing = true;
                            }
                            Phase::Recovered => {
                                prop_assert!(firing);
                                prop_assert!(v <= 80.0);
                                firing = false;
                            }
                            Phase::Acknowledged => prop_assert!(false),
                        }
                    }
                }
                prop_assert_eq!(e.firing() == 1, firing);
            }

            /// Any text is either a rule or an error.
            #[test]
            fn rule_parsing_never_panics(text in "\\PC{0,60}") {
                let _ = Rule::parse(&text);
            }

            /// Acknowledging never fires anything, and order doesn't matter.
            #[test]
            fn acknowledging_is_safe(keys in proptest::collection::vec("[a-c]", 0..30)) {
                let mut e = Engine::default();
                let t = Instant::now();
                e.raise(AlarmEvent::new("a", "r", "x", Priority::High, "s"), None, t);
                for k in keys {
                    if let Some(ev) = e.acknowledge(&k, t) {
                        prop_assert_eq!(ev.phase, Phase::Acknowledged);
                    }
                }
                prop_assert_eq!(e.firing(), 1);
            }
        }
    }

    /// Cost of judging a full set of samples. `cargo test --release -- --ignored bench`
    #[test]
    #[ignore = "benchmark"]
    fn bench_alarm_evaluation() {
        let rules: Vec<Rule> = DEFAULT_RULES.iter().map(|r| Rule::parse(r).unwrap()).collect();
        let mut e = Engine::new(rules);
        let batch: Vec<Sample> = (0..300).map(|i| Sample::new("disk.used_percent", 50.0, Unit::Percent).label("mount", i.to_string())).collect();
        let (t, n) = (Instant::now(), 2000);
        for _ in 0..n {
            e.feed(&batch, Instant::now());
        }
        let per = t.elapsed() / n;
        println!("alarm evaluation: {per:?} for {} samples", batch.len());
        assert!(per < Duration::from_millis(5), "{per:?}");
    }
}
