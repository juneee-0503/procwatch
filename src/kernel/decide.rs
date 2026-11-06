//! The last stage: should this alarm disturb anyone?
//!
//! An alarm can be real and still not worth a message. A problem that goes
//! on isn't repeated, only reminded of. Several at once on one machine become
//! one message. A cause already reported silences its effects. Maintenance
//! silences everything for a set time. Alarm fatigue destroys trust faster
//! than a missed alarm, and this exists to prevent it.

use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

use super::alarm::{AlarmEvent, Phase, Priority};

/// Alarms arriving this close together are sent as one.
const GROUP_WINDOW: Duration = Duration::from_secs(10);

/// How much an alarm of each priority may disturb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Intensity {
    /// Sent outside this machine at all.
    pub external: bool,
    /// How often to remind while unacknowledged.
    pub remind: Option<Duration>,
}

pub fn intensity(p: Priority) -> Intensity {
    match p {
        Priority::High => Intensity { external: true, remind: Some(Duration::from_secs(300)) },
        Priority::Medium => Intensity { external: true, remind: Some(Duration::from_secs(1800)) },
        Priority::Low => Intensity { external: false, remind: None },
    }
}

/// A message to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub priority: Priority,
    pub title: String,
    pub detail: String,
    pub source: String,
    pub rule: String,
}

struct Open {
    event: AlarmEvent,
    last_told: Instant,
    told: bool,
    /// Seen by someone: no more reminders, but they'll want to hear it ended.
    acknowledged: bool,
}

#[derive(Default)]
pub struct Decider {
    open: HashMap<String, Open>,
    /// Source prefixes silenced because their cause is already reported.
    silenced: BTreeSet<String>,
    quiet_until: Option<Instant>,
    /// When the current group began, and what has joined it since.
    group: Option<(Instant, Vec<AlarmEvent>)>,
    pub held_back: u64,
}

fn message(e: &AlarmEvent) -> Notice {
    let word = match e.phase {
        Phase::Firing => "",
        Phase::Acknowledged => "acknowledged: ",
        Phase::Recovered => "recovered: ",
    };
    Notice { priority: e.priority, title: format!("{word}{}", e.title), detail: e.detail.clone(), source: e.source.clone(), rule: e.rule.clone() }
}

impl Decider {
    /// Silence alarms from this source until `unsilence`: a module whose
    /// signal is lost says nothing useful about its metrics.
    pub fn silence(&mut self, source_prefix: &str) {
        self.silenced.insert(source_prefix.to_string());
    }

    pub fn unsilence(&mut self, source_prefix: &str) {
        self.silenced.remove(source_prefix);
    }

    pub fn maintenance(&mut self, until: Option<Instant>) {
        self.quiet_until = until;
    }

    pub fn in_maintenance(&self, now: Instant) -> bool {
        self.quiet_until.is_some_and(|t| now < t)
    }

    fn muted(&self, e: &AlarmEvent, now: Instant) -> bool {
        self.in_maintenance(now) || self.silenced.iter().any(|s| e.source.starts_with(s.as_str()))
    }

    pub fn on_event(&mut self, e: &AlarmEvent, now: Instant) -> Vec<Notice> {
        let muted = self.muted(e, now);
        if muted {
            self.held_back += 1;
        }
        let external = intensity(e.priority).external;
        match e.phase {
            Phase::Firing => {
                self.open.insert(e.key.clone(), Open { event: e.clone(), last_told: now, told: !muted && external, acknowledged: false });
                if muted || !external {
                    return Vec::new();
                }
                match &mut self.group {
                    // The first of a burst goes at once; the rest wait.
                    None => {
                        self.group = Some((now, Vec::new()));
                        vec![message(e)]
                    }
                    Some((_, joined)) => {
                        joined.push(e.clone());
                        Vec::new()
                    }
                }
            }
            Phase::Acknowledged => {
                if let Some(o) = self.open.get_mut(&e.key) {
                    o.acknowledged = true;
                }
                Vec::new()
            }
            Phase::Recovered => {
                // Only someone who was told needs to hear it's over.
                let told = self.open.remove(&e.key).is_some_and(|o| o.told);
                if told && !muted { vec![message(e)] } else { Vec::new() }
            }
        }
    }

    /// Call regularly: merged groups and reminders fall due here.
    pub fn tick(&mut self, now: Instant) -> Vec<Notice> {
        let mut out = Vec::new();
        if let Some((began, joined)) = &self.group {
            if now.duration_since(*began) >= GROUP_WINDOW {
                let joined = joined.clone();
                self.group = None;
                if let Some(worst) = joined.iter().map(|e| e.priority).max() {
                    let titles: Vec<&str> = joined.iter().take(8).map(|e| e.title.as_str()).collect();
                    let more = joined.len().saturating_sub(8);
                    let tail = if more > 0 { format!("\n… and {more} more") } else { String::new() };
                    out.push(Notice { priority: worst, title: format!("{} more alarms on this machine", joined.len()), detail: format!("{}{tail}", titles.join("\n")), source: "group".into(), rule: "group".into() });
                }
            }
        }
        if self.in_maintenance(now) {
            return out;
        }
        let silenced = self.silenced.clone();
        for o in self.open.values_mut() {
            let Some(every) = intensity(o.event.priority).remind else { continue };
            if !o.acknowledged && !silenced.iter().any(|s| o.event.source.starts_with(s.as_str())) && now.duration_since(o.last_told) >= every {
                o.last_told = now;
                o.told = true;
                let mut n = message(&o.event);
                n.title = format!("still active: {}", n.title);
                out.push(n);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(key: &str, p: Priority, phase: Phase, source: &str) -> AlarmEvent {
        let mut e = AlarmEvent::new(key, "r", format!("alarm {key}"), p, source);
        e.phase = phase;
        e
    }

    #[test]
    fn a_burst_becomes_two_messages() {
        let (mut d, t) = (Decider::default(), Instant::now());
        assert_eq!(d.on_event(&ev("a", Priority::Medium, Phase::Firing, "x"), t).len(), 1);
        for i in 0..20 {
            assert!(d.on_event(&ev(&i.to_string(), Priority::High, Phase::Firing, "x"), t).is_empty());
        }
        assert!(d.tick(t + Duration::from_secs(5)).is_empty());
        let group = d.tick(t + GROUP_WINDOW);
        assert_eq!(group.len(), 1);
        assert_eq!(group[0].priority, Priority::High);
        assert!(group[0].title.starts_with("20 more"));
        assert!(group[0].detail.contains("and 12 more"));
    }

    #[test]
    fn reminders_come_at_the_set_pace_until_acknowledged() {
        let (mut d, t) = (Decider::default(), Instant::now());
        d.on_event(&ev("a", Priority::High, Phase::Firing, "x"), t);
        d.tick(t + GROUP_WINDOW);
        assert!(d.tick(t + Duration::from_secs(299)).is_empty());
        let r = d.tick(t + Duration::from_secs(300));
        assert!(r[0].title.starts_with("still active"));
        assert!(d.tick(t + Duration::from_secs(301)).is_empty());
        d.on_event(&ev("a", Priority::High, Phase::Acknowledged, "x"), t + Duration::from_secs(302));
        assert!(d.tick(t + Duration::from_secs(9000)).is_empty());
    }

    #[test]
    fn whoever_acknowledged_still_hears_it_ended() {
        let (mut d, t) = (Decider::default(), Instant::now());
        d.on_event(&ev("a", Priority::High, Phase::Firing, "x"), t);
        d.on_event(&ev("a", Priority::High, Phase::Acknowledged, "x"), t);
        assert_eq!(d.on_event(&ev("a", Priority::High, Phase::Recovered, "x"), t).len(), 1);
    }

    #[test]
    fn low_priority_stays_on_this_machine() {
        let (mut d, t) = (Decider::default(), Instant::now());
        assert!(d.on_event(&ev("a", Priority::Low, Phase::Firing, "x"), t).is_empty());
        assert!(d.tick(t + Duration::from_secs(90_000)).is_empty());
        assert!(d.on_event(&ev("a", Priority::Low, Phase::Recovered, "x"), t).is_empty());
    }

    #[test]
    fn recovery_is_told_only_to_those_who_heard_the_alarm() {
        let (mut d, t) = (Decider::default(), Instant::now());
        d.on_event(&ev("a", Priority::High, Phase::Firing, "x"), t);
        let done = d.on_event(&ev("a", Priority::High, Phase::Recovered, "x"), t);
        assert!(done[0].title.starts_with("recovered"));
    }

    #[test]
    fn a_cause_silences_its_effects() {
        let (mut d, t) = (Decider::default(), Instant::now());
        d.silence("disk.");
        assert!(d.on_event(&ev("a", Priority::High, Phase::Firing, "disk.queue_depth"), t).is_empty());
        assert!(d.tick(t + Duration::from_secs(9000)).is_empty());
        assert_eq!(d.on_event(&ev("b", Priority::High, Phase::Firing, "cpu.usage"), t).len(), 1);
        assert_eq!(d.held_back, 1);
        d.unsilence("disk.");
        assert_eq!(d.tick(t + Duration::from_secs(10_000)).iter().filter(|n| n.source == "disk.queue_depth").count(), 1, "it is still active");
    }

    #[test]
    fn maintenance_ends_by_itself() {
        let (mut d, t) = (Decider::default(), Instant::now());
        d.maintenance(Some(t + Duration::from_secs(60)));
        assert!(d.on_event(&ev("a", Priority::High, Phase::Firing, "x"), t).is_empty());
        assert!(d.tick(t + Duration::from_secs(59)).is_empty());
        assert!(!d.in_maintenance(t + Duration::from_secs(60)));
        assert_eq!(d.on_event(&ev("b", Priority::High, Phase::Firing, "x"), t + Duration::from_secs(61)).len(), 1);
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// However a burst arrives, one group window yields at most two
            /// messages per burst: a storm stays small.
            #[test]
            fn storms_stay_small(n in 1usize..500) {
                let (mut d, t) = (Decider::default(), Instant::now());
                let mut sent = 0;
                for i in 0..n {
                    sent += d.on_event(&ev(&i.to_string(), Priority::Medium, Phase::Firing, "x"), t).len();
                }
                sent += d.tick(t + GROUP_WINDOW).len();
                prop_assert!(sent <= 2);
            }

            /// Maintenance silences everything, in any order of events.
            #[test]
            fn maintenance_is_total(phases in proptest::collection::vec(0u8..3, 0..100)) {
                let (mut d, t) = (Decider::default(), Instant::now());
                d.maintenance(Some(t + Duration::from_secs(3600)));
                for (i, p) in phases.iter().enumerate() {
                    let phase = [Phase::Firing, Phase::Acknowledged, Phase::Recovered][*p as usize];
                    prop_assert!(d.on_event(&ev(&(i % 5).to_string(), Priority::High, phase, "x"), t).is_empty());
                }
            }
        }
    }
}
