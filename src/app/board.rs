//! The alarm board: what is alarming now, and the lamp and tones it drives.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use super::*;
use crate::common::sound::{self, Tone};
use crate::kernel::alarm::{AlarmEvent, Input, Phase, Priority};

const MAX_HISTORY: usize = 500;

pub struct Board {
    pub active: BTreeMap<String, AlarmEvent>,
    pub history: VecDeque<AlarmEvent>,
    pub sound: bool,
    pub volume: u8,
    pub pause_seconds: u64,
    pub paused_until: Option<Instant>,
    last_tone: Option<(Tone, Instant)>,
}

impl Default for Board {
    fn default() -> Board {
        Board { active: BTreeMap::new(), history: VecDeque::new(), sound: true, volume: 60, pause_seconds: 120, paused_until: None, last_tone: None }
    }
}

impl From<&crate::defense::config::AlarmSettings> for Board {
    fn from(a: &crate::defense::config::AlarmSettings) -> Board {
        Board { sound: a.sound, volume: a.volume, pause_seconds: a.pause_seconds, ..Board::default() }
    }
}

fn tone_for(p: Priority) -> Tone {
    match p {
        Priority::High => Tone::High,
        Priority::Medium => Tone::Medium,
        Priority::Low => Tone::Low,
    }
}

impl Board {
    /// The worst alarm nobody has acknowledged.
    pub fn worst(&self) -> Option<&AlarmEvent> {
        self.active.values().filter(|e| e.phase == Phase::Firing).max_by_key(|e| (e.priority, e.at))
    }

    pub fn acknowledged(&self) -> usize {
        self.active.values().filter(|e| e.phase == Phase::Acknowledged).count()
    }

    pub fn audio_paused(&self) -> bool {
        self.paused_until.is_some_and(|t| Instant::now() < t)
    }

    fn apply(&mut self, e: AlarmEvent) {
        match e.phase {
            Phase::Recovered => {
                self.active.remove(&e.key);
            }
            _ => {
                self.active.insert(e.key.clone(), e.clone());
            }
        }
        self.history.push_front(e);
        self.history.truncate(MAX_HISTORY);
    }

    /// What should sound now, if anything.
    fn due_tone(&mut self, now: Instant) -> Option<Tone> {
        let Some(worst) = self.worst().map(|e| e.priority) else {
            // Quiet: the next alarm sounds at once, not when this one was due.
            self.last_tone = None;
            return None;
        };
        if !self.sound || self.audio_paused() {
            return None;
        }
        let tone = tone_for(worst);
        let due = match self.last_tone {
            Some((t, at)) if t == tone => now.duration_since(at) >= tone.period(),
            _ => true,
        };
        due.then(|| {
            self.last_tone = Some((tone, now));
            tone
        })
    }
}

impl App {
    pub(crate) fn on_alarm(&mut self, e: AlarmEvent) {
        if e.rule == "selfcheck" {
            return;
        }
        if e.phase == Phase::Firing && e.priority >= Priority::Medium {
            self.add_alerts(vec![crate::detection::rules::Alert { at: Local::now(), rule: e.rule.clone(), pid: 0, name: e.source.clone(), message: e.title.clone() }]);
        }
        self.board.apply(e);
    }

    pub(crate) fn board_tick(&mut self) -> bool {
        let now = Instant::now();
        // Maintenance quiets everything, on this screen as well as elsewhere.
        if let Some(tone) = self.board.due_tone(now).filter(|_| crate::common::maintenance::remaining().is_none()) {
            if !cfg!(test) {
                sound::play(tone, f64::from(self.board.volume) / 100.0);
            }
        }
        self.board.worst().is_some()
    }

    /// Alarms active now, firing first, then worst.
    pub fn alarm_list(&self) -> Vec<AlarmEvent> {
        let mut v: Vec<AlarmEvent> = self.board.active.values().cloned().collect();
        v.sort_by_key(|e| (e.phase != Phase::Firing, std::cmp::Reverse(e.priority)));
        v
    }

    pub fn acknowledge_alarm(&mut self, key: &str) {
        if let Some(k) = &self.kernel {
            k.alarms().send(Input::Acknowledge(key.to_string()));
        }
    }

    pub fn acknowledge_all(&mut self) {
        let keys: Vec<String> = self.board.active.values().filter(|e| e.phase == Phase::Firing).map(|e| e.key.clone()).collect();
        let n = keys.len();
        keys.iter().for_each(|k| self.acknowledge_alarm(k));
        self.set_status(StatusLevel::Info, format!("{n} alarms acknowledged"));
    }

    /// Quiet for a while without acknowledging, as on a bedside monitor. The
    /// lamp keeps flashing: only the sound stops.
    pub fn pause_audio(&mut self) {
        let secs = self.board.pause_seconds;
        self.board.paused_until = Some(Instant::now() + Duration::from_secs(secs));
        self.set_status(StatusLevel::Info, format!("Alarm sound paused for {secs} s"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(key: &str, p: Priority, phase: Phase) -> AlarmEvent {
        let mut e = AlarmEvent::new(key, "r", key, p, "s");
        e.phase = phase;
        e
    }

    #[test]
    fn the_worst_unacknowledged_alarm_leads() {
        let mut b = Board::default();
        b.apply(ev("a", Priority::Low, Phase::Firing));
        b.apply(ev("b", Priority::High, Phase::Firing));
        b.apply(ev("c", Priority::Medium, Phase::Firing));
        assert_eq!(b.worst().unwrap().key, "b");
        b.apply(ev("b", Priority::High, Phase::Acknowledged));
        assert_eq!(b.worst().unwrap().key, "c");
        assert_eq!(b.acknowledged(), 1);
        b.apply(ev("c", Priority::Medium, Phase::Recovered));
        b.apply(ev("a", Priority::Low, Phase::Recovered));
        b.apply(ev("b", Priority::High, Phase::Recovered));
        assert!(b.worst().is_none());
        assert_eq!(b.active.len(), 0);
        assert_eq!(b.history.len(), 7);
    }

    #[test]
    fn tones_repeat_at_their_own_pace_and_can_be_paused() {
        let mut b = Board::default();
        let t = Instant::now();
        assert_eq!(b.due_tone(t), None, "silence with nothing alarming");
        b.apply(ev("a", Priority::High, Phase::Firing));
        assert_eq!(b.due_tone(t), Some(Tone::High));
        assert_eq!(b.due_tone(t + Duration::from_secs(9)), None);
        let next = t + Tone::High.period();
        assert_eq!(b.due_tone(next), Some(Tone::High));
        b.paused_until = Some(Instant::now() + Duration::from_secs(600));
        assert_eq!(b.due_tone(next + Duration::from_secs(30)), None);
        b.paused_until = None;
        b.apply(ev("a", Priority::High, Phase::Acknowledged));
        assert_eq!(b.due_tone(next + Duration::from_secs(60)), None, "acknowledged is quiet");
    }

    #[test]
    fn a_low_alarm_repeats_slowly() {
        let mut b = Board::default();
        let t = Instant::now();
        b.apply(ev("a", Priority::Low, Phase::Firing));
        assert_eq!(b.due_tone(t), Some(Tone::Low));
        assert_eq!(b.due_tone(t + Duration::from_secs(19)), None);
        assert_eq!(b.due_tone(t + Tone::Low.period()), Some(Tone::Low));
    }

    #[test]
    fn a_new_alarm_after_silence_sounds_at_once() {
        let mut b = Board::default();
        let t = Instant::now();
        b.apply(ev("a", Priority::High, Phase::Firing));
        b.due_tone(t);
        b.apply(ev("a", Priority::High, Phase::Recovered));
        assert_eq!(b.due_tone(t + Duration::from_secs(1)), None);
        b.apply(ev("b", Priority::High, Phase::Firing));
        assert_eq!(b.due_tone(t + Duration::from_secs(2)), Some(Tone::High));
    }

    #[test]
    fn a_worse_alarm_sounds_at_once() {
        let mut b = Board::default();
        let t = Instant::now();
        b.apply(ev("a", Priority::Medium, Phase::Firing));
        b.due_tone(t);
        b.apply(ev("b", Priority::High, Phase::Firing));
        assert_eq!(b.due_tone(t + Duration::from_secs(1)), Some(Tone::High));
    }
}
