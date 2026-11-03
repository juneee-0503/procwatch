//! Response verification for `App`: every process action is logged with
//! its per-target outcome; terminations are then verified (did the
//! instance really go away?) and watched for relaunches, with candidate
//! autostart entries named — as candidates, not as proven causes.
//! A child module of `app`.

use chrono::{DateTime, Local};

use super::*;
use crate::model::{Entity, ProcKey};
use crate::process::actions::{Action, Outcome, Sig};

/// How long a terminated program is watched for relaunches.
const RELAUNCH_WINDOW_SECS: i64 = 30 * 60;
/// When a still-running terminated instance is reported.
const VERIFY_AFTER_SECS: i64 = 5;

#[derive(Debug, Clone)]
pub struct Watched {
    pub key: ProcKey,
    pub name: String,
    pub exe: Option<String>,
    pub at: DateTime<Local>,
    /// None until verified; Some(true) = gone, Some(false) = still running.
    pub gone: Option<bool>,
    pub relaunched: bool,
}

#[derive(Default)]
pub struct ResponseState {
    pub watched: Vec<Watched>,
}

fn terminates(a: Action) -> bool {
    matches!(a, Action::Signal(Sig::Term) | Action::Signal(Sig::Kill))
}

impl App {
    pub(super) fn response_begin(&mut self, action: Action, targets: &[(u32, String, u64)]) {
        if let Some(c) = &self.ir.case {
            let list: Vec<String> = targets.iter().map(|(p, n, s)| format!("{n} ({p}, started {s})")).collect();
            let _ = c.log("response requested", &format!("{}: {}", describe(action), list.join(", ")));
        }
        if terminates(action) {
            let now = Local::now();
            for (pid, name, start) in targets {
                let exe = self.tree.get(*pid).and_then(|n| n.info.exe_path.clone());
                self.ir.response.watched.push(Watched { key: ProcKey { pid: *pid, start: *start }, name: name.clone(), exe, at: now, gone: None, relaunched: false });
            }
        }
    }

    pub(super) fn response_results(&mut self, action: Action, results: &[(u32, String, Outcome)]) {
        if let Some(c) = &self.ir.case {
            for (pid, name, o) in results {
                let what = match o {
                    Outcome::Done => "done".to_string(),
                    Outcome::AlreadyExited => "already exited".to_string(),
                    Outcome::PidReused { now_started } => format!("SKIPPED — PID now belongs to a process started at {now_started}"),
                    Outcome::Failed(e) => format!("FAILED: {e}"),
                };
                let _ = c.log("response result", &format!("{} {name} ({pid}): {what}", describe(action)));
            }
        }
        // Targets that weren't acted on aren't expected to go away.
        for (pid, _, o) in results {
            if !matches!(o, Outcome::Done) {
                self.ir.response.watched.retain(|w| w.key.pid != *pid || w.gone.is_some());
            }
        }
    }

    /// Called on every snapshot: verify terminations and spot relaunches.
    pub(super) fn response_on_snapshot(&mut self) {
        if self.ir.response.watched.is_empty() {
            return;
        }
        let now = Local::now();
        self.ir.response.watched.retain(|w| (now - w.at).num_seconds() < RELAUNCH_WINDOW_SECS);
        let mut notes: Vec<(StatusLevel, String)> = Vec::new();
        let mut relaunches: Vec<(Watched, u32)> = Vec::new();
        for w in self.ir.response.watched.iter_mut() {
            let alive = self.tree.get(w.key.pid).is_some_and(|n| n.info.start_time_secs.abs_diff(w.key.start) <= 2);
            if w.gone.is_none() {
                if !alive {
                    w.gone = Some(true);
                    notes.push((StatusLevel::Success, format!("Verified: {} ({}) is gone", w.name, w.key.pid)));
                } else if (now - w.at).num_seconds() >= VERIFY_AFTER_SECS {
                    w.gone = Some(false);
                    notes.push((StatusLevel::Error, format!("{} ({}) is still running {VERIFY_AFTER_SECS} s after the request — try force quit, or it may be protected", w.name, w.key.pid)));
                }
            }
            // Relaunch: a different instance running the same executable.
            if w.gone == Some(true) && !w.relaunched {
                if let Some(exe) = &w.exe {
                    if let Some(n) = self.tree.nodes.values().find(|n| n.info.exe_path.as_deref() == Some(exe.as_str()) && n.info.start_time_secs > w.key.start) {
                        w.relaunched = true;
                        relaunches.push((w.clone(), n.info.pid));
                    }
                }
            }
        }
        for (level, msg) in notes {
            if let Some(c) = &self.ir.case {
                let _ = c.log("response verification", &msg);
            }
            self.set_status(level, msg);
        }
        for (w, new_pid) in relaunches {
            let exe = w.exe.clone().unwrap_or_default();
            let candidates: Vec<String> = self
                .persist_items()
                .iter()
                .filter(|p| p.target.as_deref() == Some(exe.as_str()) || p.command.contains(&exe))
                .map(|p| format!("{}: {} ({})", p.category, p.name, p.location))
                .collect();
            let parent = self.tree.get(new_pid).and_then(|n| n.info.ppid).map(|pp| format!("{} ({pp})", self.name_of(pp))).unwrap_or_default();
            let evidence = format!(
                "{exe} ended at {} and started again as pid {new_pid}, parent {parent}; candidate autostart entries: {}",
                w.at.format("%H:%M:%S"),
                if candidates.is_empty() {
                    if self.ir.persistence.is_none() { "persistence not scanned".to_string() } else { "none found".to_string() }
                } else {
                    candidates.join("; ")
                }
            );
            let hit = crate::triage::RuleHit {
                id: "PW-017".into(),
                name: "Relaunched after termination".into(),
                severity: crate::model::Severity::Medium,
                confidence: crate::model::Confidence::Medium,
                technique: "T1543".into(),
                evidence: evidence.clone(),
                suppressed: None,
            };
            let key = self.proc_key(new_pid);
            self.record_detection_pub(&hit, Entity::Process(key), format!("{} ({new_pid})", self.name_of(new_pid)), Some(new_pid), "response");
            if let Some(c) = &self.ir.case {
                let _ = c.log("relaunch observed", &evidence);
            }
            self.set_status(StatusLevel::Error, format!("{} came back as pid {new_pid} — see Detect (candidates are not proof of cause)", w.name));
        }
    }
}
