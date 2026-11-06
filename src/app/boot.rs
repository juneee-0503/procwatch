//! The start of a session: self-check, standby, choosing modules, loading
//! them and verifying the result, before any monitoring begins.

use std::time::{Duration, Instant};

use super::*;
use crate::engine::selfcheck::{self, Stage, Step};
use crate::kernel::ModuleState;

/// A module that hasn't settled by now is reported as it stands.
const LOAD_LIMIT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootPhase {
    SelfTest,
    Standby,
    Select,
    Loading,
    Verify,
    /// A check that must pass didn't.
    Halted,
    Monitoring,
}

#[derive(Debug, Clone)]
pub struct Choice {
    pub name: &'static str,
    pub description: &'static str,
    /// What it can't do here, in a word.
    pub support: String,
    pub chosen: bool,
}

pub struct Boot {
    pub phase: BootPhase,
    pub log: Vec<(bool, String)>,
    pub done: usize,
    pub total: usize,
    pub current: String,
    pub choices: Vec<Choice>,
    pub cursor: usize,
    began: Option<Instant>,
    fatal: bool,
}

impl Default for Boot {
    fn default() -> Boot {
        Boot { phase: BootPhase::Monitoring, log: Vec::new(), done: 0, total: 0, current: String::new(), choices: Vec::new(), cursor: 0, began: None, fatal: false }
    }
}

impl Boot {
    pub fn percent(&self) -> u16 {
        (self.done * 100).checked_div(self.total).map_or(0, |p| p.min(100) as u16)
    }
}

fn summary(m: &crate::kernel::ModuleStatus) -> String {
    use crate::kernel::Support;
    let missing = m.capabilities.iter().filter(|c| matches!(c.support, Support::No(_))).count();
    let partly = m.capabilities.iter().filter(|c| matches!(c.support, Support::Partly(_))).count();
    match (missing, partly) {
        (0, 0) => "supported".to_string(),
        (0, p) => format!("{p} partial"),
        (n, _) if n == m.capabilities.len() => "not supported here".to_string(),
        (n, _) => format!("{n} not supported"),
    }
}

impl App {
    pub fn begin_boot(&mut self) {
        self.boot.phase = BootPhase::SelfTest;
        self.boot.log.push((true, "Kernel started; no modules loaded".to_string()));
        self.boot.current = "Starting self-check".to_string();
        if let Some(k) = self.kernel.clone() {
            selfcheck::spawn(k, self.tx.clone(), Stage::Start);
        }
    }

    pub(crate) fn on_boot_step(&mut self, s: Step) {
        let ok = s.result.is_ok();
        let text = match &s.result {
            Ok(t) => format!("{}: {t}", s.name),
            Err(t) => format!("{}: FAILED: {t}", s.name),
        };
        self.boot.log.push((ok, text));
        self.boot.total = s.total;
        self.boot.done = s.index + 1;
        self.boot.current = s.name.to_string();
        self.boot.fatal |= !ok && s.fatal;
        if self.boot.done < s.total {
            return;
        }
        if self.boot.fatal {
            self.boot.phase = BootPhase::Halted;
            crate::common::audit::record("start refused", &self.boot.log.iter().filter(|l| !l.0).map(|l| l.1.as_str()).collect::<Vec<_>>().join("; "));
            return;
        }
        self.boot.phase = if s.stage == Stage::Start { BootPhase::Standby } else { BootPhase::Monitoring };
        if s.stage == Stage::Start {
            self.prepare_choices();
        } else if let Some(k) = &self.kernel {
            let names: Vec<&str> = self.boot.choices.iter().filter(|c| c.chosen).map(|c| c.name).collect();
            crate::common::audit::record("monitoring started", &names.join(", "));
            let _ = k;
            // Nothing will fill the process table if that wasn't chosen.
            self.loaded |= !self.module_on("process");
            if let Some(first) = self.first_tab() {
                self.tab = first;
            }
        }
    }

    fn prepare_choices(&mut self) {
        let Some(k) = &self.kernel else { return };
        let off = k.config().disabled;
        self.boot.choices = k.status().iter().map(|m| Choice { name: m.name, description: m.description, support: summary(m), chosen: !off.contains(m.name) }).collect();
        self.boot.cursor = 0;
    }

    /// The operator's choice: load these.
    pub fn confirm_modules(&mut self) {
        let Some(k) = self.kernel.clone() else { return };
        let names: Vec<String> = self.boot.choices.iter().filter(|c| c.chosen).map(|c| c.name.to_string()).collect();
        k.activate(&names);
        self.boot.phase = BootPhase::Loading;
        self.boot.total = names.len();
        self.boot.done = 0;
        self.boot.current = "Loading modules".to_string();
        self.boot.began = Some(Instant::now());
        self.boot.log.push((true, format!("Loading {} modules", names.len())));
        if names.is_empty() {
            self.boot.began = None;
            self.finish_loading();
        }
    }

    pub(crate) fn boot_tick(&mut self) -> bool {
        match self.boot.phase {
            BootPhase::Loading => {}
            BootPhase::SelfTest | BootPhase::Verify => return true,
            _ => return false,
        }
        let Some(k) = self.kernel.clone() else { return false };
        let chosen: Vec<&'static str> = self.boot.choices.iter().filter(|c| c.chosen).map(|c| c.name).collect();
        let status = k.status();
        let settled = |m: &&crate::kernel::ModuleStatus| !matches!(m.state, ModuleState::Starting | ModuleState::Disabled);
        let ready: Vec<_> = status.iter().filter(|m| chosen.contains(&m.name)).filter(settled).collect();
        self.boot.done = ready.len();
        self.boot.current = chosen.iter().find(|c| !ready.iter().any(|m| m.name == **c)).map_or_else(String::new, |c| format!("Loading {c}"));
        let timed_out = self.boot.began.is_some_and(|t| t.elapsed() >= LOAD_LIMIT);
        if ready.len() >= chosen.len() || timed_out {
            for m in status.iter().filter(|m| chosen.contains(&m.name)) {
                let why = m.last_error.as_deref().or(m.self_test.as_deref()).map(|e| format!(": {e}")).unwrap_or_default();
                self.boot.log.push((!matches!(m.state, ModuleState::Crashed | ModuleState::Failed | ModuleState::Stuck | ModuleState::Starting), format!("{} {}{why}", m.name, m.state.label())));
            }
            self.finish_loading();
        }
        true
    }

    fn finish_loading(&mut self) {
        self.boot.phase = BootPhase::Verify;
        self.boot.done = 0;
        self.boot.total = 0;
        self.boot.current = "Verifying integrity".to_string();
        if let Some(k) = self.kernel.clone() {
            selfcheck::spawn(k, self.tx.clone(), Stage::Verify);
        }
    }
}
