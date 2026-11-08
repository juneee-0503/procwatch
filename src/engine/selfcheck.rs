//! The checks run when procwatch starts and after modules load. They run on
//! their own thread and report one step at a time, so the screen can show
//! what is being checked and why it stopped.

use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use super::messages::WorkerMsg;
use crate::common::integrity::{self, Check};
use crate::kernel::alarm::{AlarmEvent, Input, Priority};
use crate::kernel::Kernel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Start,
    Verify,
}

#[derive(Debug, Clone)]
pub struct Step {
    pub stage: Stage,
    pub index: usize,
    pub total: usize,
    pub name: &'static str,
    pub result: Result<String, String>,
    /// Failing this means procwatch must not go on.
    pub fatal: bool,
}

type Probe = (&'static str, bool, fn(&Kernel) -> Result<String, String>);

fn kernel_alive(k: &Kernel) -> Result<String, String> {
    let h = k.health();
    Ok(format!("{} modules registered, nothing running yet", h.modules.len()))
}

fn bus_round_trip(k: &Kernel) -> Result<String, String> {
    const TOPIC: &str = "kernel.selfcheck";
    let rx = k.bus().subscribe(&[TOPIC], 1);
    k.bus().publish(TOPIC, "selfcheck", std::sync::Arc::new(7u8));
    match rx.recv_timeout(Duration::from_secs(2)).ok().and_then(|e| e.get::<u8>().copied()) {
        Some(7) => Ok("event delivered".into()),
        _ => Err("an event didn't arrive".into()),
    }
}

fn alarm_round_trip(k: &Kernel) -> Result<String, String> {
    let rx = k.alarms().subscribe();
    let key = format!("selfcheck|{}", std::process::id());
    k.alarms().send(Input::Raise { event: AlarmEvent::new(key.clone(), "selfcheck", "self-check", Priority::Low, "kernel"), lasts: None });
    let began = Instant::now();
    let seen = rx.recv_timeout(Duration::from_secs(2)).is_ok_and(|e| e.key == key);
    k.alarms().send(Input::Clear(key));
    let _ = rx.recv_timeout(Duration::from_secs(2));
    if seen {
        Ok(format!("alarm engine answered in {} ms", began.elapsed().as_millis()))
    } else {
        Err("the alarm engine didn't answer".into())
    }
}

fn settings(k: &Kernel) -> Result<String, String> {
    let problems = k.config().problems;
    crate::defense::config::DefenseConfig::load()?;
    crate::activity::filter::CaptureConfig::load()?;
    if problems.is_empty() {
        Ok("settings read".into())
    } else {
        Err(problems.join("; "))
    }
}

fn clock(_: &Kernel) -> Result<String, String> {
    let (a, wall) = (Instant::now(), std::time::SystemTime::now());
    std::thread::sleep(Duration::from_millis(20));
    if a.elapsed() < Duration::from_millis(15) {
        return Err("the monotonic clock isn't advancing".into());
    }
    wall.elapsed().map(|_| "clocks advancing".to_string()).map_err(|_| "the wall clock went backwards".to_string())
}

fn storage(_: &Kernel) -> Result<String, String> {
    let dir = crate::common::paths::data_dir().ok_or("no data folder")?;
    crate::common::paths::ensure_private_dir(&dir).map_err(|e| e.to_string())?;
    let probe = dir.join(format!(".selfcheck-{}", std::process::id()));
    std::fs::write(&probe, "x").map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::remove_file(&probe).map_err(|e| e.to_string())?;
    Ok(format!("{} is writable", dir.display()))
}

fn environment(_: &Kernel) -> Result<String, String> {
    let e = crate::common::environment::detect();
    let notes = e.notes();
    Ok(if notes.is_empty() { "ordinary host, privileged".to_string() } else { notes.join("; ") })
}

fn sound(_: &Kernel) -> Result<String, String> {
    let w = crate::common::sound::wav(crate::common::sound::Tone::Low, 0.5);
    if w.len() > 44 { Ok("alarm tones generated".into()) } else { Err("no tone".into()) }
}

fn program(_: &Kernel) -> Result<String, String> {
    match integrity::check_program() {
        Check::Recorded => Ok("first run: hash recorded".into()),
        Check::Same => Ok("matches the approved hash".into()),
        Check::Changed { was, now } => {
            let text = format!("the program changed: approved {}, running {}. If this is an upgrade, run --accept-program", &was[..12.min(was.len())], &now[..12.min(now.len())]);
            // A development build changes on every compile.
            if cfg!(debug_assertions) { Ok(format!("{text} (ignored in a debug build)")) } else { Err(text) }
        }
        Check::Unreadable(e) => Err(e),
    }
}

fn configuration(_: &Kernel) -> Result<String, String> {
    let w = integrity::take_warnings();
    if w.is_empty() { Ok("matches what was approved".into()) } else { Err(w.join("; ")) }
}

fn modules(k: &Kernel) -> Result<String, String> {
    use crate::kernel::ModuleState::{Crashed, Failed, Stuck};
    let list = k.status();
    let bad: Vec<&str> = list.iter().filter(|m| matches!(m.state, Crashed | Failed | Stuck)).map(|m| m.name).collect();
    if bad.is_empty() { Ok(format!("{} modules settled", list.len())) } else { Err(format!("not healthy: {}", bad.join(", "))) }
}

const START: &[Probe] = &[
    ("Kernel", true, kernel_alive),
    ("Event bus", true, bus_round_trip),
    ("Alarm engine", true, alarm_round_trip),
    ("Clocks", true, clock),
    ("Storage", false, storage),
    ("Settings", false, settings),
    ("Alarm tones", false, sound),
    ("Environment", false, environment),
    ("Program integrity", true, program),
];

const VERIFY: &[Probe] = &[("Modules", false, modules), ("Program integrity", true, program), ("Configuration integrity", false, configuration), ("Alarm engine", true, alarm_round_trip)];

pub fn spawn(kernel: Kernel, tx: Sender<WorkerMsg>, stage: Stage) {
    let list = if stage == Stage::Start { START } else { VERIFY };
    let _ = std::thread::Builder::new().name("selfcheck".into()).spawn(move || {
        for (index, (name, fatal, probe)) in list.iter().enumerate() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| probe(&kernel))).unwrap_or_else(|e| Err(crate::common::panic_text(&*e)));
            // Long enough to read: this screen is there to be seen.
            std::thread::sleep(Duration::from_millis(120));
            if tx.send(WorkerMsg::Boot(Step { stage, index, total: list.len(), name, result, fatal: *fatal })).is_err() {
                return;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::supervisor::Registry;
    use crate::kernel::{Bus, KernelConfig};

    #[test]
    fn the_core_checks_pass_on_a_fresh_kernel() {
        let k = Registry::default().boot(Bus::default(), KernelConfig::default());
        std::thread::sleep(Duration::from_millis(150));
        assert!(kernel_alive(&k).is_ok());
        assert!(bus_round_trip(&k).is_ok());
        assert!(alarm_round_trip(&k).is_ok());
        assert!(clock(&k).is_ok());
        k.shutdown();
    }
}
