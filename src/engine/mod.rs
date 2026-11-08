//! Where the kernel meets the program: which modules exist, and how their
//! events reach the application. The kernel knows neither.

pub mod bridge;
pub mod health;
pub mod jobs;
pub mod messages;
pub mod selfcheck;

use std::sync::mpsc::Sender;
use std::sync::Arc;

use crate::activity::module::ActivityModule;
use crate::common::pacing::SamplerCtl;
use crate::files::module::FilesModule;
use crate::host::logs::module::LogsModule;
use crate::kernel::supervisor::Registry;
use crate::kernel::{Bus, Capability, Kernel, KernelConfig, Module};
use crate::network::module::NetworkModule;
use crate::performance::exporter::ExporterModule;
use crate::performance::history::{self, HistoryModule};
use crate::performance::module::{GpuModule, PerformanceModule};
use crate::process::module::ProcessModule;
use crate::process::trace_module::TraceModule;
use messages::WorkerMsg;

/// Adding a module is one line here.
pub fn registry(ctl: Arc<SamplerCtl>, watch: Vec<String>) -> Registry {
    let mut r = Registry::default();
    r.self_probe(self_probe());
    let c = ctl.clone();
    r.add("process", "process table and system totals", move || Box::new(ProcessModule::new(c.clone())));
    r.add("network", "connections and traffic per process", move || Box::new(NetworkModule::new(ctl.clone())));
    r.add("performance", "scheduling, memory, disks, sensors, services", || Box::new(PerformanceModule::new()));
    r.add("gpu", "system GPU load", || Box::<GpuModule>::default());
    r.add("files", "file changes in watched folders", move || Box::new(FilesModule::new(watch.clone())));
    // Read when each starts, not once: a reload is how new settings apply.
    use crate::defense::config::DefenseConfig;
    r.add("defense", "attacks on this machine: logins, web, floods, compromise", || {
        Box::new(match DefenseConfig::load() {
            Ok(c) => crate::defense::module::DefenseModule::new(c),
            Err(e) => crate::defense::module::DefenseModule::unusable(e),
        })
    });
    r.add("alarm", "alarm record and notifications", || Box::new(crate::defense::alarm::AlarmModule::new(DefenseConfig::load().unwrap_or_default().alarms)));
    r.add("exporter", "Prometheus metrics endpoint", || {
        let e = DefenseConfig::load().unwrap_or_default().exporter;
        Box::new(ExporterModule::new(e.listen, e.token))
    });
    let settings = crate::defense::config::DefenseConfig::load().unwrap_or_default();
    crate::common::redact::configure(settings.privacy.redact, settings.privacy.command_lines);
    r.add("history", "keeps metrics on disk", || {
        let keep = DefenseConfig::load().unwrap_or_default().retention;
        Box::new(HistoryModule::new(history::default_dir(), keep.days, keep.max_mb.saturating_mul(1 << 19)))
    });
    r.add("persistence", "autostart entries, and changes to them", || Box::new(Feature("autostart scanning")));
    r.add("timeline", "every source merged into one timeline", || Box::new(Feature("timeline")));
    r.add("detection", "host, Sigma and content rules", || Box::new(Feature("detection rules")));
    r.add("case", "cases, evidence and reports", || Box::new(Feature("case management")));
    r.add("logs", "system logs, read on request", || Box::new(LogsModule));
    r.add("trace", "event-driven process lifecycle tracing", || Box::<TraceModule>::default());
    r.add("activity", "file, registry and network operations by process", || Box::<ActivityModule>::default());
    r
}

/// A function of the application that an operator can choose, with no work
/// of its own for the kernel to schedule. Being loaded is what lets the
/// application run it.
struct Feature(&'static str);

impl Module for Feature {
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::yes(self.0)]
    }
}

fn self_probe() -> crate::kernel::supervisor::SelfProbe {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
    let me = Pid::from_u32(std::process::id());
    let mut sys = System::new();
    Box::new(move || {
        sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[me]), ProcessRefreshKind::everything());
        sys.process(me).map_or((0.0, 0), |p| (p.cpu_usage(), p.memory()))
    })
}

/// Where the kernel's settings are kept.
pub fn config_path() -> Option<std::path::PathBuf> {
    crate::common::paths::config_path().map(|p| crate::kernel::config::path_beside(&p))
}

/// A file that fails its checks is reported, and modules start without it.
pub fn load_config() -> KernelConfig {
    let Some(path) = config_path().filter(|p| p.exists()) else { return KernelConfig::default() };
    match crate::common::integrity::read_config(&path) {
        Ok(text) => KernelConfig::parse(&text),
        Err(e) => KernelConfig { problems: vec![e], ..KernelConfig::default() },
    }
}

/// Save what `Kernel::set_enabled` changed.
pub fn save_config(c: &KernelConfig) -> std::io::Result<()> {
    let Some(p) = config_path() else { return Ok(()) };
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    crate::common::paths::write_atomic(&p, &c.serialize())?;
    crate::common::integrity::seal_config(&p).map_err(std::io::Error::other)
}

/// Start the kernel alone: modules wait to be chosen and activated.
pub fn boot(tx: Sender<WorkerMsg>, ctl: Arc<SamplerCtl>, watch: Vec<String>) -> Kernel {
    let bus = Bus::default();
    let config = load_config();
    let problems = config.problems.clone();
    let bridge = bridge::subscribe(&bus);
    let kernel = registry(ctl, watch).boot(bus, config);
    bridge::spawn(bridge, kernel.clone(), tx.clone());
    for p in problems {
        let _ = tx.send(WorkerMsg::Error(format!("modules.conf {p}")));
    }
    kernel
}

/// Start the kernel and every enabled module.
pub fn start(tx: Sender<WorkerMsg>, ctl: Arc<SamplerCtl>, watch: Vec<String>) -> Kernel {
    let bus = Bus::default();
    let config = load_config();
    let problems = config.problems.clone();
    // Subscribed before anything can publish.
    let bridge = bridge::subscribe(&bus);
    let kernel = registry(ctl, watch).start(bus, config);
    bridge::spawn(bridge, kernel.clone(), tx.clone());
    for p in problems {
        let _ = tx.send(WorkerMsg::Error(format!("modules.conf {p}")));
    }
    kernel
}
