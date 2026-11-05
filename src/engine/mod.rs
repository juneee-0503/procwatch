//! Where the kernel meets the program: which modules exist, and how their
//! events reach the application. The kernel knows neither.

pub mod bridge;
pub mod health;
pub mod jobs;
pub mod messages;

use std::sync::mpsc::Sender;
use std::sync::Arc;

use crate::activity::module::ActivityModule;
use crate::common::pacing::SamplerCtl;
use crate::files::module::FilesModule;
use crate::host::logs::module::LogsModule;
use crate::kernel::supervisor::Registry;
use crate::kernel::{Bus, Kernel, KernelConfig};
use crate::network::module::NetworkModule;
use crate::performance::module::{GpuModule, PerformanceModule};
use crate::process::module::ProcessModule;
use crate::process::trace_module::TraceModule;
use messages::WorkerMsg;

/// Adding a module is one line here.
pub fn registry(ctl: Arc<SamplerCtl>, watch: Vec<String>) -> Registry {
    let mut r = Registry::default();
    let c = ctl.clone();
    r.add("process", "process table and system totals", move || Box::new(ProcessModule::new(c.clone())));
    r.add("network", "connections and traffic per process", move || Box::new(NetworkModule::new(ctl.clone())));
    r.add("performance", "scheduling, memory, disks, sensors, services", || Box::new(PerformanceModule::new()));
    r.add("gpu", "system GPU load", || Box::<GpuModule>::default());
    r.add("files", "file changes in watched folders", move || Box::new(FilesModule::new(watch.clone())));
    r.add("logs", "system logs, read on request", || Box::new(LogsModule));
    r.add("trace", "event-driven process lifecycle tracing", || Box::<TraceModule>::default());
    r.add("activity", "file, registry and network operations by process", || Box::<ActivityModule>::default());
    r
}

/// Where the kernel's settings are kept.
pub fn config_path() -> Option<std::path::PathBuf> {
    crate::common::paths::config_path().map(|p| crate::kernel::config::path_beside(&p))
}

pub fn load_config() -> KernelConfig {
    KernelConfig::load(config_path().as_deref())
}

/// Save what `Kernel::set_enabled` changed.
pub fn save_config(c: &KernelConfig) -> std::io::Result<()> {
    let Some(p) = config_path() else { return Ok(()) };
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    crate::common::paths::write_atomic(&p, &c.serialize())
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
