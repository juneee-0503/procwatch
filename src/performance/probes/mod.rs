//! What the performance module needs from a platform. Each file here is one
//! platform's answer; the module itself knows nothing of how.

use super::metrics::{Metrics, Raw};
use super::services::Service;
use crate::kernel::Capability;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod other;
#[cfg(windows)]
mod windows;

pub trait Probe: Send {
    /// What this platform can report.
    fn capabilities(&self) -> Vec<Capability>;
    /// Current values into `m`; cumulative counters into the result.
    fn read(&mut self, m: &mut Metrics) -> Raw;
    /// System services, or why they can't be listed.
    fn services(&self) -> Result<Vec<Service>, String>;
}

/// This platform's probe.
pub fn create() -> Box<dyn Probe> {
    #[cfg(target_os = "linux")]
    return Box::new(linux::Linux);
    #[cfg(target_os = "macos")]
    return Box::new(macos::MacOs);
    #[cfg(windows)]
    return Box::new(windows::Windows);
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    return Box::new(other::Other);
}
