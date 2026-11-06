//! Platforms without a probe: everything is declared unsupported.

use crate::kernel::Capability;

use super::super::metrics::{Metrics, Raw};
use super::super::services::Service;
use super::Probe;

pub struct Other;

impl Probe for Other {
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::no("system metrics", "no probe for this platform")]
    }
    fn read(&mut self, _m: &mut Metrics) -> Raw {
        Raw::default()
    }
    fn services(&self) -> Result<Vec<Service>, String> {
        Err("no probe for this platform".into())
    }
}
