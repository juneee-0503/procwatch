//! System-wide performance: what the machine as a whole is doing, as opposed
//! to any one process.

pub mod exporter;
pub mod gpu;
pub mod history;
pub mod metrics;
pub mod module;
mod parse;
mod probes;
pub mod services;
