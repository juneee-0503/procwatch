//! Foundations every module may use, depending on nothing above them.

pub mod command;
pub mod desktop;
pub mod emit;
#[cfg(windows)]
pub mod etw;
pub mod filter;
pub mod model;
pub mod paths;
pub mod perf;
pub mod text;

/// Last panic message from a worker thread, shown in the status bar.
pub static WORKER_PANIC: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
