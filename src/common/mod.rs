//! Foundations every module may use, depending on nothing above them.

pub mod audit;
pub mod command;
pub mod desktop;
pub mod emit;
pub mod environment;
#[cfg(windows)]
pub mod etw;
pub mod filter;
pub mod integrity;
pub mod maintenance;
pub mod model;
pub mod pacing;
pub mod paths;
pub mod perf;
pub mod redact;
pub mod sound;
pub mod text;
pub mod versioned;

/// Last panic message from a worker thread, shown in the status bar.
pub static WORKER_PANIC: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// The message of a caught panic.
pub fn panic_text(e: &(dyn std::any::Any + Send)) -> String {
    e.downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| e.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".into())
}
