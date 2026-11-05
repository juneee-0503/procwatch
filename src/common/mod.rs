//! Foundations every module may use, depending on nothing above them.

pub mod command;
pub mod emit;
#[cfg(windows)]
pub mod etw;
pub mod paths;
