//! How each platform watches process lifecycles. The module above defines what to report.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub mod other;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub use other::*;
