//! The microkernel: module registry, lifecycle, scheduling, event bus,
//! unified data model, configuration and alerts.
//!
//! It contains no collection logic and depends on nothing else in the
//! program, because it is the part that must never fail. See
//! `docs/architecture.md`.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing))]

pub mod alarm;
pub mod bus;
pub mod config;
pub mod decide;
pub mod dictionary;
pub mod model;
pub mod module;
pub mod supervisor;

pub use bus::{Bus, Event, Exclusive, Subscription};
pub use config::KernelConfig;
pub use model::{Sample, Unit};
pub use module::{Capability, Context, Module, Support};
pub use supervisor::{Kernel, ModuleState, ModuleStatus};
