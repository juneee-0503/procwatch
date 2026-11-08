//! The logs module: reads system logs when asked.

use std::time::Duration;

use super::{fetch, Entry, Scope};
use crate::kernel::{Capability, Context, Event, Module};

pub const FETCH: &str = "logs.fetch";
pub const RESULT: &str = "logs.result";

#[derive(Debug, Clone, Copy)]
pub struct Fetch {
    pub minutes: u32,
    pub scope: Scope,
}

pub struct LogsModule;

impl Module for LogsModule {
    fn capabilities(&self) -> Vec<Capability> {
        vec![if cfg!(target_os = "macos") {
            Capability::yes("unified log")
        } else if cfg!(target_os = "linux") {
            Capability::partly("journal", "other users' entries need root or the systemd-journal group")
        } else if cfg!(windows) {
            Capability::partly("event logs", "the Security log needs administrator")
        } else {
            Capability::no("logs", "no probe for this platform")
        }]
    }

    fn subscribes(&self) -> Vec<&'static str> {
        vec![FETCH]
    }

    /// Reading a large log legitimately takes a while.
    fn watchdog(&self) -> Duration {
        Duration::from_secs(120)
    }

    fn on_event(&mut self, event: &Event, ctx: &Context) {
        if let Some(f) = event.get::<Fetch>() {
            ctx.publish::<Result<Vec<Entry>, String>>(RESULT, fetch(f.minutes, f.scope));
        }
    }
}
