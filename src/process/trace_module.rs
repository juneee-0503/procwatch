//! The trace module: event-driven lifecycle tracing of chosen processes.
//! The watcher starts on the first request, since most sessions need none.

use std::sync::mpsc::Sender;
use std::time::Duration;

use super::deeptrace::{DtEvent, Output, Watcher};
use crate::common::emit::Emit;
use crate::kernel::{Capability, Context, Event, Module, Support};

pub const REQUEST: &str = "trace.request";
pub const EVENTS: &str = "trace.events";
pub const ERRORS: &str = "trace.errors";

#[derive(Clone)]
pub enum Request {
    Watch(u32),
    Unwatch(u32),
    /// Answers true once the process is being watched.
    WatchConfirmed(u32, Sender<bool>),
}

#[derive(Default)]
pub struct TraceModule {
    watcher: Option<Watcher>,
}

impl Module for TraceModule {
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::new("lifecycle events", if cfg!(any(target_os = "linux", target_os = "macos", windows)) { Support::Yes } else { Support::No("no probe for this platform".into()) })]
    }

    fn subscribes(&self) -> Vec<&'static str> {
        vec![REQUEST]
    }

    fn watchdog(&self) -> Duration {
        Duration::from_secs(10)
    }

    fn on_event(&mut self, event: &Event, ctx: &Context) {
        let Some(r) = event.get::<Request>() else { return };
        if self.watcher.is_none() {
            let (a, b) = (ctx.clone(), ctx.clone());
            self.watcher = Watcher::start(Output {
                events: Emit::new(move |e: Vec<DtEvent>| {
                    a.publish(EVENTS, e);
                    a.current()
                }),
                errors: Emit::new(move |e: String| {
                    b.publish(ERRORS, e);
                    b.current()
                }),
            });
        }
        let Some(w) = &self.watcher else { return };
        match r {
            Request::Watch(pid) => w.watch(*pid),
            Request::Unwatch(pid) => w.unwatch(*pid),
            Request::WatchConfirmed(pid, reply) => {
                let _ = reply.send(w.watch_sync(*pid));
            }
        }
    }

    fn stop(&mut self) {
        self.watcher = None;
    }
}
