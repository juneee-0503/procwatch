//! The activity module: per-process operations, started and stopped on
//! request because capturing costs real resources.

use super::{start, Activity, Capture};
use crate::common::emit::Emit;
use crate::kernel::{Capability, Context, Event, Module};

pub const COMMAND: &str = "activity.command";
pub const BATCH: &str = "activity.batch";
pub const STATE: &str = "activity.state";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Start,
    Stop,
}

/// The capture method while running; an error if it couldn't start.
pub type State = Result<Option<&'static str>, String>;

#[derive(Default)]
pub struct ActivityModule {
    capture: Option<Capture>,
}

impl Module for ActivityModule {
    fn capabilities(&self) -> Vec<Capability> {
        if cfg!(windows) {
            vec![Capability::partly("file operations", "needs administrator"), Capability::partly("registry writes", "needs administrator; reads aren't captured"), Capability::partly("network operations", "needs administrator")]
        } else if cfg!(target_os = "linux") {
            vec![Capability::partly("file operations", "needs root; creates and deletes need Linux 5.9"), Capability::no("registry writes", "Linux has no registry"), Capability::partly("network operations", "sampled, so short connections can be missed")]
        } else if cfg!(target_os = "macos") {
            vec![Capability::partly("file operations", "needs root"), Capability::no("registry writes", "macOS has no registry"), Capability::partly("network operations", "sampled, so short connections can be missed")]
        } else {
            vec![Capability::no("file operations", "no probe for this platform")]
        }
    }

    fn subscribes(&self) -> Vec<&'static str> {
        vec![COMMAND]
    }

    fn on_event(&mut self, event: &Event, ctx: &Context) {
        match event.get::<Command>() {
            Some(Command::Start) if self.capture.is_none() => {
                let c = ctx.clone();
                let out = Emit::new(move |b: Vec<Activity>| {
                    c.publish(BATCH, b);
                    c.current()
                });
                match start(out) {
                    Ok(cap) => {
                        ctx.publish::<State>(STATE, Ok(Some(cap.method)));
                        self.capture = Some(cap);
                    }
                    Err(e) => ctx.publish::<State>(STATE, Err(e)),
                }
            }
            Some(Command::Stop) => {
                self.capture = None;
                ctx.publish::<State>(STATE, Ok(None));
            }
            _ => {}
        }
    }

    fn stop(&mut self) {
        self.capture = None;
    }
}
