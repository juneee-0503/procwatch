//! The files module: change notifications, with the responsible process
//! where the platform can say.

use super::watch::{self, FsEvent};
use crate::common::emit::Emit;
use crate::kernel::{Capability, Context, Module};

pub const CHANGE: &str = "files.change";
pub const STATUS: &str = "files.status";

#[derive(Debug, Clone, Default)]
pub struct WatchStatus {
    pub errors: Vec<String>,
    pub attribution: String,
}

pub struct FilesModule {
    paths: Vec<String>,
    watcher: Option<notify::RecommendedWatcher>,
}

impl FilesModule {
    pub fn new(paths: Vec<String>) -> Self {
        FilesModule { paths, watcher: None }
    }
}

impl Module for FilesModule {
    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::partly("change notifications", "watched folders only"),
            match super::attribution::unavailable_reason() {
                None => Capability::yes("which process changed a file"),
                Some(why) => Capability::partly("which process changed a file", why),
            },
        ]
    }

    fn start(&mut self, ctx: &Context) -> Result<(), String> {
        let c = ctx.clone();
        let events = Emit::new(move |e: FsEvent| {
            c.publish(CHANGE, e);
            c.current()
        });
        let (watcher, errors) = watch::start(&self.paths, events.clone());
        self.watcher = watcher;
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut attribution = String::new();
        #[cfg(target_os = "linux")]
        if super::attribution::unavailable_reason().is_none() {
            attribution = match super::attribution::start_fanotify(&self.paths, events) {
                Ok(()) => "fanotify on watched folders' mounts".into(),
                Err(e) => format!("fanotify unavailable: {e}"),
            };
        }
        #[cfg(not(target_os = "linux"))]
        drop(events);
        ctx.publish(STATUS, WatchStatus { errors, attribution });
        Ok(())
    }

    fn stop(&mut self) {
        self.watcher = None;
    }
}
