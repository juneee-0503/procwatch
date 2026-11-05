//! The network module: the socket table and bytes per process.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::traffic::{self, Totals, Traffic};
use super::Connection;
use crate::common::emit::Emit;
use crate::common::pacing::SamplerCtl;
use crate::kernel::{Capability, Context, Module};

pub const CONNECTIONS: &str = "network.connections";
pub const TRAFFIC: &str = "network.traffic";
pub const TRAFFIC_STATE: &str = "network.traffic_state";
pub const PROBLEM: &str = "network.problem";

pub type Sockets = HashMap<u32, Vec<Connection>>;

pub struct NetworkModule {
    ctl: Arc<SamplerCtl>,
    traffic: Option<Traffic>,
    last: Option<Instant>,
    failing: bool,
}

impl NetworkModule {
    pub fn new(ctl: Arc<SamplerCtl>) -> Self {
        NetworkModule { ctl, traffic: None, last: None, failing: false }
    }
}

impl Module for NetworkModule {
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::yes("connections"), traffic::capability()]
    }

    fn start(&mut self, ctx: &Context) -> Result<(), String> {
        let c = ctx.clone();
        let out = Emit::new(move |t: Totals| {
            c.publish(TRAFFIC, t);
            c.current()
        });
        // Counting bytes may need rights; connections don't, so carry on.
        match traffic::start(out) {
            Ok(t) => {
                ctx.publish(TRAFFIC_STATE, Ok::<&'static str, String>(t.method));
                self.traffic = Some(t);
            }
            Err(e) => ctx.publish(TRAFFIC_STATE, Err::<&'static str, String>(e)),
        }
        Ok(())
    }

    fn interval(&self) -> Option<Duration> {
        Some(Duration::from_millis(100))
    }

    fn tick(&mut self, ctx: &Context) {
        if self.last.is_some_and(|t| t.elapsed() < self.ctl.interval()) {
            return;
        }
        self.last = Some(Instant::now());
        let mut lap = crate::common::perf::Lap::new();
        match super::try_connections() {
            Some(c) => {
                self.failing = false;
                ctx.publish(CONNECTIONS, c);
            }
            // Leave the last table standing: empty would read as every
            // connection closing at once.
            None if !self.failing => {
                self.failing = true;
                ctx.publish(PROBLEM, "couldn't read the socket table; showing the last known connections".to_string());
            }
            None => {}
        }
        lap.mark("sampler: connections");
    }

    fn stop(&mut self) {
        self.traffic = None;
    }
}
