//! Turns bus events into the application's worker messages. Everything the
//! UI learns from modules comes through here, so the application doesn't
//! depend on how modules are arranged.

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::messages::{Snapshot, WorkerMsg};
use crate::activity::{self, Activity};
use crate::files::module as files;
use crate::files::watch::FsEvent;
use crate::host::logs::{self, Entry};
use crate::kernel::alerts::{Alert, ALERTS};
use crate::kernel::supervisor::MODULE_STATE;
use crate::kernel::{Bus, Event, Kernel, ModuleState, ModuleStatus};
use crate::network::module as net;
use crate::network::traffic::Totals;
use crate::performance::gpu::GpuSnapshot;
use crate::performance::metrics::Metrics;
use crate::performance::module as perf;
use crate::performance::services::Service;
use crate::process::deeptrace::DtEvent;
use crate::process::module::{Table, SNAPSHOT};
use crate::process::trace_module as trace;

/// A snapshot waits this long for the first socket table.
const FIRST_SOCKETS: Duration = Duration::from_secs(2);

pub fn subscribe(bus: &Bus) -> Receiver<Event> {
    use activity::module as a;
    bus.subscribe(
        &[
            SNAPSHOT,
            net::CONNECTIONS,
            net::TRAFFIC,
            net::TRAFFIC_STATE,
            net::PROBLEM,
            perf::METRICS,
            perf::SERVICES,
            perf::GPU,
            files::CHANGE,
            files::STATUS,
            logs::module::RESULT,
            trace::EVENTS,
            trace::ERRORS,
            a::BATCH,
            a::STATE,
            ALERTS,
            MODULE_STATE,
        ],
        16_384,
    )
}

#[derive(Default)]
struct Joiner {
    sockets: HashMap<u32, Vec<crate::network::Connection>>,
    seen_sockets: bool,
    held: Option<(Arc<Table>, Instant)>,
}

impl Joiner {
    /// A process table with the latest sockets. Without this hold, a table
    /// arriving first would make every existing socket look brand new.
    fn release(&mut self, force: bool) -> Option<Snapshot> {
        let ready = self.seen_sockets || force || self.held.as_ref().is_some_and(|(_, at)| at.elapsed() >= FIRST_SOCKETS);
        if !ready {
            return None;
        }
        let (table, _) = self.held.take()?;
        let (tree, stats) = table.take()?;
        Some(Snapshot { tree, stats, connections: self.sockets.clone() })
    }
}

/// The message for one event, if it needs none of the joining above.
fn convert(e: &Event) -> Option<WorkerMsg> {
    use activity::module as a;
    Some(match e.topic {
        net::TRAFFIC => WorkerMsg::Traffic(e.get::<Totals>()?.clone()),
        net::TRAFFIC_STATE => WorkerMsg::TrafficState(e.get::<Result<&'static str, String>>()?.clone()),
        net::PROBLEM => WorkerMsg::Error(e.get::<String>()?.clone()),
        perf::METRICS => WorkerMsg::Metrics(Box::new(e.get::<Metrics>()?.clone())),
        perf::SERVICES => WorkerMsg::Services(e.get::<Result<Vec<Service>, String>>()?.clone()),
        perf::GPU => WorkerMsg::Gpu(e.get::<GpuSnapshot>()?.clone()),
        files::CHANGE => WorkerMsg::Fs(e.get::<FsEvent>()?.clone()),
        files::STATUS => WorkerMsg::WatchStatus(e.get::<files::WatchStatus>()?.clone()),
        logs::module::RESULT => WorkerMsg::Logs(e.get::<Result<Vec<Entry>, String>>()?.clone()),
        trace::EVENTS => WorkerMsg::Deep(e.get::<Vec<DtEvent>>()?.clone()),
        trace::ERRORS => WorkerMsg::Error(e.get::<String>()?.clone()),
        a::BATCH => WorkerMsg::Activity(e.get::<Vec<Activity>>()?.clone()),
        a::STATE => WorkerMsg::CaptureState(e.get::<a::State>()?.clone()),
        ALERTS => WorkerMsg::MetricAlert(e.get::<Alert>()?.clone()),
        MODULE_STATE => {
            let s = e.get::<ModuleStatus>()?;
            match s.state {
                ModuleState::Crashed | ModuleState::Failed => WorkerMsg::Error(format!("module {} {}: {}", s.name, s.state.label(), s.last_error.as_deref().unwrap_or(""))),
                _ => return None,
            }
        }
        _ => return None,
    })
}

pub fn spawn(rx: Receiver<Event>, kernel: Kernel, tx: Sender<WorkerMsg>) {
    let _ = std::thread::Builder::new().name("bridge".into()).spawn(move || {
        let mut join = Joiner::default();
        loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(e) => match e.topic {
                    SNAPSHOT => {
                        // Kept as shared: the publisher may still hold its copy.
                        if let Ok(t) = e.payload.downcast::<Table>() {
                            join.held = Some((t, Instant::now()));
                        }
                    }
                    net::CONNECTIONS => {
                        if let Some(s) = e.get::<net::Sockets>() {
                            join.sockets.clone_from(s);
                            join.seen_sockets = true;
                        }
                    }
                    MODULE_STATE if e.get::<ModuleStatus>().is_some_and(|s| s.name == "network" && s.state == ModuleState::Disabled) => {
                        // Turned off: what we hold is no longer the truth.
                        join.sockets.clear();
                        join.seen_sockets = true;
                    }
                    _ => {
                        if let Some(m) = convert(&e) {
                            if tx.send(m).is_err() {
                                kernel.shutdown();
                                return;
                            }
                        }
                    }
                },
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            if let Some(s) = join.release(false) {
                if tx.send(WorkerMsg::Snapshot(Box::new(s))).is_err() {
                    kernel.shutdown();
                    return;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessTree;

    fn table() -> Arc<Table> {
        Arc::new(Table::new((ProcessTree::default(), Default::default())))
    }

    #[test]
    fn the_first_table_waits_for_sockets() {
        let mut j = Joiner { held: Some((table(), Instant::now())), ..Default::default() };
        assert!(j.release(false).is_none(), "held back");
        j.seen_sockets = true;
        assert!(j.release(false).is_some());
        assert!(j.release(false).is_none(), "released once");
    }

    #[test]
    fn a_missing_network_module_doesnt_stop_the_table() {
        let mut j = Joiner { held: Some((table(), Instant::now() - FIRST_SOCKETS)), ..Default::default() };
        assert!(j.release(false).is_some());
    }
}
