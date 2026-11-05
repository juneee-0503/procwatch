//! `procwatch --monitor`: the investigation pipeline without a screen,
//! writing every new timeline event as one JSON line in Elastic Common
//! Schema field names, for a SIEM or a log shipper. Stops on end of output,
//! after `--minutes`, or when it is killed.

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use chrono::Local;

use crate::app::App;
use crate::app::config::Config;
use crate::engine::sampler::{self, SamplerCtl};

/// Event ids remembered to avoid repeats; beyond what the timeline holds.
const MAX_SEEN: usize = 1_000_000;

fn open(out: Option<&Path>) -> std::io::Result<Box<dyn Write>> {
    Ok(match out {
        None => Box::new(std::io::stdout()),
        Some(p) => {
            Box::new(crate::common::paths::private_file().create(true).append(true).open(p)?)
        }
    })
}

pub fn run(out: Option<&Path>, minutes: Option<u64>, activity: bool) -> i32 {
    let mut sink = match open(out) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("monitor: {e}");
            return 2;
        }
    };
    // The stream is the record; the on-disk history stays the TUI's.
    let cfg = Config { interval_ms: 1000, history: false, ..Config::load() };
    let (tx, rx) = mpsc::channel();
    let ctl = Arc::new(SamplerCtl {
        interval_ms: AtomicU64::new(cfg.interval_ms),
        paused: AtomicBool::new(false),
        refresh_now: AtomicBool::new(false),
        snapshots_queued: Default::default(),
    });
    if let Err(e) = sampler::spawn_sampler(tx.clone(), ctl.clone()) {
        eprintln!("monitor: couldn't start sampler: {e}");
        return 2;
    }
    let mut app = App::new(tx, ctl, cfg);
    if activity {
        app.ir.activity_out = Some(Vec::new());
        app.toggle_capture();
        if let Some(e) = &app.ir.capture_error {
            eprintln!("monitor: activity capture unavailable: {e}");
            return 2;
        }
    }
    let started = Local::now();
    let end = minutes.map(|m| Instant::now() + Duration::from_secs(m.saturating_mul(60)));
    let mut seen: HashSet<u64> = HashSet::new();
    let mut last_tick = Instant::now();
    let mut last_emit = Instant::now();
    eprintln!("monitor: streaming ECS events{}", out.map(|p| format!(" to {}", p.display())).unwrap_or_default());
    while end.is_none_or(|e| Instant::now() < e) {
        let drained = sampler::drain_for(&rx, Duration::from_millis(100), |m| app.on_worker_msg(m));
        if drained.disconnected {
            eprintln!("monitor: sampler stopped");
            return 1;
        }
        if last_tick.elapsed() >= Duration::from_millis(250) {
            app.on_tick();
            last_tick = Instant::now();
        }
        if last_emit.elapsed() >= Duration::from_secs(2) {
            last_emit = Instant::now();
            if app.timeline_rebuild_due() {
                app.rebuild_timeline();
            }
            let mut lines = app.new_ecs_lines(started, &mut seen);
            lines.extend(app.take_activity_lines());
            for line in lines {
                // A closed pipe is the normal way for a reader to stop us.
                if writeln!(sink, "{line}").is_err() {
                    return 0;
                }
            }
            if sink.flush().is_err() {
                return 0;
            }
            if seen.len() > MAX_SEEN {
                app.retain_seen(&mut seen);
            }
        }
        if !drained.more {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    0
}
