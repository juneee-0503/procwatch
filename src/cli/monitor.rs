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
use crate::common::pacing::{self as sampler, SamplerCtl};

/// Event ids remembered to avoid repeats; beyond what the timeline holds.
const MAX_SEEN: usize = 1_000_000;
/// How often system metrics join the stream.
const METRICS_EVERY: Duration = Duration::from_secs(30);

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
    let kernel = crate::engine::start(tx.clone(), ctl.clone(), crate::app::watch_paths(&cfg));
    let mut app = App::new(tx, ctl, cfg);
    app.kernel = Some(kernel);
    // No one is watching, and a terminal bell would land in the JSON stream.
    app.board.sound = false;
    if activity {
        app.ir.activity_out = Some(Vec::new());
        // The module needs a moment to start, and answers asynchronously.
        let until = Instant::now() + Duration::from_secs(5);
        let mut asked = false;
        while app.ir.capture_method.is_none() && app.ir.capture_error.is_none() && Instant::now() < until {
            if !asked {
                asked = app.publish_capture_start();
            }
            sampler::drain_for(&rx, Duration::from_millis(100), |m| app.on_worker_msg(m));
            std::thread::sleep(Duration::from_millis(50));
        }
        if app.ir.capture_method.is_none() {
            eprintln!("monitor: activity capture unavailable: {}", app.ir.capture_error.as_deref().unwrap_or("the module didn't start"));
            return 2;
        }
    }
    let started = Local::now();
    let end = minutes.map(|m| Instant::now() + Duration::from_secs(m.saturating_mul(60)));
    let mut seen: HashSet<u64> = HashSet::new();
    let mut last_tick = Instant::now();
    let mut last_emit = Instant::now();
    let mut last_metrics = Instant::now() - METRICS_EVERY;
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
            if last_metrics.elapsed() >= METRICS_EVERY {
                if let Some(m) = &app.metrics {
                    last_metrics = Instant::now();
                    lines.push(serde_json::json!({ "@timestamp": chrono::Utc::now().to_rfc3339(), "event": { "kind": "metric", "dataset": "procwatch.metrics" }, "procwatch": { "metrics": m } }).to_string());
                }
            }
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
