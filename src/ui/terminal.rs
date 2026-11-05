//! The interactive program: terminal setup and teardown, and the event loop.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind, MouseEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use super::input::{handle_key, handle_mouse};
use crate::app::config::Config;
use crate::app::{self, App, Mode};
use crate::common::WORKER_PANIC;
use crate::engine::sampler::{self, SamplerCtl};
use crate::forensics::{case, store};
use crate::ui;

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
    let _ = execute!(io::stdout(), crossterm::cursor::Show);
}

pub fn run_interactive() -> anyhow::Result<()> {
    // Restore the terminal before a panic message is printed, otherwise it
    // lands in the alternate screen and the shell is left in raw mode.
    // Worker threads catch their own panics (see sampler::worker); only a
    // panic on the UI thread may tear the terminal down. Printing a worker
    // panic would scribble over the screen, so it's kept for the status bar.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().name() == Some("main") {
            restore_terminal();
            default_hook(info);
        } else if let Ok(mut last) = WORKER_PANIC.lock() {
            *last = Some(info.to_string());
        }
    }));

    enable_raw_mode()?;
    if let Err(e) = execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture) {
        restore_terminal();
        return Err(e.into());
    }

    let result = (|| {
        let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        terminal.hide_cursor()?;
        run(&mut terminal)
    })();

    restore_terminal();
    result
}

/// "2026-11-03T14:00:00+08:00", "2026-11-03 14:00", "2026-11-03T14:00" or "14:00" (today).
fn parse_when(s: &str) -> Option<chrono::DateTime<chrono::Local>> {
    use chrono::{Local, NaiveDateTime, NaiveTime, TimeZone};
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(t.with_timezone(&Local));
    }
    for f in ["%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(n) = NaiveDateTime::parse_from_str(s, f) {
            return Local.from_local_datetime(&n).single();
        }
    }
    let time = NaiveTime::parse_from_str(s, "%H:%M").or_else(|_| NaiveTime::parse_from_str(s, "%H:%M:%S")).ok()?;
    Local.from_local_datetime(&Local::now().date_naive().and_time(time)).single()
}

fn run<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>) -> anyhow::Result<()> {
    let cfg = Config::load();
    let (tx, rx) = mpsc::channel();
    let ctl = Arc::new(SamplerCtl {
        interval_ms: AtomicU64::new(cfg.interval_ms),
        paused: AtomicBool::new(false),
        refresh_now: AtomicBool::new(false), snapshots_queued: Default::default(),
    });
    let args: Vec<String> = std::env::args().collect();
    let replay: Option<Option<std::path::PathBuf>> = args
        .iter()
        .position(|a| a == "--replay")
        .map(|i| args.get(i + 1).filter(|a| !a.starts_with("--")).map(std::path::PathBuf::from).or_else(store::default_dir));
    if replay.is_none() {
        sampler::spawn_sampler(tx.clone(), ctl.clone())?;
    }
    let mut app = App::new(tx, ctl, Config { history: cfg.history && replay.is_none(), ..cfg.clone() });
    if let Some(path) = replay {
        let when = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).and_then(|s| parse_when(s));
        match path {
            Some(p) => match app.load_replay(&p, when("--from"), when("--to")) {
                Ok(d) => app.set_status(app::StatusLevel::Success, d),
                Err(e) => {
                    app.ir.replay = Some("REPLAY (nothing loaded)".into());
                    app.set_status(app::StatusLevel::Error, e);
                }
            },
            None => {
                app.ir.replay = Some("REPLAY (nothing loaded)".into());
                app.set_status(app::StatusLevel::Error, "no event history folder on this system".into());
            }
        }
    }
    if let Some(dir) = args.iter().position(|a| a == "--sigma").and_then(|i| args.get(i + 1)) {
        app.ir.det.sigma_dir = Some(std::path::PathBuf::from(dir));
        app.ir.det.reload_sigma();
        if !app.ir.det.sigma_errors.is_empty() {
            app.set_status(app::StatusLevel::Error, format!("{} Sigma rule(s) rejected — run procwatch --check-rules {dir}", app.ir.det.sigma_errors.len()));
        }
    }
    if let Some(i) = args.iter().position(|a| a == "--run") {
        let rest: Vec<String> = args[i + 1..].iter().skip_while(|a| *a == "--").cloned().collect();
        if !rest.is_empty() {
            app.mode = Mode::LaunchConfirm(rest);
        }
    }
    if let Some(dir) = args.iter().position(|a| a == "--case").and_then(|i| args.get(i + 1)) {
        match case::Case::open(std::path::Path::new(dir)) {
            Ok(c) => {
                let _ = c.log("case resumed", "");
                app.ir.case = Some(c);
                app.tab = app::Tab::Case;
            }
            Err(e) => app.set_status(app::StatusLevel::Error, format!("Couldn't open case {dir}: {e}")),
        }
    }

    let mut dirty = true;
    let mut last_tick = Instant::now();
    loop {
        // Handle what the workers produced, but never so long that keys and
        // drawing starve: under a flood the rest waits for the next pass.
        let drained = sampler::drain_for(&rx, Duration::from_millis(40), |msg| {
            app.on_worker_msg(msg);
            dirty = true;
        });
        if drained.disconnected {
            anyhow::bail!("sampler thread stopped unexpectedly");
        }

        if let Some(msg) = WORKER_PANIC.lock().ok().and_then(|mut m| m.take()) {
            app.set_status(app::StatusLevel::Error, format!("A background task failed: {}", msg.lines().next().unwrap_or("")));
            dirty = true;
        }

        // Spinner frames need ~10fps; otherwise wake rarely to save CPU.
        let tick_rate = if app.is_busy() { Duration::from_millis(100) } else { Duration::from_millis(250) };
        if last_tick.elapsed() >= tick_rate {
            dirty |= app.on_tick();
            last_tick = Instant::now();
        }

        if dirty {
            terminal.draw(|f| ui::draw(f, &mut app))?;
            dirty = false;
        }

        let timeout = if drained.more { Duration::ZERO } else { tick_rate.saturating_sub(last_tick.elapsed()).min(Duration::from_millis(50)) };
        if event::poll(timeout)? {
            // Handle a burst of input (held key, mouse wheel) before
            // redrawing once.
            loop {
                match event::read()? {
                    // Windows reports both press and release; act on press only.
                    Event::Key(key) if key.kind != KeyEventKind::Release => {
                        handle_key(&mut app, key);
                        dirty = true;
                    }
                    Event::Mouse(m) if !matches!(m.kind, MouseEventKind::Moved | MouseEventKind::Drag(_)) => {
                        handle_mouse(&mut app, m);
                        dirty = true;
                    }
                    Event::Resize(_, _) => dirty = true,
                    _ => {}
                }
                if app.should_quit || !event::poll(Duration::ZERO)? {
                    break;
                }
            }
        }

        if app.should_quit {
            app.stop_trace();
            if app.config() != cfg {
                app.save_config();
            }
            return Ok(());
        }
    }
}

