mod app;
mod artifacts;
mod baseline;
mod binfmt;
mod case;
mod columns;
mod config;
mod contain;
mod correlate;
mod deeptrace;
mod detect;
mod dns;
mod export;
mod filter;
mod fileinfo;
mod fswatch;
mod gpu;
mod health;
mod inspect;
mod intel;
mod ioc;
mod logs;
mod memory;
mod model;
mod network;
mod offline;
mod os;
mod rules;
mod trace;
mod yara;
mod triage;
mod persistence;
mod process;
mod sampler;
mod selftest;
mod sigma;
mod ui;

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
        MouseButton, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, layout::Position, Terminal};

use app::{App, Cmd, Mode, OptionItem, StatusLevel, Tab, ViewMode};
use config::Config;
use sampler::SamplerCtl;

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
    let _ = execute!(io::stdout(), crossterm::cursor::Show);
}

/// Last panic message from a worker thread, shown in the status bar.
static WORKER_PANIC: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

const USAGE: &str = "procwatch — terminal process analyzer

Usage:
  procwatch                         interactive monitor (press ? for help)
  procwatch --snapshot FILE         save programs + listening ports as a baseline (FILE or - for stdout)
  procwatch --diff FILE [--json]    compare now with a baseline; exit status 1 if anything changed
  procwatch --case DIR              resume an existing investigation case
  procwatch --sigma DIR             use Sigma rules from DIR (default: sigma/ next to the settings file)
  procwatch --sweep IOCFILE [--json]  sweep processes, connections and autostart entries for indicators;
                                    exit status 1 if anything matched
  procwatch --offline CASE [--iocs FILE] [--sigma DIR] [--yara DIR] [--artifacts DIR]... [--json]
                                    re-analyse a saved case (and copied .evtx/.pf/history files) without
                                    the original machine; results are added to the case as derived evidence;
                                    exit status 1 if anything of medium severity or an indicator matched
  procwatch --check-rules [DIR]     parse Sigma rules and list the ones that can't be used, and why
  procwatch --selftest [--json]     measure process-capture rates, PID-reuse protection, file-event latency
                                    and own overhead on this machine (harmless workloads only)
  procwatch --scan PATH... [--yara DIR] [--json]
                                    match files (folders recursively) against YARA-subset content rules;
                                    exit status 1 if anything matched
  procwatch --help";

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("-h" | "--help") => {
            println!("{USAGE}");
            if let Some(p) = config::path() {
                println!("\nSettings file: {}", p.display());
            }
            return Ok(());
        }
        Some("--snapshot") => {
            let Some(target) = args.get(1) else {
                eprintln!("--snapshot needs a file name (or - for stdout)\n\n{USAGE}");
                std::process::exit(2);
            };
            let base = headless_capture();
            if target == "-" {
                println!("{}", serde_json::to_string_pretty(&base)?);
            } else {
                base.save(std::path::Path::new(target))?;
                eprintln!("Saved {} programs and {} listening ports to {target}", base.programs.len(), base.listeners.len());
            }
            return Ok(());
        }
        Some("--diff") => {
            let Some(file) = args.get(1) else {
                eprintln!("--diff needs a baseline file\n\n{USAGE}");
                std::process::exit(2);
            };
            let base = match baseline::Baseline::load(std::path::Path::new(file)) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Couldn't read baseline {file}: {e}");
                    std::process::exit(2);
                }
            };
            let changes = base.diff(&headless_capture());
            if args.iter().any(|a| a == "--json") {
                println!("{}", serde_json::to_string_pretty(&changes)?);
            } else {
                print!("{}", baseline::render_text(&base, &changes));
            }
            std::process::exit(if changes.is_empty() { 0 } else { 1 });
        }
        Some("--case" | "--sigma") if args.len() >= 2 => {}
        Some("--offline") => {
            let Some(dir) = args.get(1) else {
                eprintln!("--offline needs a case folder\n\n{USAGE}");
                std::process::exit(2);
            };
            let value = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).map(std::path::PathBuf::from);
            let artifacts = args.windows(2).filter(|w| w[0] == "--artifacts").map(|w| std::path::PathBuf::from(&w[1])).collect();
            std::process::exit(offline::run(offline::Options {
                case: offline::case_dir(dir),
                iocs: value("--iocs"),
                sigma: value("--sigma"),
                yara: value("--yara"),
                artifacts,
                json: args.iter().any(|a| a == "--json"),
            }));
        }
        Some("--scan") => {
            let value = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
            let yara_dir = value("--yara");
            let paths: Vec<&String> = args[1..].iter().filter(|a| !a.starts_with("--") && Some(*a) != yara_dir.as_ref()).collect();
            if paths.is_empty() {
                eprintln!("--scan needs at least one file or folder\n\n{USAGE}");
                std::process::exit(2);
            }
            std::process::exit(headless_scan(&paths, yara_dir.as_deref(), args.iter().any(|a| a == "--json")));
        }
        Some("--selftest") => std::process::exit(selftest::run(args.iter().any(|a| a == "--json"))),
        Some("--check-rules") => {
            let dir = args.get(1).map(std::path::PathBuf::from).or_else(sigma::default_dir);
            let builtin = sigma::builtin();
            println!("{} built-in rules", builtin.len());
            match dir.filter(|d| d.exists()) {
                Some(d) => {
                    let (rules, errors) = sigma::load_dir(&d);
                    println!("{}: {} usable rules, {} rejected", d.display(), rules.len(), errors.len());
                    for e in &errors {
                        println!("  ✗ {e}");
                    }
                    std::process::exit(i32::from(!errors.is_empty()));
                }
                None => println!("no rule folder (create {} or pass one)", sigma::default_dir().map(|d| d.display().to_string()).unwrap_or_default()),
            }
            return Ok(());
        }
        Some("--sweep") => {
            let Some(file) = args.get(1) else {
                eprintln!("--sweep needs an indicator file\n\n{USAGE}");
                std::process::exit(2);
            };
            std::process::exit(headless_sweep(file, args.iter().any(|a| a == "--json")));
        }
        Some(other) => {
            eprintln!("Unknown option {other}\n\n{USAGE}");
            std::process::exit(2);
        }
        None => {}
    }

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

/// `--sweep`: match indicators against processes (with executable
/// hashes), connections and persistence entries without the UI.
fn headless_sweep(file: &str, json: bool) -> i32 {
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Couldn't read {file}: {e}");
            return 2;
        }
    };
    let (iocs, errors) = ioc::parse(&text);
    for e in &errors {
        eprintln!("skipped {e}");
    }
    if iocs.is_empty() {
        eprintln!("No usable indicators in {file}");
        return 2;
    }
    eprintln!("Collecting processes, connections and autostart entries…");
    let mut monitor = process::ProcessMonitor::new();
    let (tree, _) = monitor.snapshot();
    let conns = network::connections_by_pid();
    let persistence = persistence::scan();
    let mut hashes: std::collections::HashMap<String, Option<fileinfo::Hashes>> = std::collections::HashMap::new();
    let mut obs = Vec::new();
    let total = tree.nodes.len();
    for (i, n) in tree.nodes.values().enumerate() {
        let info = &n.info;
        let h = info.exe_path.as_ref().and_then(|p| {
            hashes
                .entry(p.clone())
                .or_insert_with(|| {
                    let meta = std::fs::metadata(p).ok()?;
                    (meta.len() <= 512 << 20).then(|| fileinfo::hash_file(std::path::Path::new(p)).ok()).flatten()
                })
                .clone()
        });
        if i % 100 == 0 {
            eprint!("\rhashing executables {i}/{total}");
        }
        obs.push(ioc::Obs {
            source: "process",
            pid: Some(info.pid),
            name: info.name.clone(),
            sha256: h.as_ref().map(|h| h.sha256.clone()),
            md5: h.as_ref().map(|h| h.md5.clone()),
            sha1: h.as_ref().map(|h| h.sha1.clone()),
            path: info.exe_path.clone(),
            text: format!("{} {}", info.name, info.cmd.join(" ")),
            ..Default::default()
        });
    }
    eprintln!("\rhashed {} executables          ", hashes.len());
    for (pid, cs) in &conns {
        let name = tree.get(*pid).map(|n| n.info.name.clone()).unwrap_or_default();
        for c in cs {
            let ip = filter::split_endpoint(&c.remote).0;
            obs.push(ioc::Obs { source: "network", pid: Some(*pid), name: name.clone(), ip: Some(ip), text: format!("{} {}", c.local, c.remote), ..Default::default() });
        }
    }
    for it in &persistence.items {
        obs.push(ioc::Obs {
            source: "persistence",
            name: format!("{}: {}", it.category, it.name),
            sha256: it.sha256.clone(),
            path: it.target.clone(),
            text: format!("{} {}", it.command, it.location),
            ..Default::default()
        });
    }
    let hits = ioc::sweep(&iocs, &obs);
    if json {
        println!("{}", serde_json::to_string_pretty(&hits).unwrap_or_default());
    } else if hits.is_empty() {
        println!("No matches for {} indicators across {} observations.", iocs.len(), obs.len());
    } else {
        for h in &hits {
            let pid = h.pid.map(|p| format!(" pid {p}")).unwrap_or_default();
            println!("MATCH {:<7} {:<40} {:<12} {}{pid}  {}", h.kind.label(), h.ioc, h.source, h.name, h.detail);
        }
    }
    if hits.is_empty() { 0 } else { 1 }
}

/// One-shot capture for the command-line modes (no terminal UI).
fn headless_capture() -> baseline::Baseline {
    let mut monitor = process::ProcessMonitor::new();
    let (tree, _) = monitor.snapshot();
    let conns = network::connections_by_pid();
    baseline::Baseline::capture(&tree, &conns)
}

/// `--scan`: YARA-subset rules over files and folders.
fn headless_scan(paths: &[&String], yara_dir: Option<&str>, json: bool) -> i32 {
    let (rules, errors) = yara::load(yara_dir.map(std::path::Path::new));
    for e in &errors {
        eprintln!("skipped rule: {e}");
    }
    let mut files: Vec<String> = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = paths.iter().map(std::path::PathBuf::from).collect();
    while let Some(p) = stack.pop() {
        if p.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                stack.extend(rd.flatten().map(|e| e.path()));
            }
        } else {
            files.push(p.display().to_string());
        }
    }
    // procwatch's own binary contains the built-in rules as text.
    if let Some(me) = std::env::current_exe().ok().and_then(|p| std::fs::canonicalize(p).ok()) {
        files.retain(|f| std::fs::canonicalize(f).ok().as_ref() != Some(&me));
    }
    let scanned = files.len();
    let (hits, failed) = yara::scan_files(&rules, &files);
    for f in &failed {
        eprintln!("{f}");
    }
    let mut results: Vec<serde_json::Value> = hits.into_iter().map(|(p, m)| serde_json::json!({"path": p, "matches": m})).collect();
    results.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    if json {
        println!("{}", serde_json::to_string_pretty(&results).unwrap_or_default());
    } else {
        println!("{} files scanned with {} rules, {} matched", scanned, rules.len(), results.len());
        for r in &results {
            println!("{}", r["path"].as_str().unwrap_or(""));
            for m in r["matches"].as_array().into_iter().flatten() {
                println!("  {}  {}", m["rule"].as_str().unwrap_or(""), m["description"].as_str().unwrap_or(""));
            }
        }
    }
    i32::from(!results.is_empty())
}

fn run<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>) -> anyhow::Result<()> {
    let cfg = Config::load();
    let (tx, rx) = mpsc::channel();
    let ctl = Arc::new(SamplerCtl {
        interval_ms: AtomicU64::new(cfg.interval_ms),
        paused: AtomicBool::new(false),
        refresh_now: AtomicBool::new(false),
    });
    sampler::spawn_sampler(tx.clone(), ctl.clone())?;
    let mut app = App::new(tx, ctl, cfg.clone());
    let args: Vec<String> = std::env::args().collect();
    if let Some(dir) = args.iter().position(|a| a == "--sigma").and_then(|i| args.get(i + 1)) {
        app.ir.det.sigma_dir = Some(std::path::PathBuf::from(dir));
        app.ir.det.reload_sigma();
        if !app.ir.det.sigma_errors.is_empty() {
            app.set_status(app::StatusLevel::Error, format!("{} Sigma rule(s) rejected — run procwatch --check-rules {dir}", app.ir.det.sigma_errors.len()));
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
        // Drain everything the workers produced since the last frame.
        loop {
            match rx.try_recv() {
                Ok(msg) => {
                    app.on_worker_msg(msg);
                    dirty = true;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => anyhow::bail!("sampler thread stopped unexpectedly"),
            }
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

        let timeout = tick_rate.saturating_sub(last_tick.elapsed()).min(Duration::from_millis(50));
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

fn handle_key(app: &mut App, key: KeyEvent) {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    if ctrl && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }
    match app.mode.clone() {
        Mode::Help => app.mode = Mode::Normal,
        Mode::Options { cursor } => options_key(app, key, cursor),
        Mode::Menu(stack) => menu_key(app, key, stack),
        Mode::Confirm { cmd, targets } => match key.code {
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') if cmd == Cmd::SaveBaseline => app.save_baseline(),
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') if matches!(cmd, Cmd::Quarantine(_)) => {
                if let Cmd::Quarantine(p) = cmd {
                    app.do_quarantine(&p);
                }
            }
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => app.execute(cmd, targets),
            _ => app.mode = Mode::Normal,
        },
        Mode::Search => search_key(app, key),
        Mode::Find { input } => find_input_key(app, key, input),
        Mode::RuleInput { input, .. } => rule_input_key(app, key, input),
        Mode::Input { purpose, input, .. } => text_input_key(app, key, purpose, input),
        Mode::Sweep => {
            let len = app.ir.sweep.as_ref().map_or(0, |s| s.hits.len());
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => app.ir.sweep_selected = (app.ir.sweep_selected + 1).min(len.saturating_sub(1)),
                KeyCode::Up | KeyCode::Char('k') => app.ir.sweep_selected = app.ir.sweep_selected.saturating_sub(1),
                KeyCode::Char('r') => app.rerun_sweep(),
                KeyCode::Char('m') => app.sweep_to_findings(),
                KeyCode::Enter => {
                    let pid = app.ir.sweep.as_ref().and_then(|s| s.hits.get(app.ir.sweep_selected)).and_then(|h| h.pid);
                    if let Some(pid) = pid {
                        app.focus_pid(pid);
                    }
                }
                _ => app.mode = Mode::Normal,
            }
        }
        Mode::FileReport => match key.code {
            KeyCode::Down | KeyCode::Char('j') => app.ir.report_scroll += 1,
            KeyCode::Up | KeyCode::Char('k') => app.ir.report_scroll = app.ir.report_scroll.saturating_sub(1),
            KeyCode::PageDown => app.ir.report_scroll += 10,
            KeyCode::PageUp => app.ir.report_scroll = app.ir.report_scroll.saturating_sub(10),
            KeyCode::Char('m') => app.finding_from_report(),
            KeyCode::Char('Q') => {
                if let Some(Ok(r)) = app.ir.file_report.as_ref().map(|f| &f.result) {
                    let p = r.path.clone();
                    app.request_quarantine(p);
                }
            }
            KeyCode::Char('c') => {
                if let Some(Ok(r)) = app.ir.file_report.as_ref().map(|f| &f.result) {
                    if let Some(h) = &r.hashes {
                        let sha = h.sha256.clone();
                        app.mode = Mode::Normal;
                        if let Ok(dest) = os::copy_to_clipboard(&sha) {
                            app.set_status(StatusLevel::Success, format!("SHA-256 copied to {dest}"));
                        }
                    }
                }
            }
            _ => app.mode = Mode::Normal,
        },
        Mode::Graph => {
            let len = app.graph_current().cloned().map_or(0, |e| app.neighbors(&e).len());
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => app.ir.graph.cursor = (app.ir.graph.cursor + 1).min(len.saturating_sub(1)),
                KeyCode::Up | KeyCode::Char('k') => app.ir.graph.cursor = app.ir.graph.cursor.saturating_sub(1),
                KeyCode::PageDown => app.ir.graph.cursor = (app.ir.graph.cursor + 10).min(len.saturating_sub(1)),
                KeyCode::PageUp => app.ir.graph.cursor = app.ir.graph.cursor.saturating_sub(10),
                KeyCode::Enter | KeyCode::Right => app.graph_pivot(),
                KeyCode::Left | KeyCode::Backspace => app.graph_back(),
                KeyCode::Char('t') => app.graph_timeline(),
                KeyCode::Char('g') => app.graph_goto(),
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('l') => app.mode = Mode::Normal,
                _ => {}
            }
        }
        Mode::Clusters => {
            let len = app.ir.clusters.len();
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => app.ir.cluster_selected = (app.ir.cluster_selected + 1).min(len.saturating_sub(1)),
                KeyCode::Up | KeyCode::Char('k') => app.ir.cluster_selected = app.ir.cluster_selected.saturating_sub(1),
                KeyCode::Enter => {
                    if let Some(c) = app.ir.clusters.get(app.ir.cluster_selected) {
                        app.query = format!("cluster:{}", c.id);
                        app.ir.tl_selected = 0;
                    }
                    app.mode = Mode::Normal;
                }
                _ => app.mode = Mode::Normal,
            }
        }
        Mode::Health => app.mode = Mode::Normal,
        Mode::Workspace => workspace_key(app, key),
        Mode::StateAt => match key.code {
            KeyCode::Down | KeyCode::Char('j') => app.ir.state_scroll += 1,
            KeyCode::Up | KeyCode::Char('k') => app.ir.state_scroll = app.ir.state_scroll.saturating_sub(1),
            KeyCode::PageDown => app.ir.state_scroll += 15,
            KeyCode::PageUp => app.ir.state_scroll = app.ir.state_scroll.saturating_sub(15),
            _ => app.mode = Mode::Normal,
        },
        Mode::Normal if app.find.is_some() => find_results_key(app, key),
        Mode::Normal => normal_key(app, key),
    }
}

fn page(app: &App) -> isize {
    app.hit.list_rows.height.max(1) as isize
}

/// Anchor for a keyboard-opened menu: next to the selected row.
fn menu_anchor(app: &App) -> (u16, u16) {
    let r = app.hit.list_rows;
    let row = app.selected.saturating_sub(app.offset) as u16;
    (r.x + 4, (r.y + row + 1).min(r.bottom().saturating_sub(1)))
}

fn normal_key(app: &mut App, key: KeyEvent) {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);

    // Keys that work on every page.
    match key.code {
        KeyCode::Char('q') => {
            if app.detail_full {
                app.detail_full = false;
            } else {
                app.should_quit = true;
            }
            return;
        }
        KeyCode::Char('?') => {
            app.mode = Mode::Help;
            return;
        }
        KeyCode::Char(c @ '0'..='9') if !app.detail_full => {
            if let Some(t) = Tab::ALL.iter().find(|t| t.key() == c) {
                app.switch_tab(*t);
            }
            return;
        }
        KeyCode::Char('m') if app.tab == Tab::Alerts && app.ir.det.focus => {
            app.detection_to_finding();
            return;
        }
        KeyCode::Char('m') if !matches!(app.tab, Tab::Performance | Tab::Trace | Tab::Case) && !app.detail_full => {
            app.mark_finding();
            return;
        }
        KeyCode::Char('l') if !ctrl && !matches!(app.tab, Tab::Performance | Tab::Case | Tab::Trace) => {
            app.open_graph();
            return;
        }
        KeyCode::Char('H') => {
            app.mode = Mode::Health;
            return;
        }
        KeyCode::Char('W') if !matches!(app.tab, Tab::Performance | Tab::Case) => {
            app.open_workspace();
            return;
        }
        KeyCode::Char('D') if matches!(app.tab, Tab::Processes | Tab::Network | Tab::Timeline | Tab::Alerts) => {
            if let Some(crate::model::Entity::Process(k)) = app.selected_entity() {
                app.toggle_deep(k.pid);
            }
            return;
        }
        KeyCode::Char('/') => {
            app.mode = Mode::Search;
            return;
        }
        KeyCode::Char('p') => {
            app.toggle_pause();
            return;
        }
        KeyCode::Char('l') if ctrl => {
            app.request_refresh();
            return;
        }
        KeyCode::Char('f') => {
            app.mode = Mode::Find { input: String::new() };
            return;
        }
        KeyCode::Char('o') => {
            app.mode = Mode::Options { cursor: 0 };
            return;
        }
        KeyCode::Down | KeyCode::Char('j') if !(shift && app.details_visible()) => {
            app.move_selection(1);
            return;
        }
        KeyCode::Up | KeyCode::Char('k') if !(shift && app.details_visible()) => {
            app.move_selection(-1);
            return;
        }
        KeyCode::PageDown if !app.detail_full => return app.move_selection(page(app)),
        KeyCode::PageUp if !app.detail_full => return app.move_selection(-page(app)),
        KeyCode::Home | KeyCode::Char('g') if !app.detail_full => return app.move_selection(isize::MIN / 2),
        KeyCode::End | KeyCode::Char('G') if !app.detail_full => return app.move_selection(isize::MAX / 2),
        _ => {}
    }

    match app.tab {
        Tab::Processes => process_key(app, key),
        Tab::Network => match key.code {
            KeyCode::Enter => {
                if let Some(pid) = app.conn_rows.get(app.conn_selected).map(|r| r.pid) {
                    app.focus_pid(pid);
                }
            }
            KeyCode::Char('d') => {
                app.ir.net_dns_view = !app.ir.net_dns_view;
                app.ir.net_hosts_view = false;
            }
            KeyCode::Char('h') => {
                app.ir.net_hosts_view = !app.ir.net_hosts_view;
                app.ir.net_dns_view = false;
            }

            KeyCode::Esc => {
                app.clear_filters();
            }
            _ => {}
        },
        Tab::Trace => trace_key(app, key),
        Tab::Alerts => alerts_key(app, key),
        Tab::Files => match key.code {
            KeyCode::Char('r') => app.refresh_files(),
            KeyCode::Char('w') => app.ir.files_changes_view = !app.ir.files_changes_view,
            KeyCode::Char('a') => {
                if let Some(p) = app.selected_path() {
                    app.analyze_file(&p);
                }
            }
            KeyCode::Char('A') => {
                app.mode = Mode::Input { purpose: app::InputPurpose::AnalyzePath, input: String::new(), error: None }
            }
            KeyCode::Char('Q') => {
                if let Some(p) = app.selected_path() {
                    app.request_quarantine(p);
                }
            }
            KeyCode::Enter if !app.ir.files_changes_view => {
                if let Some(pid) = app.selected_file_pid() {
                    app.focus_pid(pid);
                }
            }
            KeyCode::Enter => {
                if let Some(p) = app.selected_path() {
                    app.analyze_file(&p);
                }
            }
            KeyCode::Esc => app.query.clear(),
            _ => {}
        },
        Tab::Persistence => match key.code {
            KeyCode::Char('c') => app.ir.persist_changes_view = !app.ir.persist_changes_view,
            KeyCode::Char('b') if app.ir.persist_changes_view => app.request_save_baseline(),
            KeyCode::Enter if app.ir.persist_changes_view => app.open_change(),
            KeyCode::Char('r') => app.scan_persistence(),
            KeyCode::Enter | KeyCode::Char('a') => {
                if let Some(p) = app.selected_path() {
                    app.analyze_file(&p);
                }
            }
            KeyCode::Char('Q') => {
                if let Some(p) = app.selected_path() {
                    app.request_quarantine(p);
                }
            }
            KeyCode::Esc => app.query.clear(),
            _ => {}
        },
        Tab::Timeline => match key.code {
            KeyCode::Enter => {
                let pid = app.visible_timeline().get(app.ir.tl_selected).and_then(|i| app.ir.timeline[*i].pid);
                if let Some(pid) = pid {
                    app.focus_pid(pid);
                }
            }
            KeyCode::Char('r') => app.rebuild_timeline(),
            KeyCode::Char('e') => app.export_timeline_csv(),
            KeyCode::Char('b') => app.request_bookmark(),
            KeyCode::Char('s') => app.open_state_at(),
            KeyCode::Char('B') => app.remove_bookmark(),
            KeyCode::Char('c') => {
                app.rebuild_timeline();
                app.ir.cluster_selected = 0;
                app.mode = Mode::Clusters;
            }
            KeyCode::Char('t') => {
                // Narrow the timeline to the selected event's process tree.
                let pid = app.visible_timeline().get(app.ir.tl_selected).and_then(|i| app.ir.timeline[*i].pid);
                if let Some(pid) = pid {
                    app.query = format!("tree:{pid}");
                    app.ir.tl_selected = 0;
                }
            }
            KeyCode::Esc => app.query.clear(),
            _ => {}
        },
        Tab::Logs if app.ir.artifacts_view => match key.code {
            KeyCode::Char('x') => app.ir.artifacts_view = false,
            KeyCode::Char('r') => app.collect_artifacts(),
            KeyCode::Char('A') => app.mode = Mode::Input { purpose: app::InputPurpose::ArtifactDir, input: String::new(), error: None },
            KeyCode::Enter => {
                let path = app.visible_artifacts().get(app.ir.art_selected).map(|i| app.ir.artifacts[*i].subject.clone());
                if let Some(p) = path.filter(|p| std::path::Path::new(p).exists()) {
                    app.analyze_file(&p);
                }
            }
            KeyCode::Esc => app.query.clear(),
            _ => {}
        },
        Tab::Logs => match key.code {
            KeyCode::Char('x') => app.ir.artifacts_view = true,
            KeyCode::Char('r') => app.fetch_logs(),
            KeyCode::Char('w') => app.cycle_log_window(),
            KeyCode::Char('a') => app.toggle_log_scope(),
            KeyCode::Enter => {
                let pid = app.visible_logs().get(app.ir.log_selected).and_then(|i| app.log_entries()[*i].pid);
                if let Some(pid) = pid {
                    app.focus_pid(pid);
                }
            }
            KeyCode::Esc => app.query.clear(),
            _ => {}
        },
        Tab::Case => {
            let input = |p: app::InputPurpose| Mode::Input { purpose: p, input: String::new(), error: None };
            match key.code {
                KeyCode::Char('n') => app.new_case(),
                KeyCode::Char('c') => app.collect_system(),
                KeyCode::Char('s') => app.seal_evidence(),
                KeyCode::Char('v') => app.verify_evidence(),
                KeyCode::Char('e') => app.export_case_report(),
                KeyCode::Char('a') => app.mode = input(app::InputPurpose::Note),
                KeyCode::Char('C') => {
                    let current = app.ir.case.as_ref().map(|c| c.conclusion.clone()).unwrap_or_default();
                    app.mode = Mode::Input { purpose: app::InputPurpose::Conclusion, input: current, error: None };
                }
                KeyCode::Char('i') => app.mode = input(app::InputPurpose::IsolationAllow),
                KeyCode::Char('I') => app.open_sweep_dialog(),
                KeyCode::Char('Y') => app.scan_executables(),
                KeyCode::Tab | KeyCode::BackTab => app.ir.case_focus_quarantine = !app.ir.case_focus_quarantine,
                KeyCode::Char('R') if app.ir.case_focus_quarantine => app.restore_selected(),
                KeyCode::Delete | KeyCode::Backspace if !app.ir.case_focus_quarantine => app.delete_finding(),
                _ => {}
            }
        }
        Tab::Performance => {}
    }
}

fn trace_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('x') => app.stop_trace(),
        KeyCode::Char('e') => app.export_trace(),
        KeyCode::Char('c') => {
            app.trace_filter = app.trace_filter.next();
            app.trace_follow = true;
        }
        KeyCode::Char('F') => app.trace_follow = !app.trace_follow,
        KeyCode::Char('T') => {
            if let Some(pid) = app.trace.as_ref().map(|t| t.root) {
                app.start_trace(pid);
            }
        }
        KeyCode::Esc => {
            app.query.clear();
        }
        KeyCode::Enter => {
            let pid = app
                .visible_trace()
                .get(app.trace_selected)
                .and_then(|i| app.trace.as_ref().map(|t| t.events[*i].pid));
            if let Some(pid) = pid {
                app.focus_pid(pid);
            }
        }
        _ => {}
    }
}

fn workspace_key(app: &mut App, key: KeyEvent) {
    let n = app.ir.ws.dossier.events.len();
    let ws = &mut app.ir.ws;
    let replay = ws.tab == 1;
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => app.mode = Mode::Normal,
        KeyCode::Tab => {
            ws.tab = (ws.tab + 1) % app::workspace::TABS.len();
            ws.scroll = 0;
        }
        KeyCode::BackTab => {
            ws.tab = (ws.tab + app::workspace::TABS.len() - 1) % app::workspace::TABS.len();
            ws.scroll = 0;
        }
        KeyCode::Char(c @ '1'..='6') => {
            ws.tab = (c as u8 - b'1') as usize;
            ws.scroll = 0;
        }
        KeyCode::Right | KeyCode::Char('n') if replay => ws.cursor = (ws.cursor + 1).min(n.saturating_sub(1)),
        KeyCode::Left | KeyCode::Char('p') if replay => ws.cursor = ws.cursor.saturating_sub(1),
        KeyCode::Home if replay => ws.cursor = 0,
        KeyCode::End if replay => ws.cursor = n.saturating_sub(1),
        KeyCode::PageDown if replay => ws.cursor = (ws.cursor + 10).min(n.saturating_sub(1)),
        KeyCode::PageUp if replay => ws.cursor = ws.cursor.saturating_sub(10),
        KeyCode::Down | KeyCode::Char('j') if replay => ws.cursor = (ws.cursor + 1).min(n.saturating_sub(1)),
        KeyCode::Up | KeyCode::Char('k') if replay => ws.cursor = ws.cursor.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => ws.scroll += 1,
        KeyCode::Up | KeyCode::Char('k') => ws.scroll = ws.scroll.saturating_sub(1),
        KeyCode::PageDown => ws.scroll += 15,
        KeyCode::PageUp => ws.scroll = ws.scroll.saturating_sub(15),
        KeyCode::Char('e') => app.export_quick_report(),
        KeyCode::Char('D') => {
            if let Some(k) = app.ir.ws.key {
                app.toggle_deep(k.pid);
                app.refresh_workspace();
            }
        }
        KeyCode::Char('r') => app.refresh_workspace(),
        _ => {}
    }
}

fn alerts_key(app: &mut App, key: KeyEvent) {
    // tab cycles: detections → alerts → alert rules → detections
    if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
        if app.ir.det.focus {
            app.ir.det.focus = false;
            app.rules_focus = false;
        } else if !app.rules_focus {
            app.rules_focus = true;
        } else {
            app.rules_focus = false;
            app.ir.det.focus = true;
        }
        return;
    }
    if app.ir.det.focus {
        match key.code {
            KeyCode::Enter => {
                if let Some(d) = app.selected_detection().cloned() {
                    match (d.pid.filter(|p| app.tree.get(*p).is_some()), &d.subject) {
                        (Some(pid), _) => app.focus_pid(pid),
                        (None, crate::model::Entity::File(p)) => app.analyze_file(&p.clone()),
                        _ => app.open_graph(),
                    }
                }
            }
            KeyCode::Char('S') => app.request_suppress(),
            KeyCode::Char('u') => {
                app.ir.det.show_suppressed = !app.ir.det.show_suppressed;
                app.ir.det.selected = 0;
            }
            KeyCode::Char('R') => app.reload_detection_rules(),
            KeyCode::Esc => app.query.clear(),
            _ => {}
        }
        return;
    }
    match key.code {
        KeyCode::Char('a') => app.mode = Mode::RuleInput { input: String::new(), error: None },
        KeyCode::Delete | KeyCode::Backspace if app.rules_focus => app.delete_rule(),
        KeyCode::Char(' ') if app.rules_focus => app.toggle_rule(),
        KeyCode::Char('c') if !app.rules_focus => {
            app.alerts.clear();
            app.alert_selected = 0;
        }
        KeyCode::Enter if !app.rules_focus => {
            if let Some(pid) = app.selected_alert_pid() {
                app.focus_pid(pid);
            }
        }
        _ => {}
    }
}

fn text_input_key(app: &mut App, key: KeyEvent, purpose: app::InputPurpose, mut input: String) {
    match key.code {
        KeyCode::Esc => {
            app.mode = Mode::Normal;
            return;
        }
        KeyCode::Enter => return app.submit_input(purpose, input),
        KeyCode::Backspace => {
            input.pop();
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => input.clear(),
        KeyCode::Char(c) if !c.is_control() => input.push(c),
        _ => {}
    }
    app.mode = Mode::Input { purpose, input, error: None };
}

fn rule_input_key(app: &mut App, key: KeyEvent, mut input: String) {
    match key.code {
        KeyCode::Esc => {
            app.mode = Mode::Normal;
            return;
        }
        KeyCode::Enter => {
            match app.add_rule(&input) {
                Ok(()) => {
                    app.mode = Mode::Normal;
                    app.rules_focus = true;
                }
                Err(e) => app.mode = Mode::RuleInput { input, error: Some(e) },
            }
            return;
        }
        KeyCode::Backspace => {
            input.pop();
        }
        KeyCode::Char(c) if !c.is_control() => input.push(c),
        _ => {}
    }
    app.mode = Mode::RuleInput { input, error: None };
}

fn process_key(app: &mut App, key: KeyEvent) {
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);
    if app.detail_full {
        let body = app.hit.pane_body.height.max(1) as isize;
        match key.code {
            KeyCode::Esc | KeyCode::Backspace => app.detail_full = false,
            KeyCode::Tab | KeyCode::Right => app.set_pane_tab(app.pane_tab.next()),
            KeyCode::BackTab | KeyCode::Left => app.set_pane_tab(app.pane_tab.prev()),
            KeyCode::Char(c @ '0'..='9') => {
                let i = if c == '0' { 9 } else { c as usize - '1' as usize };
                if let Some(t) = app::PaneTab::ALL.get(i) {
                    app.set_pane_tab(*t);
                }
            }
            KeyCode::PageDown => app.scroll_pane(body),
            KeyCode::PageUp => app.scroll_pane(-body),
            KeyCode::Home => app.pane_scroll = 0,
            KeyCode::End => app.pane_scroll = usize::MAX / 2,
            KeyCode::Down if shift => app.scroll_pane(1),
            KeyCode::Up if shift => app.scroll_pane(-1),
            KeyCode::Char('r') => {
                if app.pane_tab == app::PaneTab::Stack {
                    app.request_stack(true);
                } else {
                    app.request_deep_info(true);
                }
            }
            KeyCode::Enter => app.open_action_menu(menu_anchor(app)),
            KeyCode::Delete => app.quick_end(false),
            KeyCode::Char('X') => app.quick_end(true),
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Esc => {
            if !app.tagged.is_empty() {
                app.tagged.clear();
            } else {
                app.clear_filters();
            }
        }
        KeyCode::Enter => app.open_action_menu(menu_anchor(app)),
        KeyCode::Char(' ') => app.toggle_tag(),
        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.tagged = app.rows.iter().filter_map(|r| match r.key {
                app::RowKey::Proc(p) => Some(p),
                _ => None,
            }).collect();
        }
        KeyCode::Delete => app.quick_end(false),
        KeyCode::Char('X') => app.quick_end(true),
        KeyCode::Char('i') => app.open_details_full(),
        KeyCode::Char('d') => app.pane_visible = !app.pane_visible,
        KeyCode::Char('z') => app.toggle_freeze(),
        KeyCode::Char('T') => {
            if let Some(pid) = app.selected_pid() {
                app.start_trace(pid);
            }
        }
        KeyCode::Char('R') => {
            app.ir.intel.clear();
            app.set_status(StatusLevel::Info, "Re-checking signatures of all running programs…".into());
        }
        KeyCode::Tab => {
            app.pane_visible = true;
            app.set_pane_tab(app.pane_tab.next());
        }
        KeyCode::BackTab => {
            app.pane_visible = true;
            app.set_pane_tab(app.pane_tab.prev());
        }
        KeyCode::Down if shift => app.scroll_pane(1),
        KeyCode::Up if shift => app.scroll_pane(-1),
        KeyCode::Right | KeyCode::Char('+') | KeyCode::Char('=') => app.set_expanded(Some(true)),
        KeyCode::Left | KeyCode::Char('-') => app.set_expanded(Some(false)),
        KeyCode::Char('v') => app.set_view(app.view.next()),
        KeyCode::Char('t') => app.set_view(if app.view == ViewMode::Tree { ViewMode::List } else { ViewMode::Tree }),
        KeyCode::Char('s') => app.open_sort_menu((app.hit.list_rows.x + 2, app.hit.list_rows.y)),
        KeyCode::Char('r') => app.reverse_sort(),
        KeyCode::Char('e') => match export::export_csv(app) {
            Ok((path, n)) => {
                let name = path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
                app.set_status(StatusLevel::Success, format!("Exported {n} processes to {name}"));
            }
            Err(e) => app.set_status(StatusLevel::Error, format!("Export failed: {e}")),
        },
        _ => {}
    }
}

fn search_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter => app.mode = Mode::Normal,
        KeyCode::Esc => {
            app.query.clear();
            app.mode = Mode::Normal;
            app.rebuild();
        }
        KeyCode::Down => app.move_selection(1),
        KeyCode::Up => app.move_selection(-1),
        KeyCode::Backspace => {
            app.query.pop();
            app.rebuild();
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.query.clear();
            app.rebuild();
        }
        KeyCode::Char(c) if !c.is_control() => {
            app.query.push(c);
            app.rebuild();
        }
        _ => {}
    }
}

fn find_input_key(app: &mut App, key: KeyEvent, mut input: String) {
    match key.code {
        KeyCode::Esc => {
            app.mode = Mode::Normal;
            return;
        }
        KeyCode::Enter => {
            app.start_find(&input);
            return;
        }
        KeyCode::Backspace => {
            input.pop();
        }
        KeyCode::Char(c) if !c.is_control() => input.push(c),
        _ => {}
    }
    app.mode = Mode::Find { input };
}

fn find_results_key(app: &mut App, key: KeyEvent) {
    let Some(find) = app.find.as_mut() else { return };
    let len = find.result.as_ref().map_or(0, |r| r.len());
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => app.find = None,
        KeyCode::Down | KeyCode::Char('j') => find.cursor = (find.cursor + 1).min(len.saturating_sub(1)),
        KeyCode::Up | KeyCode::Char('k') => find.cursor = find.cursor.saturating_sub(1),
        KeyCode::Char('f') => app.mode = Mode::Find { input: String::new() },
        KeyCode::Enter => {
            let pid = find.result.as_ref().ok().and_then(|r| r.get(find.cursor)).map(|h| h.pid);
            if let Some(pid) = pid {
                app.find = None;
                app.focus_pid(pid);
            }
        }
        _ => {}
    }
}

fn menu_key(app: &mut App, key: KeyEvent, mut stack: Vec<app::MenuLevel>) {
    let depth = stack.len();
    let Some(top) = stack.last_mut() else {
        app.mode = Mode::Normal;
        return;
    };
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            stack.pop();
        }
        KeyCode::Left if depth > 1 => {
            stack.pop();
        }
        KeyCode::Down | KeyCode::Char('j') => top.step(1),
        KeyCode::Up | KeyCode::Char('k') => top.step(-1),
        KeyCode::Enter | KeyCode::Right | KeyCode::Char(' ') => {
            let Some(item) = top.items.get(top.cursor).cloned() else { return };
            if !item.enabled || item.is_separator() {
                return;
            }
            match item.cmd {
                Cmd::Sub(items) => {
                    let (x, y) = top.anchor;
                    let width = app.hit.menus.last().map_or(30, |r| r.width);
                    let anchor = (x + width, y + top.cursor as u16);
                    stack.push(app::MenuLevel::new(item.label, items, anchor));
                }
                cmd if key.code != KeyCode::Right => {
                    app.mode = Mode::Normal;
                    return app.run_cmd(cmd);
                }
                _ => {}
            }
        }
        _ => {}
    }
    app.mode = if stack.is_empty() { Mode::Normal } else { Mode::Menu(stack) };
}

fn options_key(app: &mut App, key: KeyEvent, mut cursor: usize) {
    let items = OptionItem::all();
    let close = |app: &mut App| {
        app.mode = Mode::Normal;
        app.rebuild();
        app.save_config();
    };
    let item = items[cursor.min(items.len() - 1)];
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('o') => return close(app),
        KeyCode::Down | KeyCode::Char('j') => cursor = (cursor + 1).min(items.len() - 1),
        KeyCode::Up | KeyCode::Char('k') => cursor = cursor.saturating_sub(1),
        KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') | KeyCode::Enter => {
            let back = key.code == KeyCode::Left;
            match item {
                OptionItem::Interval => app.adjust_interval(back),
                OptionItem::View => app.view = if back { app.view.next().next() } else { app.view.next() },
                OptionItem::DetailsPane => app.pane_visible = !app.pane_visible,
                OptionItem::ConfirmEnd => app.confirm_end = !app.confirm_end,
                OptionItem::HighlightNew => app.highlight_new = !app.highlight_new,
                OptionItem::Notify => app.notify = !app.notify,
                OptionItem::Column(c) => app.toggle_column(c),
            }
        }
        _ => {}
    }
    app.mode = Mode::Options { cursor };
}

fn handle_mouse(app: &mut App, m: MouseEvent) {
    let pos = Position::new(m.column, m.row);
    let scroll = match m.kind {
        MouseEventKind::ScrollDown => 3,
        MouseEventKind::ScrollUp => -3,
        _ => 0,
    };

    // Menus: click an item to run it, click outside to close.
    if let Mode::Menu(stack) = &app.mode {
        if let MouseEventKind::Down(_) = m.kind {
            let hit = app.hit.menus.iter().enumerate().rev().find(|(_, r)| r.contains(pos)).map(|(i, r)| (i, *r));
            match hit {
                Some((level, rect)) => {
                    let mut stack = stack.clone();
                    stack.truncate(level + 1);
                    let idx = (m.row.saturating_sub(rect.y + 1)) as usize;
                    if let Some(top) = stack.last_mut() {
                        if idx < top.items.len() && top.items[idx].enabled && !top.items[idx].is_separator() {
                            top.cursor = idx;
                            app.mode = Mode::Menu(stack.clone());
                            menu_key(app, KeyEvent::from(KeyCode::Enter), stack);
                            return;
                        }
                    }
                }
                None => app.mode = Mode::Normal,
            }
        }
        return;
    }
    if matches!(app.mode, Mode::Confirm { .. } | Mode::Options { .. } | Mode::Help | Mode::Find { .. } | Mode::RuleInput { .. }) {
        if let MouseEventKind::Down(_) = m.kind {
            if matches!(app.mode, Mode::Help) {
                app.mode = Mode::Normal;
            }
        }
        return;
    }

    if let MouseEventKind::Down(MouseButton::Left) = m.kind {
        if let Some((_, tab)) = app.hit.tabs.iter().find(|(r, _)| r.contains(pos)) {
            app.tab = *tab;
            if app.tab == Tab::Alerts {
                app.unread_alerts = 0;
            }
            app.detail_full = false;
            return;
        }
        if app.hit.search.contains(pos) {
            app.mode = Mode::Search;
            return;
        }
        if app.hit.view_toggle.contains(pos) {
            app.set_view(app.view.next());
            return;
        }
        if let Some((_, tab)) = app.hit.pane_tabs.iter().find(|(r, _)| r.contains(pos)) {
            app.set_pane_tab(*tab);
            return;
        }
        if let Some((_, col)) = app.hit.list_header.iter().find(|(r, _)| r.contains(pos)) {
            app.set_sort(*col);
            return;
        }
    }

    if app.find.is_some() {
        if let MouseEventKind::Down(MouseButton::Left) = m.kind {
            if app.hit.find_rows.contains(pos) {
                let idx = (m.row - app.hit.find_rows.y) as usize;
                let double = app.register_click(m.row);
                if let Some(f) = app.find.as_mut() {
                    f.cursor = idx.min(f.result.as_ref().map_or(0, |r| r.len().saturating_sub(1)));
                }
                if double {
                    find_results_key(app, KeyEvent::from(KeyCode::Enter));
                }
            } else {
                app.find = None;
            }
        }
        return;
    }

    let in_list = app.hit.list_rows.contains(pos);
    let in_pane = app.hit.pane_body.contains(pos);
    if scroll != 0 {
        if in_pane {
            app.scroll_pane(scroll);
        } else {
            app.move_selection(scroll);
        }
        return;
    }
    let MouseEventKind::Down(button) = m.kind else { return };
    if !in_list {
        return;
    }
    let row = (m.row - app.hit.list_rows.y) as usize;
    match app.tab {
        Tab::Processes if !app.detail_full => {
            let idx = app.offset + row;
            if idx >= app.rows.len() {
                return;
            }
            let double = button == MouseButton::Left && app.register_click(m.row);
            app.hold_order_now();
            app.select_index(idx);
            match button {
                MouseButton::Right => app.open_action_menu((m.column, m.row + 1)),
                _ if double => {
                    if app.rows[idx].expandable && app.selected_pid().is_none() {
                        app.set_expanded(None);
                    } else {
                        app.open_details_full();
                    }
                }
                _ => {}
            }
        }
        Tab::Network => {
            let idx = app.conn_offset + row;
            if idx < app.conn_rows.len() {
                app.conn_selected = idx;
                if button == MouseButton::Left && app.register_click(m.row) {
                    let pid = app.conn_rows[idx].pid;
                    app.focus_pid(pid);
                }
            }
        }
        Tab::Files => {
            let idx = app.file_offset + row;
            if idx < app.visible_files().len() {
                app.file_selected = idx;
                if button == MouseButton::Left && app.register_click(m.row) {
                    if let Some(pid) = app.selected_file_pid() {
                        app.focus_pid(pid);
                    }
                }
            }
        }
        Tab::Persistence | Tab::Timeline | Tab::Logs => {
            let (offset, len) = match app.tab {
                Tab::Persistence if app.ir.persist_changes_view => (app.change_offset, app.visible_changes().len()),
                Tab::Persistence => (app.ir.persist_offset, app.visible_persistence().len()),
                Tab::Timeline => (app.ir.tl_offset, app.visible_timeline().len()),
                _ => (app.ir.log_offset, app.visible_logs().len()),
            };
            let idx = offset + row;
            if idx < len {
                match app.tab {
                    Tab::Persistence if app.ir.persist_changes_view => app.change_selected = idx,
                    Tab::Persistence => app.ir.persist_selected = idx,
                    Tab::Timeline => app.ir.tl_selected = idx,
                    _ => app.ir.log_selected = idx,
                }
                if button == MouseButton::Left && app.register_click(m.row) {
                    normal_key(app, KeyEvent::from(KeyCode::Enter));
                }
            }
        }
        _ => {}
    }
}

