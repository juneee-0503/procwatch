//! Rendering. Layout, top to bottom: title bar (page tabs + live system
//! summary), the page, and a hint bar that lists only the keys that make
//! sense right now.

mod analysis;
mod investigate;
mod details;
mod overlays;
mod pages;
mod pivot;
mod workspace;
mod processes;
mod widgets;

pub use widgets::truncate;

pub mod input;
pub mod terminal;

use std::sync::atomic::Ordering;

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};
use unicode_width::UnicodeWidthStr;

use crate::app::{App, Mode, StatusLevel, Tab};
use crate::process::human_bytes;
use widgets::{muted, ratio, ACCENT, BAD, OK, TEXT_DIM, WARN};

pub fn draw(frame: &mut Frame, app: &mut App) {
    let size = frame.area();
    if size.width < 60 || size.height < 15 {
        let msg = format!("Window too small ({}×{}) — enlarge to at least 60×15", size.width, size.height);
        frame.render_widget(Paragraph::new(msg), size);
        return;
    }

    let [title, body, hints] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(5), Constraint::Length(1)]).areas(size);
    draw_title(frame, app, title);

    app.hit.menus.clear();
    app.hit.pane_tabs.clear();
    app.hit.list_header.clear();
    app.hit.search = Rect::default();
    app.hit.view_toggle = Rect::default();
    app.hit.pane_body = Rect::default();
    match app.tab {
        Tab::Processes => processes::draw(frame, app, body),
        Tab::Performance => pages::performance(frame, app, body),
        Tab::Network => pages::network(frame, app, body),
        Tab::Files => pages::files(frame, app, body),
        Tab::Persistence if app.ir.persist_changes_view => analysis::changes(frame, app, body),
        Tab::Persistence => investigate::persistence(frame, app, body),
        Tab::Timeline => investigate::timeline(frame, app, body),
        Tab::Activity => investigate::activity(frame, app, body),
        Tab::Logs if app.ir.artifacts_view => pivot::artifacts(frame, app, body),
        Tab::Logs => investigate::logs(frame, app, body),
        Tab::Trace => analysis::trace(frame, app, body),
        Tab::Alerts if app.ir.det.focus => pivot::detections(frame, app, body),
        Tab::Alerts => analysis::alerts(frame, app, body),
        Tab::Case => investigate::case(frame, app, body),
    }
    draw_hints(frame, app, hints);

    if app.find.is_some() {
        overlays::find_results(frame, app, body);
    }
    match &app.mode {
        Mode::Menu(_) => overlays::menus(frame, app, size),
        Mode::Confirm { .. } => overlays::confirm(frame, app, size),
        Mode::Options { .. } => overlays::options(frame, app, size),
        Mode::Help => overlays::help(frame, size),
        Mode::Find { .. } => overlays::find_input(frame, app, size),
        Mode::RuleInput { .. } => analysis::rule_input(frame, app, size),
        Mode::Input { .. } => investigate::input(frame, app, size),
        Mode::FileReport => investigate::file_report(frame, app, size),
        Mode::Sweep => investigate::sweep(frame, app, size),
        Mode::Graph => pivot::graph(frame, app, size),
        Mode::Clusters => pivot::clusters(frame, app, size),
        Mode::Health => pivot::health(frame, app, size),
        Mode::ActivitySummary => investigate::activity_summary(frame, app, size),
        Mode::Modules { cursor } => pivot::modules(frame, app, size, *cursor),
        Mode::StateAt => pivot::state_at(frame, app, size),
        Mode::Workspace => workspace::draw(frame, app, size),
        Mode::LaunchConfirm(_) => overlays::launch_confirm(frame, app, size),
        Mode::Palette { .. } => overlays::palette(frame, app, size),
        _ => {}
    }
}

fn draw_title(frame: &mut Frame, app: &mut App, area: Rect) {
    let mut spans = vec![if app.ir.replay.is_some() {
        Span::styled(" REPLAY ", Style::new().fg(Color::Black).bg(WARN).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" procwatch ", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))
    }];
    let mut x = area.x + spans[0].content.width() as u16;
    app.hit.tabs.clear();
    // Full names when they fit next to the summary, short ones otherwise.
    let full: usize = Tab::ALL.iter().map(|t| t.title().width() + 4).sum::<usize>() + 60;
    let compact = (area.width as usize) < full;
    for t in Tab::ALL.iter() {
        let text = format!(" {} {} ", t.key(), if compact { t.short() } else { t.title() });
        let w = text.width() as u16;
        let style = if *t == app.tab {
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::new().fg(TEXT_DIM)
        };
        // Badges: unread alerts, trace recording.
        let badge = match t {
            Tab::Alerts if app.unread_alerts + app.ir.det.unread > 0 => {
                Some((format!("{} ", app.unread_alerts + app.ir.det.unread), Style::new().fg(Color::White).bg(BAD)))
            }
            Tab::Trace if app.trace.as_ref().is_some_and(|t| t.is_running()) => Some(("● ".to_string(), Style::new().fg(BAD))),
            Tab::Persistence if app.new_change_count() > 0 => {
                Some((format!("{} ", app.new_change_count()), Style::new().fg(Color::Black).bg(WARN)))
            }
            _ => None,
        };
        let w = w + badge.as_ref().map_or(0, |b| b.0.width() as u16);
        app.hit.tabs.push((Rect { x, y: area.y, width: w, height: 1 }, *t));
        spans.push(Span::styled(text, style));
        if let Some((b, st)) = badge {
            spans.push(Span::styled(b, st));
        }
        x += w;
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);

    // Live summary on the right (a replay has no live numbers).
    if app.ir.replay.is_some() {
        let line = Line::from(vec![Span::styled("recorded session · live system not sampled ", Style::new().fg(WARN))]);
        let w = line.width() as u16;
        if w + 1 < area.width.saturating_sub(x - area.x) {
            frame.render_widget(Paragraph::new(line), Rect { x: area.right() - w, width: w, ..area });
        }
        return;
    }
    let s = &app.stats;
    let level = |r: f64| if r >= 0.85 { BAD } else if r >= 0.6 { WARN } else { OK };
    let mem = ratio(s.mem_used, s.mem_total);
    let mut right = vec![
        muted("CPU "),
        Span::styled(format!("{:>3.0}%", s.cpu_pct), Style::new().fg(level(s.cpu_pct as f64 / 100.0))),
        muted("   Memory "),
        Span::styled(format!("{} / {}", human_bytes(s.mem_used), human_bytes(s.mem_total)), Style::new().fg(level(mem))),
        Span::raw("   "),
    ];
    if app.ctl.paused.load(Ordering::Relaxed) {
        right.push(Span::styled(" PAUSED ", Style::new().fg(Color::Black).bg(WARN)));
    } else if app.is_stale() {
        right.push(Span::styled("● not updating", Style::new().fg(BAD)));
    } else if !app.loaded {
        right.push(muted("○ starting"));
    } else {
        right.push(Span::styled("●", Style::new().fg(OK)));
        right.push(muted(format!(" {:.1}s", app.ctl.interval().as_secs_f64())));
    }
    right.push(Span::raw(" "));
    let line = Line::from(right);
    let w = line.width() as u16;
    if w + 1 < area.width.saturating_sub(x - area.x) {
        frame.render_widget(Paragraph::new(line), Rect { x: area.right() - w, width: w, ..area });
    }
}

/// Context hints on the left, latest status message on the right.
fn draw_hints(frame: &mut Frame, app: &App, area: Rect) {
    let h = |k: &'static str, d: &'static str| (k, d.to_string());
    let mut lead: Option<Span> = None;
    let items: Vec<(&str, String)> = match &app.mode {
        Mode::Search => {
            lead = Some(muted(" text or field:value — pid: name: user: path: port: ip: state: kind: type:  (-x excludes) "));
            vec![h("↑↓", "move"), h("enter", "done"), h("esc", "clear")]
        }
        Mode::Menu(stack) => {
            let mut v = vec![h("↑↓", "choose"), h("enter", "run")];
            if stack.len() > 1 {
                v.push(h("←", "back"));
            }
            v.push(h("esc", "close"));
            v
        }
        Mode::Confirm { .. } => vec![h("enter", "confirm"), h("esc", "cancel")],
        Mode::Options { .. } => vec![h("↑↓", "move"), h("space ←→", "change"), h("esc", "save & close")],
        Mode::Help => vec![h("any key", "close")],
        Mode::Find { .. } => vec![h("enter", "search"), h("esc", "cancel")],
        Mode::RuleInput { .. } => vec![h("enter", "add rule"), h("esc", "cancel")],
        Mode::Input { .. } => vec![h("enter", "save"), h("esc", "cancel"), h("ctrl+u", "clear")],
        Mode::Sweep => vec![h("↑↓", "select"), h("enter", "go to process"), h("m", "record all as findings"), h("r", "re-run"), h("esc", "close")],
        Mode::Graph => vec![h("↑↓", "select"), h("enter →", "pivot"), h("←", "back"), h("t", "timeline of this"), h("g", "go to page"), h("esc", "close")],
        Mode::Clusters => vec![h("↑↓", "select"), h("enter", "show cluster in timeline"), h("esc", "close")],
        Mode::Health | Mode::ActivitySummary => vec![h("any key", "close")],
        Mode::Modules { .. } => vec![h("↑↓", "select"), h("space", "enable / disable"), h("esc", "close")],
        Mode::LaunchConfirm(_) => vec![h("y", "run it under trace"), h("esc", "cancel")],
        Mode::Palette { .. } => vec![h("type", "filter"), h("↑↓", "choose"), h("enter", "run"), h("esc", "close")],
        Mode::StateAt => vec![h("↑↓ PgUp PgDn", "scroll"), h("esc", "close")],
        Mode::Workspace if app.ir.ws.tab == 1 => vec![h("←→", "step"), h("PgUp PgDn", "×10"), h("tab 1-6", "views"), h("D", "deep trace"), h("e", "quick report"), h("esc", "close")],
        Mode::Workspace => vec![h("tab 1-6", "views"), h("↑↓", "scroll"), h("D", "deep trace"), h("e", "quick report"), h("r", "refresh"), h("esc", "close")],
        Mode::FileReport => vec![h("↑↓", "scroll"), h("m", "record finding"), h("c", "copy SHA-256"), h("Q", "quarantine"), h("esc", "close")],
        Mode::Normal if app.find.is_some() => vec![h("↑↓", "choose"), h("enter", "go to process"), h("f", "new search"), h("esc", "close")],
        Mode::Normal => match app.tab {
            Tab::Processes if app.detail_full => vec![
                h("tab 1-0", "switch tab"),
                h("shift ↑↓", "scroll"),
                h("↑↓", "next process"),
                h("enter", "actions"),
                h("r", "reload"),
                h("esc", "back"),
            ],
            Tab::Processes if !app.tagged.is_empty() => {
                lead = Some(Span::styled(format!(" {} selected ", app.tagged.len()), Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)));
                vec![h("enter", "actions"), h("space", "toggle"), h("del", "end all"), h("esc", "clear selection")]
            }
            Tab::Processes => {
                let mut v = vec![
                    h("↑↓", "select"),
                    h("enter", "actions"),
                    h("/", "search"),
                    h("v", "view"),
                    h("s", "sort"),
                    h("space", "multi-select"),
                    h("z", if app.order_frozen { "unfreeze order" } else { "freeze order" }),
                    h("d", if app.pane_visible { "hide details" } else { "details" }),
                    h("f", "find port/file"),
                    h(":", "commands"),
                    h("?", "help"),
                    h("q", "quit"),
                ];
                if app.filtering() {
                    v.insert(0, h("esc", "clear filter"));
                }
                v
            }
            Tab::Network if app.ir.net_dns_view => vec![h("d", "connections"), h("/", "filter"), h("?", "help")],
            Tab::Network if app.ir.net_hosts_view => vec![h("↑↓", "select"), h("/", "filter"), h("h", "connections"), h("d", "DNS"), h("?", "help")],
            Tab::Network => vec![h("↑↓", "select"), h("enter", "go to process"), h("/", "filter"), h("h", "by remote host"), h("d", "DNS"), h("m", "finding"), h("?", "help")],
            Tab::Files if app.ir.files_changes_view => vec![h("↑↓", "select"), h("enter/a", "analyze"), h("Q", "quarantine"), h("w", "open files"), h("m", "finding"), h("/", "filter")],
            Tab::Files => vec![h("↑↓", "select"), h("enter", "process"), h("a", "analyze file"), h("A", "analyze path…"), h("Q", "quarantine"), h("w", "changes"), h("r", "rescan"), h("m", "finding")],
            Tab::Persistence if app.ir.persist_changes_view && app.baseline.is_none() => vec![h("b", "save baseline"), h("c", "autostart entries"), h("?", "help")],
            Tab::Persistence if app.ir.persist_changes_view => vec![h("↑↓", "select"), h("enter", "go to process"), h("b", "new baseline"), h("c", "autostart entries"), h("/", "filter")],
            Tab::Persistence => vec![h("↑↓", "select"), h("enter", "analyze target"), h("Q", "quarantine"), h("m", "finding"), h("c", "changes since baseline"), h("r", "rescan"), h("/", "filter")],
            Tab::Activity => vec![h("c", "start / stop capture"), h("s", "summary"), h("e", "save to case"), h("x", "clear"), h("/", "filter")],
            Tab::Timeline => vec![
                h("↑↓", "select"),
                h("enter", "process"),
                h("l", "graph"),
                h("t", "tree only"),
                h("c", "clusters"),
                h("s", "state then"),
                h("b", "bookmark"),
                h("/", "filter"),
                h("e", "CSV"),
                h("m", "finding"),
            ],
            Tab::Logs if app.ir.artifacts_view => vec![h("↑↓", "select"), h("enter", "analyze file"), h("A", "import folder…"), h("r", "re-collect"), h("x", "event log"), h("/", "filter"), h("l", "graph")],
            Tab::Logs => vec![h("x", "artifacts"),h("↑↓", "select"), h("enter", "process"), h("w", "time window"), h("a", "important/all"), h("r", "reload"), h("m", "finding"), h("/", "filter")],
            Tab::Case if app.ir.case.is_none() => vec![h("n", "new case"), h("?", "help")],
            Tab::Case => vec![h("I", "IOC sweep"), h("Y", "content scan"), h("X", "STIX/MISP/ECS"), h("c", "collect"), h("s", "seal"), h("v", "verify"), h("a", "note"), h("C", "conclusion"), h("i", "isolation plan"), h("e", "export report"), h("tab", "findings/quarantine")],
            Tab::Performance => vec![h("m", "charts / metrics / services"), h("↑↓", "scroll"), h("p", "pause"), h("?", "help"), h("q", "quit")],
            Tab::Trace if app.trace.is_none() => vec![h("1", "processes"), h("?", "help"), h("q", "quit")],
            Tab::Trace => {
                let running = app.trace.as_ref().is_some_and(|t| t.is_running());
                let mut v = vec![h("↑↓", "browse"), h("enter", "go to process"), h("c", "filter type"), h("/", "search")];
                v.push(if running { h("x", "stop") } else { h("T", "trace again") });
                v.extend([h("e", "export report"), h("?", "help")]);
                v
            }
            Tab::Alerts if app.ir.det.focus => vec![
                h("↑↓", "select"),
                h("enter", "go to subject"),
                h("l", "graph"),
                h("S", "suppress…"),
                h("T", "trust publisher…"),
                h("u", if app.ir.det.show_suppressed { "hide suppressed" } else { "show suppressed" }),
                h("m", "finding"),
                h("R", "reload rules"),
                h("tab", "alerts"),
            ],
            Tab::Alerts if app.rules_focus => vec![h("↑↓", "select rule"), h("a", "add"), h("space", "on/off"), h("del", "remove"), h("tab", "alerts")],
            Tab::Alerts => vec![h("↑↓", "select"), h("enter", "go to process"), h("a", "add rule"), h("c", "clear"), h("tab", "alert rules"), h("?", "help")],
        },
    };

    let mut spans: Vec<Span> = lead.into_iter().collect();
    for (k, d) in items {
        spans.push(Span::styled(format!(" {k}"), Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)));
        spans.push(Span::styled(format!(" {d} "), Style::new().fg(TEXT_DIM)));
    }
    let hints = Line::from(spans);

    if let Some(st) = &app.status {
        let (icon, color) = match st.level {
            StatusLevel::Info => ("", Color::Reset),
            StatusLevel::Success => ("✓ ", OK),
            StatusLevel::Error => ("! ", BAD),
        };
        let text = truncate(&format!("{icon}{} ", st.text), area.width as usize);
        let w = text.width() as u16;
        frame.render_widget(Paragraph::new(hints), Rect { width: area.width.saturating_sub(w + 1), ..area });
        frame.render_widget(Paragraph::new(Span::styled(text, Style::new().fg(color))), Rect { x: area.right() - w, width: w, ..area });
    } else {
        frame.render_widget(Paragraph::new(hints), area);
    }
}

/// Spinner frame for in-flight work.
pub(crate) fn spinner(app: &App) -> &'static str {
    const FRAMES: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
    FRAMES[(app.tick as usize) % FRAMES.len()]
}
