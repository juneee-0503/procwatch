//! Floating UI: action menus, confirmation, options, help, find.

use std::sync::atomic::Ordering;

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
    Frame,
};
use unicode_width::UnicodeWidthStr;

use super::spinner;
use super::widgets::*;
use crate::app::{reveal_label, App, Cmd, Mode, OptionItem};

fn frame_block(title: &str, color: Color) -> Block<'static> {
    Block::new()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::new().fg(color))
        .title(Span::styled(format!(" {title} "), Style::new().add_modifier(Modifier::BOLD)))
}

pub fn menus(frame: &mut Frame, app: &mut App, screen: Rect) {
    let Mode::Menu(stack) = &app.mode else { return };
    let stack = stack.clone();
    for level in &stack {
        let label_w = level.items.iter().map(|i| i.label.width()).max().unwrap_or(10);
        let key_w = level.items.iter().map(|i| i.shortcut.width()).max().unwrap_or(0);
        let inner_w = (2 + label_w + 3 + key_w + 1).max(level.title.width() + 4).min(screen.width as usize - 2);
        let w = inner_w as u16 + 2;
        let h = (level.items.len() as u16 + 2).min(screen.height);
        let x = level.anchor.0.min(screen.right().saturating_sub(w));
        let y = if level.anchor.1 + h > screen.bottom() { screen.bottom().saturating_sub(h) } else { level.anchor.1 };
        let rect = Rect { x, y, width: w, height: h };
        app.hit.menus.push(rect);

        frame.render_widget(Clear, rect);
        let title = truncate(&level.title, inner_w.saturating_sub(2));
        let block = frame_block(&title, ACCENT);
        let lines: Vec<Line> = level
            .items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                if item.is_separator() {
                    return Line::from(muted("─".repeat(inner_w)));
                }
                let check = if item.checked { "✓ " } else { "  " };
                let text = format!("{check}{}", item.label);
                let pad = inner_w.saturating_sub(text.width() + item.shortcut.width() + 1);
                let spans = vec![
                    Span::raw(text),
                    Span::raw(" ".repeat(pad)),
                    Span::styled(item.shortcut.to_string(), Style::new().fg(MUTED)),
                    Span::raw(" "),
                ];
                let style = if !item.enabled {
                    Some(Style::new().fg(MUTED))
                } else if i == level.cursor {
                    Some(sel_style())
                } else if matches!(item.cmd, Cmd::ForceQuit | Cmd::EndTree) {
                    Some(Style::new().fg(BAD))
                } else {
                    None
                };
                restyle(spans, style)
            })
            .collect();
        frame.render_widget(Paragraph::new(lines).block(block), rect);
    }
}

pub fn confirm(frame: &mut Frame, app: &mut App, screen: Rect) {
    let Mode::Confirm { cmd, targets } = &app.mode else { return };
    let who = app.describe_targets(targets);
    let children: usize = targets.iter().map(|p| app.tree.descendants(*p).len()).sum();
    let (title, verb, lines): (&str, &str, Vec<String>) = match cmd {
        Cmd::ForceQuit => (
            "Force quit?",
            "Force quit",
            vec![format!("{who} will be stopped immediately."), "Unsaved work in it will be lost.".into()],
        ),
        Cmd::Quarantine(path) => (
            "Quarantine file?",
            "Quarantine",
            vec![
                path.to_string(),
                "will be moved into the case's quarantine folder with all permissions removed.".into(),
                "It can be restored from the Case page. Running copies keep running — end them first.".into(),
            ],
        ),
        Cmd::SaveBaseline => (
            "Replace baseline?",
            "Save new baseline",
            vec![
                "The current state becomes the new reference point.".into(),
                "The previous baseline is kept as baseline.prev.json.".into(),
            ],
        ),
        Cmd::EndTree => (
            "End process tree?",
            "End tree",
            vec![format!("{who} and {children} child process(es) will be asked to quit.")],
        ),
        _ => (
            "End process?",
            "End process",
            vec![format!("{who} will be asked to quit."), "It can save its work first; use Force quit if it doesn't respond.".into()],
        ),
    };
    let w = lines.iter().map(|l| l.width()).max().unwrap_or(30).max(44) as u16 + 6;
    let rect = centered(screen, w, lines.len() as u16 + 6);
    frame.render_widget(Clear, rect);
    let danger = matches!(cmd, Cmd::ForceQuit | Cmd::EndTree | Cmd::Quarantine(_));
    let block = frame_block(title, if danger { BAD } else { WARN });
    let mut text: Vec<Line> = vec![Line::default()];
    text.extend(lines.into_iter().map(|l| Line::from(format!("  {l}"))));
    text.push(Line::default());
    text.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(format!(" Enter  {verb} "), Style::new().fg(Color::White).bg(if danger { BAD } else { SEL_BG }).add_modifier(Modifier::BOLD)),
        Span::raw("   "),
        Span::styled(" Esc  Cancel ", Style::new().fg(Color::Black).bg(Color::Gray)),
    ]));
    frame.render_widget(Paragraph::new(text).block(block), rect);
}

pub fn options(frame: &mut Frame, app: &mut App, screen: Rect) {
    let Mode::Options { cursor } = app.mode else { return };
    let items = OptionItem::all();
    let rect = centered(screen, 72, items.len() as u16 + 6);
    frame.render_widget(Clear, rect);
    let block = frame_block("Options", ACCENT);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let check = |on: bool| if on { "[x]" } else { "[ ]" };
    let mut lines = Vec::new();
    for (i, item) in items.iter().enumerate() {
        if matches!(item, OptionItem::Column(_)) && !matches!(items[i - 1], OptionItem::Column(_)) {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(" Columns in the process list", Style::new().add_modifier(Modifier::BOLD))));
        }
        let (value, label) = match item {
            OptionItem::Interval => (
                format!("◂ {:.2} s ▸", app.ctl.interval_ms.load(Ordering::Relaxed) as f64 / 1000.0),
                "Update every".to_string(),
            ),
            OptionItem::View => (format!("◂ {} ▸", app.view.label()), "Default view".into()),
            OptionItem::DetailsPane => (check(app.pane_visible).into(), "Show details pane under the list".into()),
            OptionItem::ConfirmEnd => (check(app.confirm_end).into(), "Ask before ending processes".into()),
            OptionItem::HighlightNew => (check(app.highlight_new).into(), "Highlight newly started processes".into()),
            OptionItem::Notify => (check(app.notify).into(), "Desktop notification when an alert fires".into()),
            OptionItem::Column(c) => (check(app.columns.contains(c)).into(), format!("{:<13} {}", c.header(), c.description())),
        };
        let text = if value.starts_with('[') { format!(" {value} {label}") } else { format!(" {label:<16} {value}") };
        let line = Line::from(pad_line(vec![Span::raw(truncate(&text, inner.width as usize))], inner.width as usize));
        lines.push(if i == cursor { line.style(sel_style()) } else { line });
    }
    // Keep the cursor visible on short terminals.
    let cursor_line = lines.iter().position(|l| l.style == sel_style()).unwrap_or(0);
    let scroll = cursor_line.saturating_sub(inner.height.saturating_sub(2) as usize);
    let footer = crate::common::paths::config_path().map(|p| format!(" Saved to {}", p.display())).unwrap_or_default();
    frame.render_widget(Paragraph::new(lines).scroll((scroll as u16, 0)), Rect { height: inner.height.saturating_sub(1), ..inner });
    frame.render_widget(Paragraph::new(muted(footer)), Rect { y: inner.bottom().saturating_sub(1), height: 1, ..inner });
}

pub fn help(frame: &mut Frame, screen: Rect) {
    let groups: [(&str, &[(&str, &str)]); 8] = [
        ("Basics", &[
            ("↑ ↓  PgUp PgDn", "move through the list"),
            ("enter", "actions for the selected process"),
            ("right-click", "same, with the mouse"),
            ("double-click  i", "open full details"),
            ("1–9, 0", "pages: Procs Perf Net Files Persist Timeline Logs Trace Alerts Case"),
            ("F2  ,", "settings"),
            ("!  @  #", "acknowledge alarms, pause sound, alarm list"),
        ]),
        ("Finding things", &[
            ("/", "search by name, PID, path, user"),
            ("/ then :8080", "processes using port 8080"),
            ("field:value", "pid: name: user: path: port: ip: state: kind: type: on every page"),
            ("-field:value", "exclude matches, e.g. -name:mdworker"),
            ("f", "find who has a file or port open"),
            ("esc", "clear search and filters"),
        ]),
        ("Views", &[
            ("v", "all → tree → by app → suspicious only"),
            ("← →", "collapse / expand a tree node or app"),
            ("s  r", "choose sort column / reverse order"),
            ("click a header", "sort by that column"),
            ("d  tab", "toggle details pane / next details tab"),
            ("z", "freeze row order (values keep updating)"),
        ]),
        ("Acting on processes", &[
            ("space", "add to selection (ctrl+a selects all)"),
            ("del", "end process (asks first)"),
            ("X", "force quit"),
            ("enter", "priority, suspend, signals, copy, reveal…"),
        ]),
        ("Analysis", &[
            ("T", "trace behavior of the selected process + children"),
            ("on Trace: c  x  e", "filter event type · stop · export report"),
            ("on Detect, tab: a", "add an alert rule, e.g. growth > 20MB/min"),
            ("o → Mem trend", "column that flags steady memory growth"),
            ("on Changes: b", "save a baseline; new programs/ports show up"),
        ]),
        ("Investigation", &[
            ("m", "record the selected item as a finding (any page)"),
            ("l", "investigation graph of the selected item (pivot with enter)"),
            ("H", "collection health: what can and can't be seen"),
            ("Risk column", "priority from rule hits; details pane lists them · R re-checks"),
            ("Case: I  Y", "IOC sweep · YARA content scan of running executables"),
            ("Net: h  d", "by remote host (beaconing) · DNS"),
            ("Timeline: t c b", "process tree only · activity clusters · bookmark"),
            ("Timeline: s B e", "system state at that moment · remove bookmark · CSV"),
            ("Logs: x  A", "execution artifacts · import a folder (.pf .evtx…)"),
            ("enter → Investigate", "analyze exe · collect evidence · quarantine"),
            ("Files: a  A  Q  w", "analyze file · analyze path · quarantine · changes"),
            ("Persist: c  r", "changes since baseline · rescan autostart"),
            ("Logs: w  a", "time window · important/all"),
            ("Case: c s v e", "collect · seal · verify · export report"),
            ("Case: X", "export STIX 2.1, MISP event, ECS timeline"),
            ("Case: a C i", "note · conclusion · isolation scripts"),
        ]),
        ("Detect page (9)", &[
            ("S", "suppress the selected rule for a program (with a reason)"),
            ("T", "trust the program's publisher (weak signals only)"),
            ("u", "show / hide suppressed detections"),
            ("R", "reload Sigma rules and suppressions from disk"),
            ("m  enter", "record as finding · go to the subject"),
            ("tab", "detections → alerts → alert rules"),
        ]),
        ("Other", &[(": ctrl+k", "command palette: every action by name"), ("p", "pause all updates"), ("e", "export list to CSV"), ("o", "options: columns, refresh rate"), ("q", "quit")]),
    ];
    let render = |groups: &[(&str, &[(&str, &str)])]| {
        let mut lines: Vec<Line> = Vec::new();
        for (title, items) in groups {
            if !lines.is_empty() {
                lines.push(Line::default());
            }
            lines.push(Line::from(Span::styled(format!(" {title}"), Style::new().add_modifier(Modifier::BOLD))));
            for (k, d) in *items {
                lines.push(Line::from(vec![Span::styled(format!("   {k:<19}"), Style::new().fg(ACCENT)), Span::raw(d.to_string())]));
            }
        }
        lines
    };
    if screen.width >= 150 {
        let (l, r) = (render(&groups[..4]), render(&groups[4..]));
        let h = l.len().max(r.len()) as u16 + 2;
        let rect = centered(screen, 148, h);
        frame.render_widget(Clear, rect);
        let block = frame_block("Keyboard & mouse", ACCENT);
        let inner = block.inner(rect);
        frame.render_widget(block, rect);
        let [a, b] = ratatui::layout::Layout::horizontal([ratatui::layout::Constraint::Percentage(48), ratatui::layout::Constraint::Percentage(52)]).areas(inner);
        frame.render_widget(Paragraph::new(l), a);
        frame.render_widget(Paragraph::new(r), b);
    } else {
        let lines = render(&groups);
        let rect = centered(screen, 82, lines.len() as u16 + 2);
        frame.render_widget(Clear, rect);
        frame.render_widget(Paragraph::new(lines).block(frame_block("Keyboard & mouse", ACCENT)), rect);
    }
}

pub fn find_input(frame: &mut Frame, app: &mut App, screen: Rect) {
    let Mode::Find { input } = &app.mode else { return };
    let rect = centered(screen, 64, 8);
    frame.render_widget(Clear, rect);
    let file_note = if cfg!(windows) { "Ports only on Windows (files need handle.exe)" } else { "a port, or part of a file path" };
    let lines = vec![
        Line::default(),
        Line::from(vec![Span::raw("  Which process is using "), muted(file_note), Span::raw("?")]),
        Line::default(),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(format!(" {input}"), Style::new().add_modifier(Modifier::UNDERLINED)),
            Span::styled(" ", Style::new().add_modifier(Modifier::REVERSED)),
        ]),
        Line::default(),
        Line::from(muted("  e.g. 8080   .sqlite   Documents/report.pdf")),
    ];
    frame.render_widget(Paragraph::new(lines).block(frame_block("Find process", ACCENT)), rect);
}

pub fn find_results(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(find) = app.find.as_ref() else { return };
    let rect = centered(area, area.width.saturating_sub(8).max(60), area.height.saturating_sub(4).max(10));
    frame.render_widget(Clear, rect);
    let title = format!("Processes using “{}”", find.query);
    let block = frame_block(&title, ACCENT);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let inner = Rect { x: inner.x + 1, width: inner.width.saturating_sub(2), ..inner };

    if find.pending {
        let msg = format!("{} Searching open files of all processes…", spinner(app));
        frame.render_widget(Paragraph::new(muted(msg)), inner);
        return;
    }
    let hits = match &find.result {
        Err(e) => {
            frame.render_widget(Paragraph::new(vec![Line::from(muted("Search failed")), Line::from(e.clone())]), inner);
            return;
        }
        Ok(h) if h.is_empty() => {
            frame.render_widget(Paragraph::new(muted("No process has it open (or it belongs to another user)")), inner);
            return;
        }
        Ok(h) => h.clone(),
    };
    let cursor = find.cursor;
    let specs = [
        ColSpec::new("Process", 24, false),
        ColSpec::new("PID", 7, true),
        ColSpec::new("Handle", 16, false),
        ColSpec::new("Path / address", 0, false),
    ];
    let path_w = (inner.width as usize).saturating_sub(55);
    let rows = hits
        .iter()
        .map(|h| {
            vec![
                vec![Span::raw(h.command.clone())],
                vec![Span::raw(h.pid.to_string())],
                vec![muted(h.fd.clone())],
                vec![Span::raw(truncate_left(&h.path, path_w))],
            ]
        })
        .collect();
    let mut scroll = 0;
    let table = Rect { height: inner.height.saturating_sub(1), ..inner };
    app.hit.find_rows = draw_table(frame, table, &specs, rows, &mut scroll, Some(cursor));
    let footer = format!("{} result(s) · enter goes to the process · {}", hits.len(), reveal_label().to_lowercase());
    let _ = footer;
    frame.render_widget(
        Paragraph::new(muted(format!("{} result(s) · enter goes to the process", hits.len()))),
        Rect { y: inner.bottom().saturating_sub(1), height: 1, ..inner },
    );
}

/// `--run` confirmation: this executes the program for real.
pub fn launch_confirm(frame: &mut Frame, app: &mut App, screen: Rect) {
    let crate::app::Mode::LaunchConfirm(argv) = &app.mode else { return };
    let rect = centered(screen, 84, 13);
    frame.render_widget(Clear, rect);
    let lines = vec![
        Line::default(),
        Line::from(Span::styled("  This will RUN the program on this computer:", Style::new().add_modifier(Modifier::BOLD))),
        Line::default(),
        Line::from(Span::styled(format!("    {}", truncate(&argv.join(" "), 76)), Style::new().fg(WARN))),
        Line::default(),
        Line::from("  Only do this inside an isolated analysis VM or sandbox you can reset."),
        Line::from("  procwatch observes it from its first instruction; it does not contain it."),
        Line::from(muted("  Output goes to a log in a new case; every step is in the custody log.")),
        Line::default(),
        Line::from(vec![Span::styled("  y", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)), Span::raw(" run under trace    "), Span::styled("esc", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)), Span::raw(" cancel")]),
    ];
    frame.render_widget(Paragraph::new(lines).block(frame_block("Launch and trace", BAD)), rect);
}

/// Command palette.
pub fn palette(frame: &mut Frame, app: &mut App, screen: Rect) {
    let crate::app::Mode::Palette { input, cursor } = &app.mode else { return };
    let list = app.palette_entries(input);
    let h = (list.len() as u16 + 4).clamp(6, screen.height.saturating_sub(6));
    let rect = Rect { y: screen.y + 3, ..centered(screen, 80, h) };
    frame.render_widget(Clear, rect);
    let mut lines = vec![Line::from(vec![Span::styled(" : ", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)), Span::raw(input.clone()), Span::styled(" ", Style::new().add_modifier(Modifier::REVERSED))]), Line::default()];
    let rows = (h as usize).saturating_sub(4);
    let off = cursor.saturating_sub(rows.saturating_sub(1));
    for (i, e) in list.iter().enumerate().skip(off).take(rows) {
        let line = Line::from(pad_line(vec![Span::raw(format!(" {:<60}", e.label)), muted(format!("{:>14}", e.hint))], 78));
        lines.push(if i == *cursor { line.style(sel_style()) } else { line });
    }
    if list.is_empty() {
        lines.push(Line::from(muted(" no matching action")));
    }
    frame.render_widget(Paragraph::new(lines).block(frame_block("Commands", ACCENT)), rect);
}
