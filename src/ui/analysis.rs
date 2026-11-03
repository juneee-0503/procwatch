//! Trace page (behavior timeline + summary) and Alerts page (alerts + rules).

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, Paragraph},
    Frame,
};

use super::spinner;
use super::widgets::*;
use crate::app::{App, Mode};
use crate::baseline::ChangeKind;
use crate::process::{cpu_time, human_bytes};
use crate::trace::{Category, Kind};

fn kind_style(k: Kind) -> Style {
    match k {
        Kind::ProcessStart => Style::new().fg(OK),
        Kind::ProcessExit => Style::new().fg(BAD),
        Kind::Connect | Kind::Listen => Style::new().fg(ACCENT),
        Kind::Disconnect | Kind::StopListen | Kind::FileClose => Style::new().fg(MUTED),
        Kind::FileOpen => Style::new().fg(Color::Reset),
        Kind::CpuSpike | Kind::MemoryGrowth => Style::new().fg(WARN),
        Kind::Note => Style::new().fg(TEXT_DIM).add_modifier(Modifier::ITALIC),
    }
}

fn heading(t: &str) -> Line<'static> {
    Line::from(Span::styled(t.to_string(), Style::new().add_modifier(Modifier::BOLD)))
}

pub fn trace(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(t) = app.trace.as_ref() else {
        let lines = vec![
            Line::default(),
            heading("  Behavior trace"),
            Line::default(),
            Line::from("  Follow a process and everything it spawns, and record what they do:"),
            Line::from(muted("    • child processes started and exited, with their command lines")),
            Line::from(muted("    • network connections opened and closed, ports it listens on")),
            Line::from(muted("    • files opened and closed")),
            Line::from(muted("    • CPU spikes and memory growth")),
            Line::default(),
            Line::from(vec![
                Span::raw("  Start one from the Processes page: select a process and press "),
                Span::styled("T", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
                Span::raw(", or choose "),
                Span::styled("Trace behavior", Style::new().add_modifier(Modifier::BOLD)),
                Span::raw(" in its action menu."),
            ]),
            Line::from(muted("  Reports can be exported as Markdown and JSON.")),
        ];
        frame.render_widget(Paragraph::new(lines), area);
        return;
    };

    // Header.
    let secs = t.elapsed().as_secs();
    let state = if t.is_running() {
        Span::styled(format!("{} recording", spinner(app)), Style::new().fg(BAD).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("stopped", Style::new().fg(TEXT_DIM))
    };
    let alive = t.procs.values().filter(|p| p.exited_at.is_none()).count();
    let header = Line::from(vec![
        Span::styled(format!(" {} ", t.root_name), Style::new().add_modifier(Modifier::BOLD)),
        muted(format!("PID {}   ", t.root)),
        state,
        muted(format!(
            "   {:02}:{:02} elapsed · {} processes ({} running) · {} events",
            secs / 60,
            secs % 60,
            t.procs.len(),
            alive,
            t.events.len()
        )),
    ]);
    frame.render_widget(Paragraph::new(header), Rect { height: 1, ..area });

    let body = Rect { y: area.y + 2, height: area.height.saturating_sub(2), ..area };
    let side_w = if body.width >= 120 { 44 } else { 0 };
    let [timeline, side] = Layout::horizontal([Constraint::Min(40), Constraint::Length(side_w)]).spacing(1).areas(body);

    // Summary panel.
    if side_w > 0 {
        let mut lines = vec![heading("Processes")];
        lines.push(Line::from(vec![
            muted("  spawned "),
            Span::raw(t.count(Kind::ProcessStart).to_string()),
            muted("   exited "),
            Span::raw(t.count(Kind::ProcessExit).to_string()),
        ]));
        let peak_cpu = t.procs.values().map(|p| p.peak_cpu).fold(0.0, f32::max);
        let peak_mem: u64 = t.procs.values().map(|p| p.peak_mem).max().unwrap_or(0);
        lines.push(Line::from(vec![
            muted("  peak CPU "),
            Span::raw(format!("{peak_cpu:.0}%")),
            muted("   peak mem "),
            Span::raw(human_bytes(peak_mem)),
        ]));
        lines.push(Line::from(vec![muted("  CPU time used "), Span::raw(cpu_time(t.cpu_time_used))]));
        lines.push(Line::default());
        lines.push(heading("Network"));
        let hosts = t.top_hosts(6);
        if hosts.is_empty() && t.listen_ports.is_empty() {
            lines.push(Line::from(muted("  no connections seen")));
        }
        for (h, n) in hosts {
            lines.push(Line::from(vec![Span::raw(format!("  {}", truncate(&h, 30))), muted(format!("  ×{n}"))]));
        }
        for l in t.listen_ports.iter().take(4) {
            lines.push(Line::from(vec![muted("  listens "), Span::styled(truncate(l, 32), Style::new().fg(ACCENT))]));
        }
        lines.push(Line::default());
        lines.push(heading(&format!("Files ({})", t.files_touched.len())));
        if let Some(e) = &t.file_errors {
            lines.push(Line::from(muted(format!("  {}", truncate(e, 40)))));
        }
        for (d, n) in t.top_dirs(8) {
            lines.push(Line::from(vec![Span::raw(format!("  {}", truncate_left(&d, 34))), muted(format!("  {n}"))]));
        }
        frame.render_widget(Paragraph::new(lines), side);
    }

    // Filter bar + timeline.
    let mut filter = vec![muted("Show ")];
    for c in Category::CYCLE {
        let style = if c == app.trace_filter { sel_style() } else { Style::new().fg(TEXT_DIM) };
        filter.push(Span::styled(format!(" {} ", c.label()), style));
    }
    if !app.query.is_empty() {
        filter.push(muted("   matching "));
        filter.push(Span::styled(app.query.clone(), Style::new().fg(WARN)));
    }
    if !app.trace_follow {
        filter.push(muted("   (scrolled — End to follow)"));
    }
    frame.render_widget(Paragraph::new(Line::from(filter)), Rect { height: 1, ..timeline });

    let visible = app.visible_trace();
    let specs = [
        ColSpec::new("Time", 8, false),
        ColSpec::new("+s", 7, true),
        ColSpec::new("Event", 8, false),
        ColSpec::new("PID", 7, true),
        ColSpec::new("Process", 18, false),
        ColSpec::new("Details", 0, false),
    ];
    let detail_w = (timeline.width as usize).saturating_sub(62);
    let rows = visible
        .iter()
        .map(|i| {
            let e = &t.events[*i];
            let detail = if matches!(e.kind, Kind::FileOpen | Kind::FileClose) { truncate_left(&e.detail, detail_w) } else { e.detail.clone() };
            vec![
                vec![muted(e.at.format("%H:%M:%S").to_string())],
                vec![muted(format!("{:.1}", e.offset))],
                vec![Span::styled(e.kind.label(), kind_style(e.kind))],
                vec![Span::raw(e.pid.to_string())],
                vec![Span::raw(e.process.clone())],
                vec![Span::styled(detail, if e.kind == Kind::Note { kind_style(Kind::Note) } else { Style::new() })],
            ]
        })
        .collect();
    let table = Rect { y: timeline.y + 2, height: timeline.height.saturating_sub(2), ..timeline };
    app.trace_selected = app.trace_selected.min(visible.len().saturating_sub(1));
    let mut off = app.trace_offset;
    app.hit.list_rows = draw_table(frame, table, &specs, rows, &mut off, (!visible.is_empty()).then_some(app.trace_selected));
    app.trace_offset = off;
}

pub fn alerts(frame: &mut Frame, app: &mut App, area: Rect) {
    let rules_h = (app.rules.len() as u16 + 4).clamp(6, area.height / 2);
    let [list, rules] = Layout::vertical([Constraint::Min(5), Constraint::Length(rules_h)]).areas(area);

    let focus = |on: bool| if on { Style::new().fg(ACCENT).add_modifier(Modifier::BOLD) } else { Style::new().add_modifier(Modifier::BOLD) };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!(" Alerts ({})", app.alerts.len()), focus(!app.rules_focus)),
            muted("   newest first · enter goes to the process · c clears"),
        ])),
        Rect { height: 1, ..list },
    );
    let table = Rect { y: list.y + 2, height: list.height.saturating_sub(3), ..list };
    if app.alerts.is_empty() {
        let msg = if app.rules.is_empty() {
            "No rules yet — press a to add one, e.g.  cpu > 80% for 10s   growth > 20MB/min   start ssh   listen"
        } else {
            "No alerts so far. Rules are checked on every refresh."
        };
        frame.render_widget(Paragraph::new(muted(format!(" {msg}"))), table);
    } else {
        let specs = [
            ColSpec::new("Time", 8, false),
            ColSpec::new("PID", 7, true),
            ColSpec::new("Process", 22, false),
            ColSpec::new("What happened", 0, false),
            ColSpec::new("Rule", 24, false),
        ];
        let visible = app.visible_alerts();
        let rows = visible
            .iter()
            .map(|i| &app.alerts[*i])
            .map(|a| {
                vec![
                    vec![muted(a.at.format("%H:%M:%S").to_string())],
                    vec![Span::raw(a.pid.to_string())],
                    vec![Span::raw(a.name.clone())],
                    vec![Span::styled(a.message.clone(), Style::new().fg(WARN))],
                    vec![muted(a.rule.clone())],
                ]
            })
            .collect();
        let mut off = app.alert_offset;
        let sel = (!app.rules_focus).then_some(app.alert_selected);
        let body = draw_table(frame, table, &specs, rows, &mut off, sel);
        if !app.rules_focus {
            app.hit.list_rows = body;
        }
        app.alert_offset = off;
    }

    // Rules list.
    let mut lines = vec![Line::from(vec![
        Span::styled(format!(" Rules ({})", app.rules.len()), focus(app.rules_focus)),
        muted("   tab switches here · a add · space on/off · del remove"),
    ])];
    lines.push(Line::default());
    if app.rules.is_empty() {
        lines.push(Line::from(muted("   none")));
    }
    for (i, r) in app.rules.iter().enumerate() {
        let check = if r.enabled { "[x]" } else { "[ ]" };
        let line = Line::from(pad_line(
            vec![
                Span::raw(format!("   {check} ")),
                Span::styled(format!("{:<28}", r.text), Style::new().fg(if r.enabled { Color::Reset } else { MUTED })),
                muted(format!("alert when {}", r.describe())),
            ],
            rules.width as usize,
        ));
        lines.push(if app.rules_focus && i == app.rule_selected { line.style(sel_style()) } else { line });
    }
    frame.render_widget(Paragraph::new(lines), rules);
}

pub fn rule_input(frame: &mut Frame, app: &mut App, screen: Rect) {
    let Mode::RuleInput { input, error } = &app.mode else { return };
    let rect = centered(screen, 74, 14);
    frame.render_widget(Clear, rect);
    let mut lines = vec![
        Line::default(),
        Line::from("  Alert me when…"),
        Line::default(),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(format!(" {input}"), Style::new().add_modifier(Modifier::UNDERLINED)),
            Span::styled(" ", Style::new().add_modifier(Modifier::REVERSED)),
        ]),
    ];
    match (error, crate::rules::Rule::parse(input)) {
        (Some(e), _) => lines.push(Line::from(Span::styled(format!("  {e}"), Style::new().fg(BAD)))),
        (None, Ok(r)) if !input.trim().is_empty() => lines.push(Line::from(Span::styled(format!("  → alert when {}", r.describe()), Style::new().fg(OK)))),
        _ => lines.push(Line::default()),
    }
    lines.push(Line::default());
    for (ex, what) in [
        ("cpu > 80% for 10s", "sustained CPU use"),
        ("mem > 2GB name=chrome", "memory above a size (optionally by name)"),
        ("growth > 20MB/min", "memory growing steadily — likely a leak"),
        ("start ssh  /  exit nginx", "a process starts or exits"),
        ("listen  /  connect :25", "new listening port / new outgoing connection"),
    ] {
        lines.push(Line::from(vec![Span::styled(format!("  {ex:<26}"), Style::new().fg(ACCENT)), muted(what)]));
    }
    let block = ratatui::widgets::Block::bordered()
        .border_style(Style::new().fg(ACCENT))
        .title(Span::styled(" New alert rule ", Style::new().add_modifier(Modifier::BOLD)));
    frame.render_widget(Paragraph::new(lines).block(block), rect);
}

pub fn changes(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(base) = app.baseline.as_ref() else {
        let lines = vec![
            Line::default(),
            heading("  What changed?"),
            Line::default(),
            Line::from("  Save a baseline of this machine — which programs run and which ports are listening —"),
            Line::from("  and this page will list everything that is new or gone compared to it."),
            Line::default(),
            Line::from(vec![
                Span::raw("  Press "),
                Span::styled("b", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
                Span::raw(" to save the current state as the baseline."),
            ]),
            Line::default(),
            Line::from(muted("  From scripts:  procwatch --snapshot base.json   then later   procwatch --diff base.json")),
            Line::from(muted("  (--diff exits with status 1 when something changed, so it works in cron jobs)")),
        ];
        frame.render_widget(Paragraph::new(lines), area);
        return;
    };

    let when = base
        .taken_at()
        .map(|t| {
            let ago = (chrono::Local::now() - t).num_seconds().max(0) as u64;
            format!("{} ({} ago)", t.format("%Y-%m-%d %H:%M"), crate::process::ago(ago))
        })
        .unwrap_or_else(|| base.taken.clone());
    let count = |k: ChangeKind| app.changes.iter().filter(|c| c.kind == k).count();
    let header = Line::from(vec![
        Span::styled(" Compared with baseline ", Style::new().add_modifier(Modifier::BOLD)),
        Span::raw(when),
        muted(format!("   {} programs · {} ports in baseline", base.programs.len(), base.listeners.len())),
    ]);
    let summary = Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("+{} new programs", count(ChangeKind::NewProgram)), Style::new().fg(WARN)),
        muted("   "),
        Span::styled(format!("+{} new ports", count(ChangeKind::NewListener)), Style::new().fg(WARN)),
        muted(format!("   −{} not running   −{} ports closed", count(ChangeKind::GoneProgram), count(ChangeKind::GoneListener))),
        if app.query.is_empty() { Span::raw("") } else { muted(format!("   matching \"{}\"", app.query)) },
    ]);
    frame.render_widget(Paragraph::new(vec![header, summary]), Rect { height: 2, ..area });

    let table = Rect { y: area.y + 3, height: area.height.saturating_sub(3), ..area };
    let visible = app.visible_changes();
    if visible.is_empty() {
        let msg = if app.changes.is_empty() { " Nothing changed since the baseline." } else { " No changes match the filter." };
        frame.render_widget(Paragraph::new(muted(msg)), table);
        return;
    }
    let specs = [
        ColSpec::new("Change", 12, false),
        ColSpec::new("Program", 26, false),
        ColSpec::new("User", 12, false),
        ColSpec::new("Path or address", 0, false),
        ColSpec::new("Reach", 9, false),
    ];
    let path_w = (table.width as usize).saturating_sub(70);
    let rows = visible
        .iter()
        .map(|i| {
            let c = &app.changes[*i];
            let style = match c.kind {
                ChangeKind::NewProgram | ChangeKind::NewListener => Style::new().fg(WARN),
                _ => Style::new().fg(MUTED),
            };
            let reach = match c.kind {
                ChangeKind::NewListener | ChangeKind::GoneListener if c.exposed => Span::styled("network", Style::new().fg(BAD)),
                ChangeKind::NewListener | ChangeKind::GoneListener => muted("local"),
                _ => Span::raw(""),
            };
            vec![
                vec![Span::styled(c.kind.label(), style)],
                vec![Span::raw(c.name.clone())],
                vec![muted(c.user.clone().unwrap_or_default())],
                vec![Span::raw(truncate_left(&c.detail, path_w))],
                vec![reach],
            ]
        })
        .collect();
    app.change_selected = app.change_selected.min(visible.len().saturating_sub(1));
    let mut off = app.change_offset;
    app.hit.list_rows = draw_table(frame, table, &specs, rows, &mut off, Some(app.change_selected));
    app.change_offset = off;
}
