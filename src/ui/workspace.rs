//! Process Investigation Workspace: one process, all its recorded
//! behaviour, a summary with its evidence, and behaviour replay.

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

use super::widgets::*;
use crate::app::workspace::{FILE_BUCKETS, TABS};
use crate::app::App;

fn basis_style(b: &str) -> Style {
    match b {
        "rule" => Style::new().fg(BAD),
        "inferred" => Style::new().fg(WARN),
        _ => Style::new().fg(OK),
    }
}

fn heat(n: usize, max: usize) -> Span<'static> {
    if n == 0 {
        return muted("·  ");
    }
    let level = (n * 4).div_ceil(max.max(1)).clamp(1, 4);
    let (ch, color) = match level {
        1 => ("░░ ", Color::Blue),
        2 => ("▒▒ ", Color::Cyan),
        3 => ("▓▓ ", Color::Yellow),
        _ => ("██ ", Color::Red),
    };
    Span::styled(ch, Style::new().fg(color))
}

pub fn draw(frame: &mut Frame, app: &mut App, screen: Rect) {
    let rect = Rect { x: screen.x + 1, y: screen.y + 1, width: screen.width.saturating_sub(2), height: screen.height.saturating_sub(2) };
    frame.render_widget(Clear, rect);
    let d = app.ir.ws.dossier.clone();
    let Some(key) = d.key else { return };
    let title = format!(" Process investigation — {} · PID {} ", d.name, key.pid);
    let block = Block::bordered().border_style(Style::new().fg(ACCENT)).title(Span::styled(title, Style::new().add_modifier(Modifier::BOLD)));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let w = inner.width as usize;

    // Identity.
    let level = match d.priority {
        0 => ("no rule hits", Style::new().fg(OK)),
        1..=24 => ("low priority", Style::new().fg(TEXT_DIM)),
        25..=49 => ("needs review", Style::new().fg(WARN).add_modifier(Modifier::BOLD)),
        _ => ("investigate", Style::new().fg(BAD).add_modifier(Modifier::BOLD)),
    };
    let mut head = vec![
        Line::from(vec![
            Span::styled(format!(" {} ", level.0), level.1.add_modifier(Modifier::REVERSED)),
            Span::raw(format!("  priority {}  ·  {}  ·  started {}", d.priority, d.state, d.started.clone().unwrap_or_else(|| "unknown".into()))),
            muted(format!("  ·  user {}", d.user.clone().unwrap_or_default())),
        ]),
        Line::from(vec![muted(" path    "), Span::raw(truncate_left(&d.path.clone().unwrap_or_default(), w.saturating_sub(10)))]),
        Line::from(vec![muted(" command "), Span::raw(truncate(&d.cmd, w.saturating_sub(10)))]),
        Line::from(vec![
            muted(" deep trace "),
            match &d.deep {
                Some(x) => Span::styled(x.clone(), Style::new().fg(Color::LightMagenta)),
                None => muted("off — press D for event-driven lifecycle, module and file tracking"),
            },
        ]),
    ];
    // Count tiles.
    let tiles = [
        (d.family.iter().filter(|m| m.depth != 0).count(), "related processes"),
        (d.file_events, "file events"),
        (d.net_events, "network events"),
        (d.modules.len(), "modules"),
        (d.detections.len(), "rule hits"),
        (d.persistence.len(), "autostart items"),
    ];
    let mut tl = vec![Span::raw(" ")];
    for (n, label) in tiles {
        let style = if label == "rule hits" && n > 0 { Style::new().fg(BAD).add_modifier(Modifier::BOLD) } else { Style::new().add_modifier(Modifier::BOLD) };
        tl.push(Span::styled(format!("{n}"), style));
        tl.push(muted(format!(" {label}    ")));
    }
    head.push(Line::default());
    head.push(Line::from(tl));
    let mut tabs = vec![Span::raw(" ")];
    for (i, t) in TABS.iter().enumerate() {
        let st = if i == app.ir.ws.tab { Style::new().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD) } else { Style::new().fg(TEXT_DIM) };
        tabs.push(Span::styled(format!(" {} {t} ", i + 1), st));
        tabs.push(Span::raw(" "));
    }
    head.push(Line::default());
    head.push(Line::from(tabs));
    let hh = head.len() as u16;
    frame.render_widget(Paragraph::new(head), Rect { height: hh, ..inner });
    let body = Rect { y: inner.y + hh + 1, height: inner.height.saturating_sub(hh + 1), ..inner };

    match app.ir.ws.tab {
        0 => summary(frame, app, &d, body),
        1 => replay(frame, app, &d, body),
        2 => network(frame, app, &d, body),
        3 => files(frame, app, &d, body),
        4 => modules(frame, app, &d, body),
        _ => family(frame, app, &d, body),
    }
}

fn scrolled(frame: &mut Frame, app: &mut App, lines: Vec<Line<'static>>, area: Rect) {
    let max = lines.len().saturating_sub(area.height as usize);
    app.ir.ws.scroll = app.ir.ws.scroll.min(max);
    frame.render_widget(Paragraph::new(lines.into_iter().skip(app.ir.ws.scroll).collect::<Vec<_>>()).wrap(Wrap { trim: false }), area);
}

fn summary(frame: &mut Frame, app: &mut App, d: &crate::app::workspace::Dossier, area: Rect) {
    let mut lines = vec![Line::from(Span::styled(" Behaviour summary", Style::new().add_modifier(Modifier::BOLD))), Line::from(muted(" generated from recorded events by fixed rules · observed / rule / inferred says how each line is supported")), Line::default()];
    for s in &d.summary {
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<9}", s.basis), basis_style(s.basis)),
            Span::raw(s.text.clone()),
            muted(if s.refs.is_empty() { String::new() } else { format!("  [{}]", s.refs.join(", ")) }),
        ]));
    }
    if !d.detections.is_empty() {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(format!(" Rule hits ({})", d.detections.len()), Style::new().add_modifier(Modifier::BOLD))));
        for x in &d.detections {
            lines.push(Line::from(vec![
                Span::styled(format!(" {:<9}", x.severity.label()), super::pivot::sev_style(x.severity)),
                muted(format!("{:<7}", x.confidence.label())),
                Span::raw(format!("{} {} ", x.rule_id, x.rule_name)),
                muted(x.evidence.first().cloned().unwrap_or_default()),
            ]));
        }
    }
    if !d.persistence.is_empty() {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(" Autostart entries launching this executable", Style::new().add_modifier(Modifier::BOLD))));
        for p in &d.persistence {
            lines.push(Line::from(format!("   {p}")));
        }
    }
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(" Limits — what this view can't show", Style::new().fg(WARN).add_modifier(Modifier::BOLD))));
    for g in &d.gaps {
        lines.push(Line::from(muted(format!("   • {g}"))));
    }
    scrolled(frame, app, lines, area);
}

fn replay(frame: &mut Frame, app: &mut App, d: &crate::app::workspace::Dossier, area: Rect) {
    if d.events.is_empty() {
        frame.render_widget(Paragraph::new(muted(" No events recorded for this process yet.")), area);
        return;
    }
    let [list, side] = Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)]).spacing(1).areas(area);
    let n = d.events.len();
    let cur = app.ir.ws.cursor.min(n - 1);
    app.ir.ws.cursor = cur;
    let height = list.height.saturating_sub(1) as usize;
    let off = scroll_window(cur.saturating_sub(height / 2), cur, height, n);
    let specs = [ColSpec::new("Time", 12, false), ColSpec::new("Source", 8, false), ColSpec::new("Event", 13, false), ColSpec::new("Process", 16, false), ColSpec::new("Detail", 0, false)];
    let tl = &app.ir.timeline;
    let rows = d.events[off..(off + height).min(n)]
        .iter()
        .map(|i| {
            let e = &tl[*i];
            vec![
                vec![muted(format!("{}{}", e.time.format("%H:%M:%S%.3f"), if e.basis == crate::common::model::Basis::Observed { "~" } else { "" }))],
                vec![Span::styled(e.source, Style::new().fg(ACCENT))],
                vec![Span::raw(e.kind.clone())],
                vec![Span::raw(e.name.clone())],
                vec![muted(e.detail.clone())],
            ]
        })
        .collect();
    let mut scroll = 0;
    draw_table(frame, list, &specs, rows, &mut scroll, Some(cur - off));
    let e = &tl[d.events[cur]];
    let mut lines = vec![
        Line::from(Span::styled(format!(" Event {}/{n}", cur + 1), Style::new().add_modifier(Modifier::BOLD))),
        Line::from(muted(format!(" {} · {}", crate::common::model::short_id(e.id), e.basis.label()))),
        Line::from(format!(" {} {} {}", e.time.format("%Y-%m-%d %H:%M:%S%.3f"), e.source, e.kind)),
        Line::from(format!(" {}", e.name)),
    ];
    for part in wrap(&e.detail, side.width.saturating_sub(2) as usize).into_iter().take(4) {
        lines.push(Line::from(muted(format!(" {part}"))));
    }
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(" State at this moment", Style::new().add_modifier(Modifier::BOLD))));
    for (k, v) in app.replay_state() {
        lines.push(Line::from(vec![muted(format!(" {k:<22}")), Span::raw(v)]));
    }
    lines.push(Line::default());
    lines.push(Line::from(muted(" ←/→ step · PgUp/PgDn ×10 · Home/End")));
    lines.push(Line::from(muted(" Replay rebuilds recorded events; nothing is re-run.")));
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(Block::new().borders(Borders::LEFT).border_style(Style::new().fg(MUTED))), side);
}

fn network(frame: &mut Frame, app: &mut App, d: &crate::app::workspace::Dossier, area: Rect) {
    let mut lines = vec![Line::from(vec![
        Span::styled(format!(" {} endpoint(s)", d.network.len()), Style::new().add_modifier(Modifier::BOLD)),
        muted(format!("   {} on the internet", d.network.iter().filter(|e| e.public).count())),
        muted(if d.net_per_bucket.is_empty() { String::new() } else { format!("   connect rate over time  {}", d.net_per_bucket.iter().map(|n| [' ', '▁', '▃', '▅', '█'][(*n).min(4)]).collect::<String>()) }),
    ])];
    lines.push(Line::default());
    lines.push(Line::from(muted(format!(" {:<44}{:<28}{:>9}{:>8}{:>7}{:>11}  {:<9}{:<9}{}", "Remote", "Host", "Connects", "Closes", "Open", "Avg open s", "First", "Last", "Pattern"))));
    for e in &d.network {
        let style = if e.public { Style::new() } else { Style::new().fg(TEXT_DIM) };
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<44}", truncate(&e.remote, 43)), style),
            muted(format!("{:<28}", truncate(&e.host.clone().unwrap_or_default(), 27))),
            Span::raw(format!("{:>9}{:>8}{:>7}{:>11}  ", e.connects, e.closes, e.open_now, e.avg_open_secs.map(|x| format!("{x:.1}")).unwrap_or_default())),
            muted(format!("{:<9}{:<9}", e.first, e.last)),
            match e.beacon {
                Some(b) => Span::styled(format!("every ~{b:.0}s"), Style::new().fg(BAD).add_modifier(Modifier::BOLD)),
                None => Span::raw(""),
            },
        ]));
    }
    if d.network.is_empty() {
        lines.push(Line::from(muted(" No connections recorded.")));
    }
    lines.push(Line::default());
    lines.push(Line::from(muted(" Connections are sampled every refresh; byte counts per process aren't available from the OS without packet capture, so none are shown.")));
    scrolled(frame, app, lines, area);
}

fn files(frame: &mut Frame, app: &mut App, d: &crate::app::workspace::Dossier, area: Rect) {
    let mut lines = vec![
        Line::from(Span::styled(" File activity heat map — folders × time (oldest → newest)", Style::new().add_modifier(Modifier::BOLD))),
        Line::from(muted(" opens come from deep-trace snapshots every 3 s; changes are file notifications attributed to this process")),
        Line::default(),
    ];
    let max = d.files.iter().flat_map(|f| f.buckets.iter()).copied().max().unwrap_or(1);
    let name_w = (area.width as usize).saturating_sub(FILE_BUCKETS * 3 + 22).max(20);
    for f in &d.files {
        let mut spans = vec![Span::raw(format!(" {:<w$} ", truncate_left(&f.dir, name_w), w = name_w))];
        spans.extend(f.buckets.iter().map(|n| heat(*n, max)));
        spans.push(muted(format!(" {} opens · {} changes", f.opens, f.changes)));
        lines.push(Line::from(spans));
    }
    if d.files.is_empty() {
        lines.push(Line::from(muted(" No file activity recorded (deep trace adds open-file snapshots — press D).")));
    } else if let Some((a, b)) = &d.span {
        lines.push(Line::default());
        lines.push(Line::from(muted(format!(" span {a} → {b}   ░ few  ▒  ▓  █ many"))));
    }
    scrolled(frame, app, lines, area);
}

fn modules(frame: &mut Frame, app: &mut App, d: &crate::app::workspace::Dossier, area: Rect) {
    let concern = d.modules.iter().filter(|m| m.concern).count();
    let mut lines = vec![
        Line::from(vec![
            Span::styled(format!(" {} modules", d.modules.len()), Style::new().add_modifier(Modifier::BOLD)),
            if concern > 0 { Span::styled(format!("   {concern} need review"), Style::new().fg(BAD)) } else { muted("   none flagged") },
            muted("   checks: on disk · location · signature · loaded after first look"),
        ]),
        Line::default(),
    ];
    for m in &d.modules {
        let st = if m.concern { Style::new().fg(BAD) } else { Style::new().fg(TEXT_DIM) };
        lines.push(Line::from(vec![
            Span::raw(format!(" {} ", truncate_left(&m.path, (area.width as usize).saturating_sub(44)))),
            Span::styled(m.status.clone(), st),
            if m.loaded_later { Span::styled("  loaded later", Style::new().fg(WARN)) } else { Span::raw("") },
        ]));
    }
    if d.modules.is_empty() {
        lines.push(Line::from(muted(" Not listed yet — deep trace lists modules every 20 s (D), or open the Modules tab in details.")));
    }
    scrolled(frame, app, lines, area);
}

fn family(frame: &mut Frame, app: &mut App, d: &crate::app::workspace::Dossier, area: Rect) {
    let mut lines = vec![Line::from(Span::styled(" Ancestors, the process, and everything it started (recorded)", Style::new().add_modifier(Modifier::BOLD))), Line::default()];
    for m in &d.family {
        let indent = if m.depth < 0 { String::new() } else { "  ".repeat(m.depth as usize) };
        let mark = match m.depth {
            x if x < 0 => muted("ancestor "),
            0 => Span::styled("▶ ", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
            _ => Span::raw("└ "),
        };
        let traced = app.ir.deep.enrolled.contains_key(&m.key);
        lines.push(Line::from(vec![
            Span::raw(format!(" {indent}")),
            mark,
            Span::styled(format!("{} ({})", m.name, m.key.pid), if m.alive { Style::new() } else { Style::new().fg(TEXT_DIM) }),
            muted(if m.alive { "" } else { "  exited" }),
            if traced { Span::styled("  deep", Style::new().fg(Color::LightMagenta)) } else { Span::raw("") },
        ]));
    }
    scrolled(frame, app, lines, area);
}
