//! Investigation pages: Persistence, Timeline, Logs, Case, plus the file
//! report and text-input dialogs.

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use super::spinner;
use super::widgets::*;
use crate::app::{App, Mode};
use crate::case::Check;

fn heading(t: &str) -> Span<'static> {
    Span::styled(t.to_string(), Style::new().add_modifier(Modifier::BOLD))
}

fn search_bar(app: &App, what: &str, count: usize, extra: Vec<Span<'static>>) -> Line<'static> {
    let searching = app.mode == Mode::Search;
    let mut spans = vec![Span::styled(" / ", Style::new().fg(Color::Black).bg(if searching { ACCENT } else { Color::Gray }))];
    if app.query.is_empty() && !searching {
        spans.push(muted(format!(" Filter {what}…")));
    } else {
        spans.push(Span::raw(format!(" {}", app.query)));
        if searching {
            spans.push(Span::styled(" ", Style::new().add_modifier(Modifier::REVERSED)));
        }
    }
    spans.push(muted(format!("    {count} {what}")));
    spans.extend(extra);
    Line::from(spans)
}

fn age(secs: u64) -> String {
    crate::process::ago(secs)
}

// ── persistence ────────────────────────────────────────────────────────

pub fn persistence(frame: &mut Frame, app: &mut App, area: Rect) {
    let visible = app.visible_persistence();
    let items = app.persist_items().to_vec();
    let flagged = items.iter().filter(|i| i.suspicious()).count();
    let status = match &app.ir.persistence {
        None => muted("   scanning…"),
        Some(p) if p.pending => muted(format!("   {} scanning autostart locations…", spinner(app))),
        Some(p) => muted(format!("   scanned {} ago · r rescan", age(p.fetched.elapsed().as_secs()))),
    };
    let flag_span = if flagged > 0 {
        Span::styled(format!("   {flagged} flagged"), Style::new().fg(BAD).add_modifier(Modifier::BOLD))
    } else {
        muted("   nothing flagged")
    };
    frame.render_widget(Paragraph::new(search_bar(app, "entries", visible.len(), vec![flag_span, status])), Rect { height: 1, ..area });
    app.hit.search = Rect { height: 1, width: area.width / 3, ..area };

    let detail_h = 7u16.min(area.height / 3);
    let table = Rect { y: area.y + 2, height: area.height.saturating_sub(3 + detail_h), ..area };
    let detail = Rect { y: table.bottom() + 1, height: detail_h, ..area };

    if items.is_empty() {
        let msg = match app.ir.persistence.as_ref().map(|p| &p.result) {
            Some(Err(e)) if !e.is_empty() => e.clone(),
            _ => "Looking for launch agents, services, scheduled tasks, cron jobs, extensions and start-up files…".into(),
        };
        frame.render_widget(Paragraph::new(muted(format!(" {msg}"))), table);
        return;
    }
    let specs = [
        ColSpec::new("", 1, false),
        ColSpec::new("Type", 18, false),
        ColSpec::new("Name", 30, false),
        ColSpec::new("Scope", 6, false),
        ColSpec::new("On", 3, false),
        ColSpec::new("Signature", 22, false),
        ColSpec::new("Runs", 0, false),
    ];
    let rows = visible
        .iter()
        .map(|i| {
            let it = &items[*i];
            let mark = if it.suspicious() { Span::styled("!", Style::new().fg(BAD).add_modifier(Modifier::BOLD)) } else { Span::raw(" ") };
            let sig = match &it.signature {
                Some(s) if s.starts_with("valid") => Span::styled(s.trim_start_matches("valid — ").to_string(), Style::new().fg(OK)),
                Some(s) => Span::styled(s.clone(), Style::new().fg(BAD)),
                None => muted("–"),
            };
            let on = match it.enabled {
                Some(true) => Span::styled("yes", Style::new().fg(OK)),
                Some(false) => muted("no"),
                None => muted("–"),
            };
            vec![
                vec![mark],
                vec![Span::raw(it.category.clone())],
                vec![Span::raw(it.name.clone())],
                vec![muted(it.scope.clone())],
                vec![on],
                vec![sig],
                vec![muted(if it.command.is_empty() { it.target.clone().unwrap_or_default() } else { it.command.clone() })],
            ]
        })
        .collect();
    app.ir.persist_selected = app.ir.persist_selected.min(visible.len().saturating_sub(1));
    let mut off = app.ir.persist_offset;
    app.hit.list_rows = draw_table(frame, table, &specs, rows, &mut off, (!visible.is_empty()).then_some(app.ir.persist_selected));
    app.ir.persist_offset = off;

    // Detail of the selected entry.
    let block = Block::new().borders(Borders::TOP).border_style(Style::new().fg(MUTED));
    let inner = block.inner(detail);
    frame.render_widget(block, detail);
    if let Some(it) = visible.get(app.ir.persist_selected).map(|i| &items[*i]) {
        let kv = |k: &str, v: String| Line::from(vec![Span::styled(format!(" {k:<12}"), Style::new().fg(TEXT_DIM)), Span::raw(v)]);
        let mut lines = vec![
            kv("Defined in", it.location.clone()),
            kv("Target", it.target.clone().unwrap_or_else(|| "–".into())),
            kv("SHA-256", it.sha256.clone().unwrap_or_else(|| "–".into())),
            kv("Detail", format!("{}{}", it.detail, it.modified.as_ref().map(|m| format!("  · target modified {m}")).unwrap_or_default())),
        ];
        if it.flags.is_empty() {
            lines.push(kv("Review", "no warning signs".into()));
        } else {
            lines.push(Line::from(vec![
                Span::styled(format!(" {:<12}", "Why"), Style::new().fg(TEXT_DIM)),
                Span::styled(it.flags.join(" · "), Style::new().fg(BAD)),
            ]));
        }
        frame.render_widget(Paragraph::new(lines), inner);
    }
    if let Some(Ok(scan)) = app.ir.persistence.as_ref().map(|p| &p.result) {
        if !scan.notes.is_empty() && inner.height > 5 {
            let note = Rect { y: inner.bottom().saturating_sub(1), height: 1, ..inner };
            frame.render_widget(Paragraph::new(muted(format!(" note: {}", scan.notes.join(" · ")))), note);
        }
    }
}

// ── timeline ───────────────────────────────────────────────────────────

fn source_style(src: &str) -> Style {
    match src {
        "process" => Style::new().fg(OK),
        "network" => Style::new().fg(ACCENT),
        "file" => Style::new().fg(WARN),
        "alert" => Style::new().fg(BAD).add_modifier(Modifier::BOLD),
        "trace" => Style::new().fg(Color::Magenta),
        "log" => Style::new().fg(TEXT_DIM),
        "case" => Style::new().fg(Color::Blue),
        "detect" => Style::new().fg(BAD),
        "persist" => Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD),
        "artifact" => Style::new().fg(Color::LightBlue),
        "deep" => Style::new().fg(Color::LightMagenta).add_modifier(Modifier::BOLD),
        _ => Style::new(),
    }
}

pub fn timeline(frame: &mut Frame, app: &mut App, area: Rect) {
    let visible = app.visible_timeline();
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for i in &visible {
        *counts.entry(app.ir.timeline[*i].source).or_default() += 1;
    }
    let mut extra: Vec<Span> = vec![muted("   ")];
    for (src, n) in &counts {
        extra.push(Span::styled(format!("{src} {n}  "), source_style(src)));
    }
    if !app.ir.clusters.is_empty() {
        extra.push(Span::styled(format!(" {} cluster(s) — c", app.ir.clusters.len()), Style::new().fg(BAD).add_modifier(Modifier::BOLD)));
    }
    frame.render_widget(Paragraph::new(search_bar(app, "events", visible.len(), extra)), Rect { height: 1, ..area });
    app.hit.search = Rect { height: 1, width: area.width / 3, ..area };
    frame.render_widget(
        Paragraph::new(muted(
            " Newest first. ~ = time procwatch observed it (the real moment is up to one refresh earlier); otherwise the OS-recorded time. \
             Filter e.g. source:network port:443  tag:execution  cluster:1  entity:process:123",
        )),
        Rect { y: area.y + 1, height: 1, ..area },
    );
    let [table, detail] = Layout::vertical([Constraint::Min(4), Constraint::Length(3)]).areas(Rect { y: area.y + 3, height: area.height.saturating_sub(3), ..area });
    if visible.is_empty() {
        frame.render_widget(Paragraph::new(muted(" No events yet — activity is recorded from the moment procwatch starts.")), table);
        return;
    }
    let specs = [
        ColSpec::new("Time", 20, false),
        ColSpec::new("Source", 8, false),
        ColSpec::new("Event", 14, false),
        ColSpec::new("PID", 7, true),
        ColSpec::new("Process", 20, false),
        ColSpec::new("◆", 3, false),
        ColSpec::new("Details", 0, false),
    ];
    let height = table.height.saturating_sub(1) as usize;
    app.ir.tl_selected = app.ir.tl_selected.min(visible.len() - 1);
    app.ir.tl_offset = scroll_window(app.ir.tl_offset, app.ir.tl_selected, height, visible.len());
    let detail_w = (table.width as usize).saturating_sub(84);
    let rows = visible
        .iter()
        .skip(app.ir.tl_offset)
        .take(height)
        .map(|i| {
            let e = &app.ir.timeline[*i];
            let text = if e.source == "file" { truncate_left(&e.detail, detail_w) } else { e.detail.clone() };
            let approx = if e.basis == crate::model::Basis::Observed { "~" } else { " " };
            let mark = match (&e.tag, e.cluster) {
                (Some(_), _) => Span::styled("★", Style::new().fg(WARN).add_modifier(Modifier::BOLD)),
                (None, Some(c)) => Span::styled(format!("{c}"), Style::new().fg(BAD)),
                _ => Span::raw(""),
            };
            vec![
                vec![muted(format!("{}{approx}", e.time.format("%Y-%m-%d %H:%M:%S")))],
                vec![Span::styled(e.source, source_style(e.source))],
                vec![Span::raw(e.kind.clone())],
                vec![muted(e.pid.map(|p| p.to_string()).unwrap_or_default())],
                vec![Span::raw(e.name.clone())],
                vec![mark],
                vec![Span::raw(text)],
            ]
        })
        .collect();
    let mut scroll = 0;
    app.hit.list_rows = draw_table(frame, table, &specs, rows, &mut scroll, Some(app.ir.tl_selected - app.ir.tl_offset));
    // Selected event: id, time semantics, links, bookmark.
    let e = &app.ir.timeline[visible[app.ir.tl_selected]];
    let mut l1 = vec![
        Span::styled(format!(" {} ", crate::model::short_id(e.id)), Style::new().fg(ACCENT)),
        muted(format!("{} time {}", e.basis.label(), e.time.to_rfc3339())),
    ];
    if let Some(o) = e.observed {
        l1.push(muted(format!(" · observed {}", o.format("%H:%M:%S"))));
    }
    if let Some(t) = &e.tag {
        l1.push(Span::styled(format!("  ★ {t}"), Style::new().fg(WARN)));
    }
    if let Some(c) = e.cluster {
        l1.push(Span::styled(format!("  cluster {c}"), Style::new().fg(BAD)));
    }
    let links: Vec<String> = e.subject.iter().map(|s| format!("about {}", s.key())).chain(e.links.iter().map(|(r, x)| format!("{} {}", r.label(), x.key()))).collect();
    let lines = vec![Line::from(l1), Line::from(muted(format!(" {}", truncate(&links.join(" · "), detail.width.saturating_sub(2) as usize))))];
    frame.render_widget(Paragraph::new(lines).block(Block::new().borders(Borders::TOP).border_style(Style::new().fg(MUTED))), detail);
}

// ── logs ───────────────────────────────────────────────────────────────

/// Per-process operations, in the manner of Process Monitor.
pub fn activity(frame: &mut Frame, app: &mut App, area: Rect) {
    app.refresh_activity_view();
    let total = app.visible_activity().len();
    let mut extra: Vec<Span> = vec![muted("   ")];
    match (&app.ir.capture, &app.ir.capture_error) {
        (Some(c), _) => extra.push(Span::styled(format!("● capturing via {}", c.method), Style::new().fg(BAD))),
        (None, Some(e)) => extra.push(Span::styled(format!("can't capture: {e}"), Style::new().fg(WARN))),
        (None, None) => extra.push(muted("stopped — press c to capture")),
    }
    let dropped = crate::activity::dropped();
    if dropped > 0 {
        extra.push(Span::styled(format!("  {dropped} events dropped"), Style::new().fg(WARN)));
    }
    frame.render_widget(Paragraph::new(search_bar(app, "operations", total, extra)), Rect { height: 1, ..area });
    app.hit.search = Rect { height: 1, width: area.width / 3, ..area };
    frame.render_widget(
        Paragraph::new(muted(" Newest first; ×n = n identical operations merged. Filter e.g. source:registry  name:powershell  kind:write  path:\\\\Run")),
        Rect { y: area.y + 1, height: 1, ..area },
    );
    let table = Rect { y: area.y + 3, height: area.height.saturating_sub(3), ..area };
    if total == 0 {
        frame.render_widget(Paragraph::new(muted(" Nothing captured. Windows needs administrator rights; Linux and macOS need root.")), table);
        return;
    }
    let specs = [
        ColSpec::new("Time", 12, false),
        ColSpec::new("Process", 18, false),
        ColSpec::new("PID", 7, true),
        ColSpec::new("Class", 8, false),
        ColSpec::new("Operation", 16, false),
        ColSpec::new("Size", 9, true),
        ColSpec::new("Target", 0, false),
    ];
    let height = table.height.saturating_sub(1) as usize;
    app.ir.ac_selected = app.ir.ac_selected.min(total - 1);
    app.ir.ac_offset = scroll_window(app.ir.ac_offset, app.ir.ac_selected, height, total);
    let target_w = (table.width as usize).saturating_sub(76);
    let rows = app
        .visible_activity()
        .iter()
        .skip(app.ir.ac_offset)
        .take(height)
        .filter_map(|seq| app.activity_at(*seq))
        .map(|e| {
            let op = if e.count > 1 { format!("{} ×{}", e.op, e.count) } else { e.op.to_string() };
            vec![
                vec![muted(e.time.format("%H:%M:%S%.3f").to_string())],
                vec![Span::raw(e.name.to_string())],
                vec![muted(e.pid.to_string())],
                vec![Span::styled(e.class.label(), source_style(e.class.label()))],
                vec![Span::raw(op)],
                vec![muted(if e.bytes > 0 { crate::ui::human_bytes(e.bytes) } else { String::new() })],
                vec![Span::raw(truncate_left(&e.path, target_w))],
            ]
        })
        .collect();
    let mut scroll = 0;
    app.hit.list_rows = draw_table(frame, table, &specs, rows, &mut scroll, Some(app.ir.ac_selected - app.ir.ac_offset));
}

/// What the shown operations add up to, like Procmon's Count Occurrences.
pub fn activity_summary(frame: &mut Frame, app: &mut App, screen: Rect) {
    let rect = centered(screen, screen.width.saturating_sub(6), screen.height.saturating_sub(4));
    frame.render_widget(Clear, rect);
    let block = Block::bordered().title(Span::styled(" Activity summary (current filter) ", Style::new().fg(ACCENT)));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let width = (inner.width as usize).saturating_sub(24);
    let mut lines = Vec::new();
    for (title, rows) in app.activity_summary() {
        lines.push(Line::from(heading(&format!(" {title}"))));
        for (count, bytes, name) in rows {
            let size = if bytes > 0 { crate::ui::human_bytes(bytes) } else { String::new() };
            lines.push(Line::from(vec![muted(format!("  {count:>8}  {size:>9}  ")), Span::raw(truncate_left(&name, width))]));
        }
        lines.push(Line::from(""));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

pub fn logs(frame: &mut Frame, app: &mut App, area: Rect) {
    let visible = app.visible_logs();
    let window = match app.ir.log_minutes {
        m if m >= 60 => format!("last {} h", m / 60),
        m => format!("last {m} min"),
    };
    let scope = if app.ir.log_scope == crate::logs::Scope::Important { "errors, warnings & security sources" } else { "all messages" };
    let status = match &app.ir.logs {
        Some(l) if l.pending => format!("   {} reading system log…", spinner(app)),
        Some(l) => format!("   read {} ago", age(l.fetched.elapsed().as_secs())),
        None => "   loading…".into(),
    };
    frame.render_widget(
        Paragraph::new(search_bar(app, "entries", visible.len(), vec![muted(format!("   {window} · {scope}{status}"))])),
        Rect { height: 1, ..area },
    );
    app.hit.search = Rect { height: 1, width: area.width / 3, ..area };
    let table = Rect { y: area.y + 2, height: area.height.saturating_sub(2), ..area };
    if let Some(Err(e)) = app.ir.logs.as_ref().map(|l| &l.result) {
        frame.render_widget(Paragraph::new(vec![Line::from(muted(" Couldn't read the event log")), Line::from(format!(" {e}"))]), table);
        return;
    }
    if visible.is_empty() {
        frame.render_widget(Paragraph::new(muted(" No entries in this window. Press w for a longer window or a for all messages.")), table);
        return;
    }
    let specs = [
        ColSpec::new("Time", 19, false),
        ColSpec::new("Level", 8, false),
        ColSpec::new("Process", 20, false),
        ColSpec::new("PID", 7, true),
        ColSpec::new("Source", 22, false),
        ColSpec::new("Message", 0, false),
    ];
    let height = table.height.saturating_sub(1) as usize;
    app.ir.log_selected = app.ir.log_selected.min(visible.len() - 1);
    app.ir.log_offset = scroll_window(app.ir.log_offset, app.ir.log_selected, height, visible.len());
    let entries = app.log_entries();
    let rows = visible
        .iter()
        .skip(app.ir.log_offset)
        .take(height)
        .map(|i| {
            let e = &entries[*i];
            let level = match e.level.as_str() {
                "fault" | "critical" | "error" => Style::new().fg(BAD),
                "warning" => Style::new().fg(WARN),
                _ => Style::new().fg(TEXT_DIM),
            };
            vec![
                vec![muted(e.time.format("%Y-%m-%d %H:%M:%S").to_string())],
                vec![Span::styled(e.level.clone(), level)],
                vec![Span::raw(e.process.clone())],
                vec![muted(e.pid.map(|p| p.to_string()).unwrap_or_default())],
                vec![muted(e.source.clone())],
                vec![
                    Span::raw(e.message.clone()),
                    if e.repeats > 0 { Span::styled(format!("  ×{}", e.repeats + 1), Style::new().fg(WARN)) } else { Span::raw("") },
                ],
            ]
        })
        .collect();
    let mut scroll = 0;
    let sel = app.ir.log_selected - app.ir.log_offset;
    app.hit.list_rows = draw_table(frame, table, &specs, rows, &mut scroll, Some(sel));
}

// ── case ───────────────────────────────────────────────────────────────

pub fn case(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(case) = app.ir.case.clone() else {
        let lines = vec![
            Line::default(),
            Line::from(heading("  Investigation case")),
            Line::default(),
            Line::from("  A case is a folder that collects evidence with a chain-of-custody log and SHA-256 manifest,"),
            Line::from("  plus your findings, notes and conclusion, and exports a report (Markdown, JSON, HTML)."),
            Line::default(),
            Line::from(vec![Span::raw("  Press "), Span::styled("n", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)), Span::raw(" to open a new case in the current directory.")]),
            Line::from(muted("  A case is also opened automatically when you collect evidence, record a finding (m) or quarantine a file.")),
        ];
        frame.render_widget(Paragraph::new(lines), area);
        return;
    };
    let manifest = case.manifest();
    let custody = case.custody();
    let quarantined = app.quarantined();

    let header = vec![
        Line::from(vec![heading(&format!(" {}", case.id)), muted(format!("   {}", case.dir.display()))]),
        Line::from(muted(format!(
            " examiner {} · host {} · opened {} · {} findings · {} notes · {} evidence files sealed · {} custody entries",
            case.examiner,
            case.host,
            case.opened.get(..16).unwrap_or(&case.opened).replace('T', " "),
            case.findings.len(),
            case.notes.len(),
            manifest.len(),
            custody.len()
        ))),
        Line::from(vec![
            Span::styled(" Conclusion: ", Style::new().fg(TEXT_DIM)),
            if case.conclusion.is_empty() { muted("none yet — press C") } else { Span::raw(case.conclusion.clone()) },
        ]),
        {
            let chain = case.chain_status_cached();
            let reg = case.register();
            let partial = reg.iter().filter(|r| r.status == crate::case::Status::Partial).count();
            let failed = reg.iter().filter(|r| r.status == crate::case::Status::Failed).count();
            let chain_span = match &chain.broken {
                Some((l, why)) => Span::styled(format!(" Custody chain BROKEN at line {l}: {why}"), Style::new().fg(BAD).add_modifier(Modifier::BOLD)),
                None if chain.head.is_empty() => muted(" Custody chain: no chained records yet"),
                None => Span::styled(
                    format!(" Custody chain intact · head {}… (note it outside the case)", chain.head.get(..16).unwrap_or("")),
                    Style::new().fg(OK),
                ),
            };
            Line::from(vec![
                chain_span,
                muted(format!(
                    "   evidence register {} item(s){}{} · {} bookmarks",
                    reg.len(),
                    if partial > 0 { format!(", {partial} partial") } else { String::new() },
                    if failed > 0 { format!(", {failed} failed") } else { String::new() },
                    case.bookmarks.len()
                )),
            ])
        },
    ];
    frame.render_widget(Paragraph::new(header), Rect { height: 4, ..area });

    let body = Rect { y: area.y + 5, height: area.height.saturating_sub(5), ..area };
    let [left, right] = Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).spacing(2).areas(body);
    let [findings, quarantine] = Layout::vertical([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(left);

    // Findings.
    let focus = |on: bool| if on { Style::new().fg(ACCENT).add_modifier(Modifier::BOLD) } else { Style::new().add_modifier(Modifier::BOLD) };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!("Findings ({})", case.findings.len()), focus(!app.ir.case_focus_quarantine)),
            muted("   m on any page records one · del removes"),
        ])),
        Rect { height: 1, ..findings },
    );
    let specs = [ColSpec::new("Sev", 6, false), ColSpec::new("Finding", 0, false), ColSpec::new("Source", 12, false)];
    let rows = case
        .findings
        .iter()
        .map(|f| {
            let sev = match f.severity.as_str() {
                "high" => Style::new().fg(BAD).add_modifier(Modifier::BOLD),
                "low" => Style::new().fg(TEXT_DIM),
                _ => Style::new().fg(WARN),
            };
            vec![vec![Span::styled(f.severity.clone(), sev)], vec![Span::raw(f.title.clone()), muted(format!("  {}", f.detail))], vec![muted(f.source.clone())]]
        })
        .collect::<Vec<_>>();
    let mut s1 = 0;
    let t1 = Rect { y: findings.y + 1, height: findings.height.saturating_sub(1), ..findings };
    if rows.is_empty() {
        frame.render_widget(Paragraph::new(muted(" none yet")), t1);
    } else {
        draw_table(frame, t1, &specs, rows, &mut s1, (!app.ir.case_focus_quarantine).then_some(app.ir.finding_selected));
    }

    // Quarantine.
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!("Quarantine ({})", quarantined.len()), focus(app.ir.case_focus_quarantine)),
            muted("   Q on Files/Persistence or in a file report · R restores"),
        ])),
        Rect { height: 1, ..quarantine },
    );
    let specs = [ColSpec::new("Original path", 0, false), ColSpec::new("SHA-256", 16, false), ColSpec::new("State", 9, false)];
    let rows = quarantined
        .iter()
        .map(|q| {
            vec![
                vec![Span::raw(truncate_left(&q.original_path, 60))],
                vec![muted(q.sha256[..16].to_string())],
                vec![if q.restored { muted("restored") } else { Span::styled("isolated", Style::new().fg(WARN)) }],
            ]
        })
        .collect::<Vec<_>>();
    let t2 = Rect { y: quarantine.y + 1, height: quarantine.height.saturating_sub(1), ..quarantine };
    let mut s2 = 0;
    if rows.is_empty() {
        frame.render_widget(Paragraph::new(muted(" nothing quarantined")), t2);
    } else {
        draw_table(frame, t2, &specs, rows, &mut s2, app.ir.case_focus_quarantine.then_some(app.ir.quarantine_selected));
    }

    // Right column: evidence status, isolation plan, custody log tail.
    let mut lines: Vec<Line> = vec![Line::from(heading("Evidence"))];
    match &app.ir.verify {
        Some(v) => {
            let bad: Vec<&(String, Check)> = v.iter().filter(|(_, c)| *c != Check::Ok).collect();
            if bad.is_empty() {
                lines.push(Line::from(Span::styled(format!(" ✓ {} files verified against the manifest", v.len()), Style::new().fg(OK))));
            } else {
                lines.push(Line::from(Span::styled(format!(" ! {} of {} files fail verification", bad.len(), v.len()), Style::new().fg(BAD))));
                for (p, c) in bad.iter().take(5) {
                    lines.push(Line::from(vec![Span::styled(format!("   {} ", c.label()), Style::new().fg(BAD)), muted(truncate_left(p, 40))]));
                }
            }
        }
        None if manifest.is_empty() => lines.push(Line::from(muted(" not sealed yet — c collects, s seals"))),
        None => lines.push(Line::from(muted(format!(" {} files sealed — v verifies", manifest.len())))),
    }
    if let Some((iso, res)) = &app.ir.isolation {
        lines.push(Line::default());
        lines.push(Line::from(heading("Network isolation plan (not applied)")));
        lines.push(Line::from(muted(format!(" review, then run as root: {}", case.rel(iso)))));
        lines.push(Line::from(muted(format!(" undo with: {}", case.rel(res)))));
    }
    lines.push(Line::default());
    lines.push(Line::from(heading("Chain of custody (latest)")));
    let room = (right.height as usize).saturating_sub(lines.len() + 1);
    for l in custody.iter().rev().take(room) {
        let f: Vec<&str> = l.splitn(4, " | ").collect();
        if f.len() == 4 {
            lines.push(Line::from(vec![
                muted(format!(" {} ", f[0].get(11..19).unwrap_or(f[0]))),
                Span::raw(format!("{} ", f[2])),
                muted(truncate(f[3], (right.width as usize).saturating_sub(f[2].len() + 12))),
            ]));
        }
    }
    frame.render_widget(Paragraph::new(lines), right);
}

// ── dialogs ────────────────────────────────────────────────────────────

pub fn input(frame: &mut Frame, app: &mut App, screen: Rect) {
    let Mode::Input { purpose, input, error } = &app.mode else { return };
    let rect = centered(screen, 84, 9);
    frame.render_widget(Clear, rect);
    let mut lines = vec![
        Line::default(),
        Line::from(muted(format!("  {}", purpose.hint()))),
        Line::default(),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(format!(" {}", truncate_left(input, 76)), Style::new().add_modifier(Modifier::UNDERLINED)),
            Span::styled(" ", Style::new().add_modifier(Modifier::REVERSED)),
        ]),
    ];
    if let Some(e) = error {
        lines.push(Line::from(Span::styled(format!("  {e}"), Style::new().fg(BAD))));
    }
    let block = Block::bordered()
        .border_style(Style::new().fg(ACCENT))
        .title(Span::styled(format!(" {} ", purpose.title()), Style::new().add_modifier(Modifier::BOLD)));
    frame.render_widget(Paragraph::new(lines).block(block), rect);
}

pub fn file_report(frame: &mut Frame, app: &mut App, screen: Rect) {
    let rect = centered(screen, 110, 24);
    frame.render_widget(Clear, rect);
    let block = Block::bordered().border_style(Style::new().fg(ACCENT)).title(Span::styled(" File analysis ", Style::new().add_modifier(Modifier::BOLD)));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let Some(loaded) = app.ir.file_report.as_ref() else { return };
    let r = match &loaded.result {
        Err(path) if loaded.pending => {
            frame.render_widget(Paragraph::new(muted(format!(" {} hashing and checking {path}…", spinner(app)))), inner);
            return;
        }
        Err(e) => {
            frame.render_widget(Paragraph::new(Span::raw(format!(" {e}"))), inner);
            return;
        }
        Ok(r) => r.clone(),
    };
    let w = inner.width as usize;
    let rect_h = rect.height;
    let _ = rect_h;
    let kv = |k: &str, v: String| Line::from(vec![Span::styled(format!(" {k:<14}"), Style::new().fg(TEXT_DIM)), Span::raw(truncate_left(&v, w.saturating_sub(16)))]);
    let mut lines = vec![kv("Path", r.path.clone())];
    if let Some(e) = &r.error {
        lines.push(Line::from(Span::styled(format!(" {e}"), Style::new().fg(BAD))));
    }
    if r.exists {
        lines.push(kv("Type", r.kind.clone()));
        lines.push(kv("Size", format!("{} ({} bytes)", crate::process::human_bytes(r.size), r.size)));
        if let Some(h) = &r.hashes {
            lines.push(kv("SHA-256", h.sha256.clone()));
            lines.push(kv("SHA-1", h.sha1.clone()));
            lines.push(kv("MD5", h.md5.clone()));
        }
        let sig_style = if r.signature.starts_with("valid") { Style::new().fg(OK) } else { Style::new().fg(WARN) };
        lines.push(Line::from(vec![Span::styled(format!(" {:<14}", "Signature"), Style::new().fg(TEXT_DIM)), Span::styled(r.signature.clone(), sig_style)]));
        if let Some(g) = &r.gatekeeper {
            let st = if g.starts_with("REJECTED") { Style::new().fg(BAD) } else if g.starts_with("accepted") { Style::new().fg(OK) } else { Style::new().fg(TEXT_DIM) };
            lines.push(Line::from(vec![Span::styled(format!(" {:<14}", "Gatekeeper"), Style::new().fg(TEXT_DIM)), Span::styled(g.clone(), st)]));
        }
        for (k, v) in &r.signature_details {
            lines.push(kv(&format!("  {k}"), v.clone()));
        }
        lines.push(kv("Created", r.created.clone().unwrap_or_default()));
        lines.push(kv("Modified", r.modified.clone().unwrap_or_default()));
        lines.push(kv("Accessed", r.accessed.clone().unwrap_or_default()));
        lines.push(kv("Permissions", format!("{}  {}", r.permissions, r.owner.clone().unwrap_or_default())));
        if !r.origin.is_empty() {
            lines.push(Line::from(vec![Span::styled(format!(" {:<14}", "Origin"), Style::new().fg(TEXT_DIM)), Span::styled(r.origin.join(" · "), Style::new().fg(WARN))]));
        }
        if crate::persistence::risky_location(&r.path) {
            lines.push(Line::from(Span::styled(" ! located in a temporary or user-writable folder", Style::new().fg(BAD))));
        }
    }
    // Binary header, entropy, entitlements, embedded indicators.
    let d = &r.deep;
    if !d.format.is_empty() {
        lines.push(Line::default());
        lines.push(Line::from(heading(" Binary")));
        for (k, v) in &d.format {
            lines.push(kv(k, v.clone()));
        }
    }
    if let Some(e) = d.entropy {
        let (style, note) = if e >= 7.2 {
            (Style::new().fg(BAD), "  very high — packed, encrypted or compressed")
        } else if e >= 6.5 {
            (Style::new().fg(WARN), "  high")
        } else {
            (Style::new(), "")
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<14}", "Entropy"), Style::new().fg(TEXT_DIM)),
            Span::styled(format!("{e:.2} bits/byte"), style),
            muted(note),
            muted(format!("  (first {})", crate::process::human_bytes(d.scanned_bytes as u64))),
        ]));
    }
    let st = &d.structure;
    if !st.sections.is_empty() || !st.libraries.is_empty() {
        lines.push(Line::default());
        lines.push(Line::from(heading(&format!(
            " Structure — {} sections · {} linked libraries{}{}",
            st.sections.len(),
            st.libraries.len(),
            if st.imports.is_empty() { String::new() } else { format!(" · {} imported functions", st.imports.iter().map(|(_, f)| f.len()).sum::<usize>()) },
            if st.exports > 0 { format!(" · {} exports", st.exports) } else { String::new() }
        ))));
        for a in &st.anomalies {
            lines.push(Line::from(Span::styled(format!("   ⚑ {a}"), Style::new().fg(WARN))));
        }
        for c in &st.capabilities {
            lines.push(Line::from(Span::styled(format!("   ◆ imports suggest {c}"), Style::new().fg(BAD))));
        }
        for sec in st.sections.iter().take(24) {
            let e = sec.entropy.map(|e| format!("{e:.2}")).unwrap_or_else(|| "–".into());
            let hot = sec.entropy.is_some_and(|e| e > 7.2) || sec.perms.contains("wx");
            lines.push(Line::from(vec![
                Span::raw(format!("   {:<28}", truncate(&sec.name, 27))),
                Span::styled(format!("{:<5}", sec.perms), if sec.perms.contains("wx") { Style::new().fg(BAD) } else { Style::new().fg(TEXT_DIM) }),
                muted(format!("{:>10}  entropy ", crate::process::human_bytes(sec.size))),
                Span::styled(e, if hot { Style::new().fg(BAD) } else { Style::new() }),
            ]));
        }
        if !st.libraries.is_empty() {
            lines.push(Line::from(muted(format!("   libraries: {}", truncate(&st.libraries.join(", "), w.saturating_sub(16))))));
        }
    }
    lines.push(Line::default());
    if r.yara.is_empty() {
        lines.push(Line::from(vec![heading(" Content rules"), muted("   no YARA rule matched (built-in + your yara/ folder)")]));
    } else {
        lines.push(Line::from(Span::styled(format!(" Content rules matched ({})", r.yara.len()), Style::new().fg(BAD).add_modifier(Modifier::BOLD))));
        for m in &r.yara {
            lines.push(Line::from(vec![Span::styled(format!("   {}", m.rule), Style::new().fg(BAD)), muted(format!("  {}", m.description))]));
            let strs: Vec<String> = m.strings.iter().map(|(id, off, n)| format!("{id}@{off:#x}{}", if *n > 1 { format!(" ×{n}") } else { String::new() })).collect();
            lines.push(Line::from(muted(format!("     {}", truncate(&strs.join("  "), w.saturating_sub(6))))));
        }
    }
    if !r.entitlements.is_empty() {
        lines.push(Line::default());
        lines.push(Line::from(heading(&format!(" Entitlements ({})", r.entitlements.len()))));
        for e in &r.entitlements {
            let style = if crate::fileinfo::risky_entitlement(e) { Style::new().fg(BAD) } else { Style::new() };
            lines.push(Line::from(vec![Span::raw("   "), Span::styled(e.clone(), style)]));
        }
    }
    if !d.indicators.is_empty() {
        lines.push(Line::default());
        lines.push(Line::from(heading(&format!(" Embedded indicators ({})", d.indicators.len()))));
        for (k, v) in &d.indicators {
            let style = if k == "behavior" { Style::new().fg(WARN) } else { Style::new() };
            lines.push(Line::from(vec![Span::styled(format!("   {k:<9}"), Style::new().fg(TEXT_DIM)), Span::styled(truncate(v, w.saturating_sub(14)), style)]));
        }
    }
    lines.push(Line::default());
    lines.push(Line::from(muted(" Use the SHA-256 to look the file up in your threat-intelligence tools.")));
    let max = lines.len().saturating_sub(inner.height as usize);
    app.ir.report_scroll = app.ir.report_scroll.min(max);
    let lines: Vec<Line> = lines.into_iter().skip(app.ir.report_scroll).collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

pub fn sweep(frame: &mut Frame, app: &mut App, screen: Rect) {
    let rect = centered(screen, screen.width.saturating_sub(6), screen.height.saturating_sub(4));
    frame.render_widget(Clear, rect);
    let Some(s) = app.ir.sweep.as_ref() else { return };
    let title = format!(" IOC sweep — {} hits ", s.hits.len());
    let color = if s.hits.is_empty() { OK } else { BAD };
    let block = Block::bordered().border_style(Style::new().fg(color)).title(Span::styled(title, Style::new().add_modifier(Modifier::BOLD)));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let mut head = vec![Line::from(muted(format!(
        " {} indicators from {} · swept {}",
        s.indicators,
        s.file,
        s.at.format("%H:%M:%S")
    )))];
    if s.hashing > 0 {
        head.push(Line::from(Span::styled(
            format!(" {} executables were still being hashed — press r in a moment to include them", s.hashing),
            Style::new().fg(WARN),
        )));
    }
    for e in s.errors.iter().take(3) {
        head.push(Line::from(muted(format!(" skipped {e}"))));
    }
    let hh = head.len() as u16 + 1;
    frame.render_widget(Paragraph::new(head), Rect { height: hh, ..inner });
    let table = Rect { y: inner.y + hh, height: inner.height.saturating_sub(hh), ..inner };
    if s.hits.is_empty() {
        frame.render_widget(Paragraph::new(Span::styled(" ✓ No indicator matched anything procwatch can see.", Style::new().fg(OK))), table);
        return;
    }
    let specs = [
        ColSpec::new("Type", 7, false),
        ColSpec::new("Indicator", 30, false),
        ColSpec::new("Found in", 13, false),
        ColSpec::new("PID", 7, true),
        ColSpec::new("Process / item", 24, false),
        ColSpec::new("Where", 0, false),
    ];
    let rows = s
        .hits
        .iter()
        .map(|h| {
            vec![
                vec![Span::styled(h.kind.label(), Style::new().fg(BAD))],
                vec![Span::raw(h.ioc.clone()), muted(if h.note.is_empty() { String::new() } else { format!("  {}", h.note) })],
                vec![Span::raw(h.source.clone())],
                vec![muted(h.pid.map(|p| p.to_string()).unwrap_or_default())],
                vec![Span::raw(h.name.clone())],
                vec![muted(h.detail.clone())],
            ]
        })
        .collect();
    let mut scroll = 0;
    let sel = app.ir.sweep_selected.min(s.hits.len() - 1);
    draw_table(frame, table, &specs, rows, &mut scroll, Some(sel));
}
