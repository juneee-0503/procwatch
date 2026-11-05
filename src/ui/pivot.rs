//! Detect page (detections), execution artifacts, and the investigation
//! graph, activity-cluster and collection-health overlays.

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
    Frame,
};

use super::spinner;
use super::widgets::*;
use crate::app::App;
use crate::common::model::Severity;

fn bold(s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), Style::new().add_modifier(Modifier::BOLD))
}

pub fn sev_style(s: Severity) -> Style {
    match s {
        Severity::Critical => Style::new().fg(BAD).add_modifier(Modifier::BOLD | Modifier::REVERSED),
        Severity::High => Style::new().fg(BAD).add_modifier(Modifier::BOLD),
        Severity::Medium => Style::new().fg(WARN),
        Severity::Low => Style::new().fg(TEXT_DIM),
        Severity::Info => Style::new().fg(MUTED),
    }
}

fn filter_line(app: &App, what: &str, count: usize, extra: Vec<Span<'static>>) -> Line<'static> {
    let searching = app.mode == crate::app::Mode::Search;
    let mut spans = vec![Span::styled(" / ", Style::new().fg(ratatui::style::Color::Black).bg(if searching { ACCENT } else { ratatui::style::Color::Gray }))];
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

// ── Detect page ────────────────────────────────────────────────────────

pub fn detections(frame: &mut Frame, app: &mut App, area: Rect) {
    let visible = app.visible_detections();
    let det = &app.ir.det;
    let active = det.store.items.iter().filter(|d| d.active && d.suppressed.is_none()).count();
    let suppressed = det.store.items.iter().filter(|d| d.suppressed.is_some()).count();
    let extra = vec![
        muted(format!("   {active} active · {suppressed} suppressed{}", if det.show_suppressed { " (shown)" } else { "" })),
        muted(format!(
            "   rules: {} host + {} Sigma{}",
            crate::detection::triage::RULES.len(),
            det.sigma.len(),
            if det.sigma_errors.is_empty() { String::new() } else { format!(" ({} rejected)", det.sigma_errors.len()) }
        )),
    ];
    frame.render_widget(Paragraph::new(filter_line(app, "detections", visible.len(), extra)), Rect { height: 1, ..area });
    app.hit.search = Rect { height: 1, width: area.width / 3, ..area };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" Detections", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
            muted("  severity = impact if real · confidence = how well the data supports it · tab → alerts & alert rules"),
        ])),
        Rect { y: area.y + 1, height: 1, ..area },
    );
    let [list, detail] = Layout::vertical([Constraint::Min(4), Constraint::Length(7)]).areas(Rect { y: area.y + 3, height: area.height.saturating_sub(3), ..area });
    if visible.is_empty() {
        let msg = if det.store.items.is_empty() {
            " No detections. Host rules run on every refresh; Sigma rules on new processes, sockets, file changes and loaded logs."
        } else {
            " Nothing matches the filter (u shows suppressed detections)."
        };
        frame.render_widget(Paragraph::new(muted(msg)), list);
        return;
    }
    let specs = [
        ColSpec::new("Severity", 9, false),
        ColSpec::new("Conf", 6, false),
        ColSpec::new("Rule", 0, false),
        ColSpec::new("Subject", 0, false),
        ColSpec::new("ATT&CK", 10, false),
        ColSpec::new("First", 8, false),
        ColSpec::new("Last", 8, false),
        ColSpec::new("State", 10, false),
    ];
    let height = list.height.saturating_sub(1) as usize;
    app.ir.det.selected = app.ir.det.selected.min(visible.len() - 1);
    app.ir.det.offset = scroll_window(app.ir.det.offset, app.ir.det.selected, height, visible.len());
    let rows = visible
        .iter()
        .skip(app.ir.det.offset)
        .take(height)
        .map(|i| {
            let d = &app.ir.det.store.items[*i];
            let state = match (&d.suppressed, d.active) {
                (Some(_), _) => muted("suppressed"),
                (None, true) => Span::styled("active", Style::new().fg(BAD)),
                (None, false) => muted("past"),
            };
            let dim = d.suppressed.is_some() || !d.active;
            vec![
                vec![Span::styled(d.severity.label(), if dim { Style::new().fg(MUTED) } else { sev_style(d.severity) })],
                vec![muted(d.confidence.label())],
                vec![muted(format!("{} ", d.rule_id)), Span::raw(d.rule_name.clone())],
                vec![Span::raw(d.subject_label.clone())],
                vec![muted(d.technique.clone())],
                vec![muted(d.first_seen.format("%H:%M:%S").to_string())],
                vec![muted(d.last_seen.format("%H:%M:%S").to_string())],
                vec![state],
            ]
        })
        .collect();
    let mut scroll = 0;
    app.hit.list_rows = draw_table(frame, list, &specs, rows, &mut scroll, Some(app.ir.det.selected - app.ir.det.offset));

    let Some(d) = app.selected_detection() else { return };
    let mut lines = vec![Line::from(vec![bold(format!(" {} ", d.rule_name)), muted(format!(" {} · {} · seen {}×", d.rule_id, d.engine, d.count))])];
    let explanation = crate::detection::triage::rule(&d.rule_id)
        .map(|r| r.description.to_string())
        .or_else(|| app.ir.det.sigma.iter().find(|r| r.id == d.rule_id).map(|r| r.description.clone()))
        .unwrap_or_default();
    if !explanation.is_empty() {
        lines.push(Line::from(muted(format!(" {explanation}"))));
    }
    for e in d.evidence.iter().rev().take(3) {
        lines.push(Line::from(vec![Span::styled(" ↳ ", Style::new().fg(ACCENT)), Span::raw(e.clone())]));
    }
    if let Some(why) = &d.suppressed {
        lines.push(Line::from(Span::styled(format!(" suppressed: {why}"), Style::new().fg(TEXT_DIM))));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(Block::new().borders(ratatui::widgets::Borders::TOP).border_style(Style::new().fg(MUTED))), detail);
}

// ── artifacts (Logs page, x) ───────────────────────────────────────────

pub fn artifacts(frame: &mut Frame, app: &mut App, area: Rect) {
    let visible = app.visible_artifacts();
    let status = match &app.ir.artifacts_live {
        Some(l) if l.pending => format!("   {} collecting…", spinner(app)),
        Some(_) => String::new(),
        None => "   loading…".into(),
    };
    let imported = app.ir.artifacts_imported.len();
    let extra = vec![muted(format!(
        "   execution artifacts{status}{}",
        if imported > 0 { format!(" · {imported} imported folder(s)") } else { String::new() }
    ))];
    frame.render_widget(Paragraph::new(filter_line(app, "artifacts", visible.len(), extra)), Rect { height: 1, ..area });
    app.hit.search = Rect { height: 1, width: area.width / 3, ..area };
    let mut notes: Vec<String> = app.ir.artifacts_live.as_ref().and_then(|l| l.result.as_ref().ok()).cloned().unwrap_or_default();
    for (d, _, n) in &app.ir.artifacts_imported {
        notes.extend(n.iter().map(|n| format!("{}: {n}", d.display())));
    }
    let note_h = notes.len().min(2) as u16;
    for (i, n) in notes.iter().take(2).enumerate() {
        frame.render_widget(Paragraph::new(Span::styled(format!(" ! {n}"), Style::new().fg(WARN))), Rect { y: area.y + 1 + i as u16, height: 1, ..area });
    }
    let [list, info] = Layout::vertical([Constraint::Min(4), Constraint::Length(5)]).areas(Rect {
        y: area.y + 2 + note_h,
        height: area.height.saturating_sub(2 + note_h),
        ..area
    });
    if visible.is_empty() {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(muted(" No artifacts. On Windows: Prefetch, ShimCache, BAM, Defender (run as administrator). On macOS/Linux: shell histories.")),
                Line::from(muted(" Press A to import a folder copied from another machine (.pf, .evtx, histories, AppCompatCache values).")),
            ]),
            list,
        );
        return;
    }
    let specs = [
        ColSpec::new("Time", 19, false),
        ColSpec::new("Kind", 13, false),
        ColSpec::new("Program / record", 0, false),
        ColSpec::new("Detail", 0, false),
        ColSpec::new("User", 12, false),
    ];
    let height = list.height.saturating_sub(1) as usize;
    app.ir.art_selected = app.ir.art_selected.min(visible.len() - 1);
    app.ir.art_offset = scroll_window(app.ir.art_offset, app.ir.art_selected, height, visible.len());
    let w = (list.width as usize).saturating_sub(50) / 2;
    let rows = visible
        .iter()
        .skip(app.ir.art_offset)
        .take(height)
        .map(|i| {
            let a = &app.ir.artifacts[*i];
            vec![
                vec![a.time.map(|t| muted(t.format("%Y-%m-%d %H:%M:%S").to_string())).unwrap_or_else(|| muted("(no time)"))],
                vec![Span::styled(a.kind, Style::new().fg(ACCENT))],
                vec![Span::raw(truncate_left(&a.subject, w.max(20)))],
                vec![muted(a.detail.clone())],
                vec![muted(a.user.clone().unwrap_or_default())],
            ]
        })
        .collect();
    let mut scroll = 0;
    app.hit.list_rows = draw_table(frame, list, &specs, rows, &mut scroll, Some(app.ir.art_selected - app.ir.art_offset));
    // What the selected kind's timestamp means and what it can support.
    let a = &app.ir.artifacts[visible[app.ir.art_selected]];
    if let Some(k) = crate::host::artifacts::info(a.kind) {
        let lines = vec![
            Line::from(vec![bold(format!(" {} ", k.kind)), muted(format!(" {} · {}", k.source, k.platforms))]),
            Line::from(vec![muted(" time: "), Span::raw(k.time_meaning)]),
            Line::from(vec![muted(" supports: "), Span::raw(k.supports)]),
            Line::from(vec![muted(" limits: "), Span::styled(k.limits, Style::new().fg(WARN))]),
        ];
        frame.render_widget(Paragraph::new(lines).block(Block::new().borders(ratatui::widgets::Borders::TOP).border_style(Style::new().fg(MUTED))), info);
    }
}

// ── overlays ───────────────────────────────────────────────────────────

fn overlay(frame: &mut Frame, screen: Rect, title: String) -> Rect {
    let rect = centered(screen, screen.width.saturating_sub(6), screen.height.saturating_sub(4));
    frame.render_widget(Clear, rect);
    let block = Block::bordered().border_style(Style::new().fg(ACCENT)).title(bold(title));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    inner
}

pub fn graph(frame: &mut Frame, app: &mut App, screen: Rect) {
    let Some(cur) = app.graph_current().cloned() else { return };
    let inner = overlay(frame, screen, format!(" Investigation graph — {} ", app.entity_label(&cur)));
    let props = app.entity_props(&cur);
    let crumbs: Vec<String> = app.ir.graph.stack.iter().map(|e| truncate(&app.entity_label(e), 28)).collect();
    let mut head = vec![Line::from(muted(format!(" {}", crumbs.join("  ›  "))))];
    for (k, v) in &props {
        head.push(Line::from(vec![muted(format!(" {k:<10} ")), Span::raw(truncate(v, inner.width.saturating_sub(13) as usize))]));
    }
    let hh = (head.len() as u16 + 1).min(inner.height / 2);
    frame.render_widget(Paragraph::new(head), Rect { height: hh, ..inner });
    let table = Rect { y: inner.y + hh, height: inner.height.saturating_sub(hh), ..inner };
    let nb = app.neighbors(&cur);
    if nb.is_empty() {
        frame.render_widget(Paragraph::new(muted(" No known relations. ← goes back.")), table);
        return;
    }
    let specs = [ColSpec::new("Relation", 15, false), ColSpec::new("Type", 11, false), ColSpec::new("Item", 0, false), ColSpec::new("Note", 0, false)];
    let height = table.height.saturating_sub(1) as usize;
    let g = &mut app.ir.graph;
    g.cursor = g.cursor.min(nb.len() - 1);
    g.offset = scroll_window(g.offset, g.cursor, height, nb.len());
    let rows = nb
        .iter()
        .skip(g.offset)
        .take(height)
        .map(|n| {
            vec![
                vec![Span::styled(n.rel.label(), Style::new().fg(ACCENT))],
                vec![muted(n.entity.kind())],
                vec![Span::raw(n.label.clone())],
                vec![muted(n.note.clone())],
            ]
        })
        .collect();
    let mut scroll = 0;
    let sel = g.cursor - g.offset;
    draw_table(frame, table, &specs, rows, &mut scroll, Some(sel));
}

pub fn clusters(frame: &mut Frame, app: &mut App, screen: Rect) {
    let inner = overlay(frame, screen, format!(" Correlated activity — {} cluster(s) ", app.ir.clusters.len()));
    if app.ir.clusters.is_empty() {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(muted(" No clusters. A cluster is one process tree doing several kinds of thing within 2 minutes —")),
                Line::from(muted(" e.g. starting a child, connecting out and writing a file or launch agent — or anything with a detection.")),
            ]),
            inner,
        );
        return;
    }
    let [list, side] = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).spacing(1).areas(inner);
    let specs = [ColSpec::new("#", 3, true), ColSpec::new("Subject", 0, false), ColSpec::new("Activity", 0, false), ColSpec::new("When", 8, false)];
    app.ir.cluster_selected = app.ir.cluster_selected.min(app.ir.clusters.len() - 1);
    let height = list.height.saturating_sub(1) as usize;
    let off = scroll_window(0, app.ir.cluster_selected, height, app.ir.clusters.len());
    let rows = app
        .ir
        .clusters
        .iter()
        .skip(off)
        .take(height)
        .map(|c| {
            let kinds: Vec<String> = c.categories.iter().map(|(k, n)| format!("{k} {n}")).collect();
            vec![
                vec![Span::raw(c.id.to_string())],
                vec![Span::styled(c.label(), if c.detections > 0 { Style::new().fg(BAD) } else { Style::new() })],
                vec![muted(kinds.join(" · "))],
                vec![muted(c.start.format("%H:%M:%S").to_string())],
            ]
        })
        .collect();
    let mut scroll = 0;
    draw_table(frame, list, &specs, rows, &mut scroll, Some(app.ir.cluster_selected - off));
    let summaries = app.cluster_summaries();
    let Some(s) = summaries.get(app.ir.cluster_selected) else { return };
    let mut lines = vec![Line::from(bold(s.subject.clone())), Line::from(muted(s.window.clone())), Line::default()];
    for (title, list) in [("Observed", &s.observed), ("Detections", &s.detections), ("Evidence", &s.evidence)] {
        if !list.is_empty() {
            lines.push(Line::from(bold(title)));
            for o in list {
                lines.push(Line::from(format!("• {o}")));
            }
        }
    }
    lines.push(Line::default());
    lines.push(Line::from(vec![bold("Assessment: "), Span::raw(s.assessment.clone())]));
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), side);
}

pub fn health(frame: &mut Frame, app: &mut App, screen: Rect) {
    let inner = overlay(frame, screen, " Collection health — what procwatch can and can't see ".into());
    let sources = app.collection_health();
    let mut lines = vec![
        Line::from(muted(" \"Nothing detected\" only covers what was observed. Partial or missing sources limit what you can conclude.")),
        Line::default(),
    ];
    for s in &sources {
        use crate::engine::health::Status::*;
        let st = match s.status {
            Available => Style::new().fg(OK),
            Partial | NotLoaded => Style::new().fg(WARN),
            Denied | Missing => Style::new().fg(BAD),
            NotUsed => Style::new().fg(MUTED),
        };
        // Wrap the detail under its own column, not back to the edge.
        let detail_w = (inner.width as usize).saturating_sub(46).max(20);
        for (n, part) in wrap(&s.detail, detail_w).into_iter().enumerate() {
            lines.push(if n == 0 {
                Line::from(vec![Span::raw(format!(" {:<28}", s.name)), Span::styled(format!("{:<16}", s.status.label()), st), muted(part)])
            } else {
                Line::from(vec![Span::raw(" ".repeat(45)), muted(part)])
            });
        }
    }
    lines.push(Line::default());
    lines.push(Line::from(muted(" any key closes · included in collected evidence (c) and in the report")));
    frame.render_widget(Paragraph::new(lines), inner);
}

pub fn state_at(frame: &mut Frame, app: &mut App, screen: Rect) {
    let Some(st) = app.ir.state_at.clone() else { return };
    let when = st.time.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_default();
    let inner = overlay(frame, screen, format!(" System state at {when} "));
    let w = inner.width as usize;
    let mut lines: Vec<Line> = Vec::new();
    for n in &st.notes {
        lines.push(Line::from(Span::styled(format!(" ! {}", truncate(n, w.saturating_sub(4))), Style::new().fg(WARN))));
    }
    let mut section = |title: String, rows: &[crate::app::state::StateRow], style: Style| {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(title, style.add_modifier(Modifier::BOLD))));
        if rows.is_empty() {
            lines.push(Line::from(muted("   none")));
        }
        for r in rows {
            lines.push(Line::from(vec![
                muted(format!("   {:<9}", r.basis)),
                Span::raw(format!("{:<34} ", truncate(&r.what, 34))),
                muted(truncate(&r.detail, w.saturating_sub(48))),
            ]));
        }
    };
    section(format!(" Processes running ({})", st.processes.len()), &st.processes, Style::new());
    section(format!(" Open sockets ({})", st.sockets.len()), &st.sockets, Style::new());
    section(format!(" Autostart entries already defined ({})", st.persistence.len()), &st.persistence, Style::new());
    section(format!(" Autostart entries added or changed AFTER this moment ({})", st.persistence_later.len()), &st.persistence_later, Style::new().fg(WARN));
    let max = lines.len().saturating_sub(inner.height as usize);
    app.ir.state_scroll = app.ir.state_scroll.min(max);
    let lines: Vec<Line> = lines.into_iter().skip(app.ir.state_scroll).collect();
    frame.render_widget(Paragraph::new(lines), inner);
}
