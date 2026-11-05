//! Processes page: toolbar (search, view, sort), the process table, and the
//! details pane below it (or full-screen details).

use chrono::{Local, TimeZone};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};
use sysinfo::ProcessStatus;
use unicode_width::UnicodeWidthStr;

use super::details;
use super::widgets::*;
use crate::app::{App, Group, Mode, PaneTab, Row, RowKey};
use crate::app::columns::Col;
use crate::process::{cpu_time, human_bytes, human_rate, ProcessInfo};

/// Gutter at the left of every row: selection marker.
const GUTTER: usize = 2;

pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    if app.detail_full {
        return details::draw_full(frame, app, area);
    }
    let toolbar = Rect { height: 1, ..area };
    draw_toolbar(frame, app, toolbar);
    let rest = Rect { y: area.y + 1, height: area.height.saturating_sub(1), ..area };

    let pane_h = if app.pane_visible && rest.height >= 16 { (rest.height * 2 / 5).max(8) } else { 0 };
    let list = Rect { height: rest.height - pane_h, ..rest };
    draw_table(frame, app, list);
    if pane_h > 0 {
        details::draw_pane(frame, app, Rect { y: list.bottom(), height: pane_h, ..rest });
    }
}

fn draw_toolbar(frame: &mut Frame, app: &mut App, area: Rect) {
    // Search box on the left.
    let searching = app.mode == Mode::Search;
    let box_w = (area.width / 3).clamp(24, 48);
    let mut spans = vec![Span::styled(" / ", Style::new().fg(Color::Black).bg(if searching { ACCENT } else { Color::Gray }))];
    if app.query.is_empty() && !searching {
        spans.push(muted(" Search processes…"));
    } else {
        spans.push(Span::raw(format!(" {}", app.query)));
        if searching {
            spans.push(Span::styled(" ", Style::new().add_modifier(Modifier::REVERSED)));
        }
    }
    let search = Line::from(spans);
    app.hit.search = Rect { width: box_w, ..area };
    frame.render_widget(Paragraph::new(search), app.hit.search);

    // Filters, view, sort, count on the right.
    let mut right: Vec<Span> = Vec::new();
    let chip = |label: &str, value: &str| {
        vec![muted(format!("{label} ")), Span::styled(format!("{value} ✕"), Style::new().fg(WARN)), Span::raw("   ")]
    };
    if let Some(a) = &app.app_filter {
        right.extend(chip("app", a));
    }
    if let Some(u) = &app.user_filter {
        right.extend(chip("user", u));
    }
    let view_label = format!("{} ▾", app.view.label());
    right.push(muted("View "));
    let view_start: usize = right.iter().map(|s| s.content.width()).sum();
    right.push(Span::styled(view_label.clone(), Style::new().add_modifier(Modifier::BOLD)));
    right.push(muted("   Sort "));
    right.push(Span::styled(
        format!("{} {}", app.sort.header(), if app.sort_desc { "↓" } else { "↑" }),
        Style::new().add_modifier(Modifier::BOLD),
    ));
    if app.order_frozen {
        right.push(Span::styled("   order frozen", Style::new().fg(Color::Black).bg(WARN)));
    } else if app.order_held() {
        right.push(muted("   order held"));
    }
    let total = app.tree.nodes.len();
    let shown = if app.filtering() { format!("   {} of {total}", app.matched.len()) } else { format!("   {total} processes") };
    right.push(muted(shown));
    right.push(Span::raw(" "));
    let line = Line::from(right);
    let w = (line.width() as u16).min(area.width.saturating_sub(box_w + 1));
    let x = area.right() - w;
    app.hit.view_toggle = Rect { x: x + view_start as u16, width: view_label.width() as u16, ..area };
    frame.render_widget(Paragraph::new(line).right_aligned(), Rect { x, width: w, ..area });
}

/// Columns to show at this width: low-priority ones are dropped (in this
/// order) until the Name column has room to be readable.
fn visible_columns(app: &App, width: usize) -> Vec<Col> {
    const DROP_ORDER: [Col; 14] = [
        Col::Command,
        Col::Started,
        Col::Virtual,
        Col::Ppid,
        Col::Priority,
        Col::DiskRead,
        Col::DiskWrite,
        Col::Trend,
        Col::CpuTime,
        Col::MemPct,
        Col::Status,
        Col::Disk,
        Col::Threads,
        Col::User,
    ];
    let mut cols = app.columns.clone();
    let fixed = |cols: &[Col]| -> usize {
        cols.iter().filter(|c| **c != Col::Name).map(|c| c.width() as usize + 2).sum::<usize>()
    };
    for drop in DROP_ORDER {
        if width.saturating_sub(fixed(&cols)) >= 24 {
            break;
        }
        cols.retain(|c| *c != drop);
    }
    cols
}

fn specs(cols: &[Col]) -> Vec<ColSpec> {
    let has_cmd = cols.contains(&Col::Command);
    cols.iter()
        .map(|c| {
            // Name shares space with the command line when both are shown.
            let width = if *c == Col::Name && has_cmd { 32 } else { c.width() };
            ColSpec::new(c.header(), width, c.right_aligned())
        })
        .collect()
}

fn draw_table(frame: &mut Frame, app: &mut App, area: Rect) {
    let total = (area.width as usize).saturating_sub(GUTTER);
    let cols = visible_columns(app, total);
    let specs = specs(&cols);
    let w = widths(&specs, total);
    let active = cols.iter().position(|c| *c == app.sort).map(|i| (i, app.sort_desc));

    let header = header_line(&specs, &w, active, total);
    let mut spans = vec![Span::styled(" ".repeat(GUTTER), header_style())];
    spans.extend(header.spans);
    frame.render_widget(Paragraph::new(Line::from(spans)), Rect { height: 1, ..area });
    let mut x = area.x + GUTTER as u16;
    for (col, cw) in cols.iter().zip(&w) {
        app.hit.list_header.push((Rect { x, y: area.y, width: *cw as u16 + 2, height: 1 }, *col));
        x += *cw as u16 + 2;
    }

    let body = Rect { y: area.y + 1, height: area.height.saturating_sub(1), ..area };
    app.hit.list_rows = body;
    let height = body.height as usize;
    if app.rows.is_empty() {
        let checking = app.ir.intel.pending();
        let msg = if !app.loaded {
            Line::from(muted("Reading process list…"))
        } else if app.view == crate::app::ViewMode::Suspicious && app.query.is_empty() {
            if checking > 0 {
                Line::from(muted(format!("Nothing suspicious yet — still checking signatures of {checking} programs…")))
            } else {
                Line::from(Span::styled("✓ No process shows warning signs.", Style::new().fg(OK)))
            }
        } else if !app.query.is_empty() {
            Line::from(vec![muted("No process matches "), Span::raw(format!("“{}”", app.query)), muted(" — press esc to clear")])
        } else {
            Line::from(muted("No processes match the current filter — press esc to clear"))
        };
        frame.render_widget(Paragraph::new(msg).centered(), Rect { y: body.y + body.height / 3, height: 1, ..body });
        return;
    }

    app.offset = scroll_window(app.offset, app.selected, height, app.rows.len());
    let end = (app.offset + height).min(app.rows.len());
    let filtering = app.filtering();
    let mut lines = Vec::with_capacity(height);
    for (i, row) in app.rows[app.offset..end].iter().enumerate() {
        let idx = app.offset + i;
        let (cells, row_style, tagged) = match &row.key {
            RowKey::Proc(pid) => {
                let Some(node) = app.tree.get(*pid) else { continue };
                let cells = cols.iter().map(|c| proc_cell(app, *c, &node.info, row)).collect::<Vec<_>>();
                let style = if filtering && !app.matched.contains(pid) {
                    Some(Style::new().fg(MUTED))
                } else if app.is_new(*pid) {
                    Some(Style::new().fg(OK))
                } else {
                    None
                };
                (cells, style, app.tagged.contains(pid))
            }
            RowKey::Group(name) => {
                let Some(g) = app.groups.get(name) else { continue };
                let cells = cols.iter().map(|c| group_cell(app, *c, g, row)).collect::<Vec<_>>();
                (cells, None, !g.members.is_empty() && g.members.iter().all(|p| app.tagged.contains(p)))
            }
        };
        let mut spans = vec![if tagged {
            Span::styled("● ", Style::new().fg(ACCENT))
        } else {
            Span::raw("  ")
        }];
        spans.extend(row_line(cells, &specs, &w, total));
        let style = if idx == app.selected { Some(sel_style()) } else if tagged { Some(Style::new().fg(ACCENT)) } else { row_style };
        lines.push(restyle(spans, style));
    }
    frame.render_widget(Paragraph::new(lines), body);
}

fn name_cell(row: &Row, name: String, suffix: Option<String>) -> Vec<Span<'static>> {
    let mut v = Vec::new();
    if !row.prefix.is_empty() {
        v.push(Span::styled(row.prefix.clone(), Style::new().fg(MUTED)));
    }
    if row.expandable {
        v.push(Span::styled(if row.expanded { "▾ " } else { "▸ " }, Style::new().fg(ACCENT)));
    }
    v.push(Span::raw(name));
    if let Some(s) = suffix {
        v.push(Span::styled(s, Style::new().fg(MUTED)));
    }
    v
}

fn pct(v: f64, heat: bool) -> Span<'static> {
    let style = if v < 0.05 {
        Style::new().fg(MUTED)
    } else if heat && v >= 50.0 {
        Style::new().fg(BAD).add_modifier(Modifier::BOLD)
    } else if heat && v >= 20.0 {
        Style::new().fg(WARN)
    } else {
        Style::new()
    };
    Span::styled(format!("{v:.1}%"), style)
}

fn mem(bytes: u64, total: u64) -> Span<'static> {
    let r = ratio(bytes, total);
    let style = if r >= 0.25 {
        Style::new().fg(BAD).add_modifier(Modifier::BOLD)
    } else if r >= 0.10 {
        Style::new().fg(WARN)
    } else if bytes < 1 << 20 {
        Style::new().fg(MUTED)
    } else {
        Style::new()
    };
    Span::styled(human_bytes(bytes), style)
}

fn rate(v: f64) -> Span<'static> {
    if v < 1.0 { muted("0") } else { Span::raw(human_rate(v)) }
}

fn opt<T: ToString>(v: Option<T>) -> Span<'static> {
    v.map(|v| Span::raw(v.to_string())).unwrap_or_else(|| muted("–"))
}

pub fn risk_span(score: u8) -> Span<'static> {
    match score {
        0 => muted("–"),
        1..=24 => Span::styled(score.to_string(), Style::new().fg(TEXT_DIM)),
        25..=49 => Span::styled(score.to_string(), Style::new().fg(WARN).add_modifier(Modifier::BOLD)),
        _ => Span::styled(score.to_string(), Style::new().fg(Color::White).bg(BAD).add_modifier(Modifier::BOLD)),
    }
}

pub fn status_span(info: &ProcessInfo) -> Span<'static> {
    let label = match info.status {
        ProcessStatus::Run => "Running",
        ProcessStatus::Sleep | ProcessStatus::Idle => "Sleeping",
        ProcessStatus::Stop => "Stopped",
        ProcessStatus::Zombie => "Zombie",
        ProcessStatus::UninterruptibleDiskSleep => "Disk wait",
        ProcessStatus::Tracing => "Traced",
        ProcessStatus::Dead => "Exited",
        _ => "Unknown",
    };
    let style = match info.status {
        ProcessStatus::Run => Style::new().fg(OK),
        ProcessStatus::Stop | ProcessStatus::Tracing => Style::new().fg(Color::Magenta),
        ProcessStatus::Zombie | ProcessStatus::UninterruptibleDiskSleep | ProcessStatus::Dead => Style::new().fg(BAD),
        _ => Style::new().fg(TEXT_DIM),
    };
    Span::styled(label, style)
}

pub fn priority_span(info: &ProcessInfo) -> Span<'static> {
    let label = info.priority_label();
    let style = match label {
        "Very high" => Style::new().fg(BAD),
        "High" => Style::new().fg(WARN),
        "Low" | "Very low" => Style::new().fg(TEXT_DIM),
        "-" => Style::new().fg(MUTED),
        _ => Style::new(),
    };
    Span::styled(label, style)
}

pub fn start_label(secs: u64) -> String {
    if secs == 0 {
        return "–".into();
    }
    let Some(t) = Local.timestamp_opt(secs as i64, 0).single() else { return "–".into() };
    if t.date_naive() == Local::now().date_naive() { t.format("%H:%M").to_string() } else { t.format("%b %d").to_string() }
}

fn proc_cell(app: &App, col: Col, info: &ProcessInfo, row: &Row) -> Vec<Span<'static>> {
    let total = app.stats.mem_total;
    vec![match col {
        Col::Name => {
            let suffix = (row.hidden > 0).then(|| format!("  +{}", row.hidden));
            return name_cell(row, info.name.clone(), suffix);
        }
        Col::Pid => Span::raw(info.pid.to_string()),
        Col::Risk => risk_span(info.risk),
        Col::Signed => match info.signed {
            'y' => Span::styled("signed", Style::new().fg(OK)),
            'n' => Span::styled("NO", Style::new().fg(WARN).add_modifier(Modifier::BOLD)),
            '!' => Span::styled("INVALID", Style::new().fg(BAD).add_modifier(Modifier::BOLD)),
            _ => muted("–"),
        },
        Col::Ppid => opt(info.ppid),
        Col::User => Span::raw(info.user.clone().unwrap_or_else(|| "–".into())),
        Col::Status => status_span(info),
        Col::Cpu => pct(info.cpu_usage_pct as f64, true),
        Col::Trend => {
            let data = app.proc_hist.get(&info.pid).map(|h| &h.cpu);
            match data {
                Some(d) => Span::styled(sparkline(d, col.width() as usize, peak(d).max(10.0)), Style::new().fg(ACCENT)),
                None => Span::raw(""),
            }
        }
        Col::Memory => mem(info.mem(), total),
        Col::MemPct => pct(ratio(info.mem(), total) * 100.0, false),
        Col::MemTrend => match info.mem_growth {
            None => muted("…"),
            Some(g) if g.abs() < 512.0 * 1024.0 => muted("steady"),
            Some(g) => {
                let style = if g >= 20.0 * 1048576.0 {
                    Style::new().fg(BAD).add_modifier(Modifier::BOLD)
                } else if g > 0.0 {
                    Style::new().fg(WARN)
                } else {
                    Style::new().fg(OK)
                };
                let sign = if g > 0.0 { "+" } else { "−" };
                Span::styled(format!("{sign}{}/m", human_bytes(g.abs() as u64)), style)
            }
        },
        Col::Virtual => Span::styled(human_bytes(info.virtual_memory_bytes), Style::new().fg(TEXT_DIM)),
        Col::Threads => opt(info.threads),
        Col::Disk => rate(info.disk_read_rate + info.disk_write_rate),
        Col::DiskRead => rate(info.disk_read_rate),
        Col::DiskWrite => rate(info.disk_write_rate),
        Col::Net => rate(info.net_rate),
        Col::CpuTime => info.cpu_time_secs.map(|t| Span::raw(cpu_time(t))).unwrap_or_else(|| muted("–")),
        Col::Started => Span::raw(start_label(info.start_time_secs)),
        Col::Priority => priority_span(info),
        Col::Command => muted(if info.cmd.is_empty() { String::new() } else { info.cmd.join(" ") }),
    }]
}

fn group_cell(app: &App, col: Col, g: &Group, row: &Row) -> Vec<Span<'static>> {
    let bold = Style::new().add_modifier(Modifier::BOLD);
    vec![match col {
        Col::Name => {
            let mut v = name_cell(row, g.name.clone(), Some(format!("  {} processes", g.members.len())));
            if let Some(name) = v.iter_mut().find(|s| s.content == g.name.as_str()) {
                name.style = bold;
            }
            return v;
        }
        Col::User => Span::raw(g.user.clone().unwrap_or_default()),
        Col::Cpu => pct(g.cpu as f64, true),
        Col::Memory => mem(g.mem, app.stats.mem_total),
        Col::MemPct => pct(ratio(g.mem, app.stats.mem_total) * 100.0, false),
        Col::Threads => Span::raw(g.threads.to_string()),
        Col::Disk => rate(g.disk),
        _ => Span::raw(""),
    }]
}

/// Used by the details pane to show which tab is active.
pub fn pane_tab_spans(app: &mut App, area: Rect, label: Line<'static>) -> Line<'static> {
    let mut spans = vec![muted("──")];
    let mut x = area.x + 2;
    for t in PaneTab::ALL {
        let text = format!(" {} ", t.title());
        let w = text.width() as u16;
        let style = if t == app.pane_tab {
            Style::new().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(TEXT_DIM)
        };
        app.hit.pane_tabs.push((Rect { x, y: area.y, width: w, height: 1 }, t));
        spans.push(Span::styled(text, style));
        x += w;
    }
    let used: usize = spans.iter().map(|s| s.content.width()).sum::<usize>() + label.width() + 2;
    spans.push(muted(format!(" {}", "─".repeat((area.width as usize).saturating_sub(used + 1)))));
    spans.push(Span::raw(" "));
    spans.extend(label.spans);
    spans.push(Span::raw(" "));
    Line::from(spans)
}
