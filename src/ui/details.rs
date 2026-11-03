//! Details for the selected process: the pane under the table and the
//! full-screen view share the same tab bodies.

use chrono::{Local, TimeZone};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};
use unicode_width::UnicodeWidthStr;

use super::processes::{pane_tab_spans, priority_span, status_span};
use super::spinner;
use super::widgets::*;
use super::widgets::truncate;
use crate::app::{App, Group, PaneTab};
use crate::inspect::SignatureStatus;
use crate::network::ConnState;
use crate::process::{ago, cpu_time, human_bytes, human_duration, human_rate, ProcessInfo};

const LABEL_W: usize = 13;

pub fn draw_pane(frame: &mut Frame, app: &mut App, area: Rect) {
    let label = match (app.selected_pid(), app.selected_group()) {
        (Some(pid), _) => Line::from(vec![
            Span::styled(app.name_of(pid), Style::new().add_modifier(Modifier::BOLD)),
            muted(format!(" {pid}")),
        ]),
        (None, Some(g)) => Line::from(Span::styled(g.name.clone(), Style::new().add_modifier(Modifier::BOLD))),
        _ => Line::default(),
    };
    let bar = Rect { height: 1, ..area };
    let line = pane_tab_spans(app, bar, label);
    frame.render_widget(Paragraph::new(line), bar);
    let body = Rect { x: area.x + 1, y: area.y + 1, width: area.width.saturating_sub(2), height: area.height.saturating_sub(1) };
    app.hit.pane_body = body;

    if let Some(g) = app.selected_group().cloned() {
        return group_summary(frame, app, &g, body);
    }
    match app.selected_pid().and_then(|p| app.tree.get(p)).map(|n| n.info.clone()) {
        Some(info) => tab_body(frame, app, &info, body),
        None => frame.render_widget(Paragraph::new(muted("Select a process to see its details")), body),
    }
}

pub fn draw_full(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(info) = app.selected_pid().and_then(|p| app.tree.get(p)).map(|n| n.info.clone()) else {
        app.detail_full = false;
        return;
    };
    let mut title = vec![
        Span::styled(format!(" {} ", info.name), Style::new().add_modifier(Modifier::BOLD)),
        muted(format!("PID {}  ", info.pid)),
        status_span(&info),
        muted("  "),
    ];
    let used: usize = title.iter().map(|s| s.content.width()).sum();
    title.push(muted(truncate_left(&info.exe_path.clone().unwrap_or_default(), (area.width as usize).saturating_sub(used + 2))));
    frame.render_widget(Paragraph::new(Line::from(title)), Rect { height: 1, ..area });

    let bar = Rect { y: area.y + 2, height: 1, ..area };
    let line = pane_tab_spans(app, bar, Line::default());
    frame.render_widget(Paragraph::new(line), bar);
    let body = Rect { x: area.x + 1, y: area.y + 3, width: area.width.saturating_sub(2), height: area.height.saturating_sub(3) };
    app.hit.pane_body = body;
    tab_body(frame, app, &info, body);
}

fn tab_body(frame: &mut Frame, app: &mut App, info: &ProcessInfo, area: Rect) {
    match app.pane_tab {
        PaneTab::Overview => {
            let lines = overview(app, info, area.width as usize);
            scrolled(frame, app, area, lines);
        }
        PaneTab::Performance => performance(frame, app, info, area),
        PaneTab::Network => network(frame, app, info.pid, area),
        PaneTab::Relations => {
            let lines = relations(app, info, area.width as usize);
            scrolled(frame, app, area, lines);
        }
        PaneTab::Stack => stack(frame, app, info.pid, area),
        PaneTab::Memory => memory(frame, app, info.pid, area),
        tab => inspected(frame, app, tab, area),
    }
}

fn scrolled(frame: &mut Frame, app: &mut App, area: Rect, lines: Vec<Line<'static>>) {
    let max = lines.len().saturating_sub(area.height as usize);
    app.pane_scroll = app.pane_scroll.min(max);
    frame.render_widget(Paragraph::new(lines).scroll((app.pane_scroll as u16, 0)), area);
}

fn label(name: &str) -> Span<'static> {
    Span::styled(format!("{name:<LABEL_W$}"), Style::new().fg(TEXT_DIM))
}

fn kv(name: &str, value: Vec<Span<'static>>) -> Line<'static> {
    let mut spans = vec![label(name)];
    spans.extend(value);
    Line::from(spans)
}

fn val(v: impl Into<String>) -> Vec<Span<'static>> {
    let v = v.into();
    if v.is_empty() { vec![muted("–")] } else { vec![Span::raw(v)] }
}

fn wrapped(lines: &mut Vec<Line<'static>>, name: &str, value: &str, avail: usize) {
    if value.is_empty() {
        lines.push(kv(name, vec![muted("–")]));
        return;
    }
    for (i, chunk) in wrap(value, avail).into_iter().enumerate() {
        lines.push(kv(if i == 0 { name } else { "" }, vec![Span::raw(chunk)]));
    }
}

fn overview(app: &App, info: &ProcessInfo, width: usize) -> Vec<Line<'static>> {
    let parent = match info.ppid {
        Some(p) => vec![Span::raw(app.name_of(p)), muted(format!(" {p}"))],
        None => vec![muted("–")],
    };
    let children = app.tree.get(info.pid).map_or(0, |n| n.children.len());
    let started = if info.start_time_secs == 0 {
        vec![muted("–")]
    } else {
        let t = Local.timestamp_opt(info.start_time_secs as i64, 0).single().map(|t| t.format("%Y-%m-%d %H:%M").to_string());
        vec![Span::raw(t.unwrap_or_default()), muted(format!("  {} ago", ago(info.run_time_secs)))]
    };
    let deep = app.deep_entry().map(|e| &e.info);
    let hist = app.proc_hist.get(&info.pid);
    let cpu_avg = hist.map(|h| avg(&h.cpu)).unwrap_or(0.0);
    let mem_pct = ratio(info.mem(), app.stats.mem_total) * 100.0;
    let sockets = app.connections.get(&info.pid).map_or(0, |c| c.len());

    let left = vec![
        kv("Parent", parent),
        kv("Children", val(children.to_string())),
        // The inspector's owner lookup covers processes sysinfo can't attribute.
        kv("User", val(info.user.clone().or_else(|| deep.and_then(|d| d.integrity_or_privilege.clone())).unwrap_or_default())),
        kv("Status", vec![status_span(info)]),
        kv("Priority", {
            let mut v = vec![priority_span(info)];
            if let Some(n) = info.nice {
                v.push(muted(format!("  nice {n}")));
            }
            v
        }),
        kv("Started", started),
    ];
    let right = vec![
        kv("CPU", vec![Span::raw(format!("{:.1}%", info.cpu_usage_pct)), muted(format!("  avg {cpu_avg:.1}%"))]),
        kv("Memory", vec![Span::raw(human_bytes(info.mem())), muted(format!("  {mem_pct:.1}% of RAM"))]),
        kv("Threads", info.threads.map(|t| val(t.to_string())).unwrap_or_else(|| val(""))),
        kv("CPU time", info.cpu_time_secs.map(|t| val(cpu_time(t))).unwrap_or_else(|| val(""))),
        kv("Disk", vec![Span::raw(format!("read {}  write {}", human_bytes(info.disk_read_total), human_bytes(info.disk_write_total))), muted(format!("  now {}", human_rate(info.disk_read_rate + info.disk_write_rate)))]),
        kv(
            "Open",
            vec![Span::raw(format!(
                "{} files · {sockets} sockets",
                deep.and_then(|d| d.handle_count).map(|n| n.to_string()).unwrap_or_else(|| "…".into())
            ))],
        ),
    ];

    let mut lines = Vec::new();
    if width >= 96 {
        let half = width / 2;
        for i in 0..left.len().max(right.len()) {
            let mut spans = left.get(i).map(|l| l.spans.clone()).unwrap_or_default();
            let w: usize = spans.iter().map(|s| s.content.width()).sum();
            spans.push(Span::raw(" ".repeat(half.saturating_sub(w).max(2))));
            if let Some(r) = right.get(i) {
                spans.extend(r.spans.clone());
            }
            lines.push(Line::from(spans));
        }
    } else {
        lines.extend(left);
        lines.extend(right);
    }
    lines.push(Line::default());

    // Triage verdict first: it's what an analyst scans for.
    if let Some(a) = app.ir.triage.get(&info.pid).filter(|a| a.score > 0) {
        let style = match a.level() {
            "high" => Style::new().fg(BAD).add_modifier(Modifier::BOLD),
            "medium" => Style::new().fg(WARN).add_modifier(Modifier::BOLD),
            _ => Style::new().fg(TEXT_DIM),
        };
        lines.push(kv(
            "Priority",
            vec![Span::styled(format!("{} ({})", a.score, a.level()), style), muted(if a.recent { "   started in the last 15 min" } else { "" })],
        ));
        for h in &a.hits {
            let sev = Style::new().fg(match h.severity {
                crate::model::Severity::Critical | crate::model::Severity::High => BAD,
                crate::model::Severity::Medium => WARN,
                _ => TEXT_DIM,
            });
            let mut v = vec![
                Span::styled(format!("{:<8}", h.severity.label()), if h.suppressed.is_some() { Style::new().fg(MUTED) } else { sev }),
                muted(format!("{:<7}", format!("conf {}", &h.confidence.label()[..1]))),
                Span::styled(format!("{} ", h.id), Style::new().fg(TEXT_DIM)),
                Span::raw(h.name.clone()),
            ];
            if let Some(why) = &h.suppressed {
                v.push(muted(format!("  suppressed: {why}")));
            }
            lines.push(kv("", v));
            if !h.evidence.is_empty() {
                lines.push(kv("", vec![muted(format!("{:15}↳ {}", "", h.evidence.chars().take(width.saturating_sub(LABEL_W + 20)).collect::<String>()))]));
            }
        }
    } else {
        lines.push(kv("Risk", vec![Span::styled("no warning signs", Style::new().fg(OK))]));
    }
    if let Some(e) = info.exe_path.as_deref().and_then(|p| app.ir.intel.get(p)) {
        let mut v = vec![Span::raw(e.sha256.clone().unwrap_or_else(|| "hashing…".into()))];
        if let Some(t) = &e.team {
            v.push(muted(format!("   team {t}")));
        }
        lines.push(kv("SHA-256", v));
    }
    lines.push(Line::default());

    let avail = width.saturating_sub(LABEL_W).max(20);
    wrapped(&mut lines, "Path", &info.exe_path.clone().unwrap_or_default(), avail);
    wrapped(&mut lines, "Command", &info.cmd.join(" "), avail);
    let cwd = deep.and_then(|d| d.working_directory.clone()).or_else(|| info.cwd.clone()).unwrap_or_default();
    wrapped(&mut lines, "Directory", &cwd, avail);

    let signature = match deep.map(|d| &d.signature_status) {
        None if app.deep_pending.contains(&info.pid) => vec![muted("checking…")],
        None => vec![muted("–")],
        Some(SignatureStatus::Valid { signer }) => vec![Span::styled("Signed", Style::new().fg(OK)), muted(format!("  {signer}"))],
        Some(SignatureStatus::Invalid { reason }) => {
            vec![Span::styled("Invalid signature", Style::new().fg(BAD).add_modifier(Modifier::BOLD)), muted(format!("  {reason}"))]
        }
        Some(SignatureStatus::Unsigned) => vec![Span::styled("Not signed", Style::new().fg(WARN))],
        Some(SignatureStatus::Unknown) => vec![muted("not available")],
    };
    lines.push(kv("Signature", signature));
    if let Some(d) = deep {
        for (k, v) in &d.signature_details {
            lines.push(kv(&format!("  {k}"), vec![muted(v.clone())]));
        }
    }
    lines
}

fn performance(frame: &mut Frame, app: &App, info: &ProcessInfo, area: Rect) {
    let Some(h) = app.proc_hist.get(&info.pid) else {
        frame.render_widget(Paragraph::new(muted("Collecting samples…")), area);
        return;
    };
    let areas = if area.width >= 90 {
        Layout::horizontal([Constraint::Ratio(1, 3); 3]).spacing(1).split(area)
    } else {
        Layout::vertical([Constraint::Ratio(1, 3); 3]).split(area)
    };
    history_chart(
        frame,
        areas[0],
        chart_title("CPU", vec![("now", format!("{:.1}%", last(&h.cpu)), OK), ("peak", format!("{:.0}%", peak(&h.cpu)), Color::Reset)]),
        &[Series { data: &h.cpu, color: OK }],
        100.0,
        |v| format!("{v:.0}%"),
    );
    history_chart(
        frame,
        areas[1],
        chart_title("Memory", vec![("now", human_bytes(last(&h.mem) as u64), ACCENT), ("peak", human_bytes(peak(&h.mem) as u64), Color::Reset)]),
        &[Series { data: &h.mem, color: ACCENT }],
        1024.0 * 1024.0,
        |v| human_bytes(v as u64),
    );
    history_chart(
        frame,
        areas[2],
        chart_title("Disk", vec![("now", human_rate(last(&h.io)), WARN)]),
        &[Series { data: &h.io, color: WARN }],
        1024.0,
        human_rate,
    );
}

pub fn conn_state_style(s: ConnState) -> Style {
    match s {
        ConnState::Listen => Style::new().fg(ACCENT),
        ConnState::Established => Style::new().fg(OK),
        ConnState::Opening => Style::new().fg(WARN),
        _ => Style::new().fg(MUTED),
    }
}

fn network(frame: &mut Frame, app: &mut App, pid: u32, area: Rect) {
    let specs = [
        ColSpec::new("Protocol", 8, false),
        ColSpec::new("Local address", 0, false),
        ColSpec::new("Remote address", 0, false),
        ColSpec::new("State", 11, false),
    ];
    let rows: Vec<_> = app
        .connections
        .get(&pid)
        .map(|cs| {
            cs.iter()
                .map(|c| {
                    vec![
                        vec![muted(c.protocol)],
                        vec![Span::raw(c.local.clone())],
                        vec![Span::raw(c.remote.clone())],
                        vec![Span::styled(c.state.label(), conn_state_style(c.state))],
                    ]
                })
                .collect()
        })
        .unwrap_or_default();
    if rows.is_empty() {
        frame.render_widget(Paragraph::new(muted("No network connections")), area);
        return;
    }
    draw_table(frame, area, &specs, rows, &mut app.pane_scroll, None);
}

fn inspected(frame: &mut Frame, app: &mut App, tab: PaneTab, area: Rect) {
    let pid = app.detail_pid();
    let loading = pid.is_some_and(|p| app.deep_pending.contains(&p));
    let entry = app.deep_entry().map(|e| (e.info.clone(), e.fetched.elapsed().as_secs()));
    let Some((info, age)) = entry.filter(|(i, _)| tab != PaneTab::Modules || i.modules_loaded) else {
        let msg = if loading {
            format!("{} Reading {}…", spinner(app), tab.title().to_lowercase())
        } else {
            "Waiting…".to_string()
        };
        frame.render_widget(Paragraph::new(muted(msg)), area);
        return;
    };
    let unavailable = |frame: &mut Frame, why: &str| {
        let lower = why.to_lowercase();
        let lines = if lower.contains("not permitted") || lower.contains("privilege") || lower.contains("denied") {
            vec![
                Line::from("This process belongs to another user or the system."),
                Line::from(muted("Run procwatch with administrator rights (sudo) to see this.")),
            ]
        } else {
            vec![Line::from(muted("Not available")), Line::from(muted(why.to_string()))]
        };
        frame.render_widget(Paragraph::new(lines), area);
    };
    // Footer with snapshot age so it's clear this isn't live.
    let footer = Rect { y: area.bottom().saturating_sub(1), height: 1, ..area };
    let table_area = Rect { height: area.height.saturating_sub(1), ..area };
    let note = if loading { format!("{} refreshing…", spinner(app)) } else { format!("snapshot from {age}s ago · r to refresh") };

    match tab {
        PaneTab::Threads => match &info.threads {
            Err(e) => unavailable(frame, e),
            Ok(threads) => {
                let specs = [
                    ColSpec::new("Thread", 12, true),
                    ColSpec::new("Name", 0, false),
                    ColSpec::new("State", 15, false),
                    ColSpec::new("CPU", 6, true),
                    ColSpec::new("Priority", 8, true),
                    ColSpec::new("User time", 10, true),
                    ColSpec::new("System time", 11, true),
                ];
                let t = |v: Option<f64>| v.map(|t| Span::raw(cpu_time(t))).unwrap_or_else(|| muted("–"));
                let rows = threads
                    .iter()
                    .map(|th| {
                        let state = match th.state.as_str() {
                            "R" => "running",
                            "S" => "sleeping",
                            "D" => "disk wait",
                            "T" => "stopped",
                            other => other,
                        }
                        .to_string();
                        let style = match state.as_str() {
                            "running" => Style::new().fg(OK),
                            "stopped" | "uninterruptible" | "disk wait" => Style::new().fg(BAD),
                            _ => Style::new().fg(TEXT_DIM),
                        };
                        vec![
                            vec![Span::raw(th.id.to_string())],
                            vec![if th.name.is_empty() { muted("–") } else { Span::raw(th.name.clone()) }],
                            vec![Span::styled(state, style)],
                            vec![th.cpu_pct.map(|c| Span::raw(format!("{c:.1}%"))).unwrap_or_else(|| muted("–"))],
                            vec![th.priority.map(|p| Span::raw(p.to_string())).unwrap_or_else(|| muted("–"))],
                            vec![t(th.user_time)],
                            vec![t(th.system_time)],
                        ]
                    })
                    .collect();
                draw_table(frame, table_area, &specs, rows, &mut app.pane_scroll, None);
                frame.render_widget(Paragraph::new(muted(format!("{} threads · {note}", threads.len()))), footer);
            }
        },
        PaneTab::Files => match &info.open_files {
            Err(e) => unavailable(frame, e),
            Ok(files) => {
                let specs = [ColSpec::new("FD", 6, true), ColSpec::new("Type", 6, false), ColSpec::new("Path or address", 0, false)];
                let name_w = (area.width as usize).saturating_sub(18);
                let rows = files
                    .iter()
                    .map(|f| {
                        let style = match f.kind.as_str() {
                            "DIR" => Style::new().fg(ACCENT),
                            "IPv4" | "IPv6" | "SOCK" | "unix" | "systm" => Style::new().fg(OK),
                            "PIPE" | "FIFO" => Style::new().fg(WARN),
                            "REG" => Style::new(),
                            _ => Style::new().fg(TEXT_DIM),
                        };
                        vec![vec![Span::raw(f.fd.clone())], vec![Span::styled(f.kind.clone(), style)], vec![Span::raw(truncate_left(&f.name, name_w))]]
                    })
                    .collect();
                draw_table(frame, table_area, &specs, rows, &mut app.pane_scroll, None);
                let mut by_type: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
                for f in files {
                    *by_type.entry(f.kind.as_str()).or_default() += 1;
                }
                let mut types: Vec<_> = by_type.into_iter().collect();
                types.sort_by_key(|t| std::cmp::Reverse(t.1));
                let summary: Vec<String> = types.iter().take(6).map(|(k, n)| format!("{} {n}", if k.is_empty() { "?" } else { k })).collect();
                frame.render_widget(Paragraph::new(muted(format!("{} handles ({}) · {note}", files.len(), summary.join(", ")))), footer);
            }
        },
        PaneTab::Modules => {
            if info.loaded_modules.is_empty() {
                let why = info.notes.iter().find(|n| n.starts_with("modules")).cloned().unwrap_or_else(|| "No modules reported".into());
                return unavailable(frame, &why);
            }
            let name_w = info.loaded_modules.iter().map(|m| file_name(m).width()).max().unwrap_or(10).clamp(10, 40) as u16;
            let specs = [ColSpec::new("Module", name_w, false), ColSpec::new("Location", 0, false)];
            let path_w = (area.width as usize).saturating_sub(name_w as usize + 2);
            let rows = info
                .loaded_modules
                .iter()
                .map(|m| {
                    let name = file_name(m);
                    let dir = m[..m.len() - name.len()].trim_end_matches(['/', '\\']);
                    vec![vec![Span::raw(name.to_string())], vec![muted(truncate_left(dir, path_w))]]
                })
                .collect();
            draw_table(frame, table_area, &specs, rows, &mut app.pane_scroll, None);
            frame.render_widget(Paragraph::new(muted(format!("{} modules · {note}", info.loaded_modules.len()))), footer);
        }
        PaneTab::Environment => match &info.environment {
            Err(e) => unavailable(frame, e),
            Ok(vars) => {
                let key_w = vars.iter().map(|(k, _)| k.width()).max().unwrap_or(8).clamp(8, 32) as u16;
                let specs = [ColSpec::new("Variable", key_w, false), ColSpec::new("Value", 0, false)];
                let rows = vars
                    .iter()
                    .map(|(k, v)| vec![vec![Span::styled(k.clone(), Style::new().fg(ACCENT))], vec![Span::raw(v.clone())]])
                    .collect();
                draw_table(frame, table_area, &specs, rows, &mut app.pane_scroll, None);
                frame.render_widget(Paragraph::new(muted(format!("{} variables · {note}", vars.len()))), footer);
            }
        },
        _ => {}
    }
}

fn group_summary(frame: &mut Frame, app: &mut App, g: &Group, area: Rect) {
    let mem_pct = ratio(g.mem, app.stats.mem_total) * 100.0;
    let head = Line::from(vec![
        Span::styled(format!("{} processes", g.members.len()), Style::new().add_modifier(Modifier::BOLD)),
        muted("   CPU "),
        Span::raw(format!("{:.1}%", g.cpu)),
        muted("   Memory "),
        Span::raw(format!("{} ({mem_pct:.1}% of RAM)", human_bytes(g.mem))),
        muted("   Threads "),
        Span::raw(g.threads.to_string()),
        muted("   → expand or press enter for actions on all"),
    ]);
    frame.render_widget(Paragraph::new(head), Rect { height: 1, ..area });
    let mut members: Vec<&ProcessInfo> = g.members.iter().filter_map(|p| app.tree.get(*p)).map(|n| &n.info).collect();
    members.sort_by(|a, b| b.cpu_usage_pct.total_cmp(&a.cpu_usage_pct));
    let specs = [
        ColSpec::new("PID", 7, true),
        ColSpec::new("Name", 0, false),
        ColSpec::new("CPU", 6, true),
        ColSpec::new("Memory", 9, true),
        ColSpec::new("Running for", 12, true),
    ];
    let rows = members
        .iter()
        .map(|i| {
            vec![
                vec![Span::raw(i.pid.to_string())],
                vec![Span::raw(i.name.clone()), muted(format!(" {}", i.args()))],
                vec![Span::raw(format!("{:.1}%", i.cpu_usage_pct))],
                vec![Span::raw(human_bytes(i.mem()))],
                vec![muted(human_duration(i.run_time_secs))],
            ]
        })
        .collect();
    draw_table(frame, Rect { y: area.y + 2, height: area.height.saturating_sub(2), ..area }, &specs, rows, &mut app.pane_scroll, None);
}

fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Family and peers of a process: ancestry, children, siblings, other
/// instances of the same program, and processes it talks to over local TCP.
fn relations(app: &App, info: &ProcessInfo, width: usize) -> Vec<Line<'static>> {
    let tree = &app.tree;
    let name = |pid: u32| tree.get(pid).map(|n| n.info.name.clone()).unwrap_or_else(|| "?".into());
    let who = |pid: u32| -> Vec<Span<'static>> {
        let user = tree.get(pid).and_then(|n| n.info.user.clone()).unwrap_or_default();
        vec![Span::raw(name(pid)), muted(format!(" {pid}")), muted(if user.is_empty() { String::new() } else { format!("  {user}") })]
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    let head = |t: &str, n: usize| {
        Line::from(vec![Span::styled(t.to_string(), Style::new().add_modifier(Modifier::BOLD)), muted(format!("  {n}"))])
    };

    // Ancestry down to this process, then its direct children.
    let mut chain = vec![info.pid];
    let mut cur = info.ppid;
    while let Some(p) = cur {
        if chain.contains(&p) || chain.len() > 64 {
            break;
        }
        chain.push(p);
        cur = tree.get(p).and_then(|n| n.info.ppid);
    }
    chain.reverse();
    let children: Vec<u32> = tree.get(info.pid).map(|n| n.children.clone()).unwrap_or_default();
    lines.push(head("Ancestry", chain.len() - 1));
    for (depth, pid) in chain.iter().enumerate() {
        let mut spans = vec![muted(format!("  {}{}", "   ".repeat(depth.saturating_sub(1)), if depth == 0 { "" } else { "└─ " }))];
        spans.extend(who(*pid));
        if *pid == info.pid {
            spans.push(Span::styled("   ← this process", Style::new().fg(ACCENT)));
        }
        lines.push(Line::from(spans));
    }
    let indent = "   ".repeat(chain.len().saturating_sub(1));
    for (i, c) in children.iter().take(30).enumerate() {
        let last = i + 1 == children.len().min(30);
        let mut spans = vec![muted(format!("  {indent}{}", if last { "└─ " } else { "├─ " }))];
        spans.extend(who(*c));
        let sub = tree.descendants(*c).len();
        if sub > 0 {
            spans.push(muted(format!("  +{sub} below")));
        }
        lines.push(Line::from(spans));
    }
    if children.len() > 30 {
        lines.push(Line::from(muted(format!("  {indent}… {} more children", children.len() - 30))));
    }

    // Siblings: same parent.
    let siblings: Vec<u32> = info
        .ppid
        .and_then(|p| tree.get(p))
        .map(|n| n.children.iter().copied().filter(|c| *c != info.pid).collect())
        .unwrap_or_default();
    lines.push(Line::default());
    lines.push(head("Siblings (same parent)", siblings.len()));
    for s in siblings.iter().take(12) {
        let mut spans = vec![Span::raw("  ")];
        spans.extend(who(*s));
        lines.push(Line::from(spans));
    }
    if siblings.len() > 12 {
        lines.push(Line::from(muted(format!("  … {} more", siblings.len() - 12))));
    }

    // Other instances of the same executable.
    let same: Vec<u32> = match &info.exe_path {
        Some(exe) => {
            let mut v: Vec<u32> =
                tree.nodes.values().filter(|n| n.info.pid != info.pid && n.info.exe_path.as_deref() == Some(exe)).map(|n| n.info.pid).collect();
            v.sort_unstable();
            v
        }
        None => Vec::new(),
    };
    lines.push(Line::default());
    lines.push(head("Same program", same.len()));
    for p in same.iter().take(12) {
        let args = tree.get(*p).map(|n| n.info.args()).unwrap_or_default();
        let mut spans = vec![Span::raw("  ")];
        spans.extend(who(*p));
        spans.push(muted(format!("  {}", truncate(&args, width.saturating_sub(40)))));
        lines.push(Line::from(spans));
    }

    // Local TCP peers: match my remote endpoint against others' local ones.
    let empty = Vec::new();
    let mine = app.connections.get(&info.pid).unwrap_or(&empty);
    let mut peers: Vec<(u32, String)> = Vec::new();
    for c in mine.iter().filter(|c| c.state == ConnState::Established) {
        let (rip, _) = crate::filter::split_endpoint(&c.remote);
        if !(rip.starts_with("127.") || rip == "::1") {
            continue;
        }
        for (pid, cs) in &app.connections {
            if *pid == info.pid {
                continue;
            }
            for o in cs {
                if o.local == c.remote && o.remote == c.local {
                    peers.push((*pid, format!("{} ⇄ {}", c.local, c.remote)));
                } else if o.state == ConnState::Listen && crate::filter::split_endpoint(&o.local).1 == crate::filter::split_endpoint(&c.remote).1 {
                    peers.push((*pid, format!("connects to its server on {}", c.remote)));
                }
            }
        }
    }
    peers.sort();
    peers.dedup();
    lines.push(Line::default());
    lines.push(head("Talks to over local TCP", peers.len()));
    if peers.is_empty() {
        lines.push(Line::from(muted("  no loopback connections to other processes")));
    }
    for (pid, how) in peers.iter().take(20) {
        let mut spans = vec![Span::raw("  ")];
        spans.extend(who(*pid));
        spans.push(muted(format!("   {how}")));
        lines.push(Line::from(spans));
    }
    lines
}

fn stack(frame: &mut Frame, app: &mut App, pid: u32, area: Rect) {
    let loading = app.stack_pending == Some(pid);
    let Some(entry) = app.stacks.get(&pid) else {
        let msg = if loading { format!("{} Sampling call stacks for about a second…", spinner(app)) } else { "Waiting…".into() };
        frame.render_widget(Paragraph::new(muted(msg)), area);
        return;
    };
    let footer = Rect { y: area.bottom().saturating_sub(1), height: 1, ..area };
    let body = Rect { height: area.height.saturating_sub(1), ..area };
    match &entry.result {
        Err(e) => {
            let lower = e.to_lowercase();
            let lines = if lower.contains("root") || lower.contains("permission") || lower.contains("not permitted") {
                vec![
                    Line::from("Can't sample this process."),
                    Line::from(muted(e.clone())),
                    Line::from(muted("Processes of other users or the system need procwatch to run with sudo.")),
                ]
            } else {
                vec![Line::from("Can't sample this process."), Line::from(muted(e.clone()))]
            };
            frame.render_widget(Paragraph::new(lines), body);
        }
        Ok(lines) => {
            let rendered: Vec<Line<'static>> = lines
                .iter()
                .map(|l| {
                    if l.ends_with(':') && !l.starts_with(' ') {
                        Line::from(Span::styled(l.clone(), Style::new().add_modifier(Modifier::BOLD)))
                    } else if l.trim_start().starts_with("Thread") || l.contains("Thread_") {
                        Line::from(Span::styled(l.clone(), Style::new().fg(ACCENT)))
                    } else {
                        Line::from(l.clone())
                    }
                })
                .collect();
            let max = rendered.len().saturating_sub(body.height as usize);
            app.pane_scroll = app.pane_scroll.min(max);
            frame.render_widget(Paragraph::new(rendered).scroll((app.pane_scroll as u16, 0)), body);
        }
    }
    let note = if loading {
        format!("{} resampling…", spinner(app))
    } else {
        format!("sampled {} ago · r to sample again · shift ↑↓ scroll", crate::process::ago(entry.fetched.elapsed().as_secs()))
    };
    frame.render_widget(Paragraph::new(muted(note)), footer);
}

fn memory(frame: &mut Frame, app: &mut App, pid: u32, area: Rect) {
    let Some((_, r)) = app.ir.memory.get(&pid).cloned() else {
        let msg = if app.deep_pending.contains(&pid) {
            format!("{} reading loaded modules…", spinner(app))
        } else {
            format!("{} analyzing memory layout and modules…", spinner(app))
        };
        frame.render_widget(Paragraph::new(muted(msg)), area);
        return;
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    let head = |t: String| Line::from(Span::styled(t, Style::new().add_modifier(Modifier::BOLD)));
    lines.push(head(format!("Abnormal modules ({})", r.anomalies.len())));
    if r.anomalies.is_empty() {
        lines.push(Line::from(Span::styled("  none found (deleted, temp-folder or unsigned modules would be listed here)", Style::new().fg(OK))));
    }
    for (m, why) in &r.anomalies {
        lines.push(Line::from(vec![Span::styled(format!("  ! {why}  "), Style::new().fg(BAD)), Span::raw(truncate_left(m, area.width as usize / 2))]));
    }
    lines.push(Line::default());
    match r.wx_regions {
        Some(0) => lines.push(Line::from(vec![Span::raw("Writable + executable regions  "), Span::styled("0", Style::new().fg(OK))])),
        Some(n) => lines.push(Line::from(vec![
            Span::raw("Writable + executable regions  "),
            Span::styled(n.to_string(), Style::new().fg(WARN).add_modifier(Modifier::BOLD)),
            muted("  (normal for JIT engines such as browsers and Java; unusual for most other programs)"),
        ])),
        None => {}
    }
    for (k, v) in &r.summary {
        lines.push(Line::from(vec![Span::styled(format!("{k:<30}"), Style::new().fg(TEXT_DIM)), Span::raw(v.clone())]));
    }
    for n in &r.notes {
        lines.push(Line::from(muted(n.clone())));
    }
    if !r.regions.is_empty() {
        lines.push(Line::default());
        lines.push(head("Address space by region type".into()));
        lines.push(Line::from(muted(format!("  {:<34}{:>12}{:>12}{:>8}", "Region", "Virtual", "Resident", "Count"))));
        for g in &r.regions {
            lines.push(Line::from(format!(
                "  {:<34}{:>12}{:>12}{:>8}",
                truncate(&g.kind, 33),
                human_bytes(g.virtual_bytes),
                if g.resident_bytes > 0 { human_bytes(g.resident_bytes) } else { "–".into() },
                g.count
            )));
        }
    }
    lines.push(Line::default());
    lines.push(Line::from(muted("Memory contents are never read or dumped; this is layout and module metadata only.")));
    scrolled(frame, app, area, lines);
}
