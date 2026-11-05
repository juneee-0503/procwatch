//! Performance, Network and Activity pages.

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

use super::details::conn_state_style;
use super::widgets::*;
use crate::app::{App, Mode};
use crate::common::filter::split_endpoint;
use crate::network::ConnState;
use crate::process::{human_bytes, human_duration, human_rate};

pub fn performance(frame: &mut Frame, app: &mut App, area: Rect) {
    match app.perf_view {
        1 => return system_metrics(frame, app, area),
        2 => return services_view(frame, app, area),
        _ => {}
    }
    let h = &app.sys_hist;
    let s = &app.stats;
    let [top, bottom] = Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(area);
    let core_w = if s.per_core.len() > 8 { 44 } else { 30 };
    let [cpu, cores] = Layout::horizontal([Constraint::Min(30), Constraint::Length(core_w)]).areas(top);
    let [mem, net, disk] = Layout::horizontal([Constraint::Ratio(1, 3); 3]).areas(bottom);

    history_chart(
        frame,
        cpu,
        chart_title(
            "CPU",
            vec![
                ("now", format!("{:.0}%", last(&h.cpu)), OK),
                ("avg", format!("{:.0}%", avg(&h.cpu)), Color::Reset),
                ("processes", format!("{} · {} threads · {} running", s.tasks, s.threads, s.running), Color::Reset),
                ("load", format!("{:.2} {:.2} {:.2}", s.load_avg[0], s.load_avg[1], s.load_avg[2]), Color::Reset),
                ("up", human_duration(s.uptime_secs), Color::Reset),
            ],
        ),
        &[Series { data: &h.cpu, color: OK }],
        100.0,
        |v| format!("{v:.0}%"),
    );

    // Per-core usage: one line per core with a sparkline of recent load.
    let block = panel(chart_title("Cores", vec![("", format!("{}", s.per_core.len()), Color::Reset)]));
    let inner = block.inner(cores);
    frame.render_widget(block, cores);
    let cols = if s.per_core.len() as u16 > inner.height { 2 } else { 1 };
    let col_w = inner.width / cols;
    let rows_per_col = s.per_core.len().div_ceil(cols as usize);
    for (i, usage) in s.per_core.iter().enumerate() {
        let (c, r) = (i / rows_per_col.max(1), i % rows_per_col.max(1));
        if r as u16 >= inner.height {
            continue;
        }
        let spark_w = (col_w as usize).saturating_sub(12);
        let color = if *usage >= 85.0 { BAD } else if *usage >= 60.0 { WARN } else { OK };
        let spark = h.per_core.get(i).map(|d| sparkline(d, spark_w, 100.0)).unwrap_or_default();
        let line = Line::from(vec![
            muted(format!("{i:>3} ")),
            Span::styled(spark, Style::new().fg(color)),
            Span::raw(format!(" {usage:>4.0}%")),
        ]);
        frame.render_widget(
            Paragraph::new(line),
            Rect { x: inner.x + c as u16 * col_w, y: inner.y + r as u16, width: col_w, height: 1 },
        );
    }

    history_chart(
        frame,
        mem,
        chart_title(
            "Memory",
            vec![
                ("used", format!("{} / {}", human_bytes(s.mem_used), human_bytes(s.mem_total)), ACCENT),
                ("swap", human_bytes(s.swap_used), Color::Magenta),
            ],
        ),
        &[Series { data: &h.mem, color: ACCENT }, Series { data: &h.swap, color: Color::Magenta }],
        100.0,
        |v| format!("{v:.0}%"),
    );
    history_chart(
        frame,
        net,
        chart_title("Network", vec![("in", human_rate(s.net_rx_rate), OK), ("out", human_rate(s.net_tx_rate), WARN)]),
        &[Series { data: &h.net_rx, color: OK }, Series { data: &h.net_tx, color: WARN }],
        1024.0,
        human_rate,
    );
    history_chart(
        frame,
        disk,
        chart_title("Disk", vec![("read", human_rate(s.disk_read_rate), OK), ("write", human_rate(s.disk_write_rate), BAD)]),
        &[Series { data: &h.disk_r, color: OK }, Series { data: &h.disk_w, color: BAD }],
        1024.0,
        human_rate,
    );
}

/// Something measured, with a colour for how worrying it is.
fn stat(label: &str, value: Option<String>, level: Style) -> Line<'static> {
    let shown = match value {
        Some(v) => Span::styled(v, level),
        None => muted("n/a"),
    };
    Line::from(vec![muted(format!("  {label:<26}")), shown])
}

fn per_sec(v: Option<f64>) -> Option<String> {
    v.map(|v| if v >= 10_000.0 { format!("{:.1}k/s", v / 1000.0) } else { format!("{v:.0}/s") })
}

fn over(v: Option<f64>, warn: f64, bad: f64) -> Style {
    match v {
        Some(v) if v >= bad => Style::new().fg(BAD),
        Some(v) if v >= warn => Style::new().fg(WARN),
        _ => Style::new(),
    }
}

/// Scheduling, memory, disks, network, sensors: as much as this system tells.
fn system_metrics(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(m) = app.metrics.as_ref() else {
        frame.render_widget(Paragraph::new(muted(" Collecting… (a few seconds on the first sample)")), area);
        return;
    };
    let s = &app.stats;
    let cores = s.per_core.len().max(1) as f64;
    let head = |t: &str| Line::from(Span::styled(format!(" {t}"), Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)));
    let plain = Style::new();
    let mem_low = m.available_memory.zip(m.total_memory).map(|(a, t)| 100.0 - a as f64 * 100.0 / t.max(1) as f64);
    let swap_pct = m.swap_used.zip(m.swap_total).filter(|(_, t)| *t > 0).map(|(u, t)| u as f64 * 100.0 / t as f64);
    let conns = app.connections.values().flatten().count();
    let established = app.connections.values().flatten().filter(|c| c.state == ConnState::Established).count();
    let listening = app.connections.values().flatten().filter(|c| c.state == ConnState::Listen).count();
    let closing = app.connections.values().flatten().filter(|c| c.state == ConnState::Closing).count();
    let pressure = |v: Option<f32>| v.map(|p| format!("{p:.1}%"));
    let mut left = vec![
        head("CPU and scheduling"),
        stat("Load (1 / 5 / 15 min)", Some(format!("{:.2}  {:.2}  {:.2}", s.load_avg[0], s.load_avg[1], s.load_avg[2])), over(Some(s.load_avg[0]), cores, cores * 2.0)),
        stat("Load per core", Some(format!("{:.2}", s.load_avg[0] / cores)), over(Some(s.load_avg[0] / cores), 1.0, 2.0)),
        stat("Run queue", m.run_queue.map(|v| format!("{v:.0}")), over(m.run_queue, cores, cores * 2.0)),
        stat("Blocked on I/O", m.blocked.map(|v| format!("{v:.0}")), over(m.blocked, 1.0, cores)),
        stat("Context switches", per_sec(m.context_switches_per_sec), plain),
        stat("Interrupts", per_sec(m.interrupts_per_sec), plain),
        stat("CPU pressure (10 s)", pressure(m.cpu_pressure), over(m.cpu_pressure.map(f64::from), 10.0, 40.0)),
        Line::from(""),
        head("Memory"),
        stat("Available", m.available_memory.zip(m.total_memory).map(|(a, t)| format!("{} of {}", human_bytes(a), human_bytes(t))), over(mem_low, 85.0, 95.0)),
        stat("Swap used", m.swap_used.zip(m.swap_total).map(|(u, t)| format!("{} of {}", human_bytes(u), human_bytes(t))), over(swap_pct, 50.0, 90.0)),
        stat("Swap in / out (pages)", m.swap_in_pages_per_sec.zip(m.swap_out_pages_per_sec).map(|(i, o)| format!("{i:.0}/s  {o:.0}/s")), over(m.swap_out_pages_per_sec, 1.0, 100.0)),
        stat("Page faults", per_sec(m.page_faults_per_sec), plain),
        stat("Major faults", per_sec(m.major_faults_per_sec), over(m.major_faults_per_sec, 10.0, 100.0)),
        stat("Memory pressure (10 s)", pressure(m.memory_pressure), over(m.memory_pressure.map(f64::from), 5.0, 20.0)),
        Line::from(""),
        head("Connections"),
        stat("Total", Some(conns.to_string()), plain),
        stat("Established", Some(established.to_string()), plain),
        stat("Listening", Some(listening.to_string()), plain),
        stat("Closing", Some(closing.to_string()), over(Some(closing as f64), 500.0, 5000.0)),
        stat("TCP retransmits", per_sec(m.retransmits_per_sec), over(m.retransmits_per_sec, 10.0, 100.0)),
    ];
    let mut right = vec![head("Disks"), Line::from(muted(format!("  {:<14}{:>10}{:>10}{:>7}{:>7}{:>6}{:>8}", "", "read", "write", "IOPS", "queue", "busy", "await")))];
    let opt = |v: Option<f64>, d: usize| v.map(|v| format!("{v:.d$}")).unwrap_or_else(|| "n/a".into());
    for d in &m.disks {
        let style = over(d.busy_pct, 70.0, 95.0).patch(over(d.queue_depth, 4.0, 32.0));
        right.push(Line::from(Span::styled(
            format!("  {:<14}{:>10}{:>10}{:>7.0}{:>7}{:>6}{:>8}", truncate(&d.name, 13), human_rate(d.read_rate), human_rate(d.write_rate), d.iops, opt(d.queue_depth, 1), opt(d.busy_pct, 0), opt(d.await_ms, 1)),
            style,
        )));
    }
    right.push(stat("I/O pressure (10 s)", pressure(m.io_pressure), over(m.io_pressure.map(f64::from), 10.0, 40.0)));
    right.push(Line::from(""));
    right.push(head("Network"));
    right.push(Line::from(muted(format!("  {:<14}{:>10}{:>10}{:>9}{:>9}", "", "in", "out", "errors", "drops"))));
    for n in m.nics.iter().filter(|n| n.rx_rate + n.tx_rate > 0.0 || n.errors_total + n.drops_total > 0) {
        let style = if n.errors_per_sec + n.drops_per_sec > 0.0 { Style::new().fg(BAD) } else { plain };
        right.push(Line::from(Span::styled(format!("  {:<14}{:>10}{:>10}{:>9}{:>9}", truncate(&n.name, 13), human_rate(n.rx_rate), human_rate(n.tx_rate), n.errors_total, n.drops_total), style)));
    }
    right.push(Line::from(""));
    right.push(head("Temperature and power"));
    for t in m.temperatures.iter().take(10) {
        right.push(stat(&t.label, Some(format!("{:.0} °C", t.value)), over(Some(t.value), 80.0, 95.0)));
    }
    for p in &m.power {
        right.push(stat(&p.label, Some(format!("{:.1} W", p.value)), plain));
    }
    if m.temperatures.is_empty() && m.power.is_empty() {
        right.push(Line::from(muted("  n/a")));
    }
    if !m.notes.is_empty() {
        left.push(Line::from(""));
        left.push(head("Not available here"));
        left.extend(m.notes.iter().map(|n| Line::from(muted(format!("  {n}")))));
    }
    let (rows, scroll) = (left.len().max(right.len()), app.perf_scroll);
    app.perf_scroll = scroll.min(rows.saturating_sub(1));
    let y = app.perf_scroll as u16;
    if area.width >= 110 {
        let [l, r] = Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)]).areas(area);
        frame.render_widget(Paragraph::new(left).scroll((y, 0)), l);
        frame.render_widget(Paragraph::new(right).scroll((y, 0)), r);
    } else {
        left.push(Line::from(""));
        left.extend(right);
        frame.render_widget(Paragraph::new(left).scroll((y, 0)), area);
    }
}

/// Critical processes and system services.
fn services_view(frame: &mut Frame, app: &mut App, area: Rect) {
    use crate::performance::services::{ServiceState, CRITICAL};
    let head = |t: String| Line::from(Span::styled(format!(" {t}"), Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)));
    let mut lines = vec![head("Critical processes".into()), Line::from(muted(format!("  {:<22}{:>7}{:>8}{:>10}  state", "name", "count", "CPU", "memory")))];
    for name in CRITICAL {
        let found: Vec<&crate::process::ProcessInfo> = app.tree.nodes.values().map(|n| &n.info).filter(|i| i.name.eq_ignore_ascii_case(name)).collect();
        // Not every system runs every one of these; absent isn't failure.
        let (cpu, mem): (f32, u64) = found.iter().fold((0.0, 0), |(c, m), i| (c + i.cpu_usage_pct, m + i.mem()));
        let state = if found.is_empty() { muted("not running") } else { Span::styled("running", Style::new().fg(OK)) };
        lines.push(Line::from(vec![Span::raw(format!("  {:<22}{:>7}{:>7.1}%{:>10}  ", name, found.len(), cpu, human_bytes(mem))), state]));
    }
    lines.push(Line::from(""));
    match &app.services {
        None => lines.push(muted("  Reading services…").into()),
        Some(Err(e)) => lines.push(muted(format!("  Services unavailable: {e}")).into()),
        Some(Ok(list)) => {
            let count = |s: ServiceState| list.iter().filter(|x| x.state == s).count();
            lines.push(head(format!("Services: {} running, {} failed, {} stopped", count(ServiceState::Running), count(ServiceState::Failed), count(ServiceState::Stopped))));
            let f = crate::common::filter::Filter::parse(&app.query);
            for s in list.iter().filter(|s| f.matches(*s)) {
                let style = match s.state {
                    ServiceState::Failed => Style::new().fg(BAD),
                    ServiceState::Running => Style::new().fg(OK),
                    _ => Style::new().fg(TEXT_DIM),
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<9}", s.state.label()), style),
                    Span::raw(format!("{:<8}", s.pid.map(|p| p.to_string()).unwrap_or_default())),
                    Span::raw(truncate(&s.name, 44)),
                    muted(format!("  {}", s.detail)),
                ]));
            }
        }
    }
    app.perf_scroll = app.perf_scroll.min(lines.len().saturating_sub(1));
    frame.render_widget(Paragraph::new(lines).scroll((app.perf_scroll as u16, 0)), area);
}

fn search_line(app: &App, what: &str, count: usize) -> Line<'static> {
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
    Line::from(spans)
}

pub fn network(frame: &mut Frame, app: &mut App, area: Rect) {
    if app.ir.net_dns_view {
        return dns_view(frame, app, area);
    }
    if app.ir.net_hosts_view {
        return hosts_view(frame, app, area);
    }
    frame.render_widget(Paragraph::new(search_line(app, "connections", app.conn_rows.len())), Rect { height: 1, ..area });
    app.hit.search = Rect { height: 1, width: area.width / 3, ..area };

    // Summary by state, and how many listeners accept outside connections.
    let count = |s: ConnState| app.conn_rows.iter().filter(|r| r.conn.state == s).count();
    let listeners: Vec<_> = app.conn_rows.iter().filter(|r| r.conn.state == ConnState::Listen).collect();
    let exposed = listeners.iter().filter(|r| reachable(&r.conn.local)).count();
    let remote_ips: std::collections::HashSet<String> = app
        .conn_rows
        .iter()
        .filter(|r| r.conn.state == ConnState::Established)
        .map(|r| split_endpoint(&r.conn.remote).0)
        .collect();
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!(" {} established", count(ConnState::Established)), Style::new().fg(OK)),
            muted(format!(" to {} addresses   ", remote_ips.len())),
            Span::styled(format!("{} listening", listeners.len()), Style::new().fg(ACCENT)),
            if exposed > 0 { Span::styled(format!(" ({exposed} reachable from network)"), Style::new().fg(BAD)) } else { muted(" (local only)") },
            muted(format!("   {} opening · {} closing", count(ConnState::Opening), count(ConnState::Closing))),
            muted("    filter e.g. state:established  port:443  ip:10.  proto:udp  -name:chrome"),
        ])),
        Rect { y: area.y + 1, height: 1, ..area },
    );

    let iface_h = (app.stats.interfaces.len().min(6) as u16 + 2).min(area.height / 3);
    let table = Rect { y: area.y + 3, height: area.height.saturating_sub(4 + iface_h), ..area };
    let ifaces = Rect { y: table.bottom() + 1, height: iface_h, ..area };

    let specs = [
        ColSpec::new("Process", 0, false),
        ColSpec::new("PID", 7, true),
        ColSpec::new("Proto", 5, false),
        ColSpec::new("Local IP", 0, false),
        ColSpec::new("Port", 6, true),
        ColSpec::new("Remote IP", 0, false),
        ColSpec::new("Port", 6, true),
        ColSpec::new("Remote host", 0, false),
        ColSpec::new("State", 11, false),
        ColSpec::new("Age", 7, true),
        ColSpec::new("Reach", 7, false),
    ];
    if app.conn_rows.is_empty() {
        let msg = if app.connections.is_empty() {
            "No connections visible (other users' sockets may need administrator rights)"
        } else {
            "No connections match the filter"
        };
        frame.render_widget(Paragraph::new(muted(msg)), table);
    } else {
        let hosts: Vec<Option<String>> = app
            .conn_rows
            .iter()
            .map(|r| split_endpoint(&r.conn.remote).0)
            .collect::<Vec<_>>()
            .into_iter()
            .map(|ip| app.ir.resolver.name(&ip))
            .collect();
        let rows = app
            .conn_rows
            .iter()
            .zip(hosts)
            .map(|(r, host)| {
                let (lip, lport) = split_endpoint(&r.conn.local);
                let (rip, rport) = split_endpoint(&r.conn.remote);
                let reach = if r.conn.state != ConnState::Listen {
                    Span::raw("")
                } else if reachable(&r.conn.local) {
                    Span::styled("network", Style::new().fg(BAD))
                } else {
                    muted("local")
                };
                vec![
                    vec![Span::raw(r.name.clone())],
                    vec![muted(r.pid.to_string())],
                    vec![muted(r.conn.protocol)],
                    vec![Span::raw(lip)],
                    vec![Span::raw(lport)],
                    vec![if rip == "*" { muted("*") } else { Span::raw(rip) }],
                    vec![if rport == "*" { muted("*") } else { Span::raw(rport) }],
                    vec![host.map(Span::raw).unwrap_or_else(|| muted(""))],
                    vec![Span::styled(r.conn.state.label(), conn_state_style(r.conn.state))],
                    vec![app
                        .ir
                        .conn_first_seen
                        .get(&(r.pid, r.conn.clone()))
                        .map(|t| muted(crate::process::ago((chrono::Local::now() - *t).num_seconds().max(0) as u64)))
                        .unwrap_or_else(|| muted(""))],
                    vec![reach],
                ]
            })
            .collect();
        let mut off = app.conn_offset;
        app.hit.list_rows = draw_table(frame, table, &specs, rows, &mut off, Some(app.conn_selected));
        app.conn_offset = off;
    }

    let specs = [
        ColSpec::new("Interface", 0, false),
        ColSpec::new("In", 10, true),
        ColSpec::new("Out", 10, true),
        ColSpec::new("Total in", 10, true),
        ColSpec::new("Total out", 10, true),
    ];
    let rows = app
        .stats
        .interfaces
        .iter()
        .map(|i| {
            vec![
                vec![Span::raw(i.name.clone())],
                vec![Span::raw(human_rate(i.rx_rate))],
                vec![Span::raw(human_rate(i.tx_rate))],
                vec![muted(human_bytes(i.rx_total))],
                vec![muted(human_bytes(i.tx_total))],
            ]
        })
        .collect();
    let mut scroll = 0;
    draw_table(frame, ifaces, &specs, rows, &mut scroll, None);
}


/// A listener bound to something other than loopback accepts connections
/// from other machines.
fn reachable(local: &str) -> bool {
    let host = split_endpoint(local).0;
    !(host.starts_with("127.") || host == "::1" || host == "localhost")
}

pub fn files(frame: &mut Frame, app: &mut App, area: Rect) {
    if app.ir.files_changes_view {
        return file_changes(frame, app, area);
    }
    let visible = app.visible_files();
    frame.render_widget(Paragraph::new(search_line(app, "open files", visible.len())), Rect { height: 1, ..area });
    app.hit.search = Rect { height: 1, width: area.width / 3, ..area };
    let table = Rect { y: area.y + 3, height: area.height.saturating_sub(3), ..area };

    let Some(list) = app.files.as_ref() else {
        frame.render_widget(Paragraph::new(muted(" Scanning open files of all processes…")), table);
        return;
    };
    let status = if list.pending {
        format!(" {} scanning all processes…", super::spinner(app))
    } else {
        format!(" scanned {} ago · r to rescan", crate::process::ago(list.fetched.elapsed().as_secs()))
    };
    let hits = match &list.result {
        Err(e) => {
            frame.render_widget(Paragraph::new(vec![Line::from(muted(" Not available")), Line::from(format!(" {e}"))]), table);
            return;
        }
        Ok(h) => h,
    };
    // Counts by type for the current filter.
    let mut by_type: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for i in &visible {
        *by_type.entry(hits[*i].kind.as_str()).or_default() += 1;
    }
    let mut types: Vec<(&str, usize)> = by_type.into_iter().collect();
    types.sort_by_key(|t| std::cmp::Reverse(t.1));
    let summary: String = types.iter().take(6).map(|(k, n)| format!("{} {n}", if k.is_empty() { "?" } else { k })).collect::<Vec<_>>().join(" · ");
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            muted(status),
            muted(format!("   {summary}")),
            muted("    filter e.g. path:/tmp  type:reg  name:chrome  pid:123"),
        ])),
        Rect { y: area.y + 1, height: 1, ..area },
    );
    if visible.is_empty() {
        frame.render_widget(Paragraph::new(muted(if list.pending { " " } else { " Nothing matches the filter." })), table);
        return;
    }
    let specs = [
        ColSpec::new("Process", 22, false),
        ColSpec::new("PID", 7, true),
        ColSpec::new("FD", 5, true),
        ColSpec::new("Type", 6, false),
        ColSpec::new("Path or address", 0, false),
    ];
    let path_w = (table.width as usize).saturating_sub(50);
    // Only build the rows that can be on screen: the list can be huge.
    let height = table.height.saturating_sub(1) as usize;
    app.file_selected = app.file_selected.min(visible.len() - 1);
    app.file_offset = scroll_window(app.file_offset, app.file_selected, height, visible.len());
    let rows = visible
        .iter()
        .skip(app.file_offset)
        .take(height)
        .map(|i| {
            let h = &hits[*i];
            let style = match h.kind.as_str() {
                "DIR" => Style::new().fg(ACCENT),
                "IPv4" | "IPv6" | "SOCK" | "unix" => Style::new().fg(OK),
                "PIPE" | "FIFO" => Style::new().fg(WARN),
                "REG" => Style::new(),
                _ => Style::new().fg(TEXT_DIM),
            };
            vec![
                vec![Span::raw(h.command.clone())],
                vec![muted(h.pid.to_string())],
                vec![muted(h.fd.clone())],
                vec![Span::styled(h.kind.clone(), style)],
                vec![Span::raw(truncate_left(&h.path, path_w))],
            ]
        })
        .collect();
    let mut scroll = 0;
    app.hit.list_rows = draw_table(frame, table, &specs, rows, &mut scroll, Some(app.file_selected - app.file_offset));
}

/// DNS: configured resolvers, processes with DNS sockets, the OS cache
/// (Windows) and every reverse name resolved for connected peers.
fn dns_view(frame: &mut Frame, app: &mut App, area: Rect) {
    let resolvers = if app.ir.resolvers.is_empty() { "–".to_string() } else { app.ir.resolvers.join(", ") };
    let dns_users: Vec<(String, u32, String)> = app
        .connections
        .iter()
        .flat_map(|(pid, cs)| cs.iter().map(move |c| (*pid, c)))
        .filter(|(_, c)| {
            let rp = split_endpoint(&c.remote).1;
            let lp = split_endpoint(&c.local).1;
            ["53", "853", "5353"].contains(&rp.as_str()) || (c.protocol == "UDP" && ["53", "5353"].contains(&lp.as_str()))
        })
        .map(|(pid, c)| (app.name_of(pid), pid, format!("{} {} → {}", c.protocol, c.local, c.remote)))
        .collect();
    let mut lines = vec![
        Line::from(vec![Span::styled(" DNS servers  ", Style::new().add_modifier(Modifier::BOLD)), Span::raw(resolvers), muted("    d returns to connections")]),
        Line::default(),
        Line::from(Span::styled(format!(" Processes using DNS sockets ({})", dns_users.len()), Style::new().add_modifier(Modifier::BOLD))),
    ];
    for (n, pid, ep) in dns_users.iter().take(8) {
        lines.push(Line::from(vec![Span::raw(format!("   {n} ")), muted(format!("{pid}  {ep}"))]));
    }
    if dns_users.is_empty() {
        lines.push(Line::from(muted("   none right now (lookups are usually brief)")));
    }
    frame.render_widget(Paragraph::new(lines.clone()), Rect { height: lines.len() as u16, ..area });

    let top = area.y + lines.len() as u16 + 1;
    let table = Rect { y: top, height: area.bottom().saturating_sub(top), ..area };
    let (title, rows): (String, Vec<(String, String)>) = match &app.ir.dns_cache {
        Some(Ok(cache)) => (format!("DNS client cache ({})", cache.len()), cache.clone()),
        Some(Err(why)) => (format!("Reverse names of connected peers — {why}"), app.ir.resolver.known()),
        None => ("Loading…".into(), Vec::new()),
    };
    let f = crate::common::filter::Filter::parse(&app.query);
    struct Pair<'a>(&'a str, &'a str);
    impl crate::common::filter::Filterable for Pair<'_> {
        fn field(&self, name: &str) -> Option<Vec<String>> {
            match name {
                "ip" => Some(vec![self.0.to_string()]),
                "name" => Some(vec![self.1.to_string()]),
                _ => None,
            }
        }
        fn text(&self) -> String {
            format!("{} {}", self.0, self.1)
        }
    }
    let rows: Vec<Vec<Vec<Span<'static>>>> = rows
        .iter()
        .filter(|(a, b)| f.matches(&Pair(a, b)))
        .map(|(a, b)| {
            let users: Vec<String> = app
                .conn_rows
                .iter()
                .filter(|r| split_endpoint(&r.conn.remote).0 == *a)
                .map(|r| r.name.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            vec![vec![Span::raw(a.clone())], vec![Span::raw(b.clone())], vec![muted(users.join(", "))]]
        })
        .collect();
    frame.render_widget(Paragraph::new(Span::styled(format!(" {title}"), Style::new().add_modifier(Modifier::BOLD))), Rect { height: 1, ..table });
    let specs = [ColSpec::new("Address", 40, false), ColSpec::new("Name", 0, false), ColSpec::new("Connected processes", 30, false)];
    let mut scroll = app.conn_offset;
    draw_table(frame, Rect { y: table.y + 1, height: table.height.saturating_sub(1), ..table }, &specs, rows, &mut scroll, None);
}

/// Changes in watched folders, newest first.
fn file_changes(frame: &mut Frame, app: &mut App, area: Rect) {
    let visible = app.visible_fs_events();
    frame.render_widget(Paragraph::new(search_line(app, "file changes", visible.len())), Rect { height: 1, ..area });
    app.hit.search = Rect { height: 1, width: area.width / 3, ..area };
    let watched = if app.ir.watch_paths.is_empty() { "nothing".to_string() } else { app.ir.watch_paths.join(" · ") };
    let mut info = vec![muted(format!(" watching {watched}"))];
    if !app.ir.watch_errors.is_empty() {
        info.push(Span::styled(format!("   ({} folder(s) couldn't be watched)", app.ir.watch_errors.len()), Style::new().fg(WARN)));
    }
    frame.render_widget(Paragraph::new(Line::from(info)), Rect { y: area.y + 1, height: 1, ..area });
    let table = Rect { y: area.y + 3, height: area.height.saturating_sub(3), ..area };
    if visible.is_empty() {
        frame.render_widget(
            Paragraph::new(muted(" No changes yet. Add folders with `watch = /path` lines in the settings file (see o → Options).")),
            table,
        );
        return;
    }
    let specs = [ColSpec::new("Time", 19, false), ColSpec::new("Change", 10, false), ColSpec::new("Path", 0, false)];
    let height = table.height.saturating_sub(1) as usize;
    app.ir.fs_selected = app.ir.fs_selected.min(visible.len() - 1);
    app.ir.fs_offset = scroll_window(app.ir.fs_offset, app.ir.fs_selected, height, visible.len());
    let path_w = (table.width as usize).saturating_sub(34);
    let rows = visible
        .iter()
        .skip(app.ir.fs_offset)
        .take(height)
        .map(|i| {
            let e = &app.ir.fs_events[*i];
            let style = match e.kind {
                "created" => Style::new().fg(OK),
                "deleted" => Style::new().fg(BAD),
                "renamed" => Style::new().fg(WARN),
                _ => Style::new().fg(TEXT_DIM),
            };
            vec![
                vec![muted(e.time.format("%Y-%m-%d %H:%M:%S").to_string())],
                vec![Span::styled(e.kind, style)],
                vec![Span::raw(truncate_left(&e.path, path_w))],
            ]
        })
        .collect();
    let mut scroll = 0;
    app.hit.list_rows = draw_table(frame, table, &specs, rows, &mut scroll, Some(app.ir.fs_selected - app.ir.fs_offset));
}

/// One row per remote address: who talks to it, how often, and whether
/// the reconnects look like a timer (beaconing).
fn hosts_view(frame: &mut Frame, app: &mut App, area: Rect) {
    let rows_src: Vec<&crate::app::RemoteSummary> = app.visible_remotes().into_iter().map(|i| &app.ir.remotes[i]).collect();
    let beacons = rows_src.iter().filter(|r| r.beacon.is_some()).count();
    let public = rows_src.iter().filter(|r| r.public).count();
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!(" {} remote addresses", rows_src.len()), Style::new().add_modifier(Modifier::BOLD)),
            muted(format!("   {public} on the internet   ")),
            if beacons > 0 { Span::styled(format!("{beacons} with a beaconing pattern"), Style::new().fg(BAD).add_modifier(Modifier::BOLD)) } else { muted("no beaconing seen") },
            muted("    h back to connections · reconnects are counted from the moment procwatch started"),
        ])),
        Rect { height: 1, ..area },
    );
    let specs = [
        ColSpec::new("Remote", 0, false),
        ColSpec::new("Host name", 0, false),
        ColSpec::new("Ports", 14, false),
        ColSpec::new("Processes", 0, false),
        ColSpec::new("Now", 4, true),
        ColSpec::new("Connects", 8, true),
        ColSpec::new("First", 8, false),
        ColSpec::new("Last", 8, false),
        ColSpec::new("Pattern", 16, false),
    ];
    let rows = rows_src
        .iter()
        .map(|r| {
            vec![
                vec![if r.public { Span::raw(r.ip.clone()) } else { muted(r.ip.clone()) }],
                vec![r.host.clone().map(Span::raw).unwrap_or_else(|| muted(""))],
                vec![muted(r.ports.join(","))],
                vec![Span::raw(r.processes.join(", "))],
                vec![Span::raw(r.current.to_string())],
                vec![Span::raw(r.connects.to_string())],
                vec![muted(r.first_seen.clone())],
                vec![muted(r.last_seen.clone())],
                vec![match r.beacon {
                    Some(iv) => Span::styled(format!("every ~{iv:.0}s"), Style::new().fg(BAD).add_modifier(Modifier::BOLD)),
                    None => muted(""),
                }],
            ]
        })
        .collect::<Vec<_>>();
    let n = rows.len();
    app.ir.host_selected = app.ir.host_selected.min(n.saturating_sub(1));
    let mut scroll = 0;
    let table = Rect { y: area.y + 2, height: area.height.saturating_sub(2), ..area };
    app.hit.list_rows = draw_table(frame, table, &specs, rows, &mut scroll, (n > 0).then_some(app.ir.host_selected));
}
