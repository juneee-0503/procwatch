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
use crate::filter::split_endpoint;
use crate::network::ConnState;
use crate::process::{human_bytes, human_duration, human_rate};

pub fn performance(frame: &mut Frame, app: &mut App, area: Rect) {
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
    let f = crate::filter::Filter::parse(&app.query);
    struct Pair<'a>(&'a str, &'a str);
    impl crate::filter::Filterable for Pair<'_> {
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
