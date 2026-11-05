//! Keyboard and mouse: turning input into `App` calls, by mode and page.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Position;

use crate::app::{self, palette, App, Cmd, Mode, OptionItem, StatusLevel, Tab, ViewMode};

pub fn handle_key(app: &mut App, key: KeyEvent) {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    if ctrl && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }
    match app.mode.clone() {
        Mode::Help => app.mode = Mode::Normal,
        Mode::Options { cursor } => options_key(app, key, cursor),
        Mode::Menu(stack) => menu_key(app, key, stack),
        Mode::Confirm { cmd, targets } => match key.code {
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') if cmd == Cmd::SaveBaseline => app.save_baseline(),
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') if matches!(cmd, Cmd::Quarantine(_)) => {
                if let Cmd::Quarantine(p) = cmd {
                    app.do_quarantine(&p);
                }
            }
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => app.execute(cmd, targets),
            _ => app.mode = Mode::Normal,
        },
        Mode::Search => search_key(app, key),
        Mode::Find { input } => find_input_key(app, key, input),
        Mode::RuleInput { input, .. } => rule_input_key(app, key, input),
        Mode::Input { purpose, input, .. } => text_input_key(app, key, purpose, input),
        Mode::Sweep => {
            let len = app.ir.sweep.as_ref().map_or(0, |s| s.hits.len());
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => app.ir.sweep_selected = (app.ir.sweep_selected + 1).min(len.saturating_sub(1)),
                KeyCode::Up | KeyCode::Char('k') => app.ir.sweep_selected = app.ir.sweep_selected.saturating_sub(1),
                KeyCode::Char('r') => app.rerun_sweep(),
                KeyCode::Char('m') => app.sweep_to_findings(),
                KeyCode::Enter => {
                    let pid = app.ir.sweep.as_ref().and_then(|s| s.hits.get(app.ir.sweep_selected)).and_then(|h| h.pid);
                    if let Some(pid) = pid {
                        app.focus_pid(pid);
                    }
                }
                _ => app.mode = Mode::Normal,
            }
        }
        Mode::FileReport => match key.code {
            KeyCode::Down | KeyCode::Char('j') => app.ir.report_scroll += 1,
            KeyCode::Up | KeyCode::Char('k') => app.ir.report_scroll = app.ir.report_scroll.saturating_sub(1),
            KeyCode::PageDown => app.ir.report_scroll += 10,
            KeyCode::PageUp => app.ir.report_scroll = app.ir.report_scroll.saturating_sub(10),
            KeyCode::Char('m') => app.finding_from_report(),
            KeyCode::Char('Q') => {
                if let Some(Ok(r)) = app.ir.file_report.as_ref().map(|f| &f.result) {
                    let p = r.path.clone();
                    app.request_quarantine(p);
                }
            }
            KeyCode::Char('c') => {
                if let Some(Ok(r)) = app.ir.file_report.as_ref().map(|f| &f.result) {
                    if let Some(h) = &r.hashes {
                        let sha = h.sha256.clone();
                        app.mode = Mode::Normal;
                        if let Ok(dest) = crate::common::desktop::copy_to_clipboard(&sha) {
                            app.set_status(StatusLevel::Success, format!("SHA-256 copied to {dest}"));
                        }
                    }
                }
            }
            _ => app.mode = Mode::Normal,
        },
        Mode::Graph => {
            let len = app.graph_current().cloned().map_or(0, |e| app.neighbors(&e).len());
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => app.ir.graph.cursor = (app.ir.graph.cursor + 1).min(len.saturating_sub(1)),
                KeyCode::Up | KeyCode::Char('k') => app.ir.graph.cursor = app.ir.graph.cursor.saturating_sub(1),
                KeyCode::PageDown => app.ir.graph.cursor = (app.ir.graph.cursor + 10).min(len.saturating_sub(1)),
                KeyCode::PageUp => app.ir.graph.cursor = app.ir.graph.cursor.saturating_sub(10),
                KeyCode::Enter | KeyCode::Right => app.graph_pivot(),
                KeyCode::Left | KeyCode::Backspace => app.graph_back(),
                KeyCode::Char('t') => app.graph_timeline(),
                KeyCode::Char('g') => app.graph_goto(),
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('l') => app.mode = Mode::Normal,
                _ => {}
            }
        }
        Mode::Clusters => {
            let len = app.ir.clusters.len();
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => app.ir.cluster_selected = (app.ir.cluster_selected + 1).min(len.saturating_sub(1)),
                KeyCode::Up | KeyCode::Char('k') => app.ir.cluster_selected = app.ir.cluster_selected.saturating_sub(1),
                KeyCode::Enter => {
                    if let Some(c) = app.ir.clusters.get(app.ir.cluster_selected) {
                        app.query = format!("cluster:{}", c.id);
                        app.ir.tl_selected = 0;
                    }
                    app.mode = Mode::Normal;
                }
                _ => app.mode = Mode::Normal,
            }
        }
        Mode::Health | Mode::ActivitySummary => app.mode = Mode::Normal,
        Mode::Modules { cursor } => {
            let names: Vec<&'static str> = app.kernel.as_ref().map(|k| k.status().iter().map(|s| s.name).collect()).unwrap_or_default();
            match key.code {
                KeyCode::Up => app.mode = Mode::Modules { cursor: cursor.saturating_sub(1) },
                KeyCode::Down => app.mode = Mode::Modules { cursor: (cursor + 1).min(names.len().saturating_sub(1)) },
                KeyCode::Char(' ') => {
                    if let Some(n) = names.get(cursor) {
                        app.toggle_module(n);
                    }
                }
                _ => app.mode = Mode::Normal,
            }
        }
        Mode::Workspace => workspace_key(app, key),
        Mode::Palette { input, cursor } => {
            let list = palette::matches(&input);
            match key.code {
                KeyCode::Esc => app.mode = Mode::Normal,
                KeyCode::Down => app.mode = Mode::Palette { cursor: (cursor + 1).min(list.len().saturating_sub(1)), input },
                KeyCode::Up => app.mode = Mode::Palette { cursor: cursor.saturating_sub(1), input },
                KeyCode::Backspace => {
                    let mut i = input;
                    i.pop();
                    app.mode = Mode::Palette { input: i, cursor: 0 };
                }
                KeyCode::Char(c) => {
                    let mut i = input;
                    i.push(c);
                    app.mode = Mode::Palette { input: i, cursor: 0 };
                }
                KeyCode::Enter => {
                    app.mode = Mode::Normal;
                    if let Some(e) = list.get(cursor) {
                        if let Some(t) = e.tab {
                            app.switch_tab(t);
                        }
                        normal_key(app, KeyEvent::new(KeyCode::Char(e.key), if e.key.is_uppercase() { KeyModifiers::SHIFT } else { KeyModifiers::NONE }));
                    }
                }
                _ => {}
            }
        }
        Mode::LaunchConfirm(argv) => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                app.mode = Mode::Normal;
                app.launch_and_trace(argv);
            }
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('q') => {
                app.mode = Mode::Normal;
                app.set_status(StatusLevel::Info, "Nothing was run.".into());
            }
            _ => {}
        },
        Mode::StateAt => match key.code {
            KeyCode::Down | KeyCode::Char('j') => app.ir.state_scroll += 1,
            KeyCode::Up | KeyCode::Char('k') => app.ir.state_scroll = app.ir.state_scroll.saturating_sub(1),
            KeyCode::PageDown => app.ir.state_scroll += 15,
            KeyCode::PageUp => app.ir.state_scroll = app.ir.state_scroll.saturating_sub(15),
            _ => app.mode = Mode::Normal,
        },
        Mode::Normal if app.find.is_some() => find_results_key(app, key),
        Mode::Normal => normal_key(app, key),
    }
}

fn page(app: &App) -> isize {
    app.hit.list_rows.height.max(1) as isize
}

/// Anchor for a keyboard-opened menu: next to the selected row.
fn menu_anchor(app: &App) -> (u16, u16) {
    let r = app.hit.list_rows;
    let row = app.selected.saturating_sub(app.offset) as u16;
    (r.x + 4, (r.y + row + 1).min(r.bottom().saturating_sub(1)))
}

fn normal_key(app: &mut App, key: KeyEvent) {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);

    // The Performance page scrolls instead of selecting.
    if app.tab == Tab::Performance && matches!(key.code, KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown | KeyCode::Home | KeyCode::End | KeyCode::Char('j' | 'k' | 'g' | 'G')) {
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => app.perf_scroll += 1,
            KeyCode::Up | KeyCode::Char('k') => app.perf_scroll = app.perf_scroll.saturating_sub(1),
            KeyCode::PageDown => app.perf_scroll += 20,
            KeyCode::PageUp => app.perf_scroll = app.perf_scroll.saturating_sub(20),
            KeyCode::Home | KeyCode::Char('g') => app.perf_scroll = 0,
            _ => app.perf_scroll = usize::MAX / 2,
        }
        return;
    }

    // Keys that work on every page.
    match key.code {
        KeyCode::Char('q') => {
            if app.detail_full {
                app.detail_full = false;
            } else {
                app.should_quit = true;
            }
            return;
        }
        KeyCode::Char('?') => {
            app.mode = Mode::Help;
            return;
        }
        KeyCode::Char('M') => {
            app.mode = Mode::Modules { cursor: 0 };
            return;
        }
        KeyCode::Char(c @ ('0'..='9' | '`')) if !app.detail_full => {
            if let Some(t) = Tab::ALL.iter().find(|t| t.key() == c) {
                app.switch_tab(*t);
            }
            return;
        }
        KeyCode::Char('m') if app.tab == Tab::Alerts && app.ir.det.focus => {
            app.detection_to_finding();
            return;
        }
        KeyCode::Char('m') if !matches!(app.tab, Tab::Performance | Tab::Trace | Tab::Case) && !app.detail_full => {
            app.mark_finding();
            return;
        }
        KeyCode::Char('l') if !ctrl && !matches!(app.tab, Tab::Performance | Tab::Case | Tab::Trace) => {
            app.open_graph();
            return;
        }
        KeyCode::Char('H') => {
            app.mode = Mode::Health;
            return;
        }
        KeyCode::Char(':') => {
            app.mode = Mode::Palette { input: String::new(), cursor: 0 };
            return;
        }
        KeyCode::Char('k') if ctrl => {
            app.mode = Mode::Palette { input: String::new(), cursor: 0 };
            return;
        }
        KeyCode::Char('W') if !matches!(app.tab, Tab::Performance | Tab::Case) => {
            app.open_workspace();
            return;
        }
        KeyCode::Char('D') if matches!(app.tab, Tab::Processes | Tab::Network | Tab::Timeline | Tab::Alerts) => {
            if let Some(crate::common::model::Entity::Process(k)) = app.selected_entity() {
                app.toggle_deep(k.pid);
            }
            return;
        }
        KeyCode::Char('/') => {
            app.mode = Mode::Search;
            return;
        }
        KeyCode::Char('p') => {
            app.toggle_pause();
            return;
        }
        KeyCode::Char('l') if ctrl => {
            app.request_refresh();
            return;
        }
        KeyCode::Char('f') => {
            app.mode = Mode::Find { input: String::new() };
            return;
        }
        KeyCode::Char('o') => {
            app.mode = Mode::Options { cursor: 0 };
            return;
        }
        KeyCode::Down | KeyCode::Char('j') if !(shift && app.details_visible()) => {
            app.move_selection(1);
            return;
        }
        KeyCode::Up | KeyCode::Char('k') if !(shift && app.details_visible()) => {
            app.move_selection(-1);
            return;
        }
        KeyCode::PageDown if !app.detail_full => return app.move_selection(page(app)),
        KeyCode::PageUp if !app.detail_full => return app.move_selection(-page(app)),
        KeyCode::Home | KeyCode::Char('g') if !app.detail_full => return app.move_selection(isize::MIN / 2),
        KeyCode::End | KeyCode::Char('G') if !app.detail_full => return app.move_selection(isize::MAX / 2),
        _ => {}
    }

    match app.tab {
        Tab::Processes => process_key(app, key),
        Tab::Network => match key.code {
            KeyCode::Enter => {
                if let Some(pid) = app.conn_rows.get(app.conn_selected).map(|r| r.pid) {
                    app.focus_pid(pid);
                }
            }
            KeyCode::Char('d') => {
                app.ir.net_dns_view = !app.ir.net_dns_view;
                app.ir.net_hosts_view = false;
            }
            KeyCode::Char('h') => {
                app.ir.net_hosts_view = !app.ir.net_hosts_view;
                app.ir.net_dns_view = false;
            }

            KeyCode::Esc => {
                app.clear_filters();
            }
            _ => {}
        },
        Tab::Trace => trace_key(app, key),
        Tab::Alerts => alerts_key(app, key),
        Tab::Files => match key.code {
            KeyCode::Char('r') => app.refresh_files(),
            KeyCode::Char('w') => app.ir.files_changes_view = !app.ir.files_changes_view,
            KeyCode::Char('a') => {
                if let Some(p) = app.selected_path() {
                    app.analyze_file(&p);
                }
            }
            KeyCode::Char('A') => {
                app.mode = Mode::Input { purpose: app::InputPurpose::AnalyzePath, input: String::new(), error: None }
            }
            KeyCode::Char('Q') => {
                if let Some(p) = app.selected_path() {
                    app.request_quarantine(p);
                }
            }
            KeyCode::Enter if !app.ir.files_changes_view => {
                if let Some(pid) = app.selected_file_pid() {
                    app.focus_pid(pid);
                }
            }
            KeyCode::Enter => {
                if let Some(p) = app.selected_path() {
                    app.analyze_file(&p);
                }
            }
            KeyCode::Esc => app.query.clear(),
            _ => {}
        },
        Tab::Persistence => match key.code {
            KeyCode::Char('c') => app.ir.persist_changes_view = !app.ir.persist_changes_view,
            KeyCode::Char('b') if app.ir.persist_changes_view => app.request_save_baseline(),
            KeyCode::Enter if app.ir.persist_changes_view => app.open_change(),
            KeyCode::Char('r') => app.scan_persistence(),
            KeyCode::Enter | KeyCode::Char('a') => {
                if let Some(p) = app.selected_path() {
                    app.analyze_file(&p);
                }
            }
            KeyCode::Char('Q') => {
                if let Some(p) = app.selected_path() {
                    app.request_quarantine(p);
                }
            }
            KeyCode::Esc => app.query.clear(),
            _ => {}
        },
        Tab::Activity => match key.code {
            KeyCode::Char('c') => app.toggle_capture(),
            KeyCode::Char('x') => app.clear_activity(),
            KeyCode::Char('s') => app.mode = Mode::ActivitySummary,
            KeyCode::Char('e') => app.save_activity(),
            _ => {}
        },
        Tab::Timeline => match key.code {
            KeyCode::Enter => {
                let pid = app.visible_timeline().get(app.ir.tl_selected).and_then(|i| app.ir.timeline[*i].pid);
                if let Some(pid) = pid {
                    app.focus_pid(pid);
                }
            }
            KeyCode::Char('r') => app.rebuild_timeline(),
            KeyCode::Char('e') => app.export_timeline_csv(),
            KeyCode::Char('b') => app.request_bookmark(),
            KeyCode::Char('s') => app.open_state_at(),
            KeyCode::Char('B') => app.remove_bookmark(),
            KeyCode::Char('c') => {
                app.rebuild_timeline();
                app.ir.cluster_selected = 0;
                app.mode = Mode::Clusters;
            }
            KeyCode::Char('t') => {
                // Narrow the timeline to the selected event's process tree.
                let pid = app.visible_timeline().get(app.ir.tl_selected).and_then(|i| app.ir.timeline[*i].pid);
                if let Some(pid) = pid {
                    app.query = format!("tree:{pid}");
                    app.ir.tl_selected = 0;
                }
            }
            KeyCode::Esc => app.query.clear(),
            _ => {}
        },
        Tab::Logs if app.ir.artifacts_view => match key.code {
            KeyCode::Char('x') => app.ir.artifacts_view = false,
            KeyCode::Char('r') => app.collect_artifacts(),
            KeyCode::Char('A') => app.mode = Mode::Input { purpose: app::InputPurpose::ArtifactDir, input: String::new(), error: None },
            KeyCode::Enter => {
                let path = app.visible_artifacts().get(app.ir.art_selected).map(|i| app.ir.artifacts[*i].subject.clone());
                if let Some(p) = path.filter(|p| std::path::Path::new(p).exists()) {
                    app.analyze_file(&p);
                }
            }
            KeyCode::Esc => app.query.clear(),
            _ => {}
        },
        Tab::Logs => match key.code {
            KeyCode::Char('x') => app.ir.artifacts_view = true,
            KeyCode::Char('r') => app.fetch_logs(),
            KeyCode::Char('w') => app.cycle_log_window(),
            KeyCode::Char('a') => app.toggle_log_scope(),
            KeyCode::Enter => {
                let pid = app.visible_logs().get(app.ir.log_selected).and_then(|i| app.log_entries()[*i].pid);
                if let Some(pid) = pid {
                    app.focus_pid(pid);
                }
            }
            KeyCode::Esc => app.query.clear(),
            _ => {}
        },
        Tab::Case => {
            let input = |p: app::InputPurpose| Mode::Input { purpose: p, input: String::new(), error: None };
            match key.code {
                KeyCode::Char('n') => app.new_case(),
                KeyCode::Char('c') => app.collect_system(),
                KeyCode::Char('s') => app.seal_evidence(),
                KeyCode::Char('v') => app.verify_evidence(),
                KeyCode::Char('e') => app.export_case_report(),
                KeyCode::Char('a') => app.mode = input(app::InputPurpose::Note),
                KeyCode::Char('C') => {
                    let current = app.ir.case.as_ref().map(|c| c.conclusion.clone()).unwrap_or_default();
                    app.mode = Mode::Input { purpose: app::InputPurpose::Conclusion, input: current, error: None };
                }
                KeyCode::Char('i') => app.mode = input(app::InputPurpose::IsolationAllow),
                KeyCode::Char('I') => app.open_sweep_dialog(),
                KeyCode::Char('Y') => app.scan_executables(),
                KeyCode::Char('X') => app.export_standard(),
                KeyCode::Tab | KeyCode::BackTab => app.ir.case_focus_quarantine = !app.ir.case_focus_quarantine,
                KeyCode::Char('R') if app.ir.case_focus_quarantine => app.restore_selected(),
                KeyCode::Delete | KeyCode::Backspace if !app.ir.case_focus_quarantine => app.delete_finding(),
                _ => {}
            }
        }
        Tab::Performance => match key.code {
            KeyCode::Char('m') | KeyCode::Tab => {
                app.perf_view = (app.perf_view + 1) % 3;
                app.perf_scroll = 0;
            }
            _ => {}
        },
    }
}

fn trace_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('x') => app.stop_trace(),
        KeyCode::Char('e') => app.export_trace(),
        KeyCode::Char('c') => {
            app.trace_filter = app.trace_filter.next();
            app.trace_follow = true;
        }
        KeyCode::Char('F') => app.trace_follow = !app.trace_follow,
        KeyCode::Char('T') => {
            if let Some(pid) = app.trace.as_ref().map(|t| t.root) {
                app.start_trace(pid);
            }
        }
        KeyCode::Esc => {
            app.query.clear();
        }
        KeyCode::Enter => {
            let pid = app
                .visible_trace()
                .get(app.trace_selected)
                .and_then(|i| app.trace.as_ref().map(|t| t.events[*i].pid));
            if let Some(pid) = pid {
                app.focus_pid(pid);
            }
        }
        _ => {}
    }
}

fn workspace_key(app: &mut App, key: KeyEvent) {
    let n = app.ir.ws.dossier.events.len();
    let ws = &mut app.ir.ws;
    let replay = ws.tab == 1;
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => app.mode = Mode::Normal,
        KeyCode::Tab => {
            ws.tab = (ws.tab + 1) % app::workspace::TABS.len();
            ws.scroll = 0;
        }
        KeyCode::BackTab => {
            ws.tab = (ws.tab + app::workspace::TABS.len() - 1) % app::workspace::TABS.len();
            ws.scroll = 0;
        }
        KeyCode::Char(c @ '1'..='6') => {
            ws.tab = (c as u8 - b'1') as usize;
            ws.scroll = 0;
        }
        KeyCode::Right | KeyCode::Char('n') if replay => ws.cursor = (ws.cursor + 1).min(n.saturating_sub(1)),
        KeyCode::Left | KeyCode::Char('p') if replay => ws.cursor = ws.cursor.saturating_sub(1),
        KeyCode::Home if replay => ws.cursor = 0,
        KeyCode::End if replay => ws.cursor = n.saturating_sub(1),
        KeyCode::PageDown if replay => ws.cursor = (ws.cursor + 10).min(n.saturating_sub(1)),
        KeyCode::PageUp if replay => ws.cursor = ws.cursor.saturating_sub(10),
        KeyCode::Down | KeyCode::Char('j') if replay => ws.cursor = (ws.cursor + 1).min(n.saturating_sub(1)),
        KeyCode::Up | KeyCode::Char('k') if replay => ws.cursor = ws.cursor.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => ws.scroll += 1,
        KeyCode::Up | KeyCode::Char('k') => ws.scroll = ws.scroll.saturating_sub(1),
        KeyCode::PageDown => ws.scroll += 15,
        KeyCode::PageUp => ws.scroll = ws.scroll.saturating_sub(15),
        KeyCode::Char('e') => app.export_quick_report(),
        KeyCode::Char('D') => {
            if let Some(k) = app.ir.ws.key {
                app.toggle_deep(k.pid);
                app.refresh_workspace();
            }
        }
        KeyCode::Char('r') => app.refresh_workspace(),
        _ => {}
    }
}

fn alerts_key(app: &mut App, key: KeyEvent) {
    // tab cycles: detections → alerts → alert rules → detections
    if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
        if app.ir.det.focus {
            app.ir.det.focus = false;
            app.rules_focus = false;
        } else if !app.rules_focus {
            app.rules_focus = true;
        } else {
            app.rules_focus = false;
            app.ir.det.focus = true;
        }
        return;
    }
    if app.ir.det.focus {
        match key.code {
            KeyCode::Enter => {
                if let Some(d) = app.selected_detection().cloned() {
                    match (d.pid.filter(|p| app.tree.get(*p).is_some()), &d.subject) {
                        (Some(pid), _) => app.focus_pid(pid),
                        (None, crate::common::model::Entity::File(p)) => app.analyze_file(&p.clone()),
                        _ => app.open_graph(),
                    }
                }
            }
            KeyCode::Char('S') => app.request_suppress(),
            KeyCode::Char('T') => app.request_trust_publisher(),
            KeyCode::Char('u') => {
                app.ir.det.show_suppressed = !app.ir.det.show_suppressed;
                app.ir.det.selected = 0;
            }
            KeyCode::Char('R') => app.reload_detection_rules(),
            KeyCode::Esc => app.query.clear(),
            _ => {}
        }
        return;
    }
    match key.code {
        KeyCode::Char('a') => app.mode = Mode::RuleInput { input: String::new(), error: None },
        KeyCode::Delete | KeyCode::Backspace if app.rules_focus => app.delete_rule(),
        KeyCode::Char(' ') if app.rules_focus => app.toggle_rule(),
        KeyCode::Char('c') if !app.rules_focus => {
            app.alerts.clear();
            app.alert_selected = 0;
        }
        KeyCode::Enter if !app.rules_focus => {
            if let Some(pid) = app.selected_alert_pid() {
                app.focus_pid(pid);
            }
        }
        _ => {}
    }
}

fn text_input_key(app: &mut App, key: KeyEvent, purpose: app::InputPurpose, mut input: String) {
    match key.code {
        KeyCode::Esc => {
            app.mode = Mode::Normal;
            return;
        }
        KeyCode::Enter => return app.submit_input(purpose, input),
        KeyCode::Backspace => {
            input.pop();
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => input.clear(),
        KeyCode::Char(c) if !c.is_control() => input.push(c),
        _ => {}
    }
    app.mode = Mode::Input { purpose, input, error: None };
}

fn rule_input_key(app: &mut App, key: KeyEvent, mut input: String) {
    match key.code {
        KeyCode::Esc => {
            app.mode = Mode::Normal;
            return;
        }
        KeyCode::Enter => {
            match app.add_rule(&input) {
                Ok(()) => {
                    app.mode = Mode::Normal;
                    app.rules_focus = true;
                }
                Err(e) => app.mode = Mode::RuleInput { input, error: Some(e) },
            }
            return;
        }
        KeyCode::Backspace => {
            input.pop();
        }
        KeyCode::Char(c) if !c.is_control() => input.push(c),
        _ => {}
    }
    app.mode = Mode::RuleInput { input, error: None };
}

fn process_key(app: &mut App, key: KeyEvent) {
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);
    if app.detail_full {
        let body = app.hit.pane_body.height.max(1) as isize;
        match key.code {
            KeyCode::Esc | KeyCode::Backspace => app.detail_full = false,
            KeyCode::Tab | KeyCode::Right => app.set_pane_tab(app.pane_tab.next()),
            KeyCode::BackTab | KeyCode::Left => app.set_pane_tab(app.pane_tab.prev()),
            KeyCode::Char(c @ '0'..='9') => {
                let i = if c == '0' { 9 } else { c as usize - '1' as usize };
                if let Some(t) = app::PaneTab::ALL.get(i) {
                    app.set_pane_tab(*t);
                }
            }
            KeyCode::PageDown => app.scroll_pane(body),
            KeyCode::PageUp => app.scroll_pane(-body),
            KeyCode::Home => app.pane_scroll = 0,
            KeyCode::End => app.pane_scroll = usize::MAX / 2,
            KeyCode::Down if shift => app.scroll_pane(1),
            KeyCode::Up if shift => app.scroll_pane(-1),
            KeyCode::Char('r') => {
                if app.pane_tab == app::PaneTab::Stack {
                    app.request_stack(true);
                } else {
                    app.request_deep_info(true);
                }
            }
            KeyCode::Enter => app.open_action_menu(menu_anchor(app)),
            KeyCode::Delete => app.quick_end(false),
            KeyCode::Char('X') => app.quick_end(true),
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Esc => {
            if !app.tagged.is_empty() {
                app.tagged.clear();
            } else {
                app.clear_filters();
            }
        }
        KeyCode::Enter => app.open_action_menu(menu_anchor(app)),
        KeyCode::Char(' ') => app.toggle_tag(),
        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.tagged = app.rows.iter().filter_map(|r| match r.key {
                app::RowKey::Proc(p) => Some(p),
                _ => None,
            }).collect();
        }
        KeyCode::Delete => app.quick_end(false),
        KeyCode::Char('X') => app.quick_end(true),
        KeyCode::Char('i') => app.open_details_full(),
        KeyCode::Char('d') => app.pane_visible = !app.pane_visible,
        KeyCode::Char('z') => app.toggle_freeze(),
        KeyCode::Char('T') => {
            if let Some(pid) = app.selected_pid() {
                app.start_trace(pid);
            }
        }
        KeyCode::Char('R') => {
            app.ir.intel.clear();
            app.set_status(StatusLevel::Info, "Re-checking signatures of all running programs…".into());
        }
        KeyCode::Tab => {
            app.pane_visible = true;
            app.set_pane_tab(app.pane_tab.next());
        }
        KeyCode::BackTab => {
            app.pane_visible = true;
            app.set_pane_tab(app.pane_tab.prev());
        }
        KeyCode::Down if shift => app.scroll_pane(1),
        KeyCode::Up if shift => app.scroll_pane(-1),
        KeyCode::Right | KeyCode::Char('+') | KeyCode::Char('=') => app.set_expanded(Some(true)),
        KeyCode::Left | KeyCode::Char('-') => app.set_expanded(Some(false)),
        KeyCode::Char('v') => app.set_view(app.view.next()),
        KeyCode::Char('t') => app.set_view(if app.view == ViewMode::Tree { ViewMode::List } else { ViewMode::Tree }),
        KeyCode::Char('s') => app.open_sort_menu((app.hit.list_rows.x + 2, app.hit.list_rows.y)),
        KeyCode::Char('r') => app.reverse_sort(),
        KeyCode::Char('e') => match crate::app::export::export_csv(app) {
            Ok((path, n)) => {
                let name = path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
                app.set_status(StatusLevel::Success, format!("Exported {n} processes to {name}"));
            }
            Err(e) => app.set_status(StatusLevel::Error, format!("Export failed: {e}")),
        },
        _ => {}
    }
}

fn search_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter => app.mode = Mode::Normal,
        KeyCode::Esc => {
            app.query.clear();
            app.mode = Mode::Normal;
            app.rebuild();
        }
        KeyCode::Down => app.move_selection(1),
        KeyCode::Up => app.move_selection(-1),
        KeyCode::Backspace => {
            app.query.pop();
            app.rebuild();
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.query.clear();
            app.rebuild();
        }
        KeyCode::Char(c) if !c.is_control() => {
            app.query.push(c);
            app.rebuild();
        }
        _ => {}
    }
}

fn find_input_key(app: &mut App, key: KeyEvent, mut input: String) {
    match key.code {
        KeyCode::Esc => {
            app.mode = Mode::Normal;
            return;
        }
        KeyCode::Enter => {
            app.start_find(&input);
            return;
        }
        KeyCode::Backspace => {
            input.pop();
        }
        KeyCode::Char(c) if !c.is_control() => input.push(c),
        _ => {}
    }
    app.mode = Mode::Find { input };
}

fn find_results_key(app: &mut App, key: KeyEvent) {
    let Some(find) = app.find.as_mut() else { return };
    let len = find.result.as_ref().map_or(0, |r| r.len());
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => app.find = None,
        KeyCode::Down | KeyCode::Char('j') => find.cursor = (find.cursor + 1).min(len.saturating_sub(1)),
        KeyCode::Up | KeyCode::Char('k') => find.cursor = find.cursor.saturating_sub(1),
        KeyCode::Char('f') => app.mode = Mode::Find { input: String::new() },
        KeyCode::Enter => {
            let pid = find.result.as_ref().ok().and_then(|r| r.get(find.cursor)).map(|h| h.pid);
            if let Some(pid) = pid {
                app.find = None;
                app.focus_pid(pid);
            }
        }
        _ => {}
    }
}

fn menu_key(app: &mut App, key: KeyEvent, mut stack: Vec<app::MenuLevel>) {
    let depth = stack.len();
    let Some(top) = stack.last_mut() else {
        app.mode = Mode::Normal;
        return;
    };
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            stack.pop();
        }
        KeyCode::Left if depth > 1 => {
            stack.pop();
        }
        KeyCode::Down | KeyCode::Char('j') => top.step(1),
        KeyCode::Up | KeyCode::Char('k') => top.step(-1),
        KeyCode::Enter | KeyCode::Right | KeyCode::Char(' ') => {
            let Some(item) = top.items.get(top.cursor).cloned() else { return };
            if !item.enabled || item.is_separator() {
                return;
            }
            match item.cmd {
                Cmd::Sub(items) => {
                    let (x, y) = top.anchor;
                    let width = app.hit.menus.last().map_or(30, |r| r.width);
                    let anchor = (x + width, y + top.cursor as u16);
                    stack.push(app::MenuLevel::new(item.label, items, anchor));
                }
                cmd if key.code != KeyCode::Right => {
                    app.mode = Mode::Normal;
                    return app.run_cmd(cmd);
                }
                _ => {}
            }
        }
        _ => {}
    }
    app.mode = if stack.is_empty() { Mode::Normal } else { Mode::Menu(stack) };
}

fn options_key(app: &mut App, key: KeyEvent, mut cursor: usize) {
    let items = OptionItem::all();
    let close = |app: &mut App| {
        app.mode = Mode::Normal;
        app.rebuild();
        app.save_config();
    };
    let item = items[cursor.min(items.len() - 1)];
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('o') => return close(app),
        KeyCode::Down | KeyCode::Char('j') => cursor = (cursor + 1).min(items.len() - 1),
        KeyCode::Up | KeyCode::Char('k') => cursor = cursor.saturating_sub(1),
        KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') | KeyCode::Enter => {
            let back = key.code == KeyCode::Left;
            match item {
                OptionItem::Interval => app.adjust_interval(back),
                OptionItem::View => app.view = if back { app.view.next().next() } else { app.view.next() },
                OptionItem::DetailsPane => app.pane_visible = !app.pane_visible,
                OptionItem::ConfirmEnd => app.confirm_end = !app.confirm_end,
                OptionItem::HighlightNew => app.highlight_new = !app.highlight_new,
                OptionItem::Notify => app.notify = !app.notify,
                OptionItem::Column(c) => app.toggle_column(c),
            }
        }
        _ => {}
    }
    app.mode = Mode::Options { cursor };
}

pub fn handle_mouse(app: &mut App, m: MouseEvent) {
    let pos = Position::new(m.column, m.row);
    let scroll = match m.kind {
        MouseEventKind::ScrollDown => 3,
        MouseEventKind::ScrollUp => -3,
        _ => 0,
    };

    // Menus: click an item to run it, click outside to close.
    if let Mode::Menu(stack) = &app.mode {
        if let MouseEventKind::Down(_) = m.kind {
            let hit = app.hit.menus.iter().enumerate().rev().find(|(_, r)| r.contains(pos)).map(|(i, r)| (i, *r));
            match hit {
                Some((level, rect)) => {
                    let mut stack = stack.clone();
                    stack.truncate(level + 1);
                    let idx = (m.row.saturating_sub(rect.y + 1)) as usize;
                    if let Some(top) = stack.last_mut() {
                        if idx < top.items.len() && top.items[idx].enabled && !top.items[idx].is_separator() {
                            top.cursor = idx;
                            app.mode = Mode::Menu(stack.clone());
                            menu_key(app, KeyEvent::from(KeyCode::Enter), stack);
                            return;
                        }
                    }
                }
                None => app.mode = Mode::Normal,
            }
        }
        return;
    }
    if matches!(app.mode, Mode::Confirm { .. } | Mode::Options { .. } | Mode::Help | Mode::Find { .. } | Mode::RuleInput { .. }) {
        if let MouseEventKind::Down(_) = m.kind {
            if matches!(app.mode, Mode::Help) {
                app.mode = Mode::Normal;
            }
        }
        return;
    }

    if let MouseEventKind::Down(MouseButton::Left) = m.kind {
        if let Some((_, tab)) = app.hit.tabs.iter().find(|(r, _)| r.contains(pos)) {
            app.tab = *tab;
            if app.tab == Tab::Alerts {
                app.unread_alerts = 0;
            }
            app.detail_full = false;
            return;
        }
        if app.hit.search.contains(pos) {
            app.mode = Mode::Search;
            return;
        }
        if app.hit.view_toggle.contains(pos) {
            app.set_view(app.view.next());
            return;
        }
        if let Some((_, tab)) = app.hit.pane_tabs.iter().find(|(r, _)| r.contains(pos)) {
            app.set_pane_tab(*tab);
            return;
        }
        if let Some((_, col)) = app.hit.list_header.iter().find(|(r, _)| r.contains(pos)) {
            app.set_sort(*col);
            return;
        }
    }

    if app.find.is_some() {
        if let MouseEventKind::Down(MouseButton::Left) = m.kind {
            if app.hit.find_rows.contains(pos) {
                let idx = (m.row - app.hit.find_rows.y) as usize;
                let double = app.register_click(m.row);
                if let Some(f) = app.find.as_mut() {
                    f.cursor = idx.min(f.result.as_ref().map_or(0, |r| r.len().saturating_sub(1)));
                }
                if double {
                    find_results_key(app, KeyEvent::from(KeyCode::Enter));
                }
            } else {
                app.find = None;
            }
        }
        return;
    }

    let in_list = app.hit.list_rows.contains(pos);
    let in_pane = app.hit.pane_body.contains(pos);
    if scroll != 0 {
        if in_pane {
            app.scroll_pane(scroll);
        } else {
            app.move_selection(scroll);
        }
        return;
    }
    let MouseEventKind::Down(button) = m.kind else { return };
    if !in_list {
        return;
    }
    let row = (m.row - app.hit.list_rows.y) as usize;
    match app.tab {
        Tab::Processes if !app.detail_full => {
            let idx = app.offset + row;
            if idx >= app.rows.len() {
                return;
            }
            let double = button == MouseButton::Left && app.register_click(m.row);
            app.hold_order_now();
            app.select_index(idx);
            match button {
                MouseButton::Right => app.open_action_menu((m.column, m.row + 1)),
                _ if double => {
                    if app.rows[idx].expandable && app.selected_pid().is_none() {
                        app.set_expanded(None);
                    } else {
                        app.open_details_full();
                    }
                }
                _ => {}
            }
        }
        Tab::Network => {
            let idx = app.conn_offset + row;
            if idx < app.conn_rows.len() {
                app.conn_selected = idx;
                if button == MouseButton::Left && app.register_click(m.row) {
                    let pid = app.conn_rows[idx].pid;
                    app.focus_pid(pid);
                }
            }
        }
        Tab::Files => {
            let idx = app.file_offset + row;
            if idx < app.visible_files().len() {
                app.file_selected = idx;
                if button == MouseButton::Left && app.register_click(m.row) {
                    if let Some(pid) = app.selected_file_pid() {
                        app.focus_pid(pid);
                    }
                }
            }
        }
        Tab::Activity => {
            let idx = app.ir.ac_offset + row;
            if idx < app.visible_activity().len() {
                app.ir.ac_selected = idx;
            }
        }
        Tab::Persistence | Tab::Timeline | Tab::Logs => {
            let (offset, len) = match app.tab {
                Tab::Persistence if app.ir.persist_changes_view => (app.change_offset, app.visible_changes().len()),
                Tab::Persistence => (app.ir.persist_offset, app.visible_persistence().len()),
                Tab::Timeline => (app.ir.tl_offset, app.visible_timeline().len()),
                _ => (app.ir.log_offset, app.visible_logs().len()),
            };
            let idx = offset + row;
            if idx < len {
                match app.tab {
                    Tab::Persistence if app.ir.persist_changes_view => app.change_selected = idx,
                    Tab::Persistence => app.ir.persist_selected = idx,
                    Tab::Timeline => app.ir.tl_selected = idx,
                    _ => app.ir.log_selected = idx,
                }
                if button == MouseButton::Left && app.register_click(m.row) {
                    normal_key(app, KeyEvent::from(KeyCode::Enter));
                }
            }
        }
        _ => {}
    }
}


#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn the_performance_page_scrolls_with_the_arrow_keys() {
        let mut app = app::tests_support::app();
        app.tab = Tab::Performance;
        let press = |app: &mut App, k| handle_key(app, KeyEvent::new(k, KeyModifiers::NONE));
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.perf_scroll, 2);
        press(&mut app, KeyCode::Up);
        assert_eq!(app.perf_scroll, 1);
        press(&mut app, KeyCode::Home);
        assert_eq!(app.perf_scroll, 0);
        press(&mut app, KeyCode::Char('m'));
        assert_eq!((app.perf_view, app.perf_scroll), (1, 0));
    }

    /// Navigation only: no key here reaches an action, export or confirm.
    #[test]
    fn random_navigation_never_panics() {
        use ratatui::{backend::TestBackend, Terminal};
        let keys: Vec<KeyCode> = [KeyCode::Up, KeyCode::Down, KeyCode::Left, KeyCode::Right, KeyCode::PageUp, KeyCode::PageDown, KeyCode::Home, KeyCode::End, KeyCode::Tab, KeyCode::BackTab, KeyCode::Esc, KeyCode::Enter]
            .into_iter()
            .chain("123456789jk?".chars().map(KeyCode::Char))
            .collect();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut app = app::tests_support::app();
        let mut term = Terminal::new(TestBackend::new(100, 30)).unwrap();
        for _ in 0..20_000 {
            let k = keys[(next() % keys.len() as u64) as usize];
            handle_key(&mut app, KeyEvent::new(k, crossterm::event::KeyModifiers::NONE));
            if next().is_multiple_of(4) {
                term.draw(|f| crate::ui::draw(f, &mut app)).unwrap();
            }
        }
    }
}
