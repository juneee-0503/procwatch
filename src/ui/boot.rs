//! The screens before monitoring begins, and the alarm lamp.

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Gauge, Paragraph},
    Frame,
};

use super::widgets::*;
use crate::app::boot::BootPhase;
use crate::app::App;
use crate::kernel::alarm::{Phase, Priority};

const STANDBY: [&str; 5] = [
    "███ ███  █  █  █ ██  ██  █ █",
    "█    █  █ █ ██ █ █ █ █ █ █ █",
    "███  █  ███ █ ██ █ █ ██   █ ",
    "  █  █  █ █ █  █ █ █ █ █  █ ",
    "███  █  █ █ █  █ ██  ██   █ ",
];

fn log_view(frame: &mut Frame, app: &App, area: Rect) {
    let height = area.height as usize;
    let log = &app.boot.log;
    let lines: Vec<Line> = log[log.len().saturating_sub(height)..]
        .iter()
        .map(|(ok, text)| {
            let (mark, color) = if *ok { (" ok  ", OK) } else { (" FAIL", BAD) };
            Line::from(vec![Span::styled(mark, Style::new().fg(color)), Span::raw(" "), Span::raw(truncate(text, area.width.saturating_sub(7) as usize))])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

fn progress(frame: &mut Frame, app: &App, title: &str, screen: Rect) {
    let [head, gauge, current, _, log] = Layout::vertical([Constraint::Length(2), Constraint::Length(1), Constraint::Length(2), Constraint::Length(1), Constraint::Min(1)]).areas(screen.inner(ratatui::layout::Margin { horizontal: 2, vertical: 1 }));
    frame.render_widget(Paragraph::new(Span::styled(title, Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))), head);
    let label = format!("{} of {}", app.boot.done, app.boot.total);
    frame.render_widget(Gauge::default().gauge_style(Style::new().fg(ACCENT)).percent(app.boot.percent()).label(label), gauge);
    frame.render_widget(Paragraph::new(Span::styled(app.boot.current.clone(), Style::new().fg(TEXT_DIM))), current);
    log_view(frame, app, log);
}

fn standby(frame: &mut Frame, screen: Rect) {
    let width = STANDBY[0].chars().count() as u16;
    let rect = centered(screen, width.min(screen.width), (STANDBY.len() as u16 + 3).min(screen.height));
    let mut lines: Vec<Line> = STANDBY.iter().map(|l| Line::from(Span::styled(*l, Style::new().fg(WARN).add_modifier(Modifier::BOLD)))).collect();
    lines.push(Line::default());
    lines.push(Line::from(muted("Self-check passed. Nothing is being monitored.")));
    lines.push(Line::from(muted("enter choose modules  ,  settings  q  quit")));
    frame.render_widget(Paragraph::new(lines).alignment(ratatui::layout::Alignment::Center), rect);
}

fn select(frame: &mut Frame, app: &App, screen: Rect) {
    let rect = centered(screen, screen.width.min(84), screen.height.min(app.boot.choices.len() as u16 + 6));
    let block = Block::bordered().border_style(Style::new().fg(ACCENT)).title(Span::styled(" Modules for this session ", Style::new().add_modifier(Modifier::BOLD)));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let mut lines = Vec::new();
    for (i, c) in app.boot.choices.iter().enumerate() {
        let mark = if c.chosen { "[x]" } else { "[ ]" };
        let style = if c.support.starts_with("not supported here") { Style::new().fg(MUTED) } else { Style::default() };
        let text = format!(" {mark} {:<12} {:<20} {}", c.name, c.support, c.description);
        let line = Line::from(Span::styled(truncate(&text, inner.width as usize), style));
        lines.push(if i == app.boot.cursor { line.style(sel_style()) } else { line });
    }
    lines.push(Line::default());
    lines.push(Line::from(muted(" ↑↓ move  space select  a all  n none  enter load  esc back")));
    let scroll = app.boot.cursor.saturating_sub(inner.height.saturating_sub(3) as usize) as u16;
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), inner);
}

fn halted(frame: &mut Frame, app: &App, screen: Rect) {
    let [head, log, hint] = Layout::vertical([Constraint::Length(3), Constraint::Min(1), Constraint::Length(2)]).areas(screen.inner(ratatui::layout::Margin { horizontal: 2, vertical: 1 }));
    frame.render_widget(Paragraph::new(vec![Line::from(Span::styled("SELF-CHECK FAILED", Style::new().fg(Color::White).bg(BAD).add_modifier(Modifier::BOLD))), Line::from(muted("procwatch can't vouch for itself, so it won't monitor."))]), head);
    log_view(frame, app, log);
    frame.render_widget(Paragraph::new(muted("q  quit")), hint);
}

pub fn draw(frame: &mut Frame, app: &mut App) {
    let screen = frame.area();
    frame.render_widget(Clear, screen);
    match app.boot.phase {
        BootPhase::SelfTest => progress(frame, app, "Self-check", screen),
        BootPhase::Standby => standby(frame, screen),
        BootPhase::Select => select(frame, app, screen),
        BootPhase::Loading => progress(frame, app, "Loading modules", screen),
        BootPhase::Verify => progress(frame, app, "Verifying integrity", screen),
        BootPhase::Halted => halted(frame, app, screen),
        BootPhase::Monitoring => {}
    }
}

/// Flash rates of IEC 60601-1-8: high about 2 Hz, medium about 0.6 Hz, low
/// steady. Colours likewise: red, yellow and cyan.
fn lamp_on(p: Priority, ms: u128) -> bool {
    match p {
        Priority::High => ms % 500 < 250,
        Priority::Medium => ms % 1600 < 800,
        Priority::Low => true,
    }
}

fn color(p: Priority) -> Color {
    match p {
        Priority::High => Color::Red,
        Priority::Medium => Color::Yellow,
        Priority::Low => Color::Cyan,
    }
}

/// The lamp, top right.
pub fn lamp(frame: &mut Frame, app: &App, rect: Rect) {
    let worst = app.board.worst();
    let held = app.board.acknowledged();
    let (text, style) = match worst {
        Some(e) => {
            let count = app.board.active.values().filter(|a| a.phase == Phase::Firing).count();
            let word = format!("{} {count}", e.priority.label().to_uppercase());
            let lit = lamp_on(e.priority, app.started.elapsed().as_millis());
            (word, if lit { Style::new().fg(Color::Black).bg(color(e.priority)).add_modifier(Modifier::BOLD) } else { Style::new().fg(color(e.priority)).bg(Color::Black) })
        }
        None if held > 0 => (format!("ACK {held}"), Style::new().fg(Color::Gray).bg(Color::DarkGray)),
        None => ("NO ALARM".to_string(), Style::new().fg(Color::DarkGray)),
    };
    let block = Block::bordered().border_style(style).style(style);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let mark = if app.board.audio_paused() { "♪̸ " } else if !app.board.sound { "♪off " } else { "" };
    frame.render_widget(Paragraph::new(format!("{mark}{text}")).alignment(ratatui::layout::Alignment::Center).style(style), inner);
}

/// The alarm messages beside the lamp, worst first.
pub fn banner(frame: &mut Frame, app: &App, rect: Rect) {
    let mut active: Vec<_> = app.board.active.values().collect();
    active.sort_by_key(|e| (std::cmp::Reverse(e.phase == Phase::Firing), std::cmp::Reverse(e.priority)));
    let lines: Vec<Line> = active
        .iter()
        .take(rect.height as usize)
        .map(|e| {
            let style = if e.phase == Phase::Firing { Style::new().fg(color(e.priority)) } else { Style::new().fg(MUTED) };
            Line::from(Span::styled(truncate(&format!(" {} {}", e.priority.label().to_uppercase(), e.title), rect.width as usize), style))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), rect);
}

/// Everything alarming now, and what happened.
pub fn alarms(frame: &mut Frame, app: &mut App, screen: Rect, cursor: usize) {
    let rect = centered(screen, screen.width.saturating_sub(6), screen.height.saturating_sub(4));
    frame.render_widget(Clear, rect);
    let block = Block::bordered().border_style(Style::new().fg(ACCENT)).title(Span::styled(" Alarms ", Style::new().add_modifier(Modifier::BOLD)));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let width = inner.width as usize;
    let mut lines = vec![Line::from(muted(" enter acknowledge  ! all  @ pause sound  any other key closes"))];
    let list = app.alarm_list();
    if list.is_empty() {
        lines.push(Line::from(muted(" No alarms active.")));
    }
    for (i, e) in list.iter().enumerate() {
        let text = format!(" {:<7}{:<13}{}", e.priority.label(), format!("{:?}", e.phase).to_lowercase(), e.title);
        let line = Line::from(Span::styled(truncate(&text, width), Style::new().fg(color(e.priority))));
        lines.push(if i == cursor { line.style(sel_style()) } else { line });
    }
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(" Recent", Style::new().add_modifier(Modifier::BOLD))));
    for e in app.board.history.iter().take(inner.height as usize) {
        lines.push(Line::from(muted(truncate(&format!(" {:<7}{:<13}{}", e.priority.label(), format!("{:?}", e.phase).to_lowercase(), e.title), width))));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flash_rates_follow_the_standard() {
        let transitions = |p| (0..10_000u128).step_by(10).map(|ms| lamp_on(p, ms)).collect::<Vec<_>>().windows(2).filter(|w| w[0] != w[1]).count() as f64 / 2.0 / 10.0;
        assert!((1.4..=2.8).contains(&transitions(Priority::High)));
        assert!((0.4..=0.8).contains(&transitions(Priority::Medium)));
        assert_eq!(transitions(Priority::Low), 0.0, "steady");
    }

    #[test]
    fn standby_lines_are_even() {
        assert!(STANDBY.iter().all(|l| l.chars().count() == STANDBY[0].chars().count()));
    }
}
