//! The settings screen.

use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
    Frame,
};

use super::widgets::*;
use crate::app::App;

pub fn draw(frame: &mut Frame, app: &mut App, screen: Rect, cursor: usize) {
    let rect = centered(screen, screen.width.saturating_sub(4).min(100), screen.height.saturating_sub(2));
    frame.render_widget(Clear, rect);
    let block = Block::bordered().border_style(Style::new().fg(ACCENT)).title(Span::styled(" Settings ", Style::new().add_modifier(Modifier::BOLD)));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let width = inner.width as usize;
    let mut lines = Vec::new();
    let mut at = 0;
    let mut section = "";
    for (i, item) in app.settings_items().iter().enumerate() {
        if item.section != section {
            section = item.section;
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(format!(" {section}"), Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))));
        }
        let text = format!("   {:<42} {}", item.label, item.value);
        let line = Line::from(Span::raw(truncate(&text, width)));
        if i == cursor {
            at = lines.len();
            lines.push(line.style(sel_style()));
        } else {
            lines.push(line);
        }
    }
    let scroll = at.saturating_sub(inner.height.saturating_sub(3) as usize) as u16;
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), inner);
}
