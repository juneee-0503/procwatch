//! Shared building blocks: theme, hand-laid-out tables (exact column
//! alignment), history charts, and display-width-aware text helpers.

pub use crate::common::text::truncate;
use std::collections::VecDeque;

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    symbols::Marker,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, Paragraph},
    Frame,
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::app::HISTORY;

// ── theme ──────────────────────────────────────────────────────────────
// Named ANSI colours only, so the palette follows the terminal theme.

pub const ACCENT: Color = Color::Cyan;
pub const MUTED: Color = Color::DarkGray;
pub const TEXT_DIM: Color = Color::Gray;
pub const OK: Color = Color::Green;
pub const WARN: Color = Color::Yellow;
pub const BAD: Color = Color::Red;
pub const SEL_BG: Color = Color::Blue;

pub fn muted(s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), Style::new().fg(MUTED))
}

pub fn sel_style() -> Style {
    Style::new().fg(Color::White).bg(SEL_BG).add_modifier(Modifier::BOLD)
}

pub fn header_style() -> Style {
    Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
}

pub fn panel(title: Line<'static>) -> Block<'static> {
    Block::new().borders(Borders::ALL).border_style(Style::new().fg(MUTED)).title(title)
}

// ── tables ─────────────────────────────────────────────────────────────

pub struct ColSpec {
    pub title: String,
    /// Fixed width; 0 = share the remaining space.
    pub width: u16,
    pub right: bool,
}

impl ColSpec {
    pub fn new(title: impl Into<String>, width: u16, right: bool) -> Self {
        Self { title: title.into(), width, right }
    }
}

/// Column widths for `total` cells with two spaces between columns.
pub fn widths(specs: &[ColSpec], total: usize) -> Vec<usize> {
    let fixed: usize = specs.iter().map(|s| s.width as usize).sum::<usize>() + 2 * specs.len().saturating_sub(1);
    let fills = specs.iter().filter(|s| s.width == 0).count().max(1);
    let rest = total.saturating_sub(fixed);
    let mut extra = rest % fills;
    specs
        .iter()
        .map(|s| {
            if s.width > 0 {
                s.width as usize
            } else {
                let w = rest / fills + usize::from(extra > 0);
                extra = extra.saturating_sub(1);
                w
            }
        })
        .collect()
}

pub fn header_line(specs: &[ColSpec], widths: &[usize], active: Option<(usize, bool)>, total: usize) -> Line<'static> {
    let mut spans = Vec::new();
    for (i, (s, w)) in specs.iter().zip(widths).enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        let title = match active {
            Some((a, desc)) if a == i => format!("{}{}", s.title, if desc { " ↓" } else { " ↑" }),
            _ => s.title.clone(),
        };
        let style = if active.is_some_and(|(a, _)| a == i) { Style::new().fg(ACCENT) } else { Style::new() };
        spans.push(Span::styled(fit(&title, *w, s.right), style));
    }
    Line::from(pad_line(spans, total)).style(header_style())
}

/// One row; each cell is a list of styled pieces fitted as a unit.
pub fn row_line(cells: Vec<Vec<Span<'static>>>, specs: &[ColSpec], widths: &[usize], total: usize) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (i, ((cell, s), w)) in cells.into_iter().zip(specs).zip(widths).enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        spans.extend(fit_spans(cell, *w, s.right));
    }
    pad_line(spans, total)
}

fn fit_spans(pieces: Vec<Span<'static>>, width: usize, right: bool) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    let mut used = 0;
    for p in pieces {
        if used >= width {
            break;
        }
        let w = p.content.width();
        if used + w <= width {
            used += w;
            out.push(p);
        } else {
            let t = truncate(&p.content, width - used);
            used += t.width();
            out.push(Span::styled(t, p.style));
            break;
        }
    }
    let pad = " ".repeat(width.saturating_sub(used));
    if right {
        out.insert(0, Span::raw(pad));
    } else {
        out.push(Span::raw(pad));
    }
    out
}

/// Apply a row-level style (selection etc.) over cell styles: the row's
/// colours win, cell modifiers survive.
pub fn restyle(spans: Vec<Span<'static>>, row: Option<Style>) -> Line<'static> {
    match row {
        None => Line::from(spans),
        Some(rs) => Line::from(
            spans
                .into_iter()
                .map(|s| {
                    let fg = rs.fg.or(s.style.fg);
                    Span::styled(s.content, Style { fg, bg: rs.bg.or(s.style.bg), add_modifier: s.style.add_modifier | rs.add_modifier, ..s.style })
                })
                .collect::<Vec<_>>(),
        ),
    }
}

/// Keep `selected` inside the window of `height` rows starting at `offset`.
pub fn scroll_window(offset: usize, selected: usize, height: usize, len: usize) -> usize {
    let mut off = offset.min(len.saturating_sub(height));
    if selected < off {
        off = selected;
    } else if height > 0 && selected >= off + height {
        off = selected + 1 - height;
    }
    off
}

/// Scrolling table with an optional highlighted row.
pub fn draw_table(
    frame: &mut Frame,
    area: Rect,
    specs: &[ColSpec],
    rows: Vec<Vec<Vec<Span<'static>>>>,
    scroll: &mut usize,
    selected: Option<usize>,
) -> Rect {
    let total = area.width as usize;
    let w = widths(specs, total);
    frame.render_widget(Paragraph::new(header_line(specs, &w, None, total)), Rect { height: 1, ..area });
    let body = Rect { y: area.y + 1, height: area.height.saturating_sub(1), ..area };
    let height = body.height as usize;
    *scroll = match selected {
        Some(sel) => scroll_window(*scroll, sel, height, rows.len()),
        None => (*scroll).min(rows.len().saturating_sub(height)),
    };
    let lines: Vec<Line> = rows
        .into_iter()
        .enumerate()
        .skip(*scroll)
        .take(height)
        .map(|(i, cells)| restyle(row_line(cells, specs, &w, total), (selected == Some(i)).then(sel_style)))
        .collect();
    frame.render_widget(Paragraph::new(lines), body);
    body
}

// ── charts ─────────────────────────────────────────────────────────────

pub struct Series<'a> {
    pub data: &'a VecDeque<f64>,
    pub color: Color,
}

/// Line chart of up to `HISTORY` samples, newest on the right; the y axis
/// scales to the data with `floor` as the minimum top.
pub fn history_chart(frame: &mut Frame, area: Rect, title: Line<'static>, series: &[Series], floor: f64, fmt: fn(f64) -> String) {
    let points: Vec<Vec<(f64, f64)>> = series
        .iter()
        .map(|s| {
            let start = HISTORY.saturating_sub(s.data.len());
            s.data.iter().enumerate().map(|(i, v)| ((start + i) as f64, *v)).collect()
        })
        .collect();
    let peak = series.iter().flat_map(|s| s.data.iter().copied()).fold(0.0f64, f64::max);
    let top = if peak <= floor { floor } else { peak * 1.15 };
    let datasets: Vec<Dataset> = series
        .iter()
        .zip(&points)
        .map(|(s, p)| Dataset::default().marker(Marker::Braille).graph_type(GraphType::Line).style(Style::new().fg(s.color)).data(p))
        .collect();
    let chart = Chart::new(datasets)
        .block(panel(title))
        .x_axis(Axis::default().bounds([0.0, HISTORY as f64]))
        .y_axis(
            Axis::default()
                .bounds([0.0, top])
                .style(Style::new().fg(MUTED))
                .labels([Span::raw(fmt(0.0)), Span::raw(fmt(top))]),
        )
        .legend_position(None);
    frame.render_widget(chart, area);
}

/// `▁▂▄▇` mini graph of the last `width` samples, scaled to `max`.
pub fn sparkline(data: &VecDeque<f64>, width: usize, max: f64) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let skip = data.len().saturating_sub(width);
    let mut s: String = " ".repeat(width.saturating_sub(data.len()));
    for v in data.iter().skip(skip) {
        let r = if max > 0.0 { (v / max).clamp(0.0, 1.0) } else { 0.0 };
        s.push(if *v <= 0.0 { ' ' } else { BARS[((r * 7.0).round() as usize).min(7)] });
    }
    s
}

pub fn chart_title(name: &str, parts: Vec<(&str, String, Color)>) -> Line<'static> {
    let mut spans = vec![Span::styled(format!(" {name} "), Style::new().add_modifier(Modifier::BOLD))];
    for (label, value, color) in parts {
        spans.push(Span::styled(format!(" {label} "), Style::new().fg(MUTED)));
        spans.push(Span::styled(value, Style::new().fg(color)));
    }
    spans.push(Span::raw(" "));
    Line::from(spans)
}

pub fn last(d: &VecDeque<f64>) -> f64 {
    d.back().copied().unwrap_or(0.0)
}

pub fn avg(d: &VecDeque<f64>) -> f64 {
    if d.is_empty() { 0.0 } else { d.iter().sum::<f64>() / d.len() as f64 }
}

pub fn peak(d: &VecDeque<f64>) -> f64 {
    d.iter().copied().fold(0.0, f64::max)
}

// ── text ───────────────────────────────────────────────────────────────

/// Fit `s` into exactly `width` cells, truncating by display width.
pub fn fit(s: &str, width: usize, right: bool) -> String {
    let t = truncate(s, width);
    let pad = width.saturating_sub(t.width());
    if right { format!("{}{t}", " ".repeat(pad)) } else { format!("{t}{}", " ".repeat(pad)) }
}


/// Keep the end of `s` (`…/lib/foo`) when it doesn't fit.
pub fn truncate_left(s: &str, max: usize) -> String {
    if s.width() <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let mut tail: Vec<char> = Vec::new();
    let mut w = 0;
    for c in s.chars().rev() {
        let cw = c.width().unwrap_or(0);
        if w + cw > max - 1 {
            break;
        }
        tail.push(c);
        w += cw;
    }
    std::iter::once('…').chain(tail.into_iter().rev()).collect()
}

/// Wrap to `width` columns, preferring breaks after spaces/separators.
pub fn wrap(s: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out = Vec::new();
    let mut line = String::new();
    let mut w = 0;
    for c in s.chars() {
        let c = if c.is_control() { ' ' } else { c };
        let cw = c.width().unwrap_or(0);
        if w + cw > width {
            let brk = line
                .char_indices()
                .rev()
                .take_while(|(i, _)| line[*i..].width() < width / 3)
                .find(|(_, ch)| matches!(ch, ' ' | '/' | '\\' | ',' | '-'))
                .map(|(i, ch)| i + ch.len_utf8());
            match brk {
                Some(i) if i < line.len() => {
                    let rest = line.split_off(i);
                    out.push(std::mem::replace(&mut line, rest));
                }
                _ => out.push(std::mem::take(&mut line)),
            }
            w = line.width();
        }
        line.push(c);
        w += cw;
    }
    if !line.is_empty() || out.is_empty() {
        out.push(line);
    }
    out
}

pub fn pad_line(mut spans: Vec<Span<'static>>, width: usize) -> Vec<Span<'static>> {
    let w: usize = spans.iter().map(|s| s.content.width()).sum();
    if w < width {
        spans.push(Span::raw(" ".repeat(width - w)));
    }
    spans
}

pub fn ratio(used: u64, total: u64) -> f64 {
    if total == 0 { 0.0 } else { used as f64 / total as f64 }
}

/// Centered rectangle of at most `w`×`h` inside `area`.
pub fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width.saturating_sub(2));
    let h = h.min(area.height.saturating_sub(2));
    Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_helpers() {
        assert_eq!(truncate("hello world", 6), "hello…");
        assert_eq!(truncate("微信进程", 5), "微信…");
        assert_eq!(truncate_left("/usr/lib/libfoo", 8), "…/libfoo");
        assert_eq!(fit("ab", 4, true), "  ab");
        assert_eq!(fit("微信", 5, false).width(), 5);
        let lines = wrap("/Applications/Some App.app/Contents/MacOS/Some App --flag", 20);
        assert!(lines.iter().all(|l| l.width() <= 20));
        assert_eq!(lines.concat(), "/Applications/Some App.app/Contents/MacOS/Some App --flag");
    }

    #[test]
    fn table_rows_are_exact_width() {
        let specs = vec![ColSpec::new("Name", 0, false), ColSpec::new("PID", 7, true), ColSpec::new("CPU", 6, true)];
        let w = widths(&specs, 40);
        assert_eq!(w.iter().sum::<usize>() + 4, 40);
        let cells = vec![vec![Span::raw("├─ "), Span::raw("a very long process name indeed")], vec![Span::raw("1")], vec![Span::raw("2.0%")]];
        assert_eq!(Line::from(row_line(cells, &specs, &w, 40)).width(), 40);
        assert_eq!(scroll_window(0, 15, 10, 100), 6);
        assert_eq!(scroll_window(95, 99, 10, 100), 90);
    }

    #[test]
    fn sparkline_width() {
        let d: VecDeque<f64> = [0.0, 50.0, 100.0].into();
        assert_eq!(sparkline(&d, 5, 100.0).chars().count(), 5);
        assert!(sparkline(&d, 5, 100.0).ends_with('█'));
    }
}
