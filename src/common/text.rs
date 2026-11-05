//! Text helpers for display.

/// `println!` for lines holding text from the system under investigation.
#[macro_export]
macro_rules! safe_println {
    ($($arg:tt)*) => { println!("{}", $crate::common::text::printable(&format!($($arg)*))) };
}

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub fn truncate(s: &str, max: usize) -> String {
    if s.width() <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut w = 0;
    for c in s.chars() {
        let cw = c.width().unwrap_or(0);
        if w + cw > max - 1 {
            break;
        }
        out.push(c);
        w += cw;
    }
    out.push('…');
    out
}

/// Text from the system under investigation, safe for a terminal. A file
/// name or command line can hold escape sequences that rewrite the screen.
pub fn printable(s: &str) -> String {
    s.chars().map(|c| if c.is_control() && c != '\n' && c != '\t' { '\u{fffd}' } else { c }).collect()
}

/// A CSV field. Command lines are attacker-chosen, and a spreadsheet runs a
/// cell starting with one of these characters as a formula.
pub fn csv_field(s: &str) -> String {
    let guarded = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) && s.parse::<f64>().is_err() { format!("'{s}") } else { s.to_string() };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_formulas_are_neutralised() {
        assert_eq!(printable("a\u{1b}[2Jb\nc"), "a\u{fffd}[2Jb\nc");
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0");
        assert_eq!(csv_field("@SUM(1)"), "'@SUM(1)");
        assert_eq!(csv_field("-1.5"), "-1.5", "a number stays a number");
        assert_eq!(csv_field("-e bad,x"), "\"'-e bad,x\"");
    }
}
