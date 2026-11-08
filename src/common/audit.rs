//! procwatch's own record of what changed in it: settings, maintenance,
//! integrity. Separate from everything it monitors, and from the agent's log.

use std::io::Write;

const MAX_BYTES: u64 = 16 << 20;

/// One line, best effort: a full disk must not stop the program.
pub fn record(what: &str, detail: &str) {
    let Some(dir) = crate::common::paths::data_dir() else { return };
    if crate::common::paths::ensure_private_dir(&dir).is_err() {
        return;
    }
    let line = serde_json::json!({ "v": 1, "time": chrono::Local::now().to_rfc3339(), "what": what, "detail": crate::common::redact::redact(detail) });
    let path = dir.join("audit.jsonl");
    // One old generation is kept: this log must not fill a disk either.
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_BYTES) {
        let _ = std::fs::rename(&path, dir.join("audit.1.jsonl"));
    }
    if let Ok(mut f) = crate::common::paths::private_file().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{line}");
    }
}

/// The last lines, oldest first, for diagnosis.
pub fn recent(lines: usize) -> Vec<String> {
    let Some(dir) = crate::common::paths::data_dir() else { return Vec::new() };
    let text = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].iter().map(|l| (*l).to_string()).collect()
}
