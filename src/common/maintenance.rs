//! Controlled maintenance: alarms stay quiet for a set time, so upgrades and
//! repairs aren't mistaken for attacks. It always ends by itself.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const MAX_MINUTES: u64 = 24 * 60;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Window {
    pub v: u32,
    pub until: u64,
    pub reason: String,
}

fn path() -> Option<PathBuf> {
    crate::common::paths::data_dir().map(|d| d.join("maintenance.json"))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Time left in `w`, if it is still open.
pub fn left(w: &Window, at: u64) -> Option<Duration> {
    // A window further off than the limit was not set by this program.
    (w.until > at && w.until - at <= MAX_MINUTES * 60).then(|| Duration::from_secs(w.until - at))
}

pub fn remaining() -> Option<Duration> {
    let text = std::fs::read_to_string(path()?).ok()?;
    left(&serde_json::from_str(&text).ok()?, now())
}

pub fn begin(minutes: u64, reason: &str) -> Result<(), String> {
    if minutes == 0 || minutes > MAX_MINUTES {
        return Err(format!("maintenance must last 1 to {MAX_MINUTES} minutes"));
    }
    let p = path().ok_or("no data folder")?;
    if let Some(d) = p.parent() {
        crate::common::paths::ensure_private_dir(d).map_err(|e| e.to_string())?;
    }
    let w = Window { v: 1, until: now() + minutes * 60, reason: reason.to_string() };
    let text = serde_json::to_string(&w).map_err(|e| e.to_string())?;
    crate::common::paths::write_atomic(&p, &text).map_err(|e| e.to_string())?;
    crate::common::audit::record("maintenance started", &format!("{minutes} minutes: {reason}"));
    Ok(())
}

pub fn end() {
    if let Some(p) = path() {
        if std::fs::remove_file(p).is_ok() {
            crate::common::audit::record("maintenance ended", "by hand");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_end_and_cannot_be_endless() {
        let w = |until| Window { v: 1, until, reason: String::new() };
        assert_eq!(left(&w(160), 100), Some(Duration::from_secs(60)));
        assert_eq!(left(&w(100), 100), None);
        assert_eq!(left(&w(50), 100), None);
        assert_eq!(left(&w(u64::MAX), 100), None, "a forged far-off end is ignored");
    }
}
