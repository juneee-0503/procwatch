//! Persistent settings in a tiny `key = value` file, so we don't pull in a
//! serialization stack for half a dozen fields. Unknown keys and malformed
//! values are ignored; a missing or unreadable file means defaults.

use std::fs;
use std::path::PathBuf;

use crate::app::ViewMode;
use crate::columns::Col;
use crate::sampler::{MAX_INTERVAL_MS, MIN_INTERVAL_MS};

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub columns: Vec<Col>,
    pub sort: Col,
    pub sort_desc: bool,
    pub view: ViewMode,
    pub interval_ms: u64,
    pub highlight_new: bool,
    pub details_pane: bool,
    pub confirm_end: bool,
    pub notify: bool,
    pub rules: Vec<String>,
    /// Folders watched for file changes (empty = defaults).
    pub watch: Vec<String>,
    /// Keep a persistent event history on disk (see `store`).
    pub history: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            columns: Col::DEFAULT.to_vec(),
            sort: Col::Cpu,
            sort_desc: true,
            view: ViewMode::List,
            interval_ms: 1500,
            highlight_new: true,
            details_pane: true,
            confirm_end: true,
            notify: true,
            rules: Vec::new(),
            watch: Vec::new(),
            history: true,
        }
    }
}

pub fn path() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    base.map(|b| b.join("procwatch").join("config"))
}

impl Config {
    pub fn load() -> Self {
        path().and_then(|p| fs::read_to_string(p).ok()).map(|t| Self::parse(&t)).unwrap_or_default()
    }

    pub fn parse(text: &str) -> Self {
        let mut cfg = Config::default();
        let flag = |v: &str| matches!(v, "1" | "true" | "yes" | "on");
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else { continue };
            let value = value.trim();
            match key.trim() {
                "columns" => {
                    let cols: Vec<Col> = value.split(',').filter_map(Col::from_key).collect();
                    if !cols.is_empty() {
                        cfg.columns = cols;
                    }
                }
                "sort" => cfg.sort = Col::from_key(value).unwrap_or(cfg.sort),
                "sort_desc" => cfg.sort_desc = flag(value),
                "view" => cfg.view = ViewMode::from_key(value).unwrap_or(cfg.view),
                "interval_ms" => {
                    if let Ok(v) = value.parse::<u64>() {
                        cfg.interval_ms = v.clamp(MIN_INTERVAL_MS, MAX_INTERVAL_MS);
                    }
                }
                "highlight_new" => cfg.highlight_new = flag(value),
                "details_pane" => cfg.details_pane = flag(value),
                "confirm_end" => cfg.confirm_end = flag(value),
                "notify" => cfg.notify = flag(value),
                "rule" if !value.is_empty() => cfg.rules.push(value.to_string()),
                "watch" if !value.is_empty() => cfg.watch.push(value.to_string()),
                "history" => cfg.history = flag(value),
                _ => {}
            }
        }
        // The name column anchors the tree; never allow hiding it.
        if !cfg.columns.contains(&Col::Name) {
            cfg.columns.insert(0, Col::Name);
        }
        cfg
    }

    pub fn serialize(&self) -> String {
        let cols: Vec<&str> = self.columns.iter().map(|c| c.key()).collect();
        format!(
            "# procwatch settings — edited from the Options screen (o)\n\
             columns = {}\nsort = {}\nsort_desc = {}\nview = {}\ninterval_ms = {}\nhighlight_new = {}\n\
             details_pane = {}\nconfirm_end = {}\n",
            cols.join(","),
            self.sort.key(),
            self.sort_desc,
            self.view.key(),
            self.interval_ms,
            self.highlight_new,
            self.details_pane,
            self.confirm_end,
        ) + &format!("notify = {}\n", self.notify)
            + &self.rules.iter().map(|r| format!("rule = {r}\n")).collect::<String>()
            + &self.watch.iter().map(|w| format!("watch = {w}\n")).collect::<String>()
            + &format!("history = {}\n", if self.history { "on" } else { "off" })
    }

    pub fn save(&self) -> anyhow::Result<PathBuf> {
        let path = path().ok_or_else(|| anyhow::anyhow!("no config directory"))?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        write_atomic(&path, &self.serialize())?;
        Ok(path)
    }
}

/// Write-then-rename so a crash never leaves a truncated file.
pub fn write_atomic(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_tolerates_garbage() {
        let cfg = Config { columns: vec![Col::Pid, Col::Cpu], view: ViewMode::Tree, interval_ms: 99_999, ..Config::default() };
        let parsed = Config::parse(&(cfg.serialize() + "\nbogus line\ncolumns_x = 1\n"));
        assert_eq!(parsed.columns, vec![Col::Name, Col::Pid, Col::Cpu]);
        assert_eq!(parsed.view, ViewMode::Tree);
        assert_eq!(parsed.interval_ms, MAX_INTERVAL_MS);
        assert_eq!(Config::parse("sort = nope\n").sort, Col::Cpu);
    }
}
