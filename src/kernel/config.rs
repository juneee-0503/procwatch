//! Kernel settings: which modules run, and metric alert rules. A small
//! `key = value` file, so a mistake in it can't stop the program: anything
//! unreadable is reported and skipped.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::alerts::Rule;

#[derive(Debug, Clone, Default)]
pub struct KernelConfig {
    pub disabled: BTreeSet<String>,
    pub alerts: Vec<Rule>,
    /// Lines that couldn't be used, for the user to see.
    pub problems: Vec<String>,
}

impl KernelConfig {
    pub fn parse(text: &str) -> KernelConfig {
        let mut c = KernelConfig::default();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                c.problems.push(format!("line {}: expected key = value", n + 1));
                continue;
            };
            match key.trim() {
                "disabled" => c.disabled.extend(value.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from)),
                "alert" => match Rule::parse(value) {
                    Ok(r) => c.alerts.push(r),
                    Err(e) => c.problems.push(format!("line {}: {e}", n + 1)),
                },
                other => c.problems.push(format!("line {}: unknown setting {other}", n + 1)),
            }
        }
        c
    }

    pub fn load(path: Option<&Path>) -> KernelConfig {
        path.and_then(|p| std::fs::read_to_string(p).ok()).map(|t| KernelConfig::parse(&t)).unwrap_or_default()
    }

    pub fn serialize(&self) -> String {
        let mut out = String::from("# procwatch modules. See docs/modules.md.\n");
        out.push_str(&format!("disabled = {}\n", self.disabled.iter().cloned().collect::<Vec<_>>().join(", ")));
        for r in &self.alerts {
            out.push_str(&format!("alert = {}\n", r.text));
        }
        out
    }
}

/// Where kernel settings live, beside the settings file `config`.
pub fn path_beside(config: &Path) -> PathBuf {
    config.with_file_name("modules.conf")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mistakes_are_reported_not_fatal() {
        let c = KernelConfig::parse("# comment\ndisabled = logs, trace\nalert = cpu.run_queue > 8 for 30s\nalert = nonsense\nwhat\nmystery = 1\n");
        assert!(c.disabled.contains("logs") && c.disabled.contains("trace"));
        assert_eq!(c.alerts.len(), 1);
        assert_eq!(c.problems.len(), 3, "{:?}", c.problems);
        let again = KernelConfig::parse(&c.serialize());
        assert_eq!(again.disabled, c.disabled);
        assert_eq!(again.alerts.len(), 1);
        assert!(again.problems.is_empty());
    }
}
