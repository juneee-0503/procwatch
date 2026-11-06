//! What a capture keeps, from `capture.yml` beside the settings file.
//!
//! ```yaml
//! registry_reads: false   # far more numerous than writes
//! stacks: false           # call stacks on Windows events
//! rules:
//!   - { action: exclude, process: ["SearchIndexer.exe"] }
//!   - { action: exclude, class: [file], op: [read], path: ["*\\Windows\\*"] }
//!   - { action: include, path: ["*\\Temp\\*"] }
//! ```
//!
//! The first rule that matches decides; nothing matching means keep. Every
//! condition given must hold, and each lists alternatives.

use std::path::Path;

use serde::Deserialize;

use super::Class;
use crate::common::text::glob;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterAction {
    Include,
    Exclude,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterRule {
    pub action: FilterAction,
    #[serde(default)]
    pub class: Vec<String>,
    #[serde(default)]
    pub op: Vec<String>,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub process: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfig {
    #[serde(default)]
    pub registry_reads: bool,
    #[serde(default)]
    pub stacks: bool,
    #[serde(default)]
    pub rules: Vec<FilterRule>,
}

/// A filter's verdict on one operation.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Verdict {
    Keep,
    Drop,
}

impl CaptureConfig {
    pub fn parse(text: &str) -> Result<CaptureConfig, String> {
        serde_yaml::from_str(text).map_err(|e| e.to_string())
    }

    /// The file beside the settings; a missing one means keep everything.
    pub fn load() -> Result<CaptureConfig, String> {
        match crate::common::paths::config_path().map(|p| p.with_file_name("capture.yml")) {
            Some(p) if p.exists() => CaptureConfig::load_from(&p),
            _ => Ok(CaptureConfig::default()),
        }
    }

    pub fn load_from(path: &Path) -> Result<CaptureConfig, String> {
        let text = crate::common::integrity::read_config(path)?;
        CaptureConfig::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// `process` is None where a source doesn't know the name yet: rules
    /// about processes are then skipped, and applied once it is known.
    pub fn verdict(&self, class: Class, op: &str, path: &str, process: Option<&str>) -> Verdict {
        for r in &self.rules {
            let holds = (r.class.is_empty() || r.class.iter().any(|c| c.eq_ignore_ascii_case(class.label())))
                && (r.op.is_empty() || r.op.iter().any(|o| o.eq_ignore_ascii_case(op)))
                && (r.path.is_empty() || r.path.iter().any(|p| glob(p, path)))
                && (r.process.is_empty() || process.is_some_and(|n| r.process.iter().any(|p| glob(p, n))));
            if holds {
                return if r.action == FilterAction::Exclude { Verdict::Drop } else { Verdict::Keep };
            }
        }
        Verdict::Keep
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_matching_rule_decides() {
        let c = CaptureConfig::parse(
            r#"
registry_reads: true
rules:
  - { action: include, path: ["*/keep/*"] }
  - { action: exclude, class: [file], op: [read] }
  - { action: exclude, process: ["noisy*"] }
"#,
        )
        .unwrap();
        assert!(c.registry_reads);
        assert_eq!(c.verdict(Class::File, "read", "/keep/a", None), Verdict::Keep);
        assert_eq!(c.verdict(Class::File, "read", "/other", None), Verdict::Drop);
        assert_eq!(c.verdict(Class::File, "write", "/other", None), Verdict::Keep);
        assert_eq!(c.verdict(Class::Registry, "read", "/other", None), Verdict::Keep, "class differs");
        assert_eq!(c.verdict(Class::File, "write", "/x", None), Verdict::Keep, "process unknown yet");
        assert_eq!(c.verdict(Class::File, "write", "/x", Some("noisyd")), Verdict::Drop);
    }

    #[test]
    fn mistakes_are_errors_not_silence() {
        assert!(CaptureConfig::parse("rules:\n  - { action: drop }\n").is_err());
        assert!(CaptureConfig::parse("rules:\n  - { action: exclude, proces: [x] }\n").is_err());
        assert!(CaptureConfig::parse("stacks: true\n").unwrap().stacks);
    }
}
