//! `defense.yml`, beside the settings file. Everything has a default, so
//! detection works with no file; alarms and the metrics port stay off until
//! configured, because they send data somewhere.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::alarm::Destination;
use super::filter::Cidr;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Thresholds {
    pub ssh_failures: usize,
    pub ssh_window_seconds: u64,
    pub ssh_failures_before_login: usize,
    pub ssh_users_per_source: usize,
    pub ssh_sources_per_user: usize,
    pub sudo_failures: usize,
    pub http_per_minute: usize,
    pub http_errors_per_minute: usize,
    pub half_open: usize,
    pub connections_per_source: usize,
    pub syncookies_per_second: u64,
    pub listen_drops_per_second: u64,
    pub scan_ports: usize,
    pub syns_per_second: usize,
}

impl Default for Thresholds {
    fn default() -> Thresholds {
        Thresholds {
            ssh_failures: 10,
            ssh_window_seconds: 60,
            ssh_failures_before_login: 5,
            ssh_users_per_source: 5,
            ssh_sources_per_user: 20,
            sudo_failures: 3,
            http_per_minute: 600,
            http_errors_per_minute: 60,
            half_open: 256,
            connections_per_source: 200,
            syncookies_per_second: 100,
            listen_drops_per_second: 100,
            scan_ports: 15,
            syns_per_second: 2000,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Exporter {
    /// Address for the Prometheus endpoint; empty leaves it off.
    pub listen: String,
    /// Required on anything but loopback.
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DefenseConfig {
    /// Authentication logs; empty means the system's usual places.
    pub auth_logs: Vec<PathBuf>,
    /// Web server access logs; empty means the usual nginx and Apache ones.
    pub web_logs: Vec<PathBuf>,
    /// Addresses and networks that are never reported.
    pub allow: Vec<String>,
    /// Repeats of one finding within this time stay quiet.
    pub quiet_seconds: u64,
    pub thresholds: Thresholds,
    pub alarms: Vec<Destination>,
    pub exporter: Exporter,
}

impl Default for DefenseConfig {
    fn default() -> DefenseConfig {
        DefenseConfig { auth_logs: Vec::new(), web_logs: Vec::new(), allow: Vec::new(), quiet_seconds: 600, thresholds: Thresholds::default(), alarms: Vec::new(), exporter: Exporter::default() }
    }
}

impl DefenseConfig {
    pub fn parse(text: &str) -> Result<DefenseConfig, String> {
        let c: DefenseConfig = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
        c.allowed()?;
        c.alarms.iter().try_for_each(Destination::validate)?;
        Ok(c)
    }

    pub fn allowed(&self) -> Result<Vec<Cidr>, String> {
        self.allow.iter().map(|a| Cidr::parse(a)).collect()
    }

    pub fn path() -> Option<PathBuf> {
        crate::common::paths::config_path().map(|p| p.with_file_name("defense.yml"))
    }

    /// Webhook addresses are secrets, and whoever edits this file chooses
    /// where alarms go and what commands run.
    pub fn load_from(path: &Path) -> Result<DefenseConfig, String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
            if m.mode() & 0o022 != 0 {
                return Err(format!("{}: other users can write to it", path.display()));
            }
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        DefenseConfig::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn load() -> Result<DefenseConfig, String> {
        match DefenseConfig::path() {
            Some(p) if p.exists() => DefenseConfig::load_from(&p),
            _ => Ok(DefenseConfig::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_settings_and_refuses_mistakes() {
        let c = DefenseConfig::parse(
            r#"
allow: [10.0.0.0/8]
thresholds: { ssh_failures: 3 }
exporter: { listen: "127.0.0.1:9187" }
alarms:
  - { type: syslog, min_severity: high }
"#,
        )
        .unwrap();
        assert_eq!(c.thresholds.ssh_failures, 3);
        assert_eq!(c.thresholds.scan_ports, 15, "the rest keep their defaults");
        assert_eq!(c.alarms.len(), 1);
        assert!(DefenseConfig::parse("allow: [nonsense]").is_err());
        assert!(DefenseConfig::parse("thresholds: { ssh_failure: 3 }").is_err());
        assert!(DefenseConfig::parse("alarms:\n  - { type: webhook, url: 'ftp://x' }\n").is_err());
        assert_eq!(DefenseConfig::parse("{}").unwrap().quiet_seconds, 600);
    }
}
