//! `defense.yml`, beside the settings file. Everything has a default, so
//! every module works with no file. Nothing leaves the machine until a
//! destination is set: alarms stay local, and the metrics port is loopback.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::alarm::Destination;
use super::filter::Cidr;

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Exporter {
    /// Address for the Prometheus endpoint; empty leaves it off.
    pub listen: String,
    /// Required on anything but loopback.
    pub token: String,
}

impl Default for Exporter {
    fn default() -> Exporter {
        Exporter { listen: "127.0.0.1:9187".to_string(), token: String::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AlarmSettings {
    pub sound: bool,
    pub volume: u8,
    pub pause_seconds: u64,
}

impl Default for AlarmSettings {
    fn default() -> AlarmSettings {
        AlarmSettings { sound: true, volume: 60, pause_seconds: 120 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Privacy {
    /// Hide secrets before anything is stored or sent.
    pub redact: bool,
    /// Keep command lines in alarms and logs at all.
    pub command_lines: bool,
}

impl Default for Privacy {
    fn default() -> Privacy {
        Privacy { redact: true, command_lines: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Retention {
    pub days: u64,
    /// The most procwatch may keep on disk.
    pub max_mb: u64,
}

impl Default for Retention {
    fn default() -> Retention {
        Retention { days: 30, max_mb: 1024 }
    }
}

/// The current format of `defense.yml`.
pub const VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DefenseConfig {
    pub version: u32,
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
    pub alarm: AlarmSettings,
    pub privacy: Privacy,
    pub retention: Retention,
    pub heartbeat: crate::defense::heartbeat::Settings,
    pub sync: crate::defense::heartbeat::SyncSettings,
}

impl Default for DefenseConfig {
    fn default() -> DefenseConfig {
        DefenseConfig { version: VERSION, auth_logs: Vec::new(), web_logs: Vec::new(), allow: Vec::new(), quiet_seconds: 600, thresholds: Thresholds::default(), alarms: Vec::new(), exporter: Exporter::default(), alarm: AlarmSettings::default(), privacy: Privacy::default(), retention: Retention::default(), heartbeat: Default::default(), sync: Default::default() }
    }
}

impl DefenseConfig {
    pub fn parse(text: &str) -> Result<DefenseConfig, String> {
        let c: DefenseConfig = crate::common::versioned::parse(text, VERSION)?;
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
        let text = crate::common::integrity::read_config(path)?;
        DefenseConfig::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Write the file, and approve it: this is the deliberate way to change it.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = serde_yaml::to_string(self).map_err(|e| e.to_string())?;
        DefenseConfig::parse(&text)?;
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        crate::common::paths::write_atomic(path, &text).map_err(|e| e.to_string())?;
        crate::common::integrity::seal_config(path)
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

    #[test]
    fn a_saved_file_reads_back_and_newer_files_still_load() {
        let mut c = DefenseConfig::default();
        c.thresholds.scan_ports = 33;
        c.alarm.volume = 5;
        let text = serde_yaml::to_string(&c).unwrap();
        let back = DefenseConfig::parse(&text).unwrap();
        assert_eq!((back.thresholds.scan_ports, back.alarm.volume), (33, 5));
        assert!(DefenseConfig::parse("speling: 1").is_err(), "a mistake in today's format");
        assert_eq!(DefenseConfig::parse("version: 99\nfuture_setting: 1\nquiet_seconds: 5").unwrap().quiet_seconds, 5, "tomorrow's format");
    }
}
