//! The settings screen. Every value here lives in a file that can be read
//! and backed up, but none needs editing by hand. Saving goes through the
//! same validation as loading, records what changed, and keeps the previous
//! version.

use super::*;
use crate::defense::config::DefenseConfig;
use crate::kernel::alarm::{Input, Rule};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Toggle,
    Number,
    Text,
    /// An alarm rule, by its place in the list.
    Rule(usize),
    AddRule,
    Module(&'static str),
}

#[derive(Debug, Clone)]
pub struct Item {
    pub section: &'static str,
    pub key: &'static str,
    pub label: String,
    pub value: String,
    pub kind: Kind,
}

const THRESHOLDS: &[(&str, &str)] = &[
    ("ssh_failures", "SSH failures to call it brute force"),
    ("ssh_window_seconds", "… within seconds"),
    ("ssh_failures_before_login", "Failures before a login is suspicious"),
    ("ssh_users_per_source", "User names from one source"),
    ("ssh_sources_per_user", "Sources against one user"),
    ("sudo_failures", "Failed privilege attempts"),
    ("http_per_minute", "HTTP requests a minute from one source"),
    ("http_errors_per_minute", "HTTP errors a minute from one source"),
    ("half_open", "Half-open connections"),
    ("connections_per_source", "Connections from one source"),
    ("syncookies_per_second", "SYN cookies a second"),
    ("listen_drops_per_second", "Accept queue drops a second"),
    ("scan_ports", "Ports to call it a scan"),
    ("syns_per_second", "Connection attempts a second"),
];

/// Values as text, by key: everything editable in `defense.yml`.
fn threshold(c: &DefenseConfig, key: &str) -> String {
    serde_yaml::to_value(&c.thresholds).ok().and_then(|v| v.get(key).and_then(serde_yaml::Value::as_u64)).map_or_else(String::new, |n| n.to_string())
}

fn set_threshold(c: &mut DefenseConfig, key: &str, n: u64) -> Result<(), String> {
    let mut v = serde_yaml::to_value(&c.thresholds).map_err(|e| e.to_string())?;
    if let Some(m) = v.as_mapping_mut() {
        m.insert(key.into(), n.into());
    }
    c.thresholds = serde_yaml::from_value(v).map_err(|e| e.to_string())?;
    Ok(())
}

impl App {
    pub fn settings_items(&self) -> Vec<Item> {
        let c = &self.settings;
        let on = |b: bool| if b { "on" } else { "off" }.to_string();
        let item = |section, key, label: &str, value: String, kind| Item { section, key, label: label.to_string(), value, kind };
        let mut v = vec![
            item("System", "interval_ms", "Refresh interval, ms", self.ctl.interval_ms.load(Ordering::Relaxed).to_string(), Kind::Number),
            item("System", "notify", "Desktop notifications", on(self.notify), Kind::Toggle),
            item("System", "confirm_end", "Ask before ending processes", on(self.confirm_end), Kind::Toggle),
            item("Alarm", "sound", "Alarm sound", on(c.alarm.sound), Kind::Toggle),
            item("Alarm", "volume", "Volume, percent", c.alarm.volume.to_string(), Kind::Number),
            item("Alarm", "pause", "Sound pause, seconds", c.alarm.pause_seconds.to_string(), Kind::Number),
            item("Alarm", "quiet", "Repeat quiet time, seconds", c.quiet_seconds.to_string(), Kind::Number),
            item("Alarm", "maintenance", "Maintenance, minutes left (0 ends it)", crate::common::maintenance::remaining().map_or(0, |d| d.as_secs().div_ceil(60)).to_string(), Kind::Number),
        ];
        let shipped = self.kernel_config.rules().len() - self.kernel_config.alerts.len();
        v.push(item("Alarm rules", "default_rules", &format!("{shipped} built-in rules"), on(!self.kernel_config.no_default_rules), Kind::Toggle));
        for (i, r) in self.kernel_config.alerts.iter().enumerate() {
            v.push(item("Alarm rules", "rule", &format!("Rule {}", i + 1), r.text.clone(), Kind::Rule(i)));
        }
        v.push(item("Alarm rules", "add_rule", "Add a rule", "e.g. cpu.usage > 90 clear 80 for 60s priority high".to_string(), Kind::AddRule));
        for (key, label) in THRESHOLDS {
            v.push(item("Attack detection", key, label, threshold(c, key), Kind::Number));
        }
        v.push(item("Attack detection", "allow", "Never report or ban (comma separated)", c.allow.join(", "), Kind::Text));
        if c.alarms.is_empty() {
            v.push(item("Notifications", "none", "Destinations", "none: alarms stay on this screen".to_string(), Kind::Text));
        }
        for a in &c.alarms {
            v.push(item("Notifications", "none", "Destination", a.describe(), Kind::Text));
        }
        v.push(item("Privacy", "redact", "Hide secrets in logs and alarms", on(c.privacy.redact), Kind::Toggle));
        v.push(item("Privacy", "command_lines", "Keep whole command lines", on(c.privacy.command_lines), Kind::Toggle));
        v.push(item("Storage", "keep_days", "Keep metrics and logs, days", c.retention.days.to_string(), Kind::Number));
        v.push(item("Storage", "max_mb", "Most disk to use, MB", c.retention.max_mb.to_string(), Kind::Number));
        if let Some(k) = &self.kernel {
            for m in k.status() {
                let enabled = !self.kernel_config.disabled.contains(m.name);
                v.push(item("Modules at start", "module", m.name, on(enabled), Kind::Module(m.name)));
            }
        }
        v
    }

    pub fn settings_toggle(&mut self, item: &Item) {
        match (item.key, item.kind) {
            ("notify", _) => self.notify = !self.notify,
            ("confirm_end", _) => self.confirm_end = !self.confirm_end,
            ("sound", _) => {
                self.settings.alarm.sound = !self.settings.alarm.sound;
                self.board.sound = self.settings.alarm.sound;
            }
            ("redact" | "command_lines", _) => {
                let p = &mut self.settings.privacy;
                if item.key == "redact" {
                    p.redact = !p.redact;
                } else {
                    p.command_lines = !p.command_lines;
                }
                crate::common::redact::configure(p.redact, p.command_lines);
            }
            ("default_rules", _) => {
                self.kernel_config.no_default_rules = !self.kernel_config.no_default_rules;
                self.apply_rules();
            }
            (_, Kind::Module(name)) => {
                if !self.kernel_config.disabled.remove(name) {
                    self.kernel_config.disabled.insert(name.to_string());
                }
                self.save_kernel_config();
            }
            _ => return,
        }
        self.save_settings();
    }

    /// A new value for `item`, typed by the operator.
    pub fn settings_set(&mut self, item: &Item, text: &str) -> Result<(), String> {
        let text = text.trim();
        let number = || text.parse::<u64>().map_err(|_| format!("'{text}' isn't a whole number"));
        match item.kind {
            Kind::Rule(i) => {
                if text.is_empty() {
                    self.kernel_config.alerts.remove(i);
                } else {
                    let rule = Rule::parse(text)?;
                    if let Some(r) = self.kernel_config.alerts.get_mut(i) {
                        *r = rule;
                    }
                }
                self.apply_rules();
                return Ok(());
            }
            Kind::AddRule => {
                self.kernel_config.alerts.push(Rule::parse(text)?);
                self.apply_rules();
                return Ok(());
            }
            _ => {}
        }
        match item.key {
            "interval_ms" => {
                let n = number()?;
                if !(250..=60_000).contains(&n) {
                    return Err("between 250 and 60000".into());
                }
                self.ctl.interval_ms.store(n, Ordering::Relaxed);
                return Ok(());
            }
            "volume" => {
                let n = number()?.min(100) as u8;
                self.settings.alarm.volume = n;
                self.board.volume = n;
            }
            "pause" => {
                self.settings.alarm.pause_seconds = number()?;
                self.board.pause_seconds = self.settings.alarm.pause_seconds;
            }
            "quiet" => self.settings.quiet_seconds = number()?,
            "maintenance" => {
                let n = number()?;
                if n == 0 {
                    crate::common::maintenance::end();
                } else {
                    crate::common::maintenance::begin(n, "from the settings screen")?;
                }
                return Ok(());
            }
            "allow" => {
                let list: Vec<String> = text.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect();
                list.iter().try_for_each(|a| crate::defense::filter::Cidr::parse(a).map(|_| ()))?;
                self.settings.allow = list;
            }
            "keep_days" => self.settings.retention.days = number()?.max(1),
            "max_mb" => self.settings.retention.max_mb = number()?.max(16),
            key if THRESHOLDS.iter().any(|(k, _)| *k == key) => set_threshold(&mut self.settings, key, number()?)?,
            _ => return Err("this one can't be changed here".into()),
        }
        self.save_settings();
        Ok(())
    }

    fn apply_rules(&mut self) {
        self.save_kernel_config();
        if let Some(k) = &self.kernel {
            k.alarms().send(Input::SetRules(self.kernel_config.rules()));
        }
    }

    fn save_kernel_config(&mut self) {
        let result = crate::engine::save_config(&self.kernel_config).map_err(|e| e.to_string());
        let sealed = result.and_then(|()| crate::engine::config_path().map_or(Ok(()), |p| crate::common::integrity::seal_config(&p)));
        if let Err(e) = sealed {
            self.set_status(StatusLevel::Error, format!("Couldn't save: {e}"));
        }
    }

    fn save_settings(&mut self) {
        let Some(path) = DefenseConfig::path() else { return };
        match self.settings.save(&path) {
            Ok(()) => self.set_status(StatusLevel::Success, "Saved. Detection settings apply at the next start.".into()),
            Err(e) => self.set_status(StatusLevel::Error, format!("Couldn't save: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_read_and_write_by_name() {
        let mut c = DefenseConfig::default();
        assert_eq!(threshold(&c, "scan_ports"), "15");
        set_threshold(&mut c, "scan_ports", 40).unwrap();
        assert_eq!(c.thresholds.scan_ports, 40);
        assert!(THRESHOLDS.iter().all(|(k, _)| !threshold(&c, k).is_empty()), "every listed key exists");
    }
}
