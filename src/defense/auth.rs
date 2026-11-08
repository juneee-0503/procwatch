//! Login attacks, from the authentication log.
//!
//! Usernames in these lines are whatever an attacker typed, including text
//! made to look like the rest of the line, so addresses are always taken from
//! the end.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use chrono::{DateTime, Local};

use super::config::Thresholds;
use super::filter::{source_key, Counter, Distinct};
use super::{Stage, Threat};
use crate::common::model::Severity;

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    Failed { user: String, ip: IpAddr, invalid: bool },
    Accepted { user: String, ip: IpAddr, method: String },
    SudoFailed { user: String },
    SudoCommand { user: String, command: String },
    SuFailed { user: String },
    NewUser { name: String, uid: Option<u32> },
    AddedToGroup { user: String, group: String },
}

/// (program, message) of a syslog line, in either journal or file format.
fn split(line: &str) -> Option<(&str, &str)> {
    // The program comes before anything a remote user can put in the line.
    let mut rest = line;
    for _ in 0..6 {
        let (word, tail) = rest.trim_start().split_once(' ')?;
        if let Some(name) = word.strip_suffix(':') {
            let program = name.split('[').next().unwrap_or(name);
            if matches!(program, "sshd" | "sudo" | "su" | "useradd" | "usermod" | "login") {
                return Some((program, tail));
            }
        }
        rest = tail;
    }
    None
}

fn after_from(text: &str) -> Option<(&str, IpAddr)> {
    let (who, tail) = text.rsplit_once(" from ")?;
    Some((who, tail.split_whitespace().next()?.parse().ok()?))
}

fn ssh(m: &str) -> Option<Event> {
    if let Some(rest) = m.strip_prefix("Accepted ") {
        let (method, rest) = rest.split_once(" for ")?;
        let (user, ip) = after_from(rest)?;
        return Some(Event::Accepted { user: user.to_string(), ip, method: method.to_string() });
    }
    if m.starts_with("Failed ") {
        let (_, rest) = m.split_once(" for ")?;
        let (user, ip) = after_from(rest)?;
        let (user, invalid) = match user.strip_prefix("invalid user ") {
            Some(u) => (u, true),
            None => (user, false),
        };
        return Some(Event::Failed { user: user.to_string(), ip, invalid });
    }
    if let Some(rest) = m.strip_prefix("Invalid user ") {
        let padded = format!(" {rest}");
        let (user, ip) = after_from(&padded)?;
        return Some(Event::Failed { user: user.trim().to_string(), ip, invalid: true });
    }
    // Key-only servers: the client gives up before any "Failed" line.
    for prefix in ["Connection closed by authenticating user ", "Disconnected from authenticating user "] {
        if let Some(rest) = m.strip_prefix(prefix) {
            let mut words = rest.rsplit(' ');
            let _preauth = words.next()?;
            let _port_number = words.next()?;
            let _port = words.next()?;
            let ip = words.next()?.parse().ok()?;
            let user = rest.rsplit_once(&format!(" {ip} port"))?.0;
            return Some(Event::Failed { user: user.to_string(), ip, invalid: false });
        }
    }
    None
}

fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let (_, tail) = text.split_once(key)?;
    Some(tail.split([',', ' ', ';']).next().unwrap_or(tail).trim_matches('\''))
}

pub fn parse(line: &str) -> Option<Event> {
    let (program, m) = split(line)?;
    match program {
        "sshd" => ssh(m),
        "sudo" => {
            let (user, tail) = m.split_once(" : ")?;
            let user = user.trim().to_string();
            if tail.contains("incorrect password attempt") || tail.contains("NOT in sudoers") || tail.contains("user NOT authorized") {
                return Some(Event::SudoFailed { user });
            }
            let (_, command) = tail.rsplit_once("COMMAND=")?;
            Some(Event::SudoCommand { user, command: command.to_string() })
        }
        "su" => {
            let rest = m.strip_prefix("FAILED SU (to ").or_else(|| m.strip_prefix("FAILED su for "))?;
            Some(Event::SuFailed { user: rest.split([')', ' ']).next()?.to_string() })
        }
        "useradd" => {
            let rest = m.strip_prefix("new user: ")?;
            Some(Event::NewUser { name: field(rest, "name=")?.to_string(), uid: field(rest, "UID=")?.parse().ok() })
        }
        "usermod" => {
            let rest = m.strip_prefix("add '")?;
            let (user, tail) = rest.split_once("' to group '")?;
            Some(Event::AddedToGroup { user: user.to_string(), group: tail.split('\'').next()?.to_string() })
        }
        _ => None,
    }
}

const ADMIN_GROUPS: &[&str] = &["sudo", "wheel", "admin", "root", "docker", "lxd"];
const SHELLS: &[&str] = &["/bash", "/sh", "/zsh", "/dash", "/su"];
/// Failures this long before a success still count against it.
const FAILURE_MEMORY: i64 = 3600;
const MAX_KNOWN: usize = 65_536;

pub struct Detector {
    limits: Thresholds,
    fails: Counter<IpAddr>,
    recent: Counter<IpAddr>,
    sources_per_user: Distinct<String, IpAddr>,
    users_per_source: Distinct<IpAddr, String>,
    sudo: Counter<String>,
    /// Where each user has logged in from.
    known: HashMap<String, HashSet<IpAddr>>,
}

impl Detector {
    pub fn new(limits: Thresholds) -> Detector {
        Detector {
            fails: Counter::new(limits.ssh_window_seconds as i64),
            recent: Counter::new(FAILURE_MEMORY),
            sources_per_user: Distinct::new(600),
            users_per_source: Distinct::new(600),
            sudo: Counter::new(300),
            known: HashMap::new(),
            limits,
        }
    }

    pub fn known_sources(&self) -> &HashMap<String, HashSet<IpAddr>> {
        &self.known
    }

    pub fn learn(&mut self, known: HashMap<String, HashSet<IpAddr>>) {
        self.known = known;
    }

    pub fn feed(&mut self, line: &str, now: DateTime<Local>) -> Vec<Threat> {
        match parse(line) {
            Some(e) => self.event(e, line, now),
            None => Vec::new(),
        }
    }

    fn event(&mut self, e: Event, line: &str, now: DateTime<Local>) -> Vec<Threat> {
        let t = now.timestamp();
        let mut out = Vec::new();
        match e {
            Event::Failed { user, ip, invalid } => {
                let key = source_key(ip);
                let n = self.fails.add(key, t);
                self.recent.add(key, t);
                let names = self.users_per_source.add(key, user.clone(), t);
                let spread = self.sources_per_user.add(user.clone(), key, t);
                if n >= self.limits.ssh_failures {
                    out.push(Threat::new(now, "ssh-bruteforce", Severity::High, Stage::Attempt, format!("SSH brute force: {n} failures from {ip}")).source_ip(ip).with_evidence(line));
                }
                if names >= self.limits.ssh_users_per_source {
                    out.push(Threat::new(now, "ssh-user-enumeration", Severity::Medium, Stage::Recon, format!("{ip} tried {names} user names")).source_ip(ip).with_evidence(line));
                }
                if !invalid && spread >= self.limits.ssh_sources_per_user {
                    out.push(Threat::new(now, "ssh-distributed", Severity::High, Stage::Attempt, format!("Distributed attack on {user}: {spread} sources")).of_user(&user).with_evidence(line));
                }
            }
            Event::Accepted { user, ip, method } => {
                let key = source_key(ip);
                let failed = self.recent.count(&key, t);
                if failed >= self.limits.ssh_failures_before_login {
                    out.push(Threat::new(now, "login-after-failures", Severity::Critical, Stage::Foothold, format!("{user} logged in from {ip} after {failed} failures")).source_ip(ip).of_user(&user).with_evidence(line));
                }
                let known_here = self.known.get(&user).is_some_and(|s| s.contains(&key));
                let seen_user = self.known.get(&user).is_some_and(|s| !s.is_empty());
                if seen_user && !known_here && failed < self.limits.ssh_failures_before_login {
                    out.push(Threat::new(now, "login-new-source", Severity::Medium, Stage::Foothold, format!("{user} logged in from a new address, {ip}")).source_ip(ip).of_user(&user).with_evidence(line));
                }
                if user == "root" && method == "password" {
                    out.push(Threat::new(now, "root-password-login", Severity::High, Stage::Foothold, format!("root logged in with a password from {ip}")).source_ip(ip).of_user(&user).with_evidence(line));
                }
                if self.known.len() < MAX_KNOWN {
                    let set = self.known.entry(user).or_default();
                    if set.len() < 1024 {
                        set.insert(key);
                    }
                }
            }
            Event::SudoFailed { user } | Event::SuFailed { user } => {
                let n = self.sudo.add(user.clone(), t);
                if n >= self.limits.sudo_failures {
                    out.push(Threat::new(now, "privilege-guessing", Severity::High, Stage::Privilege, format!("{user}: {n} failed attempts to gain privileges")).of_user(&user).with_evidence(line));
                }
            }
            Event::SudoCommand { user, command } => {
                let first = command.split_whitespace().next().unwrap_or("");
                if SHELLS.iter().any(|s| first.ends_with(s)) {
                    out.push(Threat::new(now, "sudo-root-shell", Severity::Low, Stage::Privilege, format!("{user} opened a root shell")).of_user(&user).with_evidence(line));
                }
            }
            Event::NewUser { name, uid } => {
                let (rule, severity) = if uid == Some(0) { ("uid0-created", Severity::Critical) } else { ("account-created", Severity::Medium) };
                out.push(Threat::new(now, rule, severity, Stage::Persistence, format!("Account created: {name}")).of_user(&name).with_evidence(line));
            }
            Event::AddedToGroup { user, group } if ADMIN_GROUPS.contains(&group.as_str()) => {
                out.push(Threat::new(now, "added-to-admin-group", Severity::High, Stage::Privilege, format!("{user} added to {group}")).of_user(&user).with_evidence(line));
            }
            Event::AddedToGroup { .. } => {}
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(s: i64) -> DateTime<Local> {
        Local.timestamp_opt(1_800_000_000 + s, 0).unwrap()
    }

    fn failed(user: &str, ip: &str) -> String {
        format!("Nov  5 10:00:00 web sshd[812]: Failed password for {user} from {ip} port 4242 ssh2")
    }

    #[test]
    fn reads_every_form_of_login_line() {
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert_eq!(parse(&failed("root", "203.0.113.5")), Some(Event::Failed { user: "root".into(), ip, invalid: false }));
        assert_eq!(parse("2026-11-05T10:00:00+0800 web sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 1 ssh2"), Some(Event::Failed { user: "admin".into(), ip, invalid: true }));
        assert_eq!(parse("Nov  5 10:00:00 web sshd[1]: Invalid user test from 203.0.113.5 port 1"), Some(Event::Failed { user: "test".into(), ip, invalid: true }));
        assert_eq!(parse("Nov  5 10:00:00 web sshd-session[1]: x"), None);
        assert_eq!(parse("Nov  5 10:00:00 web sshd[1]: Connection closed by authenticating user git 203.0.113.5 port 77 [preauth]"), Some(Event::Failed { user: "git".into(), ip, invalid: false }));
        assert_eq!(parse("Nov  5 10:00:00 web sshd[1]: Accepted publickey for alice from 203.0.113.5 port 1 ssh2: ED25519 SHA256:x"), Some(Event::Accepted { user: "alice".into(), ip, method: "publickey".into() }));
        assert_eq!(parse("Nov  5 10:00:00 web sudo:      bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"), Some(Event::SudoFailed { user: "bob".into() }));
        assert_eq!(parse("Nov  5 10:00:00 web sudo:      bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash -i"), Some(Event::SudoCommand { user: "bob".into(), command: "/bin/bash -i".into() }));
        assert_eq!(parse("Nov  5 10:00:00 web useradd[9]: new user: name=evil, UID=0, GID=0, home=/root, shell=/bin/bash, from=none"), Some(Event::NewUser { name: "evil".into(), uid: Some(0) }));
        assert_eq!(parse("Nov  5 10:00:00 web usermod[9]: add 'evil' to group 'sudo'"), Some(Event::AddedToGroup { user: "evil".into(), group: "sudo".into() }));
        assert_eq!(parse("Nov  5 10:00:00 web cron[9]: Failed password for root from 1.1.1.1 port 1"), None);
        assert_eq!(parse(""), None);
    }

    /// An attacker chooses the user name: it must not choose the address.
    #[test]
    fn a_forged_address_in_the_user_name_is_ignored() {
        let line = failed("x from 192.0.2.77 port 1", "203.0.113.5");
        let Some(Event::Failed { ip, .. }) = parse(&line) else { panic!() };
        assert_eq!(ip.to_string(), "203.0.113.5");
    }

    #[test]
    fn brute_force_then_success_is_critical() {
        let mut d = Detector::new(Thresholds::default());
        let mut rules = Vec::new();
        for i in 0..12 {
            rules.extend(d.feed(&failed("root", "203.0.113.5"), at(i)).into_iter().map(|t| t.rule));
        }
        assert!(rules.contains(&"ssh-bruteforce"));
        let t = d.feed("Nov  5 10:00:00 web sshd[1]: Accepted password for root from 203.0.113.5 port 1 ssh2", at(20));
        let rules: Vec<_> = t.iter().map(|x| x.rule).collect();
        assert!(rules.contains(&"login-after-failures") && rules.contains(&"root-password-login"), "{rules:?}");
        assert_eq!(t[0].severity, Severity::Critical);
    }

    #[test]
    fn slow_guessing_stays_under_the_rate_limit_but_not_the_memory() {
        let mut d = Detector::new(Thresholds::default());
        for i in 0..8 {
            assert!(d.feed(&failed("root", "203.0.113.5"), at(i * 120)).is_empty());
        }
        let t = d.feed("x web sshd[1]: Accepted password for bob from 203.0.113.5 port 1 ssh2", at(1000));
        assert_eq!(t[0].rule, "login-after-failures");
    }

    #[test]
    fn many_sources_on_one_user_is_seen() {
        let mut d = Detector::new(Thresholds::default());
        let mut hit = false;
        for i in 0..40 {
            hit |= d.feed(&failed("root", &format!("198.51.100.{i}")), at(i)).iter().any(|t| t.rule == "ssh-distributed");
        }
        assert!(hit);
    }

    #[test]
    fn a_login_from_a_new_place_is_noted_only_once_a_user_is_known() {
        let mut d = Detector::new(Thresholds::default());
        let line = |ip: &str| format!("x web sshd[1]: Accepted publickey for alice from {ip} port 1 ssh2");
        assert!(d.feed(&line("192.0.2.1"), at(0)).is_empty());
        assert!(d.feed(&line("192.0.2.1"), at(1)).is_empty());
        assert_eq!(d.feed(&line("198.51.100.9"), at(2))[0].rule, "login-new-source");
    }

    #[test]
    fn privilege_events() {
        let mut d = Detector::new(Thresholds::default());
        let mut rules = Vec::new();
        for i in 0..5 {
            rules.extend(d.feed("x web sudo: bob : 3 incorrect password attempts ; TTY=x ; COMMAND=/bin/ls", at(i)).into_iter().map(|t| t.rule));
        }
        assert!(rules.contains(&"privilege-guessing"));
        assert_eq!(d.feed("x web useradd[1]: new user: name=e, UID=0, GID=0", at(9))[0].severity, Severity::Critical);
        assert_eq!(d.feed("x web usermod[1]: add 'e' to group 'docker'", at(9))[0].rule, "added-to-admin-group");
        assert!(d.feed("x web usermod[1]: add 'e' to group 'audio'", at(9)).is_empty());
    }
}
