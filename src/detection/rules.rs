//! Alert rules written in plain language, evaluated on every refresh.
//!
//! ```text
//! cpu > 80%            cpu > 50% for 30s name=chrome
//! mem > 2GB            growth > 20MB/min
//! start ssh            exit nginx
//! listen               listen name=python
//! connect :25          connect 10.0.0.5
//! ```
//!
//! `name=` limits a rule to processes whose name contains the text.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};

use crate::network::{ConnState, Connection};
use crate::process::{human_bytes, ProcessInfo, ProcessTree};

#[derive(Debug, Clone, PartialEq)]
pub enum Cond {
    Cpu { pct: f32, for_secs: u64 },
    Mem { bytes: u64 },
    Growth { bytes_per_min: f64 },
    Start { pattern: String },
    Exit { pattern: String },
    Listen,
    Connect { target: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub text: String,
    pub cond: Cond,
    pub name: Option<String>,
    pub enabled: bool,
}

fn parse_bytes(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();
    let split = s.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: f64 = num.parse().ok()?;
    let mult = match unit.trim() {
        "" | "b" => 1.0,
        "k" | "kb" => 1024.0,
        "m" | "mb" => 1024.0 * 1024.0,
        "g" | "gb" => 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((n * mult) as u64)
}

fn parse_secs(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();
    if let Some(m) = s.strip_suffix("min").or_else(|| s.strip_suffix('m')) {
        return m.parse::<u64>().ok().and_then(|v| v.checked_mul(60));
    }
    s.trim_end_matches('s').parse().ok()
}

impl Rule {
    /// Parse a rule. Errors are short, user-facing messages.
    pub fn parse(text: &str) -> Result<Rule, String> {
        let text = text.trim();
        let mut words: Vec<&str> = text.split_whitespace().collect();
        let mut name = None;
        words.retain(|w| match w.strip_prefix("name=") {
            Some(n) => {
                name = Some(n.to_lowercase());
                false
            }
            None => true,
        });
        let lower: Vec<String> = words.iter().map(|w| w.to_lowercase()).collect();
        let first = lower.first().map(String::as_str).ok_or("empty rule")?;
        let rest = || words[1..].join(" ");
        let cond = match first {
            "cpu" => {
                let v = lower.get(2).ok_or("expected e.g. cpu > 80%")?;
                if lower.get(1).map(String::as_str) != Some(">") {
                    return Err("only '>' is supported, e.g. cpu > 80%".into());
                }
                let pct: f32 = v.trim_end_matches('%').parse().map_err(|_| "CPU must be a percentage, e.g. 80%")?;
                let for_secs = match (lower.get(3).map(String::as_str), lower.get(4)) {
                    (Some("for"), Some(d)) => parse_secs(d).ok_or("duration must look like 10s or 2m")?,
                    (None, _) => 0,
                    _ => return Err("expected 'for 10s' after the percentage".into()),
                };
                Cond::Cpu { pct, for_secs }
            }
            "mem" | "memory" => {
                let v = lower.get(2).ok_or("expected e.g. mem > 2GB")?;
                Cond::Mem { bytes: parse_bytes(v).ok_or("size must look like 500MB or 2GB")? }
            }
            "growth" => {
                let v = lower.get(2).ok_or("expected e.g. growth > 20MB/min")?;
                let amount = v.trim_end_matches("/min").trim_end_matches("/m");
                Cond::Growth { bytes_per_min: parse_bytes(amount).ok_or("rate must look like 20MB/min")? as f64 }
            }
            "start" | "starts" => Cond::Start { pattern: rest().to_lowercase() },
            "exit" | "exits" => Cond::Exit { pattern: rest().to_lowercase() },
            "listen" => Cond::Listen,
            "connect" => {
                let t = rest();
                if t.is_empty() {
                    return Err("expected a port or address, e.g. connect :25".into());
                }
                Cond::Connect { target: t }
            }
            other => return Err(format!("unknown rule '{other}' — try cpu, mem, growth, start, exit, listen, connect")),
        };
        if let Cond::Start { pattern } | Cond::Exit { pattern } = &cond {
            if pattern.is_empty() {
                return Err("expected a process name, e.g. start ssh".into());
            }
        }
        Ok(Rule { text: text.to_string(), cond, name, enabled: true })
    }

    fn applies(&self, info: &ProcessInfo) -> bool {
        self.name.as_deref().is_none_or(|n| info.name.to_lowercase().contains(n))
    }

    /// One-line explanation shown in the rule list.
    pub fn describe(&self) -> String {
        let who = self.name.as_deref().map(|n| format!(" (processes named *{n}*)")).unwrap_or_default();
        let what = match &self.cond {
            Cond::Cpu { pct, for_secs: 0 } => format!("CPU above {pct}%"),
            Cond::Cpu { pct, for_secs } => format!("CPU above {pct}% for {for_secs}s"),
            Cond::Mem { bytes } => format!("memory above {}", human_bytes(*bytes)),
            Cond::Growth { bytes_per_min } => format!("memory growing faster than {}/min", human_bytes(*bytes_per_min as u64)),
            Cond::Start { pattern } => format!("a process matching '{pattern}' starts"),
            Cond::Exit { pattern } => format!("a process matching '{pattern}' exits"),
            Cond::Listen => "a process starts listening on a new port".into(),
            Cond::Connect { target } => format!("a new connection to {target}"),
        };
        format!("{what}{who}")
    }
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub at: DateTime<Local>,
    pub rule: String,
    pub pid: u32,
    pub name: String,
    pub message: String,
}

/// Memory growth in bytes per minute from evenly spaced samples (least
/// squares slope). Needs at least `min` samples to say anything.
pub fn growth_per_min(samples: &VecDeque<f64>, interval: Duration, min: usize) -> Option<f64> {
    let n = samples.len();
    if n < min || interval.is_zero() {
        return None;
    }
    let nf = n as f64;
    let mean_x = (nf - 1.0) / 2.0;
    let mean_y = samples.iter().sum::<f64>() / nf;
    let (mut num, mut den) = (0.0, 0.0);
    for (i, y) in samples.iter().enumerate() {
        let dx = i as f64 - mean_x;
        num += dx * (y - mean_y);
        den += dx * dx;
    }
    if den == 0.0 {
        return None;
    }
    Some(num / den * 60.0 / interval.as_secs_f64())
}

/// Lifecycle facts from the latest refresh, fed to the engine.
pub struct Changes<'a> {
    pub started: &'a [&'a ProcessInfo],
    pub exited: &'a [&'a ProcessInfo],
}

#[derive(Default)]
pub struct Engine {
    /// Keyed by rule position, pid and start time, so a process that takes
    /// over a PID doesn't inherit another's state.
    cpu_since: HashMap<(usize, u32, u64), Instant>,
    fired: HashSet<(usize, u32, u64)>,
    sockets: Option<HashSet<(u32, Connection)>>,
}

impl Engine {
    /// A rule was removed: positions shifted, so per-rule state is stale.
    pub fn rules_changed(&mut self) {
        self.cpu_since.clear();
        self.fired.clear();
    }

    /// Evaluate every enabled rule against the new state. Each rule fires
    /// once per process per episode and re-arms when the condition clears.
    pub fn evaluate(
        &mut self,
        rules: &[Rule],
        tree: &ProcessTree,
        conns: &HashMap<u32, Vec<Connection>>,
        changes: &Changes,
        growth: &dyn Fn(u32) -> Option<f64>,
    ) -> Vec<Alert> {
        let mut out = Vec::new();
        let now = Instant::now();
        let mut alert = |rule: &Rule, info: &ProcessInfo, message: String| {
            out.push(Alert { at: Local::now(), rule: rule.text.clone(), pid: info.pid, name: info.name.clone(), message });
        };

        let sockets: HashSet<(u32, Connection)> =
            conns.iter().flat_map(|(pid, cs)| cs.iter().map(move |c| (*pid, c.clone()))).collect();
        let new_sockets: Vec<&(u32, Connection)> = match &self.sockets {
            Some(prev) => sockets.difference(prev).collect(),
            None => Vec::new(), // first refresh is the baseline
        };

        for (idx, rule) in rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            match &rule.cond {
                Cond::Cpu { .. } | Cond::Mem { .. } | Cond::Growth { .. } => {
                    for node in tree.nodes.values() {
                        let i = &node.info;
                        if !rule.applies(i) {
                            continue;
                        }
                        let key = (idx, i.pid, i.start_time_secs);
                        let (hit, message) = match &rule.cond {
                            Cond::Cpu { pct, for_secs } => {
                                if i.cpu_usage_pct > *pct {
                                    let since = *self.cpu_since.entry(key).or_insert(now);
                                    let held = now.duration_since(since) >= Duration::from_secs(*for_secs);
                                    (held, format!("CPU {:.0}% (limit {pct}%)", i.cpu_usage_pct))
                                } else {
                                    self.cpu_since.remove(&key);
                                    (false, String::new())
                                }
                            }
                            Cond::Mem { bytes } => (i.mem() > *bytes, format!("memory {} (limit {})", human_bytes(i.mem()), human_bytes(*bytes))),
                            Cond::Growth { bytes_per_min } => match growth(i.pid) {
                                Some(g) => (g > *bytes_per_min, format!("memory growing {}/min, now {}", human_bytes(g.max(0.0) as u64), human_bytes(i.mem()))),
                                None => (false, String::new()),
                            },
                            _ => unreachable!(),
                        };
                        if hit {
                            if self.fired.insert(key) {
                                alert(rule, i, message);
                            }
                        } else {
                            self.fired.remove(&key);
                        }
                    }
                }
                Cond::Start { pattern } => {
                    for i in changes.started.iter().filter(|i| rule.applies(i) && matches_proc(i, pattern)) {
                        let parent = i.ppid.and_then(|p| tree.get(p)).map(|n| format!(" by {}", n.info.name)).unwrap_or_default();
                        alert(rule, i, format!("started{parent}: {}", i.cmd.join(" ")));
                    }
                }
                Cond::Exit { pattern } => {
                    for i in changes.exited.iter().filter(|i| rule.applies(i) && matches_proc(i, pattern)) {
                        alert(rule, i, "exited".into());
                    }
                }
                Cond::Listen | Cond::Connect { .. } => {
                    for (pid, c) in &new_sockets {
                        let Some(node) = tree.get(*pid) else { continue };
                        if !rule.applies(&node.info) {
                            continue;
                        }
                        match &rule.cond {
                            Cond::Listen if c.state == ConnState::Listen => {
                                alert(rule, &node.info, format!("{} listening on {}", c.protocol, c.local));
                            }
                            Cond::Connect { target } if c.state != ConnState::Listen && c.remote.contains(target.as_str()) => {
                                alert(rule, &node.info, format!("{} {} → {}", c.protocol, c.local, c.remote));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // Forget state for processes that are gone.
        let alive = |pid: u32, start: u64| tree.get(pid).is_some_and(|n| n.info.start_time_secs == start);
        self.cpu_since.retain(|(_, pid, start), _| alive(*pid, *start));
        self.fired.retain(|(_, pid, start)| alive(*pid, *start));
        self.sockets = Some(sockets);
        out
    }
}

fn matches_proc(i: &ProcessInfo, pattern: &str) -> bool {
    i.name.to_lowercase().contains(pattern) || i.exe_path.as_deref().is_some_and(|p| p.to_lowercase().contains(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::tests::{info, sample};

    #[test]
    fn parses_rules() {
        assert_eq!(Rule::parse("cpu > 80% for 10s").unwrap().cond, Cond::Cpu { pct: 80.0, for_secs: 10 });
        assert_eq!(Rule::parse("mem > 2GB name=Chrome").unwrap().name.as_deref(), Some("chrome"));
        assert_eq!(Rule::parse("growth > 20MB/min").unwrap().cond, Cond::Growth { bytes_per_min: 20.0 * 1024.0 * 1024.0 });
        assert_eq!(Rule::parse("connect :25").unwrap().cond, Cond::Connect { target: ":25".into() });
        assert!(Rule::parse("cpu < 5%").is_err());
        assert!(Rule::parse("start").is_err());
        assert!(Rule::parse("frobnicate").is_err());
        assert!(Rule::parse("mem > lots").is_err());
    }

    #[test]
    fn slope_of_linear_growth() {
        let s: VecDeque<f64> = (0..30).map(|i| 1000.0 + i as f64 * 100.0).collect();
        let g = growth_per_min(&s, Duration::from_secs(1), 20).unwrap();
        assert!((g - 6000.0).abs() < 1e-6);
        assert!(growth_per_min(&s, Duration::from_secs(1), 40).is_none());
    }

    #[test]
    fn fires_once_per_episode() {
        let mut tree = sample(); // cpu == pid in the sample tree
        let rules = vec![Rule::parse("cpu > 4%").unwrap(), Rule::parse("start p9").unwrap()];
        let mut e = Engine::default();
        let none = Changes { started: &[], exited: &[] };
        let no_growth = |_: u32| None;
        let a = e.evaluate(&rules, &tree, &HashMap::new(), &none, &no_growth);
        assert_eq!(a.iter().map(|a| a.pid).collect::<HashSet<_>>(), [5, 6].into());
        assert!(e.evaluate(&rules, &tree, &HashMap::new(), &none, &no_growth).is_empty(), "no repeat while still high");
        tree.nodes.get_mut(&5).unwrap().info.cpu_usage_pct = 1.0;
        e.evaluate(&rules, &tree, &HashMap::new(), &none, &no_growth);
        tree.nodes.get_mut(&5).unwrap().info.cpu_usage_pct = 50.0;
        assert_eq!(e.evaluate(&rules, &tree, &HashMap::new(), &none, &no_growth).len(), 1, "re-armed after dropping");

        let p9 = info(9, None);
        let started = [&p9];
        let ch = Changes { started: &started, exited: &[] };
        let a = e.evaluate(&rules, &tree, &HashMap::new(), &ch, &no_growth);
        assert!(a.iter().any(|a| a.pid == 9 && a.message.starts_with("started")));
    }
}
