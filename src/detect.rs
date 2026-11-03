//! Detections: rule hits remembered over time, with their subject, the
//! evidence that matched, when they were first and last seen, and whether
//! an analyst suppressed them.
//!
//! Suppressions live in `suppressions.txt` next to the settings file, one
//! per line:
//!
//! ```text
//! # rule    | filter (same syntax as the search box)          | reason
//! PW-002    | path:"/Applications/My Tool.app"                 | in-house build, unsigned
//! *         | team:ABCDE12345                                  | trusted vendor
//! ```
//!
//! A suppressed hit is still recorded (and shown when asked) but no longer
//! counts towards priority.

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Local};
use serde::Serialize;

use crate::filter::{Filter, Filterable};
use crate::model::{Confidence, Entity, Severity};

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub rule_id: String,
    pub rule_name: String,
    /// "host rule", "sigma", "ioc".
    pub engine: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub technique: String,
    pub subject: Entity,
    pub subject_label: String,
    pub pid: Option<u32>,
    /// Distinct evidence strings, newest last (capped).
    pub evidence: Vec<String>,
    pub first_seen: DateTime<Local>,
    pub last_seen: DateTime<Local>,
    pub count: u32,
    pub suppressed: Option<String>,
    /// Still true on the latest evaluation (host rules re-evaluate every
    /// refresh; event rules stay active once seen).
    pub active: bool,
}

const MAX_EVIDENCE: usize = 12;
const MAX_DETECTIONS: usize = 5000;

#[derive(Default)]
pub struct Store {
    pub items: Vec<Detection>,
    index: HashMap<(String, String), usize>,
    /// Bumped on every change, so views can cache.
    pub generation: u64,
}

impl Store {
    /// Record a hit. Returns true if it is new.
    pub fn upsert(&mut self, d: Detection) -> bool {
        self.generation += 1;
        let key = (d.rule_id.clone(), d.subject.key());
        if let Some(&i) = self.index.get(&key) {
            let cur = &mut self.items[i];
            // Host rules are re-checked every refresh; count how often the
            // condition (re)appeared, not how often it was evaluated.
            if !cur.active || cur.engine != "host rule" {
                cur.count = cur.count.saturating_add(1);
            }
            cur.last_seen = d.last_seen;
            cur.active = true;
            cur.suppressed = d.suppressed;
            for ev in d.evidence {
                if !cur.evidence.contains(&ev) {
                    if cur.evidence.len() >= MAX_EVIDENCE {
                        cur.evidence.remove(0);
                    }
                    cur.evidence.push(ev);
                }
            }
            return false;
        }
        if self.items.len() >= MAX_DETECTIONS {
            // Drop the oldest inactive one, else the oldest.
            let victim = self.items.iter().enumerate().filter(|(_, d)| !d.active).min_by_key(|(_, d)| d.last_seen).map(|(i, _)| i).unwrap_or(0);
            self.items.remove(victim);
            self.reindex();
        }
        self.index.insert(key, self.items.len());
        self.items.push(d);
        true
    }

    fn reindex(&mut self) {
        self.index = self.items.iter().enumerate().map(|(i, d)| ((d.rule_id.clone(), d.subject.key()), i)).collect();
    }

    /// Host rules are re-evaluated each refresh: anything of `engine` not
    /// in `seen` is no longer true.
    pub fn settle(&mut self, engine: &str, seen: &std::collections::HashSet<(String, String)>) {
        for d in self.items.iter_mut().filter(|d| d.engine == engine && d.active) {
            if !seen.contains(&(d.rule_id.clone(), d.subject.key())) {
                d.active = false;
                self.generation += 1;
            }
        }
    }

    pub fn for_subject<'a>(&'a self, e: &'a Entity) -> impl Iterator<Item = &'a Detection> + 'a {
        self.items.iter().filter(move |d| &d.subject == e)
    }
}

impl Filterable for Detection {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        match name {
            "rule" => Some(vec![self.rule_id.clone(), self.rule_name.clone()]),
            "sev" => Some(vec![self.severity.label().into()]),
            "pid" => Some(vec![self.pid.map(|p| p.to_string()).unwrap_or_default()]),
            "name" => Some(vec![self.subject_label.clone()]),
            "source" => Some(vec![self.engine.into()]),
            "entity" => Some(vec![self.subject.key()]),
            "state" => Some(vec![if self.suppressed.is_some() { "suppressed" } else if self.active { "active" } else { "past" }.into()]),
            _ => None,
        }
    }
    fn text(&self) -> String {
        format!("{} {} {} {} {}", self.rule_id, self.rule_name, self.subject_label, self.technique, self.evidence.join(" "))
    }
}

// ── suppressions ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Suppression {
    pub rule: String,
    pub filter: String,
    pub reason: String,
}

/// What a suppression filter is matched against.
pub struct Facts<'a> {
    pub name: &'a str,
    pub path: &'a str,
    pub user: &'a str,
    pub cmd: &'a str,
    pub team: &'a str,
}

impl Filterable for Facts<'_> {
    fn field(&self, name: &str) -> Option<Vec<String>> {
        let v = match name {
            "name" => self.name,
            "path" => self.path,
            "user" => self.user,
            "cmd" => self.cmd,
            "team" => self.team,
            _ => return None,
        };
        Some(vec![v.to_string()])
    }
    fn text(&self) -> String {
        format!("{} {} {}", self.name, self.path, self.cmd)
    }
}

pub fn path() -> Option<PathBuf> {
    crate::config::path().map(|p| p.with_file_name("suppressions.txt"))
}

pub fn parse(text: &str) -> Vec<Suppression> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut f = l.splitn(3, '|').map(str::trim);
            let rule = f.next()?.to_string();
            let filter = f.next().unwrap_or("").to_string();
            let reason = f.next().unwrap_or("").to_string();
            // A suppression with no filter would silence a rule everywhere;
            // require one unless the rule is named explicitly.
            (!rule.is_empty() && (!filter.is_empty() || rule != "*")).then_some(Suppression { rule, filter, reason })
        })
        .collect()
}

pub fn load() -> Vec<Suppression> {
    path().and_then(|p| std::fs::read_to_string(p).ok()).map(|t| parse(&t)).unwrap_or_default()
}

pub fn append(s: &Suppression) -> anyhow::Result<PathBuf> {
    let p = path().ok_or_else(|| anyhow::anyhow!("no config folder"))?;
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut text = std::fs::read_to_string(&p).unwrap_or_else(|_| {
        "# procwatch suppressions: rule | filter | reason   (rule may be *)\n".to_string()
    });
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!("{} | {} | {}\n", s.rule, s.filter, s.reason.replace('\n', " ")));
    crate::config::write_atomic(&p, &text)?;
    Ok(p)
}

/// The reason, if any suppression covers `rule` for these facts.
pub fn suppressed(list: &[Suppression], rule: &str, facts: &Facts) -> Option<String> {
    list.iter()
        .find(|s| (s.rule == "*" || s.rule.eq_ignore_ascii_case(rule)) && (s.filter.is_empty() || Filter::parse(&s.filter).matches(facts)))
        .map(|s| if s.reason.is_empty() { "suppressed".to_string() } else { s.reason.clone() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(rule: &str, pid: u32) -> Detection {
        Detection {
            rule_id: rule.into(),
            rule_name: rule.into(),
            engine: "host rule",
            severity: Severity::Low,
            confidence: Confidence::Low,
            technique: String::new(),
            subject: Entity::Process(crate::model::ProcKey { pid, start: 1 }),
            subject_label: "x".into(),
            pid: Some(pid),
            evidence: vec!["a".into()],
            first_seen: Local::now(),
            last_seen: Local::now(),
            count: 1,
            suppressed: None,
            active: true,
        }
    }

    #[test]
    fn store_dedupes_and_settles() {
        let mut s = Store::default();
        assert!(s.upsert(det("R1", 1)));
        let mut again = det("R1", 1);
        again.evidence = vec!["b".into()];
        assert!(!s.upsert(again));
        assert_eq!(s.items.len(), 1);
        assert_eq!(s.items[0].evidence, vec!["a", "b"]);
        assert_eq!(s.items[0].count, 1, "re-evaluation of a still-true host rule");
        s.upsert(det("R2", 2));
        let seen = [("R2".to_string(), Entity::Process(crate::model::ProcKey { pid: 2, start: 1 }).key())].into_iter().collect();
        s.settle("host rule", &seen);
        assert!(!s.items[0].active && s.items[1].active);
    }

    #[test]
    fn suppressions() {
        let list = parse("# c\nPW-002 | path:\"/Applications/My Tool.app\" | in-house\n* | | ignored: no filter\nPW-004 | | dev box\n");
        assert_eq!(list.len(), 2);
        let f = Facts { name: "tool", path: "/Applications/My Tool.app/Contents/MacOS/tool", user: "a", cmd: "", team: "" };
        assert_eq!(suppressed(&list, "PW-002", &f).as_deref(), Some("in-house"));
        assert_eq!(suppressed(&list, "PW-004", &f).as_deref(), Some("dev box"));
        assert!(suppressed(&list, "PW-001", &f).is_none());
    }
}

/// Detection engine state kept by the app.
#[derive(Default)]
pub struct State {
    pub store: Store,
    pub suppressions: Vec<Suppression>,
    pub sigma: Vec<crate::sigma::Rule>,
    pub sigma_errors: Vec<String>,
    /// Behaviour-sequence rules and the matches already recorded.
    pub behavior: Vec<crate::behave::Rule>,
    pub behavior_errors: Vec<String>,
    pub behavior_seen: std::collections::HashSet<(String, String)>,
    pub sigma_dir: Option<PathBuf>,
    /// Process instances already run through Sigma, and whether their
    /// executable hash was known at the time (re-run once it is).
    pub sigma_seen: HashMap<crate::model::ProcKey, bool>,
    /// Sigma hits per live process (start time, hits): part of priority.
    pub sigma_hits: HashMap<u32, (u64, Vec<crate::triage::RuleHit>)>,
    /// UI: detections list focused on the Detect page, selection, options.
    pub focus: bool,
    pub selected: usize,
    pub offset: usize,
    pub show_suppressed: bool,
    /// New medium+ detections since the Detect page was last open.
    pub unread: usize,
}

impl State {
    pub fn load(sigma_dir: Option<PathBuf>) -> State {
        let mut s = State { suppressions: load(), focus: true, ..Default::default() };
        s.sigma_dir = sigma_dir.or_else(crate::sigma::default_dir);
        s.reload_sigma();
        (s.behavior, s.behavior_errors) = crate::behave::load();
        s
    }

    pub fn reload_sigma(&mut self) {
        let (user, errors) = match &self.sigma_dir {
            Some(d) if d.exists() => crate::sigma::load_dir(d),
            _ => (Vec::new(), Vec::new()),
        };
        // User rules with the same id replace built-in ones.
        let mut rules: Vec<crate::sigma::Rule> = crate::sigma::builtin().into_iter().filter(|b| !user.iter().any(|u| u.id == b.id)).collect();
        rules.extend(user);
        self.sigma = rules;
        self.sigma_errors = errors;
        self.sigma_seen.clear();
        self.sigma_hits.clear();
    }
}
