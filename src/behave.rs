//! Behaviour-sequence rules: multi-step patterns over the unified event
//! stream — "a file is written, then run", "a download tool runs, then
//! something starts from a temp folder", "five discovery commands within a
//! minute". Each rule has a time window and a scope (the same process tree,
//! the same process, or anywhere), steps can capture fields and refer back
//! to them, and a step can count distinct values.
//!
//! ```yaml
//! id: pw-seq-001
//! title: File written, then executed
//! level: high
//! confidence: medium
//! technique: T1204.002
//! within: 600s
//! scope: any            # any | tree | process
//! steps:
//!   - event: file_write
//!     capture: { file: path }
//!   - event: process_start
//!     where: { image: "{file}" }
//! ```
//!
//! Conditions: `field: value` (case-insensitive equality), lists (any),
//! modifiers `|contains`, `|startswith`, `|endswith`; `{name}` refers to a
//! captured value. Count steps: `count: 5` with `distinct: name`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Local};
use serde::Serialize;

use crate::model::{Confidence, Severity};

/// One normalized event.
#[derive(Debug, Clone, Default)]
pub struct Ev {
    pub time: DateTime<Local>,
    pub id: String,
    pub kind: &'static str,
    pub pid: Option<u32>,
    /// The pid and its known ancestors, nearest first.
    pub lineage: Vec<u32>,
    pub fields: BTreeMap<&'static str, String>,
}

#[derive(Debug, Clone)]
struct Cond {
    field: String,
    op: &'static str,
    values: Vec<String>,
}

#[derive(Debug, Clone)]
struct Step {
    event: String,
    conds: Vec<Cond>,
    capture: Vec<(String, String)>,
    count: usize,
    distinct: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub level: Severity,
    pub confidence: Confidence,
    pub technique: String,
    pub description: String,
    pub within_secs: i64,
    pub scope: String,
    #[serde(skip)]
    steps: Vec<Step>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Match {
    pub rule: String,
    pub title: String,
    pub level: Severity,
    pub confidence: Confidence,
    pub technique: String,
    pub pid: Option<u32>,
    pub events: Vec<String>,
    pub evidence: String,
    #[serde(serialize_with = "ser_time")]
    pub at: DateTime<Local>,
}

fn ser_time<S: serde::Serializer>(t: &DateTime<Local>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&t.to_rfc3339())
}

const KINDS: &[&str] = &["process_start", "process_exit", "file_write", "file_open", "net_connect", "net_listen", "persistence_change", "module_load", "detection"];

fn yaml_str(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn parse_secs(s: &str) -> Option<i64> {
    let s = s.trim();
    let (n, mult) = if let Some(x) = s.strip_suffix('s') { (x, 1) } else if let Some(x) = s.strip_suffix('m') { (x, 60) } else if let Some(x) = s.strip_suffix('h') { (x, 3600) } else { (s, 1) };
    n.trim().parse::<i64>().ok().map(|v| v * mult)
}

fn parse_rule(doc: &serde_yaml::Value) -> Result<Rule, String> {
    let s = |k: &str| doc.get(k).and_then(yaml_str).unwrap_or_default();
    let id = s("id");
    if id.is_empty() {
        return Err("rule has no id".into());
    }
    let scope = if s("scope").is_empty() { "tree".to_string() } else { s("scope") };
    if !["any", "tree", "process"].contains(&scope.as_str()) {
        return Err(format!("{id}: scope must be any, tree or process"));
    }
    let within = parse_secs(&s("within")).ok_or_else(|| format!("{id}: within must be like 120s, 5m or 1h"))?;
    let steps_v = doc.get("steps").and_then(|v| v.as_sequence()).ok_or_else(|| format!("{id}: no steps"))?;
    let mut steps = Vec::new();
    for st in steps_v {
        let event = st.get("event").and_then(yaml_str).ok_or_else(|| format!("{id}: step without event"))?;
        if !KINDS.contains(&event.as_str()) {
            return Err(format!("{id}: unknown event '{event}' (expected one of {})", KINDS.join(", ")));
        }
        let mut conds = Vec::new();
        if let Some(m) = st.get("where").and_then(|w| w.as_mapping()) {
            for (k, v) in m {
                let key = yaml_str(k).unwrap_or_default();
                let (field, op) = match key.split_once('|') {
                    Some((f, "contains")) => (f.to_string(), "contains"),
                    Some((f, "startswith")) => (f.to_string(), "startswith"),
                    Some((f, "endswith")) => (f.to_string(), "endswith"),
                    Some((_, m)) => return Err(format!("{id}: modifier '{m}' is not supported")),
                    None => (key.clone(), "eq"),
                };
                let values = match v {
                    serde_yaml::Value::Sequence(items) => items.iter().filter_map(yaml_str).collect(),
                    other => yaml_str(other).into_iter().collect(),
                };
                conds.push(Cond { field, op, values });
            }
        }
        let capture = st
            .get("capture")
            .and_then(|c| c.as_mapping())
            .map(|m| m.iter().filter_map(|(k, v)| Some((yaml_str(k)?, yaml_str(v)?))).collect())
            .unwrap_or_default();
        let count = st.get("count").and_then(|c| c.as_u64()).unwrap_or(1).max(1) as usize;
        let distinct = st.get("distinct").and_then(yaml_str);
        steps.push(Step { event, conds, capture, count, distinct });
    }
    if steps.is_empty() {
        return Err(format!("{id}: no steps"));
    }
    Ok(Rule {
        id: id.clone(),
        title: if s("title").is_empty() { id } else { s("title") },
        level: Severity::parse(&s("level")),
        confidence: match s("confidence").as_str() {
            "high" => Confidence::High,
            "low" => Confidence::Low,
            _ => Confidence::Medium,
        },
        technique: s("technique"),
        description: s("description"),
        within_secs: within,
        scope,
        steps,
    })
}

pub fn parse(text: &str) -> (Vec<Rule>, Vec<String>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    for doc in serde_yaml::Deserializer::from_str(text) {
        match <serde_yaml::Value as serde::Deserialize>::deserialize(doc) {
            Ok(v) if v.is_null() => {}
            Ok(v) => match parse_rule(&v) {
                Ok(r) => rules.push(r),
                Err(e) => errors.push(e),
            },
            Err(e) => {
                errors.push(e.to_string());
                break;
            }
        }
    }
    (rules, errors)
}

pub fn builtin() -> Vec<Rule> {
    parse(include_str!("../rules/behavior/procwatch-builtin.yml")).0
}

/// Built-in rules plus `behavior/*.yml` next to the settings file.
pub fn load() -> (Vec<Rule>, Vec<String>) {
    let mut rules = builtin();
    let mut errors = Vec::new();
    if let Some(dir) = crate::config::path().map(|p| p.with_file_name("behavior")).filter(|d| d.is_dir()) {
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            if e.path().extension().is_some_and(|x| x == "yml" || x == "yaml") {
                match std::fs::read_to_string(e.path()) {
                    Ok(t) => {
                        let (r, errs) = parse(&t);
                        rules.retain(|b| !r.iter().any(|x| x.id == b.id));
                        rules.extend(r);
                        errors.extend(errs);
                    }
                    Err(err) => errors.push(format!("{}: {err}", e.path().display())),
                }
            }
        }
    }
    (rules, errors)
}

fn resolve(v: &str, caps: &HashMap<String, String>) -> String {
    let mut out = v.to_string();
    for (k, val) in caps {
        out = out.replace(&format!("{{{k}}}"), val);
    }
    out.to_lowercase()
}

fn cond_ok(c: &Cond, e: &Ev, caps: &HashMap<String, String>) -> bool {
    let Some(actual) = e.fields.get(c.field.as_str()).map(|v| v.to_lowercase()) else { return false };
    c.values.iter().any(|v| {
        let want = resolve(v, caps);
        // A reference to an uncaptured name never matches.
        if want.contains('{') && want.contains('}') {
            return false;
        }
        match c.op {
            "contains" => actual.contains(&want),
            "startswith" => actual.starts_with(&want),
            "endswith" => actual.ends_with(&want),
            _ => actual == want,
        }
    })
}

fn step_ok(s: &Step, e: &Ev, caps: &HashMap<String, String>) -> bool {
    s.event == e.kind && s.conds.iter().all(|c| cond_ok(c, e, caps))
}

/// Scope anchor: the first matched process and its parent.
#[derive(Clone, Copy)]
struct Anchor {
    pid: u32,
    parent: Option<u32>,
}

impl Anchor {
    fn of(e: &Ev) -> Option<Anchor> {
        e.pid.map(|pid| Anchor { pid, parent: e.lineage.get(1).copied() })
    }
    /// `tree`: a descendant of the anchor, or a direct sibling of it (same
    /// parent, unless that parent is the init process).
    fn tree(&self, e: &Ev) -> bool {
        e.lineage.contains(&self.pid) || (self.parent.is_some_and(|p| p > 1) && e.lineage.get(1).copied() == self.parent)
    }
}

#[derive(Clone)]
struct Partial {
    step: usize,
    start: DateTime<Local>,
    scope: Option<Anchor>,
    pid: Option<u32>,
    caps: HashMap<String, String>,
    events: Vec<String>,
    distinct: BTreeSet<String>,
}

const MAX_PARTIALS: usize = 2000;

/// Run every rule over `events` (oldest first).
pub fn evaluate(rules: &[Rule], events: &[Ev]) -> Vec<Match> {
    let mut out = Vec::new();
    for r in rules {
        let mut partials: Vec<Partial> = Vec::new();
        let mut done: BTreeSet<String> = BTreeSet::new();
        for e in events {
            let window = chrono::Duration::seconds(r.within_secs);
            partials.retain(|p| e.time - p.start <= window);
            let in_scope = |p: &Partial, e: &Ev| match (r.scope.as_str(), p.scope) {
                (_, None) | ("any", _) => true,
                ("process", Some(a)) => e.pid == Some(a.pid),
                (_, Some(a)) => a.tree(e),
            };
            let mut next: Vec<Partial> = Vec::new();
            // Count steps advance in place: keeping the original as well
            // would double the partial on every matching event.
            let mut consumed = vec![false; partials.len()];
            for (idx, p) in partials.iter().enumerate() {
                let s = &r.steps[p.step];
                if !in_scope(p, e) {
                    continue;
                }
                if !step_ok(s, e, &p.caps) {
                    continue;
                }
                let mut q = p.clone();
                if s.count > 1 {
                    let key = s.distinct.as_ref().and_then(|d| e.fields.get(d.as_str()).cloned()).unwrap_or_else(|| e.id.clone());
                    if !q.distinct.insert(key.to_lowercase()) {
                        continue;
                    }
                    q.events.push(e.id.clone());
                    consumed[idx] = true;
                    if q.distinct.len() < s.count {
                        next.push(q);
                        continue;
                    }
                    q.distinct.clear();
                } else {
                    q.events.push(e.id.clone());
                }
                for (name, field) in &s.capture {
                    if let Some(v) = e.fields.get(field.as_str()) {
                        q.caps.insert(name.clone(), v.clone());
                    }
                }
                q.pid = q.pid.or(e.pid);
                if q.scope.is_none() && r.scope != "any" {
                    q.scope = Anchor::of(e);
                }
                q.step += 1;
                next.push(q);
            }
            // A new sequence can start at this event.
            let first = &r.steps[0];
            if step_ok(first, e, &HashMap::new()) {
                let mut p = Partial { step: 0, start: e.time, scope: if r.scope == "any" { None } else { Anchor::of(e) }, pid: e.pid, caps: HashMap::new(), events: Vec::new(), distinct: BTreeSet::new() };
                if first.count > 1 {
                    let key = first.distinct.as_ref().and_then(|d| e.fields.get(d.as_str()).cloned()).unwrap_or_else(|| e.id.clone());
                    p.distinct.insert(key.to_lowercase());
                    p.events.push(e.id.clone());
                    if first.count > 1 {
                        next.push(p);
                    }
                } else {
                    p.events.push(e.id.clone());
                    for (name, field) in &first.capture {
                        if let Some(v) = e.fields.get(field.as_str()) {
                            p.caps.insert(name.clone(), v.clone());
                        }
                    }
                    p.step = 1;
                    next.push(p);
                }
            }
            // Keep unmatched partials alive, add advanced ones; complete ones
            // become matches (once per first event).
            let mut keep: Vec<Partial> = partials.into_iter().zip(consumed).filter(|(p, used)| !used && p.step < r.steps.len()).map(|(p, _)| p).collect();
            for q in next {
                if q.step >= r.steps.len() {
                    let first_event = q.events.first().cloned().unwrap_or_default();
                    if done.insert(first_event) {
                        let caps: Vec<String> = q.caps.iter().map(|(k, v)| format!("{k}={v}")).collect();
                        out.push(Match {
                            rule: r.id.clone(),
                            title: r.title.clone(),
                            level: r.level,
                            confidence: r.confidence,
                            technique: r.technique.clone(),
                            pid: q.pid,
                            events: q.events.clone(),
                            evidence: format!("{} within {} s{}: events {}", r.title, r.within_secs, if caps.is_empty() { String::new() } else { format!(" ({})", caps.join(", ")) }, q.events.join(" → ")),
                            at: e.time,
                        });
                    }
                } else {
                    keep.push(q);
                }
            }
            if keep.len() > MAX_PARTIALS {
                let drop = keep.len() - MAX_PARTIALS;
                keep.drain(..drop);
            }
            partials = keep;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(secs: i64, kind: &'static str, pid: Option<u32>, parent: Option<u32>, fields: &[(&'static str, &str)]) -> Ev {
        Ev {
            time: chrono::DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap().with_timezone(&Local),
            id: format!("e{secs}"),
            kind,
            pid,
            lineage: pid.into_iter().chain(parent).chain(std::iter::once(1)).collect(),
            fields: fields.iter().map(|(k, v)| (*k, v.to_string())).collect(),
        }
    }

    #[test]
    fn builtin_rules_parse() {
        let (r, e) = parse(include_str!("../rules/behavior/procwatch-builtin.yml"));
        assert!(e.is_empty(), "{e:?}");
        assert!(r.len() >= 5);
    }

    #[test]
    fn dropped_then_executed_uses_capture() {
        let rules = builtin();
        let evs = vec![
            ev(0, "file_write", None, None, &[("path", "/Users/a/Downloads/tool")]),
            ev(5, "process_start", Some(9), Some(9), &[("image", "/usr/bin/true"), ("name", "true")]),
            ev(30, "process_start", Some(10), Some(10), &[("image", "/Users/a/Downloads/tool"), ("name", "tool")]),
        ];
        let m = evaluate(&rules, &evs);
        let hit = m.iter().find(|m| m.rule == "pw-seq-001").expect("dropped and executed");
        assert_eq!(hit.events, vec!["e0", "e30"]);
        assert_eq!(hit.pid, Some(10));
        // Outside the window: no match.
        let late = vec![evs[0].clone(), ev(5000, "process_start", Some(10), Some(10), &[("image", "/Users/a/Downloads/tool")])];
        assert!(!evaluate(&rules, &late).iter().any(|m| m.rule == "pw-seq-001"));
    }

    #[test]
    fn discovery_burst_counts_distinct_names_in_one_tree() {
        let rules = builtin();
        let mut evs: Vec<Ev> = ["whoami", "id", "uname", "hostname", "ifconfig"]
            .iter()
            .enumerate()
            .map(|(i, n)| ev(i as i64, "process_start", Some(100 + i as u32), Some(50), &[("name", n), ("image", &format!("/usr/bin/{n}"))]))
            .collect();
        assert!(evaluate(&rules, &evs).iter().any(|m| m.rule == "pw-seq-005"));
        // Same command five times is not a burst; another tree doesn't count.
        evs = (0..5).map(|i| ev(i, "process_start", Some(200 + i as u32), Some(60), &[("name", "id")])).collect();
        evs.push(ev(6, "process_start", Some(300), Some(61), &[("name", "whoami")]));
        assert!(!evaluate(&rules, &evs).iter().any(|m| m.rule == "pw-seq-005"));
    }

    #[test]
    fn rejects_bad_rules() {
        let (_, e) = parse("id: x\nwithin: 10s\nsteps:\n  - event: teleport\n");
        assert!(e[0].contains("unknown event"));
        let (_, e) = parse("id: y\nwithin: soon\nsteps:\n  - event: file_write\n");
        assert!(e[0].contains("within"));
    }
}
