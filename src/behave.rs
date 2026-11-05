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

use std::borrow::Cow;
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
    if let Some(dir) = crate::common::paths::config_path().map(|p| p.with_file_name("behavior")).filter(|d| d.is_dir()) {
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

/// A value with `{name}` references filled in, lowercased. None when it
/// refers to something not captured. `caps` holds lowercased values.
fn resolve<'a>(v: &'a str, caps: &'a HashMap<String, String>) -> Option<Cow<'a, str>> {
    if !v.contains('{') {
        return Some(if v.chars().any(char::is_uppercase) { Cow::Owned(v.to_lowercase()) } else { Cow::Borrowed(v) });
    }
    if let Some(val) = v.strip_prefix('{').and_then(|r| r.strip_suffix('}')).and_then(|k| caps.get(k)) {
        return Some(Cow::Borrowed(val));
    }
    let mut out = String::with_capacity(v.len());
    let mut rest = v;
    while let Some((i, j)) = rest.find('{').and_then(|i| Some((i, i + rest[i..].find('}')?))) {
        out.push_str(&rest[..i].to_lowercase());
        out.push_str(caps.get(&rest[i + 1..j])?);
        rest = &rest[j + 1..];
    }
    out.push_str(&rest.to_lowercase());
    Some(Cow::Owned(out))
}

/// Field values of one event, lowercased once rather than per comparison.
type Lowered<'a> = BTreeMap<&'a str, String>;

fn cond_ok(c: &Cond, fields: &Lowered, caps: &HashMap<String, String>) -> bool {
    let Some(actual) = fields.get(c.field.as_str()) else { return false };
    c.values.iter().any(|v| {
        let Some(want) = resolve(v, caps) else { return false };
        match c.op {
            "contains" => actual.contains(want.as_ref()),
            "startswith" => actual.starts_with(want.as_ref()),
            "endswith" => actual.ends_with(want.as_ref()),
            _ => *actual == *want,
        }
    })
}

fn step_ok(s: &Step, e: &Ev, fields: &Lowered, caps: &HashMap<String, String>) -> bool {
    s.event == e.kind && s.conds.iter().all(|c| cond_ok(c, fields, caps))
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
    /// As seen, for the evidence text.
    caps: HashMap<String, String>,
    /// Lowercased, for matching.
    lower_caps: HashMap<String, String>,
    events: Vec<String>,
    distinct: BTreeSet<String>,
}

impl Partial {
    fn capture(&mut self, step: &Step, e: &Ev) {
        for (name, field) in &step.capture {
            if let Some(v) = e.fields.get(field.as_str()) {
                self.caps.insert(name.clone(), v.clone());
                self.lower_caps.insert(name.clone(), v.to_lowercase());
            }
        }
    }
}

/// Live partials per step of a rule.
const MAX_PARTIALS: usize = 2000;

/// Run every rule over `events` (oldest first).
///
/// Partials wait in one list per step, so an event only touches those
/// waiting for its kind. File writes start a partial each and thousands can
/// be live, while the step they wait for (a process start) is rare.
pub fn evaluate(rules: &[Rule], events: &[Ev]) -> Vec<Match> {
    let lowered: Vec<Lowered> = events.iter().map(|e| e.fields.iter().map(|(k, v)| (*k, v.to_lowercase())).collect()).collect();
    let none = HashMap::new();
    let mut out = Vec::new();
    for r in rules {
        let mut waiting: Vec<Vec<Partial>> = vec![Vec::new(); r.steps.len()];
        let mut done: BTreeSet<String> = BTreeSet::new();
        let window = chrono::Duration::seconds(r.within_secs);
        let in_scope = |p: &Partial, e: &Ev| match (r.scope.as_str(), p.scope) {
            (_, None) | ("any", _) => true,
            ("process", Some(a)) => e.pid == Some(a.pid),
            (_, Some(a)) => a.tree(e),
        };
        for (e, fields) in events.iter().zip(&lowered) {
            if !r.steps.iter().any(|s| s.event == e.kind) {
                continue;
            }
            let mut next: Vec<Partial> = Vec::new();
            for (at, s) in r.steps.iter().enumerate() {
                if s.event != e.kind {
                    continue;
                }
                let list = &mut waiting[at];
                list.retain(|p| e.time - p.start <= window);
                // Count steps advance in place: keeping the original as well
                // would double the partial on every matching event.
                let mut consumed: Vec<usize> = Vec::new();
                for (idx, p) in list.iter().enumerate() {
                    if !in_scope(p, e) || !step_ok(s, e, fields, &p.lower_caps) {
                        continue;
                    }
                    let mut q = p.clone();
                    if s.count > 1 {
                        let key = s.distinct.as_ref().and_then(|d| e.fields.get(d.as_str()).cloned()).unwrap_or_else(|| e.id.clone());
                        if !q.distinct.insert(key.to_lowercase()) {
                            continue;
                        }
                        q.events.push(e.id.clone());
                        consumed.push(idx);
                        if q.distinct.len() < s.count {
                            next.push(q);
                            continue;
                        }
                        q.distinct.clear();
                    } else {
                        q.events.push(e.id.clone());
                    }
                    q.capture(s, e);
                    q.pid = q.pid.or(e.pid);
                    if q.scope.is_none() && r.scope != "any" {
                        q.scope = Anchor::of(e);
                    }
                    q.step += 1;
                    next.push(q);
                }
                if !consumed.is_empty() {
                    let (mut idx, mut used) = (0, consumed.iter().copied().peekable());
                    list.retain(|_| {
                        let hit = used.next_if_eq(&idx).is_some();
                        idx += 1;
                        !hit
                    });
                }
            }
            // A new sequence can start at this event.
            let first = &r.steps[0];
            if step_ok(first, e, fields, &none) {
                let mut p = Partial {
                    step: 0,
                    start: e.time,
                    scope: if r.scope == "any" { None } else { Anchor::of(e) },
                    pid: e.pid,
                    caps: HashMap::new(),
                    lower_caps: HashMap::new(),
                    events: vec![e.id.clone()],
                    distinct: BTreeSet::new(),
                };
                if first.count > 1 {
                    let key = first.distinct.as_ref().and_then(|d| e.fields.get(d.as_str()).cloned()).unwrap_or_else(|| e.id.clone());
                    p.distinct.insert(key.to_lowercase());
                } else {
                    p.capture(first, e);
                    p.step = 1;
                }
                next.push(p);
            }
            // Complete sequences become matches (once per first event);
            // the rest wait for their next step.
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
                    let list = &mut waiting[q.step];
                    list.push(q);
                    if list.len() > MAX_PARTIALS {
                        let drop = list.len() - MAX_PARTIALS;
                        list.drain(..drop);
                    }
                }
            }
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
    fn a_write_among_thousands_still_matches_and_count_steps_advance() {
        let mut evs: Vec<Ev> = (0..4000).map(|i| ev(i / 100, "file_write", None, None, &[("path", &format!("/Users/a/Downloads/f{i}"))])).collect();
        evs.push(ev(50, "process_start", Some(7), Some(1), &[("image", "/Users/a/Downloads/f3999"), ("name", "f3999")]));
        for (i, n) in ["whoami", "id", "uname", "hostname", "ifconfig", "ps", "netstat", "ls"].iter().enumerate() {
            evs.push(ev(51 + i as i64, "process_start", Some(20 + i as u32), Some(7), &[("name", n)]));
        }
        evs.sort_by_key(|e| e.time);
        let t = std::time::Instant::now();
        let m = evaluate(&builtin(), &evs);
        assert!(m.iter().any(|x| x.rule == "pw-seq-001"), "{m:?}");
        assert!(m.iter().any(|x| x.rule == "pw-seq-005"), "{m:?}");
        assert!(t.elapsed() < std::time::Duration::from_secs(5), "{:?}", t.elapsed());
    }

    #[test]
    fn captured_paths_with_braces_and_case_differences_match() {
        let dir = r"C:\Users\A\Temp\{6F9619FF-8B86-D011-B42D-00C04FC964FF}\Tool.EXE";
        let evs = vec![
            ev(0, "file_write", None, None, &[("path", dir)]),
            ev(1, "process_start", Some(7), Some(1), &[("image", &dir.to_lowercase()), ("name", "tool.exe")]),
        ];
        assert!(evaluate(&builtin(), &evs).iter().any(|m| m.rule == "pw-seq-001"));
        let caps: HashMap<String, String> = [("a".to_string(), "x{y}".to_string())].into();
        assert_eq!(resolve("{a}", &caps).as_deref(), Some("x{y}"));
        assert_eq!(resolve("Pre/{a}/End", &caps).as_deref(), Some("pre/x{y}/end"));
        assert_eq!(resolve("{missing}", &caps), None);
        assert_eq!(resolve("Plain", &caps).as_deref(), Some("plain"));
    }

    #[test]
    fn a_later_step_expires_with_the_window() {
        let evs = vec![
            ev(0, "file_write", None, None, &[("path", "/tmp/x")]),
            ev(100_000, "process_start", Some(7), Some(1), &[("image", "/tmp/x"), ("name", "x")]),
        ];
        assert!(!evaluate(&builtin(), &evs).iter().any(|m| m.rule == "pw-seq-001"));
    }

    #[test]
    fn rejects_bad_rules() {
        let (_, e) = parse("id: x\nwithin: 10s\nsteps:\n  - event: teleport\n");
        assert!(e[0].contains("unknown event"));
        let (_, e) = parse("id: y\nwithin: soon\nsteps:\n  - event: file_write\n");
        assert!(e[0].contains("within"));
    }
}
