//! A Sigma rule engine for the subset of the format that single-event
//! detection needs, plus the field-mapping layer that turns what procwatch
//! sees (processes, sockets, file changes, log lines, EVTX records,
//! execution artifacts) into Sigma's field names.
//!
//! Supported:
//! - `logsource` category / product / service matching
//! - selections as maps (AND of fields) or lists of maps (OR); keyword lists
//! - values: strings with `*` / `?` wildcards (case-insensitive), numbers,
//!   booleans, `null`; lists are OR unless `|all`
//! - modifiers `contains`, `startswith`, `endswith`, `all`, `exists`,
//!   `cidr`, `gt`, `gte`, `lt`, `lte`, `windash`
//! - conditions with `and`, `or`, `not`, parentheses, `1 of x*`,
//!   `all of x*`, `1 of them`, `all of them`; a list of conditions is OR
//!
//! Rules that need anything else (`re`, `base64offset`, aggregations such
//! as `| count()`, correlation rules) are rejected with a reason rather
//! than silently mis-evaluated.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::model::{Confidence, Severity};

#[derive(Debug, Clone, Default, Serialize)]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

#[derive(Debug, Clone)]
enum Value {
    Pattern(String),
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Op {
    Glob,
    Contains,
    StartsWith,
    EndsWith,
    Exists,
    Cidr,
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Debug, Clone)]
struct FieldCond {
    field: String,
    op: Op,
    all: bool,
    windash: bool,
    values: Vec<Value>,
}

#[derive(Debug, Clone)]
enum Selection {
    /// Map: every field condition must hold.
    All(Vec<FieldCond>),
    /// List of maps: any may hold.
    Any(Vec<Selection>),
    /// List of plain values: any must appear in any field.
    Keywords(Vec<String>),
}

#[derive(Debug, Clone)]
enum Cond {
    Sel(String),
    Not(Box<Cond>),
    And(Vec<Cond>),
    Or(Vec<Cond>),
    OneOf(String),
    AllOf(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub level: Severity,
    pub confidence: Confidence,
    pub status: String,
    pub tags: Vec<String>,
    pub logsource: LogSource,
    pub file: String,
    #[serde(skip)]
    selections: BTreeMap<String, Selection>,
    #[serde(skip)]
    condition: Cond,
}

impl Rule {
    /// ATT&CK technique from tags like `attack.t1059.001`.
    pub fn technique(&self) -> String {
        self.tags
            .iter()
            .filter_map(|t| t.strip_prefix("attack.t"))
            .map(|t| format!("T{}", t.to_uppercase()))
            .next()
            .unwrap_or_default()
    }
}

/// One thing to evaluate rules against, in Sigma's vocabulary.
#[derive(Debug, Clone, Default)]
pub struct Event {
    pub category: &'static str,
    pub product: &'static str,
    pub service: String,
    pub fields: BTreeMap<String, String>,
}

impl Event {
    pub fn new(category: &'static str) -> Event {
        Event { category, product: crate::sigma::product(), ..Default::default() }
    }
    pub fn set(&mut self, k: &str, v: impl Into<String>) -> &mut Event {
        let v = v.into();
        if !v.is_empty() {
            self.fields.insert(k.to_string(), v);
        }
        self
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.fields.get(k).map(String::as_str).or_else(|| {
            self.fields.iter().find(|(name, _)| name.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
        })
    }
}

pub fn product() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

// ── loading ────────────────────────────────────────────────────────────

fn yaml_str(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn parse_values(v: &serde_yaml::Value) -> Result<Vec<Value>, String> {
    match v {
        serde_yaml::Value::Null => Ok(vec![Value::Null]),
        serde_yaml::Value::Sequence(items) => items.iter().map(|i| parse_values(i).map(|mut v| v.remove(0))).collect(),
        other => yaml_str(other).map(|s| vec![Value::Pattern(s)]).ok_or_else(|| "unsupported value type".to_string()),
    }
}

fn parse_map(m: &serde_yaml::Mapping) -> Result<Selection, String> {
    let mut conds = Vec::new();
    for (k, v) in m {
        let key = yaml_str(k).ok_or("field name must be text")?;
        let mut parts = key.split('|');
        let field = parts.next().unwrap_or_default().to_string();
        let (mut op, mut all, mut windash) = (Op::Glob, false, false);
        for m in parts {
            match m {
                "contains" => op = Op::Contains,
                "startswith" => op = Op::StartsWith,
                "endswith" => op = Op::EndsWith,
                "exists" => op = Op::Exists,
                "cidr" => op = Op::Cidr,
                "gt" => op = Op::Gt,
                "gte" => op = Op::Gte,
                "lt" => op = Op::Lt,
                "lte" => op = Op::Lte,
                "all" => all = true,
                "windash" => windash = true,
                other => return Err(format!("modifier '{other}' is not supported")),
            }
        }
        conds.push(FieldCond { field, op, all, windash, values: parse_values(v)? });
    }
    Ok(Selection::All(conds))
}

fn parse_selection(v: &serde_yaml::Value) -> Result<Selection, String> {
    match v {
        serde_yaml::Value::Mapping(m) => parse_map(m),
        serde_yaml::Value::Sequence(items) if items.iter().all(|i| i.is_mapping()) => {
            Ok(Selection::Any(items.iter().map(parse_selection).collect::<Result<_, _>>()?))
        }
        serde_yaml::Value::Sequence(items) => Ok(Selection::Keywords(items.iter().filter_map(yaml_str).collect())),
        other => yaml_str(other).map(|s| Selection::Keywords(vec![s])).ok_or_else(|| "unsupported selection".into()),
    }
}

fn tokenize(s: &str) -> Vec<String> {
    s.replace('(', " ( ").replace(')', " ) ").split_whitespace().map(str::to_string).collect()
}

/// Rules come from anywhere; a stack overflow can't be caught.
const MAX_NESTING: usize = 64;

struct Parser {
    depth: usize,
    toks: Vec<String>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&str> {
        self.toks.get(self.pos).map(String::as_str)
    }
    fn next(&mut self) -> Option<String> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }
    fn expr(&mut self) -> Result<Cond, String> {
        let mut terms = vec![self.term()?];
        while self.peek().is_some_and(|t| t.eq_ignore_ascii_case("or")) {
            self.pos += 1;
            terms.push(self.term()?);
        }
        Ok(if terms.len() == 1 { terms.remove(0) } else { Cond::Or(terms) })
    }
    fn term(&mut self) -> Result<Cond, String> {
        let mut f = vec![self.factor()?];
        while self.peek().is_some_and(|t| t.eq_ignore_ascii_case("and")) {
            self.pos += 1;
            f.push(self.factor()?);
        }
        Ok(if f.len() == 1 { f.remove(0) } else { Cond::And(f) })
    }
    fn factor(&mut self) -> Result<Cond, String> {
        self.depth += 1;
        if self.depth > MAX_NESTING {
            return Err("condition nested too deeply".into());
        }
        let c = self.factor_inner();
        self.depth -= 1;
        c
    }
    fn factor_inner(&mut self) -> Result<Cond, String> {
        let t = self.next().ok_or("condition ends too early")?;
        match t.to_lowercase().as_str() {
            "not" => Ok(Cond::Not(Box::new(self.factor()?))),
            "(" => {
                let e = self.expr()?;
                if self.next().as_deref() != Some(")") {
                    return Err("missing ')' in condition".into());
                }
                Ok(e)
            }
            "1" | "any" | "all" => {
                if !self.next().is_some_and(|t| t.eq_ignore_ascii_case("of")) {
                    return Err(format!("expected 'of' after '{t}'"));
                }
                let target = self.next().ok_or("expected a selection name after 'of'")?;
                Ok(if t == "all" { Cond::AllOf(target) } else { Cond::OneOf(target) })
            }
            "|" => Err("aggregations ('| count()' etc.) are not supported".into()),
            _ => Ok(Cond::Sel(t)),
        }
    }
}

fn parse_condition(s: &str) -> Result<Cond, String> {
    if s.contains('|') {
        return Err("aggregations ('| count()' etc.) are not supported".into());
    }
    let mut p = Parser { depth: 0, toks: tokenize(s), pos: 0 };
    let c = p.expr()?;
    if p.pos < p.toks.len() {
        return Err(format!("unexpected '{}' in condition", p.toks[p.pos]));
    }
    Ok(c)
}

fn parse_rule(doc: &serde_yaml::Value, file: &str) -> Result<Rule, String> {
    let get = |k: &str| doc.get(k);
    let s = |k: &str| get(k).and_then(yaml_str).unwrap_or_default();
    if get("correlation").is_some() || s("action") == "global" {
        return Err("correlation and multi-document rules are not supported".into());
    }
    let title = s("title");
    let det = get("detection").and_then(|d| d.as_mapping()).ok_or("no detection section")?;
    let mut selections = BTreeMap::new();
    let mut condition = None;
    for (k, v) in det {
        let name = yaml_str(k).unwrap_or_default();
        if name == "condition" {
            condition = Some(match v {
                serde_yaml::Value::Sequence(list) => {
                    Cond::Or(list.iter().filter_map(yaml_str).map(|c| parse_condition(&c)).collect::<Result<_, _>>()?)
                }
                other => parse_condition(&yaml_str(other).ok_or("condition must be text")?)?,
            });
        } else if name != "timeframe" {
            selections.insert(name.clone(), parse_selection(v).map_err(|e| format!("{name}: {e}"))?);
        }
    }
    let condition = condition.ok_or("no condition")?;
    check_refs(&condition, &selections)?;
    let ls = get("logsource");
    let lsf = |k: &str| ls.and_then(|l| l.get(k)).and_then(yaml_str).map(|v| v.to_lowercase());
    let status = s("status");
    Ok(Rule {
        id: if s("id").is_empty() { title.clone() } else { s("id") },
        title: if title.is_empty() { file.to_string() } else { title },
        description: s("description"),
        level: Severity::parse(&s("level")),
        confidence: match status.as_str() {
            "stable" => Confidence::High,
            "experimental" | "unsupported" | "deprecated" => Confidence::Low,
            _ => Confidence::Medium,
        },
        status,
        tags: get("tags").and_then(|t| t.as_sequence()).map(|t| t.iter().filter_map(yaml_str).map(|t| t.to_lowercase()).collect()).unwrap_or_default(),
        logsource: LogSource { category: lsf("category"), product: lsf("product"), service: lsf("service") },
        file: file.to_string(),
        selections,
        condition,
    })
}

fn names_matching<'a>(pat: &str, sels: &'a BTreeMap<String, Selection>) -> Vec<&'a String> {
    sels.keys().filter(|k| pat == "them" || glob(&k.to_lowercase(), &pat.to_lowercase())).collect()
}

fn check_refs(c: &Cond, sels: &BTreeMap<String, Selection>) -> Result<(), String> {
    match c {
        Cond::Sel(n) if !sels.contains_key(n) => Err(format!("condition names unknown selection '{n}'")),
        Cond::OneOf(p) | Cond::AllOf(p) if names_matching(p, sels).is_empty() => Err(format!("'{p}' matches no selection")),
        Cond::Not(c) => check_refs(c, sels),
        Cond::And(v) | Cond::Or(v) => v.iter().try_for_each(|c| check_refs(c, sels)),
        _ => Ok(()),
    }
}

/// Parse every rule in a YAML text (several documents allowed).
pub fn parse(text: &str, file: &str) -> (Vec<Rule>, Vec<String>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    for (n, doc) in serde_yaml::Deserializer::from_str(text).enumerate() {
        let value = match serde_yaml::Value::deserialize(doc) {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("{file}: {e}"));
                break;
            }
        };
        if value.is_null() {
            continue;
        }
        match parse_rule(&value, file) {
            Ok(r) => rules.push(r),
            Err(e) => errors.push(format!("{file}#{}: {e}", n + 1)),
        }
    }
    (rules, errors)
}

/// Load every `.yml` / `.yaml` file under `dir` (recursively).
pub fn load_dir(dir: &Path) -> (Vec<Rule>, Vec<String>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    let mut files = 0;
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            if d == dir {
                errors.push(format!("can't read rule folder {}", dir.display()));
            }
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "yml" || x == "yaml") && files < 5000 {
                files += 1;
                match std::fs::read_to_string(&p) {
                    Ok(t) => {
                        let (r, e) = parse(&t, &p.file_name().unwrap_or_default().to_string_lossy());
                        rules.extend(r);
                        errors.extend(e);
                    }
                    Err(e) => errors.push(format!("{}: {e}", p.display())),
                }
            }
        }
    }
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    (rules, errors)
}

/// Rules shipped inside the binary (rules/sigma/procwatch-builtin.yml).
pub fn builtin() -> Vec<Rule> {
    parse(include_str!("../rules/sigma/procwatch-builtin.yml"), "built-in").0
}

/// Default rule folder: `sigma/` next to the settings file.
pub fn default_dir() -> Option<std::path::PathBuf> {
    crate::config::path().map(|p| p.with_file_name("sigma"))
}

// ── evaluation ─────────────────────────────────────────────────────────

/// Case-insensitive glob with `*` and `?`; `\*` `\?` `\\` are literals.
/// Both sides must already be lowercase.
fn glob(text: &str, pat: &str) -> bool {
    #[derive(Clone, Copy, PartialEq)]
    enum T {
        Star,
        One,
        Ch(char),
    }
    let mut toks = Vec::new();
    let mut it = pat.chars();
    while let Some(c) = it.next() {
        toks.push(match c {
            '*' => T::Star,
            '?' => T::One,
            '\\' => match it.clone().next() {
                Some(n @ ('*' | '?' | '\\')) => {
                    it.next();
                    T::Ch(n)
                }
                _ => T::Ch('\\'),
            },
            c => T::Ch(c),
        });
    }
    let t: Vec<char> = text.chars().collect();
    // Iterative matcher with single backtrack point.
    let (mut ti, mut pi) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        match toks.get(pi) {
            Some(T::Ch(c)) if *c == t[ti] => {
                ti += 1;
                pi += 1;
            }
            Some(T::One) => {
                ti += 1;
                pi += 1;
            }
            Some(T::Star) => {
                star = Some(pi);
                mark = ti;
                pi += 1;
            }
            _ => match star {
                Some(s) => {
                    pi = s + 1;
                    mark += 1;
                    ti = mark;
                }
                None => return false,
            },
        }
    }
    toks[pi..].iter().all(|t| *t == T::Star)
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('*', "\\*").replace('?', "\\?")
}

fn cidr(ip: &str, net: &str) -> bool {
    let Some((base, bits)) = net.split_once('/') else { return ip == net };
    let Ok(bits) = bits.parse::<u32>() else { return false };
    match (ip.trim_matches(['[', ']']).parse::<std::net::IpAddr>(), base.parse::<std::net::IpAddr>()) {
        (Ok(std::net::IpAddr::V4(a)), Ok(std::net::IpAddr::V4(b))) if bits <= 32 => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (Ok(std::net::IpAddr::V6(a)), Ok(std::net::IpAddr::V6(b))) if bits <= 128 => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}

fn value_matches(fc: &FieldCond, actual: Option<&str>, v: &Value) -> bool {
    let Value::Pattern(p) = v else { return actual.is_none_or(str::is_empty) };
    let Some(actual) = actual else { return false };
    let a = actual.to_lowercase();
    let p = p.to_lowercase();
    let num = |x: &str| x.trim().parse::<f64>().ok();
    match fc.op {
        Op::Exists => (p == "true") == !actual.is_empty(),
        Op::Cidr => cidr(actual, &p),
        Op::Gt | Op::Gte | Op::Lt | Op::Lte => match (num(&a), num(&p)) {
            (Some(x), Some(y)) => match fc.op {
                Op::Gt => x > y,
                Op::Gte => x >= y,
                Op::Lt => x < y,
                _ => x <= y,
            },
            _ => false,
        },
        _ => {
            let variants: Vec<String> = if fc.windash && p.contains('-') {
                ["-", "/", "–", "—"].iter().map(|d| p.replacen('-', d, 1)).collect()
            } else {
                vec![p]
            };
            variants.iter().any(|p| {
                let pat = match fc.op {
                    Op::Contains => format!("*{p}*"),
                    Op::StartsWith => format!("{p}*"),
                    Op::EndsWith => format!("*{p}"),
                    _ => p.clone(),
                };
                glob(&a, &pat)
            })
        }
    }
}

fn field_matches(fc: &FieldCond, e: &Event) -> bool {
    if fc.op == Op::Exists {
        let present = e.get(&fc.field).is_some();
        return fc.values.iter().any(|v| matches!(v, Value::Pattern(p) if (p.eq_ignore_ascii_case("true")) == present));
    }
    let actual = e.get(&fc.field);
    if fc.all {
        fc.values.iter().all(|v| value_matches(fc, actual, v))
    } else {
        fc.values.iter().any(|v| value_matches(fc, actual, v))
    }
}

fn selection_matches(s: &Selection, e: &Event) -> bool {
    match s {
        Selection::All(conds) => conds.iter().all(|c| field_matches(c, e)),
        Selection::Any(list) => list.iter().any(|s| selection_matches(s, e)),
        Selection::Keywords(words) => {
            let hay: Vec<String> = e.fields.values().map(|v| v.to_lowercase()).collect();
            words.iter().any(|w| {
                let w = w.to_lowercase();
                let pat = if w.contains('*') { w } else { format!("*{}*", escape(&w)) };
                hay.iter().any(|h| glob(h, &pat))
            })
        }
    }
}

fn eval(c: &Cond, r: &Rule, e: &Event) -> bool {
    match c {
        Cond::Sel(n) => r.selections.get(n).is_some_and(|s| selection_matches(s, e)),
        Cond::Not(c) => !eval(c, r, e),
        Cond::And(v) => v.iter().all(|c| eval(c, r, e)),
        Cond::Or(v) => v.iter().any(|c| eval(c, r, e)),
        Cond::OneOf(p) => names_matching(p, &r.selections).iter().any(|n| selection_matches(&r.selections[*n], e)),
        Cond::AllOf(p) => names_matching(p, &r.selections).iter().all(|n| selection_matches(&r.selections[*n], e)),
    }
}

fn logsource_matches(ls: &LogSource, e: &Event) -> bool {
    ls.category.as_deref().is_none_or(|c| c == e.category)
        && ls.product.as_deref().is_none_or(|p| p == e.product)
        && ls.service.as_deref().is_none_or(|s| s.eq_ignore_ascii_case(&e.service))
}

impl Rule {
    pub fn matches(&self, e: &Event) -> bool {
        logsource_matches(&self.logsource, e) && eval(&self.condition, self, e)
    }

    /// The field values that made the rule match, for the evidence line.
    pub fn evidence(&self, e: &Event) -> String {
        let mut fields: Vec<&str> = Vec::new();
        for s in self.selections.values() {
            collect_fields(s, &mut fields);
        }
        fields.sort();
        fields.dedup();
        let parts: Vec<String> =
            fields.iter().filter_map(|f| e.get(f).map(|v| format!("{f}={}", v.chars().take(160).collect::<String>()))).collect();
        if parts.is_empty() { format!("{} event", e.category) } else { parts.join(" · ") }
    }
}

fn collect_fields<'a>(s: &'a Selection, out: &mut Vec<&'a str>) {
    match s {
        Selection::All(c) => out.extend(c.iter().map(|c| c.field.as_str())),
        Selection::Any(v) => v.iter().for_each(|s| collect_fields(s, out)),
        Selection::Keywords(_) => {}
    }
}

/// Every rule that matches `e`.
pub fn evaluate<'a>(rules: &'a [Rule], e: &Event) -> Vec<&'a Rule> {
    rules.iter().filter(|r| r.matches(e)).collect()
}

// ── field mapping ──────────────────────────────────────────────────────

/// Mapping from what procwatch observes to Sigma field names. One place,
/// so rules don't depend on platform-specific record layouts.
pub mod map {
    use super::Event;
    use crate::process::ProcessInfo;

    pub fn process(p: &ProcessInfo, parent: Option<&ProcessInfo>, sha256: Option<&str>, md5: Option<&str>) -> Event {
        let mut e = Event::new("process_creation");
        e.set("Image", p.exe_path.clone().unwrap_or_else(|| p.name.clone()))
            .set("CommandLine", p.cmd.join(" "))
            .set("ProcessId", p.pid.to_string())
            .set("User", p.user.clone().unwrap_or_default())
            .set("CurrentDirectory", p.cwd.clone().unwrap_or_default());
        if let Some(pp) = parent {
            e.set("ParentImage", pp.exe_path.clone().unwrap_or_else(|| pp.name.clone()))
                .set("ParentCommandLine", pp.cmd.join(" "))
                .set("ParentProcessId", pp.pid.to_string());
        }
        let mut hashes = Vec::new();
        if let Some(h) = sha256 {
            hashes.push(format!("SHA256={}", h.to_uppercase()));
        }
        if let Some(h) = md5 {
            hashes.push(format!("MD5={}", h.to_uppercase()));
        }
        e.set("Hashes", hashes.join(","));
        e
    }

    pub fn connection(image: &str, pid: u32, proto: &str, local: &str, remote: &str, listening: bool) -> Event {
        let (sip, sport) = crate::filter::split_endpoint(local);
        let (dip, dport) = crate::filter::split_endpoint(remote);
        let mut e = Event::new("network_connection");
        e.set("Image", image)
            .set("ProcessId", pid.to_string())
            .set("Protocol", proto.to_lowercase())
            .set("SourceIp", sip)
            .set("SourcePort", sport)
            .set("Initiated", if listening { "false" } else { "true" });
        if !listening {
            e.set("DestinationIp", dip).set("DestinationPort", dport);
        }
        e
    }

    pub fn file(kind: &str, path: &str) -> Event {
        let mut e = Event::new(match kind {
            "deleted" | "removed" => "file_delete",
            "renamed" => "file_rename",
            "modified" => "file_change",
            _ => "file_event",
        });
        e.set("TargetFilename", path);
        e
    }

    /// A line from the live system log (macOS unified log, journald,
    /// Windows event log via PowerShell).
    pub fn log_line(source: &str, process: &str, pid: Option<u32>, level: &str, message: &str, event_id: Option<u32>) -> Event {
        let mut e = Event::new("");
        e.service = service_of(source);
        e.set("Channel", source)
            .set("Provider_Name", source)
            .set("Image", process)
            .set("ProcessId", pid.map(|p| p.to_string()).unwrap_or_default())
            .set("Level", level)
            .set("Message", message);
        if let Some(id) = event_id {
            e.set("EventID", id.to_string());
        }
        e
    }

    /// Sigma's `service` from a Windows channel / log source name.
    pub fn service_of(channel: &str) -> String {
        let c = channel.to_lowercase();
        let known = [
            ("microsoft-windows-sysmon", "sysmon"),
            ("powershell", "powershell"),
            ("windows defender", "windefend"),
            ("taskscheduler", "taskscheduler"),
            ("security", "security"),
            ("system", "system"),
            ("application", "application"),
        ];
        known.iter().find(|(k, _)| c.contains(k)).map(|(_, s)| s.to_string()).unwrap_or(c)
    }

    /// A parsed Windows event record (from an EVTX file). Sysmon and the
    /// Security log's 4688 are mapped to `process_creation` etc. so the
    /// same rules apply to live and recorded data.
    pub fn windows_record(channel: &str, provider: &str, event_id: u32, data: &std::collections::BTreeMap<String, String>) -> Event {
        let service = service_of(channel);
        let category: &'static str = match (service.as_str(), event_id) {
            ("sysmon", 1) | ("security", 4688) => "process_creation",
            ("sysmon", 3) => "network_connection",
            ("sysmon", 11) => "file_event",
            ("sysmon", 23) | ("sysmon", 26) => "file_delete",
            ("sysmon", 12) | ("sysmon", 13) | ("sysmon", 14) => "registry_event",
            ("sysmon", 7) => "image_load",
            ("sysmon", 22) => "dns_query",
            ("powershell", 4104) => "ps_script",
            _ => "",
        };
        let mut e = Event::new(category);
        e.product = "windows";
        e.service = service;
        for (k, v) in data {
            e.set(k, v.clone());
        }
        e.set("EventID", event_id.to_string()).set("Channel", channel).set("Provider_Name", provider);
        if service_of(channel) == "security" && event_id == 4688 {
            // Security 4688 names differ from Sysmon's.
            let copy = |e: &mut Event, from: &str, to: &str| {
                if let Some(v) = data.get(from) {
                    e.set(to, v.clone());
                }
            };
            copy(&mut e, "NewProcessName", "Image");
            copy(&mut e, "ParentProcessName", "ParentImage");
            copy(&mut e, "SubjectUserName", "User");
        }
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deeply_nested_conditions_are_rejected() {
        assert!(parse_condition(&format!("{}a{}", "( ".repeat(100_000), " )".repeat(100_000))).is_err());
        assert!(parse_condition(&format!("{}a", "not ".repeat(100_000))).is_err());
        assert!(parse_condition("not ( a and ( b or not c ) )").is_ok());
    }

    const RULES: &str = r#"
title: Shell from document
id: t-1
status: stable
level: high
tags: [attack.execution, attack.t1059.004]
logsource: { category: process_creation }
detection:
  parent:
    ParentImage|endswith: ['/Microsoft Word', '\winword.exe']
  child:
    Image|endswith: ['/sh', '/bash', '\cmd.exe']
  filter:
    CommandLine|contains: 'safe-helper'
  condition: parent and child and not filter
---
title: Any of
id: t-2
logsource: { category: network_connection }
detection:
  sel_port:
    DestinationPort: [4444, 1337]
  sel_net:
    DestinationIp|cidr: 203.0.113.0/24
  condition: 1 of sel_*
---
title: Bad
logsource: { category: process_creation }
detection:
  sel:
    CommandLine|re: 'x.*'
  condition: sel
---
title: Count
logsource: { category: process_creation }
detection:
  sel: { Image: x }
  condition: sel | count() > 5
"#;

    #[test]
    fn parses_supported_rules_and_rejects_the_rest() {
        let (rules, errors) = parse(RULES, "test.yml");
        assert_eq!(rules.len(), 2, "{errors:?}");
        assert_eq!(errors.len(), 2);
        assert!(errors[0].contains("'re'"));
        assert!(errors[1].contains("aggregations"));
        assert_eq!(rules[0].level, Severity::High);
        assert_eq!(rules[0].confidence, Confidence::High);
        assert_eq!(rules[0].technique(), "T1059.004");
    }

    #[test]
    fn evaluates_conditions() {
        let (rules, _) = parse(RULES, "test.yml");
        let mut e = Event::new("process_creation");
        e.set("ParentImage", "/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word").set("Image", "/bin/sh").set("CommandLine", "sh -c id");
        assert_eq!(evaluate(&rules, &e).len(), 1);
        assert!(rules[0].evidence(&e).contains("Image=/bin/sh"));
        e.set("CommandLine", "sh -c SAFE-HELPER run");
        assert!(evaluate(&rules, &e).is_empty(), "filter excludes, case-insensitively");

        let mut n = Event::new("network_connection");
        n.set("DestinationIp", "203.0.113.9").set("DestinationPort", "443");
        assert_eq!(evaluate(&rules, &n).len(), 1, "cidr");
        n.set("DestinationIp", "198.51.100.1");
        assert!(evaluate(&rules, &n).is_empty());
        n.set("DestinationPort", "4444");
        assert_eq!(evaluate(&rules, &n).len(), 1, "numbers as strings");
    }

    #[test]
    fn glob_and_modifiers() {
        assert!(glob("c:\\windows\\system32\\cmd.exe", "*\\\\cmd.exe"));
        assert!(glob("abc", "a?c") && !glob("abc", "a?d") && glob("", "*"));
        assert!(glob("a*c", "a\\*c") && !glob("abc", "a\\*c"));
        assert!(cidr("10.1.2.3", "10.0.0.0/8") && !cidr("11.1.2.3", "10.0.0.0/8"));
        assert!(cidr("fe80::1", "fe80::/10"));
        let (r, e) = parse(
            "title: w\nlogsource: {product: windows}\ndetection:\n  s:\n    CommandLine|windash|contains: ' -enc '\n    EventID|gte: 4000\n    Missing: null\n  condition: s\n",
            "w",
        );
        assert!(e.is_empty(), "{e:?}");
        let mut ev = Event::new("");
        ev.product = "windows";
        ev.set("CommandLine", "powershell /enc AAA").set("EventID", "4104");
        assert!(r[0].matches(&ev));
        ev.set("Missing", "x");
        assert!(!r[0].matches(&ev), "null means absent");
    }

    #[test]
    fn builtin_rules_all_parse() {
        let (rules, errors) = parse(include_str!("../rules/sigma/procwatch-builtin.yml"), "built-in");
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(rules.len(), 14);
        let mut e = Event::new("process_creation");
        e.product = "macos";
        e.set("Image", "/usr/bin/xattr").set("CommandLine", "xattr -d com.apple.quarantine /tmp/x.app");
        assert!(evaluate(&rules, &e).iter().any(|r| r.id == "pw-sigma-002"));
        let mut d = BTreeMap::new();
        d.insert("ScriptBlockText".to_string(), "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')".to_string());
        let ps = map::windows_record("Microsoft-Windows-PowerShell/Operational", "PowerShell", 4104, &d);
        assert!(evaluate(&rules, &ps).iter().any(|r| r.id == "pw-sigma-013"));
        let sec = map::windows_record("Security", "x", 1102, &BTreeMap::new());
        assert!(evaluate(&rules, &sec).iter().any(|r| r.id == "pw-sigma-009"));
    }

    #[test]
    fn maps_security_4688() {
        let mut d = BTreeMap::new();
        d.insert("NewProcessName".to_string(), "C:\\Windows\\System32\\cmd.exe".to_string());
        d.insert("CommandLine".to_string(), "cmd /c whoami".to_string());
        let e = map::windows_record("Security", "Microsoft-Windows-Security-Auditing", 4688, &d);
        assert_eq!(e.category, "process_creation");
        assert_eq!(e.get("Image"), Some("C:\\Windows\\System32\\cmd.exe"));
        assert_eq!(e.service, "security");
    }
}
