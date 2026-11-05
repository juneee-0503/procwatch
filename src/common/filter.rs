//! One filter syntax for every list in the app.
//!
//! ```text
//! chrome                 free text: matches any field
//! pid:123  port:443      exact match for numeric fields
//! name:helper user:root  substring match for text fields
//! state:established ip:10.0.  path:/tmp  kind:connect  type:reg
//! -name:mdworker         a leading '-' excludes matches
//! path:"/Applications/My App.app"   quotes keep spaces in one value
//! ```
//!
//! All terms must match (AND). Unknown `field:` prefixes are treated as
//! plain text, so searching for `C:\Windows` still works.

/// Fields compared for equality rather than substring.
const EXACT: &[&str] = &["pid", "ppid", "port", "fd", "tree", "cluster", "id"];

/// Field names the parser recognizes.
pub const FIELDS: &[&str] =
    &[
        "pid", "ppid", "name", "user", "path", "cmd", "port", "ip", "state", "proto", "kind", "type", "fd", "rule", "source", "tree",
        "sev", "tag", "cluster", "entity", "team", "basis", "id",
    ];

#[derive(Debug, Clone, PartialEq)]
struct Term {
    field: Option<&'static str>,
    value: String,
    negate: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Filter {
    terms: Vec<Term>,
}

/// Something a filter can be applied to.
pub trait Filterable {
    /// Values of a named field (several for e.g. both ports of a
    /// connection). `None` if the item has no such field.
    fn field(&self, name: &str) -> Option<Vec<String>>;
    /// Text searched by free terms.
    fn text(&self) -> String;
}

impl Filter {
    pub fn parse(q: &str) -> Filter {
        let terms = tokens(q)
            .into_iter()
            .filter_map(|raw| {
                let raw = raw.as_str();
                let (negate, body) = match raw.strip_prefix('-') {
                    Some(rest) if !rest.is_empty() => (true, rest),
                    _ => (false, raw),
                };
                let lower = body.to_lowercase();
                // `:8080` is shorthand for `port:8080`.
                if let Some(port) = lower.strip_prefix(':').filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())) {
                    return Some(Term { field: Some("port"), value: port.to_string(), negate });
                }
                let (field, value) = match lower.split_once(':') {
                    Some((f, v)) if !v.is_empty() => match FIELDS.iter().find(|k| **k == f) {
                        Some(k) => (Some(*k), v.to_string()),
                        None => (None, lower.clone()),
                    },
                    _ => (None, lower.clone()),
                };
                (!value.is_empty()).then_some(Term { field, value, negate })
            })
            .collect();
        Filter { terms }
    }

    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    pub fn matches(&self, item: &dyn Filterable) -> bool {
        let mut text: Option<String> = None;
        self.terms.iter().all(|t| {
            let hit = match t.field {
                None => text.get_or_insert_with(|| item.text().to_lowercase()).contains(&t.value),
                Some(f) => match item.field(f) {
                    None => false,
                    Some(values) => values.iter().any(|v| {
                        let v = v.to_lowercase();
                        if EXACT.contains(&f) { v == t.value } else { v.contains(&t.value) }
                    }),
                },
            };
            hit != t.negate
        })
    }
}

/// Whitespace-separated terms; a double-quoted run (anywhere in a term,
/// e.g. `path:"/My App"`) keeps its spaces and loses the quotes.
fn tokens(q: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in q.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Quote a value for use in a filter if it needs it.
pub fn quote(v: &str) -> String {
    if v.chars().any(char::is_whitespace) { format!("\"{}\"", v.replace('"', "")) } else { v.to_string() }
}

/// Split `host:port` / `[v6]:port` into its parts.
pub fn split_endpoint(ep: &str) -> (String, String) {
    match ep.rsplit_once(':') {
        Some((h, p)) => (h.trim_start_matches('[').trim_end_matches(']').to_string(), p.to_string()),
        None => (ep.to_string(), String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Item {
        pid: u32,
        name: &'static str,
        ports: Vec<&'static str>,
    }

    impl Filterable for Item {
        fn field(&self, name: &str) -> Option<Vec<String>> {
            match name {
                "pid" => Some(vec![self.pid.to_string()]),
                "name" => Some(vec![self.name.to_string()]),
                "port" => Some(self.ports.iter().map(|p| p.to_string()).collect()),
                _ => None,
            }
        }
        fn text(&self) -> String {
            format!("{} {}", self.pid, self.name)
        }
    }

    #[test]
    fn field_text_and_negation() {
        let a = Item { pid: 123, name: "Chrome Helper", ports: vec!["443", "51000"] };
        assert!(Filter::parse("chrome").matches(&a));
        assert!(Filter::parse("pid:123 port:443").matches(&a));
        assert!(!Filter::parse("pid:12").matches(&a), "pid is exact");
        assert!(Filter::parse("name:helper").matches(&a), "name is substring, case-insensitive");
        assert!(!Filter::parse("-name:helper").matches(&a));
        assert!(Filter::parse("-port:80").matches(&a));
        assert!(!Filter::parse("state:listen").matches(&a), "missing field doesn't match");
        assert!(Filter::parse("c:\\").terms[0].field.is_none(), "unknown prefix is text");
        assert!(Filter::parse("").is_empty());
        assert!(Filter::parse(":443").matches(&a), ":443 means port:443");
        assert_eq!(split_endpoint("[::1]:22"), ("::1".into(), "22".into()));
        let b = Item { pid: 1, name: "My Helper App", ports: vec![] };
        assert!(Filter::parse("name:\"helper app\"").matches(&b));
        assert!(!Filter::parse("name:\"helper  x\"").matches(&b));
        assert_eq!(quote("a b"), "\"a b\"");
    }
}
