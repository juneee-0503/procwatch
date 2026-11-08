//! `procwatch --coverage`: which MITRE ATT&CK techniques the built-in and
//! installed rules look for, per engine. It lists what is covered, and
//! says nothing about how reliably a rule catches a technique.

use std::collections::BTreeMap;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Entry {
    pub engine: &'static str,
    pub rule: String,
    pub title: String,
}

/// `attack.t1059.001` → `T1059.001`.
fn technique_from_tag(tag: &str) -> Option<String> {
    let t = tag.strip_prefix("attack.").unwrap_or(tag).to_ascii_uppercase();
    let digits = t.strip_prefix('T')?;
    digits.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())).then_some(t)
}

/// Technique → rules, plus the rules that name no technique.
pub fn collect() -> (BTreeMap<String, Vec<Entry>>, Vec<Entry>) {
    let mut map: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
    let mut none = Vec::new();
    let mut add = |techniques: Vec<String>, e: Entry| {
        if techniques.is_empty() {
            none.push(e);
        } else {
            for t in techniques {
                map.entry(t).or_default().push(e.clone());
            }
        }
    };
    for r in crate::detection::triage::RULES {
        let t = if r.technique.is_empty() { Vec::new() } else { vec![r.technique.to_string()] };
        add(t, Entry { engine: "host rule", rule: r.id.into(), title: r.name.into() });
    }
    let mut sigma = crate::detection::sigma::builtin();
    if let Some((more, _)) = crate::detection::sigma::default_dir().filter(|d| d.exists()).map(|d| crate::detection::sigma::load_dir(&d)) {
        sigma.extend(more);
    }
    for r in sigma {
        add(r.tags.iter().filter_map(|t| technique_from_tag(t)).collect(), Entry { engine: "sigma", rule: r.id, title: r.title });
    }
    for r in crate::detection::behave::load().0 {
        add(technique_from_tag(&r.technique).into_iter().collect(), Entry { engine: "sequence", rule: r.id, title: r.title });
    }
    for r in crate::files::yara::load(None).0.rules {
        let tags = r.tags.iter().chain(r.meta.iter().filter(|(k, _)| k == "technique" || k == "attack").map(|(_, v)| v));
        add(tags.filter_map(|t| technique_from_tag(t)).collect(), Entry { engine: "yara", rule: r.name.clone(), title: r.meta.iter().find(|(k, _)| k == "description").map(|(_, v)| v.clone()).unwrap_or(r.name) });
    }
    (map, none)
}

pub fn run(json: bool) -> i32 {
    let (map, none) = collect();
    if json {
        println!("{}", serde_json::json!({"techniques": map, "without_technique": none}));
        return 0;
    }
    println!("{} techniques covered by {} rule mappings; {} rules name no technique\n", map.len(), map.values().map(Vec::len).sum::<usize>(), none.len());
    for (t, rules) in &map {
        println!("{t}");
        for e in rules {
            println!("  {:<10} {:<28} {}", e.engine, e.rule, e.title);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_engine_and_parses_tags() {
        assert_eq!(technique_from_tag("attack.t1059.001").as_deref(), Some("T1059.001"));
        assert_eq!(technique_from_tag("T1620").as_deref(), Some("T1620"));
        assert_eq!(technique_from_tag("attack.execution"), None);
        assert_eq!(technique_from_tag("t"), None);
        let (map, _) = collect();
        assert!(map.get("T1620").is_some_and(|r| r.iter().any(|e| e.rule == "PW-021")));
        let engines: std::collections::BTreeSet<&str> = map.values().flatten().map(|e| e.engine).collect();
        assert!(engines.contains("host rule") && engines.contains("sigma") && engines.contains("sequence"), "{engines:?}");
    }
}
