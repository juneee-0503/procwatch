//! The module layering, enforced. A module may only use the modules listed
//! for it here; anything else fails the build's tests. See
//! `docs/architecture.md` before widening this table.

/// (module, what it may depend on)
const LAYERS: &[(&str, &[&str])] = &[
    ("kernel", &[]),
    ("common", &[]),
    ("network", &["common"]),
    ("performance", &["common"]),
    ("process", &["common", "network"]),
    ("files", &["common", "process"]),
    ("host", &["common", "files", "process"]),
    ("activity", &["common", "files", "network"]),
    ("detection", &["common", "files", "host", "network", "process"]),
    ("forensics", &["common", "detection", "files", "host", "network", "process"]),
    ("response", &["activity", "common", "process"]),
    ("engine", &["activity", "common", "files", "host", "network", "performance", "process"]),
    ("app", &["activity", "common", "detection", "engine", "files", "forensics", "host", "network", "performance", "process"]),
    ("ui", &["activity", "app", "common", "detection", "engine", "files", "forensics", "host", "network", "performance", "process"]),
    ("cli", &["activity", "app", "common", "detection", "engine", "files", "forensics", "host", "network", "performance", "process", "response", "ui"]),
];

/// The part of a source file that isn't test code.
fn production(source: &str) -> &str {
    source.split("#[cfg(test)]\nmod ").next().unwrap_or(source)
}

fn violations() -> Vec<String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    for (module, allowed) in LAYERS {
        let mut stack = vec![root.join(module)];
        while let Some(p) = stack.pop() {
            if p.is_dir() {
                stack.extend(std::fs::read_dir(&p).unwrap().flatten().map(|e| e.path()));
                continue;
            }
            if p.extension().is_none_or(|x| x != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&p).unwrap();
            for part in production(&text).split("crate::").skip(1) {
                let used: String = part.chars().take_while(|c| c.is_ascii_lowercase() || *c == '_').collect();
                if used != *module && !allowed.contains(&used.as_str()) && LAYERS.iter().any(|(m, _)| *m == used) {
                    let v = format!("{}: {module} must not use {used}", p.strip_prefix(&root).unwrap().display());
                    if !out.contains(&v) {
                        out.push(v);
                    }
                }
            }
        }
    }
    out
}

#[test]
fn modules_only_depend_downward() {
    let v = violations();
    assert!(v.is_empty(), "{} layering violations:\n{}", v.len(), v.join("\n"));
}

#[test]
fn the_table_has_no_cycles() {
    // Each module may only name modules listed before it.
    for (i, (module, allowed)) in LAYERS.iter().enumerate() {
        for dep in *allowed {
            assert!(LAYERS[..i].iter().any(|(m, _)| m == dep), "{module} depends on {dep}, which isn't below it");
        }
    }
}

#[test]
fn every_module_is_in_the_table() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for e in std::fs::read_dir(root).unwrap().flatten().filter(|e| e.path().is_dir()) {
        let name = e.file_name().to_string_lossy().into_owned();
        assert!(LAYERS.iter().any(|(m, _)| *m == name), "{name} is missing from LAYERS");
    }
}
