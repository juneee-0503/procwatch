//! The module layering, enforced. A module may only use the modules listed
//! for it here; anything else fails the build's tests. See
//! `docs/architecture.md` before widening this table.

/// (module, what it may depend on)
const LAYERS: &[(&str, &[&str])] = &[
    ("kernel", &[]),
    ("common", &["kernel"]),
    ("network", &["common", "kernel"]),
    ("performance", &["common", "kernel"]),
    ("process", &["common", "kernel", "network"]),
    ("files", &["common", "kernel", "process"]),
    ("host", &["common", "files", "kernel", "process"]),
    ("activity", &["common", "files", "kernel", "network"]),
    ("detection", &["common", "files", "host", "network", "process"]),
    ("forensics", &["common", "detection", "files", "host", "network", "process"]),
    ("response", &["activity", "common", "process"]),
    ("engine", &["activity", "common", "files", "host", "kernel", "network", "performance", "process"]),
    ("app", &["activity", "common", "detection", "engine", "files", "forensics", "host", "kernel", "network", "performance", "process"]),
    ("ui", &["activity", "app", "common", "detection", "engine", "files", "forensics", "host", "kernel", "network", "performance", "process"]),
    ("cli", &["activity", "app", "common", "detection", "engine", "files", "forensics", "host", "kernel", "network", "performance", "process", "response", "ui"]),
];

/// The part of a source file that isn't test code.
fn production(source: &str) -> &str {
    // Checkouts on Windows may have CRLF line endings.
    let end = ["#[cfg(test)]\nmod ", "#[cfg(test)]\r\nmod "].iter().filter_map(|m| source.find(m)).min();
    &source[..end.unwrap_or(source.len())]
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

/// Modules talk over the bus. A module's own file may use its own domain,
/// `common` and the kernel, and nothing else.
#[test]
fn module_files_reach_no_other_module() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for (file, domain) in [
        ("process/module.rs", "process"),
        ("process/trace_module.rs", "process"),
        ("network/module.rs", "network"),
        ("performance/module.rs", "performance"),
        ("files/module.rs", "files"),
        ("host/logs/module.rs", "host"),
        ("activity/module.rs", "activity"),
    ] {
        let text = std::fs::read_to_string(root.join(file)).unwrap();
        for part in production(&text).split("crate::").skip(1) {
            let used: String = part.chars().take_while(|c| c.is_ascii_lowercase() || *c == '_').collect();
            assert!(["common", "kernel", domain].contains(&used.as_str()), "{file} uses {used}");
        }
    }
}

/// The kernel contains no collection: nothing that reads the system.
#[test]
fn the_kernel_collects_nothing() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/kernel");
    for e in std::fs::read_dir(root).unwrap().flatten() {
        let text = std::fs::read_to_string(e.path()).unwrap();
        for banned in ["sysinfo", "netstat2", "/proc", "Command::new", "cfg(target_os", "cfg(windows)"] {
            assert!(!production(&text).contains(banned), "{}: {banned}", e.path().display());
        }
    }
}
