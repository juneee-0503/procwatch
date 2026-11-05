//! Content rules: the full YARA language and its modules, through YARA-X, run
//! against files on disk. Process memory is never scanned.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use yara_x::{Compiler, MetaValue, Rules, Scanner};

use crate::common::model::{Confidence, Severity};

/// First line of the built-in rule file; marks procwatch's own files, which
/// hold the rules' strings as text.
const SELF_MARKER: &str = "// procwatch built-in content rules";

/// Files are read up to this size.
pub const MAX_SCAN: u64 = 64 << 20;

/// A rule written badly enough to crawl must not stall a whole sweep.
const SCAN_TIMEOUT: Duration = Duration::from_secs(30);

/// Rule files larger than this aren't rule files.
const MAX_RULE_SOURCE: usize = 16 << 20;

const BUILTIN_NAMESPACE: &str = "procwatch_builtin";

/// What a compiled rule says about itself.
#[derive(Debug, Clone, Serialize)]
pub struct RuleInfo {
    pub name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: Vec<(String, String)>,
}

impl RuleInfo {
    #[cfg(test)]
    pub fn meta(&self, k: &str) -> Option<&str> {
        self.meta.iter().find(|(m, _)| m.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
}

/// Compiled rules, ready to scan with.
pub struct RuleSet {
    compiled: Rules,
    pub rules: Vec<RuleInfo>,
}

impl RuleSet {
    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Match {
    pub rule: String,
    pub tags: Vec<String>,
    pub description: String,
    /// From the rule's `severity` meta (default medium).
    pub severity: Severity,
    /// From the rule's `confidence` meta (default medium).
    pub confidence: Confidence,
    /// (string id, first offset, count)
    pub strings: Vec<(String, usize, usize)>,
}

fn meta_text(v: &MetaValue) -> String {
    match v {
        MetaValue::Integer(i) => i.to_string(),
        MetaValue::Float(f) => f.to_string(),
        MetaValue::Bool(b) => b.to_string(),
        MetaValue::String(s) => s.to_string(),
        MetaValue::Bytes(b) => String::from_utf8_lossy(b.as_ref()).into_owned(),
    }
}

fn first_line(e: impl std::fmt::Display) -> String {
    e.to_string().lines().next().unwrap_or("rule error").to_string()
}

/// Compile sources as (namespace, text, label). A source that doesn't compile
/// is reported and left out; the others still work.
fn compile(sources: &[(String, String, String)]) -> (RuleSet, Vec<String>) {
    let mut errors = Vec::new();
    let mut c = Compiler::new();
    // Rule sets written for the original YARA often rely on this.
    c.relaxed_re_syntax(true);
    for (namespace, text, label) in sources {
        if text.len() > MAX_RULE_SOURCE {
            errors.push(format!("{label}: too large"));
            continue;
        }
        c.new_namespace(namespace);
        if let Err(e) = c.add_source(text.as_str()) {
            errors.push(format!("{label}: {}", first_line(e)));
        }
    }
    let compiled = c.build();
    let rules = compiled
        .iter()
        .map(|r| RuleInfo {
            name: r.identifier().to_string(),
            namespace: r.namespace().to_string(),
            tags: r.tags().map(|t| t.identifier().to_string()).collect(),
            meta: r.metadata().map(|(k, v)| (k.to_string(), meta_text(&v))).collect(),
        })
        .collect();
    (RuleSet { compiled, rules }, errors)
}

/// Compile one source text.
#[cfg(test)]
pub fn parse(src: &str, file: &str) -> (RuleSet, Vec<String>) {
    compile(&[("default".to_string(), src.to_string(), file.to_string())])
}

const BUILTIN: &str = include_str!("../../rules/yara/procwatch-builtin.yar");

fn builtin_source() -> (String, String, String) {
    (BUILTIN_NAMESPACE.to_string(), BUILTIN.to_string(), "built-in".to_string())
}

/// `.yar` / `.yara` files under `dir`, each in its own namespace so two rule
/// sets can reuse a rule name.
fn read_dir_sources(dir: &Path, errors: &mut Vec<String>) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            errors.push(format!("can't read {}", d.display()));
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "yar" || x == "yara") {
                match std::fs::read_to_string(&p) {
                    Ok(t) => out.push((format!("user{}", out.len()), t, p.display().to_string())),
                    Err(e) => errors.push(format!("{}: {e}", p.display())),
                }
            }
        }
    }
    out
}

#[cfg(test)]
pub fn builtin() -> RuleSet {
    compile(&[builtin_source()]).0
}

pub fn default_dir() -> Option<std::path::PathBuf> {
    crate::common::paths::config_path().map(|p| p.with_file_name("yara"))
}

/// Built-in rules plus the user's folder. A user rule replaces a built-in one
/// of the same name.
pub fn load(dir: Option<&Path>) -> (RuleSet, Vec<String>) {
    let mut errors = Vec::new();
    let mut sources = vec![builtin_source()];
    if let Some(d) = dir.map(Path::to_path_buf).or_else(default_dir).filter(|d| d.exists()) {
        sources.extend(read_dir_sources(&d, &mut errors));
    }
    let (set, more) = compile(&sources);
    errors.extend(more);
    (set, errors)
}

fn to_match(r: &yara_x::Rule<'_, '_>) -> Match {
    let meta = |k: &str| r.metadata().find(|(m, _)| m.eq_ignore_ascii_case(k)).map(|(_, v)| meta_text(&v));
    let mut strings: Vec<(String, usize, usize)> = r
        .patterns()
        .filter_map(|p| {
            let n = p.matches().len();
            let first = p.matches().next()?.range().start;
            Some((p.identifier().to_string(), first, n))
        })
        .collect();
    strings.sort();
    Match {
        rule: r.identifier().to_string(),
        tags: r.tags().map(|t| t.identifier().to_string()).collect(),
        description: meta("description").unwrap_or_default(),
        severity: meta("severity").map(|s| Severity::parse(&s)).unwrap_or(Severity::Medium),
        confidence: match meta("confidence").map(|s| s.to_lowercase()).as_deref() {
            Some("high") => Confidence::High,
            Some("low") => Confidence::Low,
            _ => Confidence::Medium,
        },
        strings,
    }
}

fn collect(set: &RuleSet, results: &yara_x::ScanResults<'_, '_>) -> Vec<Match> {
    let replaced = |r: &yara_x::Rule<'_, '_>| r.namespace() == BUILTIN_NAMESPACE && set.rules.iter().any(|i| i.namespace != BUILTIN_NAMESPACE && i.name == r.identifier());
    results.matching_rules().filter(|r| !replaced(r)).map(|r| to_match(&r)).collect()
}

fn scanner(set: &RuleSet) -> Scanner<'_> {
    let mut s = Scanner::new(&set.compiled);
    s.set_timeout(SCAN_TIMEOUT);
    s
}

/// Match `data`.
#[cfg(test)]
pub fn scan_bytes(set: &RuleSet, data: &[u8]) -> Vec<Match> {
    let mut s = scanner(set);
    match s.scan(data) {
        Ok(r) => collect(set, &r),
        Err(_) => Vec::new(),
    }
}

/// Match many files on several threads. Returns hits and unreadable files.
pub fn scan_files(set: &RuleSet, paths: &[String]) -> (Vec<(String, Vec<Match>)>, Vec<String>) {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()).clamp(2, 8);
    let chunk = paths.len().div_ceil(threads).max(1);
    std::thread::scope(|s| {
        let handles: Vec<_> = paths
            .chunks(chunk)
            .map(|part| {
                s.spawn(move || {
                    let mut hits = Vec::new();
                    let mut failed = Vec::new();
                    for p in part {
                        match scan_file(set, Path::new(p)) {
                            Ok((m, _)) if !m.is_empty() => hits.push((p.clone(), m)),
                            Ok(_) => {}
                            Err(e) => failed.push(format!("{p}: {e}")),
                        }
                    }
                    (hits, failed)
                })
            })
            .collect();
        let mut hits = Vec::new();
        let mut failed = Vec::new();
        for h in handles {
            match h.join() {
                Ok((a, b)) => {
                    hits.extend(a);
                    failed.extend(b);
                }
                Err(_) => failed.push("a scan thread crashed".into()),
            }
        }
        (hits, failed)
    })
}

/// Scan one file (first `MAX_SCAN` bytes). The flag says it was cut short.
pub fn scan_file(set: &RuleSet, path: &Path) -> Result<(Vec<Match>, bool), String> {
    use std::io::Read;
    crate::files::info::require_regular(path).map_err(|e| e.to_string())?;
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut data = Vec::with_capacity(size.min(MAX_SCAN) as usize);
    f.take(MAX_SCAN).read_to_end(&mut data).map_err(|e| e.to_string())?;
    // procwatch's own rule files would match themselves.
    if memchr::memmem::find(&data, SELF_MARKER.as_bytes()).is_some() {
        return Ok((Vec::new(), false));
    }
    let mut s = scanner(set);
    let results = s.scan(&data).map_err(|e| e.to_string())?;
    Ok((collect(set, &results), size > MAX_SCAN))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(src: &str, data: &[u8]) -> Vec<String> {
        let (set, errors) = parse(src, "test");
        assert!(errors.is_empty(), "{errors:?}");
        scan_bytes(&set, data).into_iter().map(|m| m.rule).collect()
    }

    #[test]
    fn the_builtin_rules_compile() {
        let (set, errors) = compile(&[builtin_source()]);
        assert!(errors.is_empty(), "{errors:?}");
        assert!(set.len() >= 6);
    }

    #[test]
    fn language_features_the_old_subset_lacked() {
        assert_eq!(hits(r#"rule r { strings: $a = /ev[il]+\d{2}/ condition: $a }"#, b"xx evil42 yy"), ["r"]);
        assert_eq!(hits(r#"rule r { strings: $a = "secret" xor condition: $a }"#, &b"secret".iter().map(|b| b ^ 0x20).collect::<Vec<_>>()), ["r"]);
        assert_eq!(hits(r#"rule r { strings: $a = "hello" base64 condition: $a }"#, b"aGVsbG8gd29ybGQ="), ["r"]);
        assert_eq!(hits("rule r { strings: $a = \"x\" condition: for all i in (1..#a): (@a[i] < 10) }", b"xx"), ["r"]);
        assert!(hits(r#"rule r { condition: filesize > 10 }"#, b"short").is_empty());
    }

    #[test]
    fn modules_are_available() {
        assert_eq!(hits(r#"import "math" rule r { condition: math.entropy(0, filesize) < 1.0 }"#, &[7u8; 64]), ["r"]);
        assert_eq!(hits(r#"import "hash" rule r { condition: hash.md5(0, filesize) == "900150983cd24fb0d6963f7d28e17f72" }"#, b"abc"), ["r"]);
        assert!(hits(r#"import "pe" rule r { condition: pe.is_pe }"#, b"not a pe").is_empty());
        assert!(hits(r#"import "elf" rule r { condition: elf.type == elf.ET_EXEC }"#, b"nope").is_empty());
        assert!(hits(r#"import "macho" rule r { condition: macho.magic == 1 }"#, b"nope").is_empty());
    }

    #[test]
    fn a_bad_rule_is_reported_and_the_good_ones_still_work() {
        let (set, errors) = compile(&[("a".into(), "rule good { condition: true }".into(), "good.yar".into()), ("b".into(), "rule bad { condition: nonsense( }".into(), "bad.yar".into())]);
        assert_eq!(set.len(), 1);
        assert!(errors[0].starts_with("bad.yar"), "{errors:?}");
    }

    #[test]
    fn meta_decides_severity_and_a_user_rule_replaces_a_builtin() {
        let src = r#"rule r : tag1 { meta: description = "d" severity = "high" confidence = "low" strings: $a = "x" condition: $a }"#;
        let (set, _) = parse(src, "t");
        assert_eq!(set.rules[0].meta("description"), Some("d"));
        let m = &scan_bytes(&set, b"axxa")[0];
        assert_eq!((m.severity, m.confidence, m.tags[0].as_str()), (Severity::High, Confidence::Low, "tag1"));
        assert_eq!(m.strings[0], ("$a".to_string(), 1, 2));
        let (both, _) = compile(&[(BUILTIN_NAMESPACE.into(), "rule same { condition: true }".into(), "b".into()), ("user0".into(), "rule same { meta: description = \"mine\" condition: true }".into(), "u".into())]);
        let found = scan_bytes(&both, b"x");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].description, "mine");
    }

    #[test]
    fn hostile_rules_are_rejected_or_bounded() {
        let deep = format!("rule a {{ strings: $a = \"x\" condition: {}$a{} }}", "(".repeat(5_000), ")".repeat(5_000));
        assert!(parse(&deep, "t").0.len() <= 1);
        let nots = format!("rule a {{ strings: $a = \"x\" condition: {}$a }}", "not ".repeat(5_000));
        assert!(parse(&nots, "t").0.len() <= 1);
        assert!(!compile(&[("n".into(), "a".repeat(MAX_RULE_SOURCE + 1), "huge".into())]).1.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_instead_of_blocking() {
        let d = crate::common::paths::private_temp_dir("fifo-test").unwrap();
        let p = d.join("f");
        let c = std::ffi::CString::new(p.display().to_string()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(scan_file(&builtin(), &p).is_err());
        assert!(crate::files::info::hash_file(&p).is_err());
        assert!(crate::files::binfmt::analyze(&p).is_err());
        assert_eq!(crate::files::info::file_type(&p), "not a regular file");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn files_holding_the_builtin_rules_skip_themselves() {
        let d = crate::common::paths::private_temp_dir("self-test").unwrap();
        let p = d.join("rules.yar");
        std::fs::write(&p, BUILTIN).unwrap();
        assert!(scan_file(&builtin(), &p).unwrap().0.is_empty());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
