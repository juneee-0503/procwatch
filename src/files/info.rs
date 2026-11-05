//! File analysis: hashes, type, metadata, signature and (on macOS) where a
//! download came from. Read-only; used for executables of processes,
//! persistence targets, quarantine records and evidence manifests.

use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::SystemTime;

use chrono::{DateTime, Local};
use md5::Md5;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::process::inspect::{self, SignatureStatus};

#[derive(Debug, Clone, Serialize, Default)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Opening a FIFO blocks forever and a device never ends, and either can
/// sit wherever an attacker can write. Follows symlinks, like `open`.
pub fn require_regular(path: &Path) -> std::io::Result<()> {
    if std::fs::metadata(path)?.is_file() {
        Ok(())
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file"))
    }
}

/// MD5, SHA-1 and SHA-256 in one pass over the file.
pub fn hash_file(path: &Path) -> std::io::Result<Hashes> {
    require_regular(path)?;
    let mut r = BufReader::with_capacity(1 << 20, File::open(path)?);
    let (mut m, mut s1, mut s2) = (Md5::new(), Sha1::new(), Sha256::new());
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        m.update(&buf[..n]);
        s1.update(&buf[..n]);
        s2.update(&buf[..n]);
    }
    Ok(Hashes { md5: hex(&m.finalize()), sha1: hex(&s1.finalize()), sha256: hex(&s2.finalize()) })
}

/// SHA-256 only (evidence manifests).
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    require_regular(path)?;
    let mut r = BufReader::with_capacity(1 << 20, File::open(path)?);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

/// Identify the format from the first bytes.
pub fn file_type(path: &Path) -> String {
    if require_regular(path).is_err() {
        return "not a regular file".into();
    }
    let mut head = [0u8; 8];
    let n = File::open(path).and_then(|mut f| f.read(&mut head)).unwrap_or(0);
    let h = &head[..n];
    let t = match h {
        [0xcf, 0xfa, 0xed, 0xfe, ..] | [0xce, 0xfa, 0xed, 0xfe, ..] => "Mach-O executable",
        [0xca, 0xfe, 0xba, 0xbe, ..] => "Mach-O universal binary",
        [0x7f, b'E', b'L', b'F', ..] => "ELF executable",
        [b'M', b'Z', ..] => "Windows PE executable",
        [b'#', b'!', ..] => "script",
        [b'P', b'K', 3, 4, ..] => "ZIP archive (or .jar/.docx/…)",
        [0x1f, 0x8b, ..] => "gzip archive",
        [b'%', b'P', b'D', b'F', ..] => "PDF document",
        [b'b', b'p', b'l', b'i', b's', b't', ..] => "binary property list",
        [b'<', b'?', b'x', b'm', b'l', ..] => "XML",
        [0x78, 0x01 | 0x9c | 0xda, ..] => "zlib data",
        [] => "empty",
        _ if h.iter().all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace()) => "text",
        _ => "data",
    };
    t.to_string()
}

#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub path: String,
    pub exists: bool,
    pub size: u64,
    pub kind: String,
    pub hashes: Option<Hashes>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub accessed: Option<String>,
    pub permissions: String,
    pub owner: Option<String>,
    pub signature: String,
    pub signature_details: Vec<(String, String)>,
    /// macOS: download origin (quarantine attribute / Spotlight metadata).
    pub origin: Vec<String>,
    /// Header facts, entropy and embedded indicators.
    pub deep: crate::files::binfmt::Deep,
    /// macOS code-signing entitlements (privileges the binary requests).
    pub entitlements: Vec<String>,
    /// YARA-subset content rule matches (built-in + user rules).
    pub yara: Vec<crate::files::yara::Match>,
    /// macOS Gatekeeper assessment (notarization), e.g. "accepted · Notarized Developer ID".
    pub gatekeeper: Option<String>,
    pub error: Option<String>,
}

fn fmt_time(t: std::io::Result<SystemTime>) -> Option<String> {
    t.ok().map(|t| DateTime::<Local>::from(t).format("%Y-%m-%d %H:%M:%S").to_string())
}

pub fn signature_text(s: &SignatureStatus) -> String {
    match s {
        SignatureStatus::Valid { signer } => format!("valid — {signer}"),
        SignatureStatus::Invalid { reason } => format!("INVALID — {reason}"),
        SignatureStatus::Unsigned => "not signed".into(),
        SignatureStatus::Unknown => "not checked on this platform".into(),
    }
}

/// Empty report for `path` (used when analysis can't run).
pub fn analyze_stub(path: &str) -> FileReport {
    FileReport {
        path: path.to_string(),
        exists: false,
        size: 0,
        kind: String::new(),
        hashes: None,
        created: None,
        modified: None,
        accessed: None,
        permissions: String::new(),
        owner: None,
        signature: String::new(),
        signature_details: Vec::new(),
        origin: Vec::new(),
        deep: crate::files::binfmt::Deep::default(),
        entitlements: Vec::new(),
        yara: Vec::new(),
        gatekeeper: None,
        error: None,
    }
}

/// Full report for one file. Hashing large files takes a while; callers
/// run this on a worker.
pub fn analyze(path: &str) -> FileReport {
    let p = Path::new(path);
    let meta = fs::metadata(p);
    let mut r = analyze_stub(path);
    r.exists = meta.is_ok();
    let meta = match meta {
        Ok(m) => m,
        Err(e) => {
            r.error = Some(e.to_string());
            return r;
        }
    };
    r.size = meta.len();
    r.created = fmt_time(meta.created());
    r.modified = fmt_time(meta.modified());
    r.accessed = fmt_time(meta.accessed());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        r.permissions = format!("{:o}", meta.permissions().mode() & 0o7777);
        r.owner = Some(format!("uid {} gid {}", meta.uid(), meta.gid()));
    }
    #[cfg(not(unix))]
    {
        r.permissions = if meta.permissions().readonly() { "read-only".into() } else { "read-write".into() };
    }
    if meta.is_dir() {
        r.kind = "directory".into();
        return r;
    }
    r.kind = file_type(p);
    match hash_file(p) {
        Ok(h) => r.hashes = Some(h),
        Err(e) => r.error = Some(format!("hashing: {e}")),
    }
    let (sig, details) = inspect::file_signature_thorough(path);
    r.signature = signature_text(&sig);
    r.signature_details = details;
    r.origin = origin(path);
    match crate::files::binfmt::analyze(p) {
        Ok(d) => r.deep = d,
        Err(e) => {
            if r.error.is_none() {
                r.error = Some(format!("reading contents: {e}"));
            }
        }
    }
    r.entitlements = entitlements(path);
    r.gatekeeper = gatekeeper(path);
    if meta.is_file() {
        let (rules, _) = crate::files::yara::load(None);
        if let Ok((m, _)) = crate::files::yara::scan_file(&rules, p) {
            r.yara = m;
        }
    }
    r
}

/// Gatekeeper's verdict (`spctl --assess`), which includes notarization.
/// Apps are assessed as such; other files as executables, where a plain
/// command-line tool is "rejected" only because it isn't an app — that's
/// reported as "not an app bundle", not as a failure.
fn gatekeeper(path: &str) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let target = path.find(".app/").map(|i| &path[..i + 4]).unwrap_or(path);
        let out = crate::common::command::run_command(
            std::process::Command::new("/usr/sbin/spctl").args(["--assess", "--type", "execute", "-vv", target]),
            std::time::Duration::from_secs(15),
        )
        .ok()?;
        let text = String::from_utf8_lossy(&out.stderr).into_owned() + &String::from_utf8_lossy(&out.stdout);
        let verdict = if text.contains(": accepted") { "accepted" } else if text.contains("does not seem to be an app") { "not an app bundle" } else if text.contains(": rejected") { "REJECTED" } else { return None };
        let source = text.lines().find_map(|l| l.strip_prefix("source=")).unwrap_or("");
        return Some(if source.is_empty() { verdict.to_string() } else { format!("{verdict} · {source}") });
    }
    #[allow(unreachable_code)]
    {
        let _ = path;
        None
    }
}

/// Entitlements requested by a signed macOS binary, e.g.
/// `com.apple.security.cs.disable-library-validation`. Only true-valued
/// keys are listed.
fn entitlements(path: &str) -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        use crate::common::command::run_command;
        use std::process::Command;
        use std::time::Duration;
        let Ok(o) = run_command(Command::new("codesign").args(["-d", "--entitlements", "-", "--xml", path]), Duration::from_secs(10)) else {
            return Vec::new();
        };
        let Ok(v) = plist::Value::from_reader_xml(&o.stdout[..]) else { return Vec::new() };
        let Some(d) = v.as_dictionary() else { return Vec::new() };
        let mut out: Vec<String> = d
            .iter()
            .filter(|(_, v)| v.as_boolean() != Some(false))
            .map(|(k, v)| match v.as_boolean() {
                Some(true) => k.clone(),
                _ => format!("{k} (set)"),
            })
            .collect();
        out.sort();
        out
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Vec::new()
    }
}

/// Entitlements that weaken the protection of a process.
pub fn risky_entitlement(e: &str) -> bool {
    [
        "disable-library-validation",
        "allow-dyld-environment-variables",
        "allow-unsigned-executable-memory",
        "disable-executable-page-protection",
        "get-task-allow",
        "cs.debugger",
    ]
    .iter()
    .any(|k| e.contains(k))
}

/// Where a file was downloaded from (macOS only): the quarantine
/// attribute's agent and the Spotlight "where from" URLs.
fn origin(path: &str) -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        use crate::common::command::run_command;
        use std::process::Command;
        use std::time::Duration;
        let mut out = Vec::new();
        if let Ok(o) = run_command(Command::new("xattr").args(["-p", "com.apple.quarantine", path]), Duration::from_secs(5)) {
            let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if o.status.success() && !v.is_empty() {
                // flags;hex-time;agent;uuid
                let agent = v.split(';').nth(2).unwrap_or("").to_string();
                out.push(format!("quarantined download{}", if agent.is_empty() { String::new() } else { format!(" via {agent}") }));
            }
        }
        if let Ok(o) = run_command(Command::new("mdls").args(["-raw", "-name", "kMDItemWhereFroms", path]), Duration::from_secs(5)) {
            let v = String::from_utf8_lossy(&o.stdout);
            out.extend(
                v.lines()
                    .map(|l| l.trim().trim_matches(|c| c == '"' || c == ',' || c == '(' || c == ')').to_string())
                    .filter(|l| !l.is_empty() && l != "null"),
            );
        }
        out
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_known_input() {
        let dir = std::env::temp_dir().join(format!("pw-hash-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("abc.txt");
        fs::write(&f, b"abc").unwrap();
        let h = hash_file(&f).unwrap();
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(h.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(sha256_file(&f).unwrap(), h.sha256);
        assert_eq!(file_type(&f), "text");
        let r = analyze(f.to_str().unwrap());
        assert!(r.exists && r.size == 3);
        let _ = fs::remove_dir_all(dir);
    }
}
