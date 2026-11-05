//! Investigation case: an evidence folder with a chain-of-custody log, a
//! SHA-256 manifest that can be re-verified, findings, notes, a
//! conclusion, and report export (Markdown, JSON, HTML).
//!
//! Layout of a case folder:
//! ```text
//! procwatch-case-20261102-101500/
//!   case.json          case metadata, findings, notes, conclusion, bookmarks
//!   custody.log        append-only, hash-chained log of every action
//!   evidence.json      evidence register: id, class, source, method,
//!                      status (complete/partial/failed) and problems
//!   evidence/…         collected files
//!   quarantine/…       quarantined files + records
//!   manifest.json      sha256 of every evidence file
//!   manifest.sha256    same, in `sha256sum -c` format
//!   seal.json          when sealed, manifest hash, custody chain head
//!   report.md / .json / .html
//! ```
//!
//! Custody records are chained: each line ends in `chain=<sha256>` over
//! the previous record's chain value and this record's text. Editing,
//! removing or reordering any earlier record breaks every later link. An
//! append-only text file can still be rewritten wholesale by someone with
//! write access, so the head value is shown in the UI and the report for
//! the examiner to record outside the case (ticket, notebook, signed mail).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::files::info::sha256_file;

/// SHA-256 of an evidence file. Quarantined files have every permission
/// removed; grant read access just long enough to hash them.
pub fn hash_evidence(p: &Path) -> std::io::Result<String> {
    match sha256_file(p) {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(p)?.permissions().mode();
                fs::set_permissions(p, fs::Permissions::from_mode(0o400))?;
                let r = sha256_file(p);
                fs::set_permissions(p, fs::Permissions::from_mode(mode & 0o7777))?;
                r
            }
            #[cfg(not(unix))]
            Err(e)
        }
        r => r,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub time: String,
    pub severity: String,
    pub title: String,
    pub source: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    pub time: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// An analyst bookmark on a timeline event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    /// Timeline event id (T-…).
    pub event: String,
    pub tag: String,
    /// When the event happened.
    pub time: String,
    pub summary: String,
    pub note: String,
    pub added: String,
}

/// Investigation phases an event can be tagged with.
pub const BOOKMARK_TAGS: [&str; 6] =
    ["initial anomaly", "suspicious execution", "persistence change", "network activity", "containment", "recovery check"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    pub examiner: String,
    pub host: String,
    pub opened: String,
    pub conclusion: String,
    pub findings: Vec<Finding>,
    pub notes: Vec<Note>,
    #[serde(default)]
    pub bookmarks: Vec<Bookmark>,
    #[serde(skip)]
    pub dir: PathBuf,
}

/// What kind of thing an evidence item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// Collected from the live system (snapshots, listings, logs).
    Original,
    /// A byte copy of a file from the system.
    Copy,
    /// Produced by analysis of other evidence (sweeps, offline analysis).
    Derived,
    /// A report generated from the case.
    Report,
}

impl Class {
    pub fn label(self) -> &'static str {
        match self {
            Class::Original => "original",
            Class::Copy => "copy",
            Class::Derived => "derived",
            Class::Report => "report",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    /// Written, but some of what should be in it couldn't be collected.
    Partial,
    /// Nothing usable was written.
    Failed,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Complete => "complete",
            Status::Partial => "partial",
            Status::Failed => "failed",
        }
    }
}

/// How an evidence item came to be.
#[derive(Debug, Clone)]
pub struct Provenance {
    pub class: Class,
    pub source: String,
    pub method: String,
    pub subject: Option<String>,
    pub problems: Vec<String>,
}

impl Provenance {
    pub fn live(method: &str) -> Provenance {
        Provenance { class: Class::Original, source: "live system".into(), method: method.into(), subject: None, problems: Vec::new() }
    }
    pub fn derived(method: &str) -> Provenance {
        Provenance { class: Class::Derived, ..Provenance::live(method) }
    }
    pub fn subject(mut self, s: impl Into<String>) -> Provenance {
        self.subject = Some(s.into());
        self
    }
    pub fn problems(mut self, p: Vec<String>) -> Provenance {
        self.problems = p;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub id: String,
    /// Relative to the case folder; empty for a failed collection.
    pub path: String,
    pub class: Class,
    pub source: String,
    pub method: String,
    pub subject: Option<String>,
    pub collected_at: String,
    pub tool: String,
    pub host: String,
    pub examiner: String,
    pub size: u64,
    pub sha256: String,
    pub status: Status,
    pub problems: Vec<String>,
}

/// One parsed custody record.
#[derive(Debug, Clone, Serialize)]
pub struct CustodyRecord {
    pub time: String,
    pub examiner: String,
    pub action: String,
    pub detail: String,
    pub chain: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainStatus {
    pub records: usize,
    /// Records written before chaining existed (older procwatch).
    pub legacy: usize,
    /// First bad record (1-based line) and why.
    pub broken: Option<(usize, String)>,
    pub head: String,
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn chain_next(prev: &str, body: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(body.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Check the custody chain of a log's text.
pub fn verify_chain(text: &str) -> ChainStatus {
    let mut prev = GENESIS.to_string();
    let mut st = ChainStatus { records: 0, legacy: 0, broken: None, head: String::new() };
    let mut chained_seen = false;
    for (i, line) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        st.records += 1;
        match line.rsplit_once(" | chain=") {
            Some((body, chain)) => {
                chained_seen = true;
                let want = chain_next(&prev, body);
                if chain.trim() != want && st.broken.is_none() {
                    st.broken = Some((i + 1, "record was changed, removed or reordered".into()));
                }
                prev = chain.trim().to_string();
            }
            None if chained_seen => {
                if st.broken.is_none() {
                    st.broken = Some((i + 1, "unchained record after chained ones".into()));
                }
            }
            None => st.legacy += 1,
        }
    }
    st.head = if prev == GENESIS { String::new() } else { prev };
    st
}

/// The chain value of the last record, without re-hashing the whole log on
/// every append. Same result as `verify_chain(..).head`.
fn last_chain(path: &Path) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    const TAIL: u64 = 64 * 1024;
    let mut f = fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let start = len.saturating_sub(TAIL);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut tail = Vec::new();
    f.read_to_end(&mut tail).ok()?;
    let text = String::from_utf8_lossy(&tail);
    // The first line of a partial read may be cut off.
    let whole = if start > 0 { text.split_once('\n').map_or("", |(_, r)| r) } else { &text };
    if let Some(chain) = whole.lines().rev().find_map(|l| l.rsplit_once(" | chain=").map(|(_, c)| c.trim().to_string())) {
        return Some(chain);
    }
    if start == 0 {
        return None;
    }
    Some(verify_chain(&fs::read_to_string(path).ok()?).head).filter(|h| !h.is_empty())
}

/// Serialises custody appends and register updates across threads.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Check {
    Ok,
    Modified,
    Missing,
    Unlisted,
}

impl Check {
    pub fn label(self) -> &'static str {
        match self {
            Check::Ok => "ok",
            Check::Modified => "MODIFIED",
            Check::Missing => "MISSING",
            Check::Unlisted => "not in manifest",
        }
    }
}

pub fn now() -> String {
    Local::now().to_rfc3339()
}

fn examiner() -> String {
    std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "unknown".into())
}

/// Filename-safe version of `s`.
pub fn safe(s: &str) -> String {
    let t: String = s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect();
    t.chars().take(80).collect()
}

impl Case {
    /// Create a new case folder under `parent`.
    pub fn create(parent: &Path) -> anyhow::Result<Case> {
        // Exclusive, and private: evidence can hold secrets from the system.
        fs::create_dir_all(parent)?;
        let stamp = Local::now().format("%Y%m%d-%H%M%S").to_string();
        let mut id = format!("procwatch-case-{stamp}");
        let mut n = 1;
        loop {
            match crate::common::paths::create_private_dir(&parent.join(&id)) {
                Ok(()) => break,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 100 => {
                    n += 1;
                    id = format!("procwatch-case-{stamp}-{n}");
                }
                Err(e) => return Err(e.into()),
            }
        }
        let dir = parent.join(&id);
        fs::create_dir(dir.join("evidence"))?;
        let case = Case {
            id,
            examiner: examiner(),
            host: sysinfo::System::host_name().unwrap_or_else(|| "unknown".into()),
            opened: now(),
            conclusion: String::new(),
            findings: Vec::new(),
            notes: Vec::new(),
            bookmarks: Vec::new(),
            dir,
        };
        case.save()?;
        case.log("case opened", &format!("examiner {} on host {}", case.examiner, case.host))?;
        Ok(case)
    }

    pub fn open(dir: &Path) -> anyhow::Result<Case> {
        let mut c: Case = serde_json::from_str(&fs::read_to_string(dir.join("case.json"))?)?;
        c.dir = dir.to_path_buf();
        Ok(c)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let tmp = self.dir.join("case.json.tmp");
        fs::write(&tmp, serde_json::to_string_pretty(self)?)?;
        fs::rename(tmp, self.dir.join("case.json"))?;
        Ok(())
    }

    /// Append a hash-chained record to the custody log (never rewritten).
    pub fn log(&self, action: &str, detail: &str) -> anyhow::Result<()> {
        let _g = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.dir.join("custody.log");
        let prev = last_chain(&path).unwrap_or_else(|| GENESIS.into());
        let clean = |s: &str| s.replace(['\n', '\r'], " ");
        let body = format!("{} | {} | {} | {}", now(), clean(&self.examiner), clean(action), clean(detail));
        let chain = chain_next(&prev, &body);
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(f, "{body} | chain={chain}")?;
        f.sync_data()?;
        Ok(())
    }

    pub fn custody(&self) -> Vec<String> {
        fs::read_to_string(self.dir.join("custody.log")).map(|t| t.lines().map(str::to_string).collect()).unwrap_or_default()
    }

    pub fn custody_records(&self) -> Vec<CustodyRecord> {
        self.custody()
            .iter()
            .filter_map(|l| {
                let (body, chain) = match l.rsplit_once(" | chain=") {
                    Some((b, c)) => (b, Some(c.trim().to_string())),
                    None => (l.as_str(), None),
                };
                let f: Vec<&str> = body.splitn(4, " | ").collect();
                (f.len() == 4).then(|| CustodyRecord { time: f[0].into(), examiner: f[1].into(), action: f[2].into(), detail: f[3].into(), chain })
            })
            .collect()
    }

    pub fn chain_status(&self) -> ChainStatus {
        verify_chain(&fs::read_to_string(self.dir.join("custody.log")).unwrap_or_default())
    }

    /// For display, which happens on every draw: re-hashes only when the
    /// log changed. Sealing and verifying use [`Case::chain_status`].
    pub fn chain_status_cached(&self) -> ChainStatus {
        type Memo = Option<(PathBuf, u64, Option<std::time::SystemTime>, ChainStatus)>;
        static MEMO: Mutex<Memo> = Mutex::new(None);
        let path = self.dir.join("custody.log");
        let meta = fs::metadata(&path).ok();
        let (len, mtime) = (meta.as_ref().map_or(0, |m| m.len()), meta.as_ref().and_then(|m| m.modified().ok()));
        let mut memo = MEMO.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((p, l, t, st)) = memo.as_ref() {
            if *p == path && *l == len && *t == mtime {
                return st.clone();
            }
        }
        let st = self.chain_status();
        *memo = Some((path, len, mtime, st.clone()));
        st
    }

    // ── evidence register ──────────────────────────────────────────────

    pub fn register(&self) -> Vec<EvidenceItem> {
        fs::read_to_string(self.dir.join("evidence.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    /// Add (or, for the same path, supersede) a register entry.
    fn enter(&self, path: Option<&Path>, prov: &Provenance, status: Status) -> anyhow::Result<EvidenceItem> {
        let _g = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut reg = self.register();
        let (rel, size, sha256) = match path {
            Some(p) => (self.rel(p), fs::metadata(p).map(|m| m.len()).unwrap_or(0), hash_evidence(p)?),
            None => (String::new(), 0, String::new()),
        };
        let item = EvidenceItem {
            id: format!("E{:04}", reg.len() + 1),
            path: rel,
            class: prov.class,
            source: prov.source.clone(),
            method: prov.method.clone(),
            subject: prov.subject.clone(),
            collected_at: now(),
            tool: format!("procwatch {}", env!("CARGO_PKG_VERSION")),
            host: self.host.clone(),
            examiner: self.examiner.clone(),
            size,
            sha256,
            status,
            problems: prov.problems.clone(),
        };
        reg.push(item.clone());
        crate::common::paths::write_atomic(&self.dir.join("evidence.json"), &serde_json::to_string_pretty(&reg)?)?;
        Ok(item)
    }

    /// Record a collection that produced nothing usable.
    pub fn record_failure(&self, what: &str, prov: Provenance) -> anyhow::Result<()> {
        let item = self.enter(None, &prov, Status::Failed)?;
        self.log("collection failed", &format!("{} {what}: {}", item.id, prov.problems.join("; ")))
    }

    /// Write a text artifact into `evidence/`, hash it, register and log it.
    pub fn add_text(&self, name: &str, content: &str) -> anyhow::Result<PathBuf> {
        self.add_text_with(name, content, Provenance::live("procwatch live collection")).map(|(p, _)| p)
    }

    pub fn add_text_with(&self, name: &str, content: &str, prov: Provenance) -> anyhow::Result<(PathBuf, EvidenceItem)> {
        let path = self.dir.join("evidence").join(safe(name));
        if let Some(d) = path.parent() {
            fs::create_dir_all(d)?;
        }
        self.keep_earlier(&path)?;
        fs::write(&path, content)?;
        let status = if prov.problems.is_empty() { Status::Complete } else { Status::Partial };
        let item = self.enter(Some(&path), &prov, status)?;
        let gaps = if prov.problems.is_empty() { String::new() } else { format!(" partial: {}", prov.problems.join("; ")) };
        self.log("collected", &format!("{} {} [{}] sha256={}{gaps}", item.id, item.path, prov.class.label(), item.sha256))?;
        Ok((path, item))
    }

    /// Collecting again must not destroy what was collected before: move
    /// the earlier file aside and point its register entry at the new place.
    fn keep_earlier(&self, path: &Path) -> anyhow::Result<()> {
        if !path.is_file() {
            return Ok(());
        }
        let hash = hash_evidence(path)?;
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let dir = self.dir.join("evidence").join("earlier");
        fs::create_dir_all(&dir)?;
        let dest = dir.join(format!("{}_{name}", hash.get(..16).unwrap_or(&hash)));
        let (old, new) = (self.rel(path), self.rel(&dest));
        fs::rename(path, &dest)?;
        {
            let _g = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let mut reg = self.register();
            if let Some(item) = reg.iter_mut().rev().find(|i| i.path == old) {
                item.path = new.clone();
                crate::common::paths::write_atomic(&self.dir.join("evidence.json"), &serde_json::to_string_pretty(&reg)?)?;
            }
        }
        self.log("kept earlier collection", &format!("{old} → {new} sha256={hash}"))
    }

    /// Copy a file (e.g. a suspicious executable) into `evidence/files/`.
    pub fn add_copy(&self, src: &Path) -> anyhow::Result<PathBuf> {
        let hash = sha256_file(src)?;
        let name = src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
        let dir = self.dir.join("evidence").join("files");
        fs::create_dir_all(&dir)?;
        let dest = dir.join(format!("{}_{}", &hash[..16], safe(&name)));
        // Named by content: an existing read-only copy is this same file.
        if dest.exists() && sha256_file(&dest)? == hash {
            self.log("copy already held", &format!("{} sha256={hash}", self.rel(&dest)))?;
            return Ok(dest);
        }
        fs::copy(src, &dest)?;
        // Collected copies must not be runnable by accident.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dest, fs::Permissions::from_mode(0o444))?;
        }
        let mtime = fs::metadata(src).and_then(|m| m.modified()).ok().map(|t| DateTime::<Local>::from(t).to_rfc3339()).unwrap_or_default();
        let prov = Provenance {
            class: Class::Copy,
            source: format!("{} (mtime {mtime})", src.display()),
            method: "byte copy, stored read-only".into(),
            subject: Some(src.display().to_string()),
            problems: Vec::new(),
        };
        let item = self.enter(Some(&dest), &prov, Status::Complete)?;
        if item.sha256 != hash {
            anyhow::bail!("copy of {} doesn't match the source hash", src.display());
        }
        self.log("copied file", &format!("{} {} → {} sha256={hash}", item.id, src.display(), item.path))?;
        Ok(dest)
    }

    /// Register a file that was written into the case by other means
    /// (e.g. the output log of a launched program).
    pub fn register_existing(&self, path: &Path, prov: Provenance) -> anyhow::Result<EvidenceItem> {
        let item = self.enter(Some(path), &prov, Status::Complete)?;
        self.log("collected", &format!("{} {} [{}] sha256={}", item.id, item.path, prov.class.label(), item.sha256))?;
        Ok(item)
    }

    /// Register a quarantined file (called by `contain`).
    pub fn register_quarantine(&self, stored: &Path, original: &str) -> anyhow::Result<EvidenceItem> {
        let prov = Provenance {
            class: Class::Original,
            source: original.to_string(),
            method: "moved to quarantine, all permissions removed".into(),
            subject: Some(original.to_string()),
            problems: Vec::new(),
        };
        self.enter(Some(stored), &prov, Status::Complete)
    }

    pub fn add_bookmark(&mut self, b: Bookmark) -> anyhow::Result<()> {
        let line = format!("[{}] {} {} {}", b.tag, b.event, b.summary, b.note);
        self.bookmarks.retain(|x| x.event != b.event);
        self.bookmarks.push(b);
        self.save()?;
        self.log("bookmark", &line)
    }

    pub fn remove_bookmark(&mut self, event: &str) -> anyhow::Result<()> {
        let before = self.bookmarks.len();
        self.bookmarks.retain(|x| x.event != event);
        if before == self.bookmarks.len() {
            return Ok(());
        }
        self.save()?;
        self.log("bookmark removed", event)
    }

    pub fn rel(&self, p: &Path) -> String {
        p.strip_prefix(&self.dir).unwrap_or(p).display().to_string()
    }

    pub fn add_finding(&mut self, severity: &str, title: &str, source: &str, detail: &str) -> anyhow::Result<()> {
        self.findings.push(Finding { time: now(), severity: severity.into(), title: title.into(), source: source.into(), detail: detail.into() });
        self.save()?;
        self.log("finding", &format!("[{severity}] {title}"))
    }

    pub fn add_note(&mut self, text: &str) -> anyhow::Result<()> {
        self.notes.push(Note { time: now(), text: text.into() });
        self.save()?;
        self.log("note", text)
    }

    pub fn set_conclusion(&mut self, text: &str) -> anyhow::Result<()> {
        self.conclusion = text.into();
        self.save()?;
        self.log("conclusion", text)
    }

    fn evidence_files(&self) -> Vec<PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = fs::read_dir(dir) else { return };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else {
                    out.push(p);
                }
            }
        }
        let mut v = Vec::new();
        walk(&self.dir.join("evidence"), &mut v);
        walk(&self.dir.join("quarantine"), &mut v);
        v.sort();
        v
    }

    /// Hash every evidence file and write `manifest.json` + `manifest.sha256`.
    pub fn seal(&self) -> anyhow::Result<Vec<ManifestEntry>> {
        let mut entries = Vec::new();
        for p in self.evidence_files() {
            let size = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            entries.push(ManifestEntry { path: self.rel(&p), size, sha256: hash_evidence(&p)? });
        }
        fs::write(self.dir.join("manifest.json"), serde_json::to_string_pretty(&entries)?)?;
        let sums: String = entries.iter().map(|e| format!("{}  {}\n", e.sha256, e.path)).collect();
        fs::write(self.dir.join("manifest.sha256"), &sums)?;
        let manifest_hash = sha256_file(&self.dir.join("manifest.json"))?;
        self.log("manifest sealed", &format!("{} files, manifest.json sha256={manifest_hash}", entries.len()))?;
        let chain = self.chain_status();
        let seal = serde_json::json!({
            "sealed_at": now(),
            "files": entries.len(),
            "manifest_sha256": manifest_hash,
            "custody_records": chain.records,
            "custody_head": chain.head,
            "tool": format!("procwatch {}", env!("CARGO_PKG_VERSION")),
        });
        fs::write(self.dir.join("seal.json"), serde_json::to_string_pretty(&seal)?)?;
        Ok(entries)
    }

    pub fn manifest(&self) -> Vec<ManifestEntry> {
        fs::read_to_string(self.dir.join("manifest.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    /// Re-hash evidence and compare with the sealed manifest.
    pub fn verify(&self) -> anyhow::Result<Vec<(String, Check)>> {
        let manifest = self.manifest();
        if manifest.is_empty() {
            anyhow::bail!("no sealed manifest yet — seal the evidence first");
        }
        let mut out = Vec::new();
        for e in &manifest {
            let p = self.dir.join(&e.path);
            let status = match hash_evidence(&p) {
                Ok(h) if h == e.sha256 => Check::Ok,
                Ok(_) => Check::Modified,
                Err(_) => Check::Missing,
            };
            out.push((e.path.clone(), status));
        }
        for p in self.evidence_files() {
            let rel = self.rel(&p);
            if !manifest.iter().any(|e| e.path == rel) {
                out.push((rel, Check::Unlisted));
            }
        }
        // The manifest itself must be the one that was sealed, and the
        // custody chain must be intact and still contain the sealed head.
        if let Ok(seal) = fs::read_to_string(self.dir.join("seal.json")).map(|t| serde_json::from_str::<serde_json::Value>(&t).unwrap_or_default()) {
            let want = seal["manifest_sha256"].as_str().unwrap_or_default();
            if sha256_file(&self.dir.join("manifest.json")).ok().as_deref() != Some(want) {
                out.push(("manifest.json".into(), Check::Modified));
            }
            let head = seal["custody_head"].as_str().unwrap_or_default();
            if !head.is_empty() && !self.custody().iter().any(|l| l.ends_with(&format!("chain={head}"))) {
                out.push(("custody.log (sealed record missing)".into(), Check::Modified));
            }
        }
        let chain = self.chain_status();
        if let Some((line, why)) = &chain.broken {
            out.push((format!("custody.log line {line}: {why}"), Check::Modified));
        }
        // Reports are registered when generated; flag later edits.
        for item in self.register().iter().filter(|i| i.class == Class::Report) {
            let p = self.dir.join(&item.path);
            if p.exists() && hash_evidence(&p).ok().as_deref() != Some(item.sha256.as_str()) && self.latest_report_entry(&item.path).is_some_and(|l| l.id == item.id) {
                out.push((format!("{} (edited after generation)", item.path), Check::Modified));
            }
        }
        let bad = out.iter().filter(|(_, c)| *c != Check::Ok).count();
        self.log("verified evidence", &format!("{} files, {bad} problem(s), custody chain {}", out.len(), if chain.broken.is_some() { "BROKEN" } else { "intact" }))?;
        Ok(out)
    }

    fn latest_report_entry(&self, path: &str) -> Option<EvidenceItem> {
        self.register().into_iter().rev().find(|i| i.path == path)
    }
}

/// Data from the live session that goes into the report.
#[derive(Default, Serialize)]
pub struct ReportExtras {
    /// (time, source, description)
    pub timeline: Vec<(String, String, String)>,
    /// (category, name, command, flags)
    pub persistence: Vec<(String, String, String, String)>,
    /// (process, pid, endpoint summary)
    pub network: Vec<(String, u32, String)>,
    pub alerts: Vec<String>,
    pub detections: Vec<DetectionRow>,
    pub summaries: Vec<crate::detection::correlate::SummaryBlock>,
    /// (data source, status, detail)
    pub health: Vec<(String, String, String)>,
}

#[derive(Default, Serialize, Clone)]
pub struct DetectionRow {
    pub severity: String,
    pub confidence: String,
    pub rule: String,
    pub technique: String,
    pub subject: String,
    pub evidence: String,
    pub first_seen: String,
    pub last_seen: String,
    pub state: String,
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn md(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

impl Case {
    /// Write report.md, report.json and report.html; returns the folder.
    pub fn export_report(&self, extras: &ReportExtras) -> anyhow::Result<PathBuf> {
        let manifest = self.manifest();
        let custody = self.custody();
        let chain = self.chain_status();
        let register = self.register();
        let generated: DateTime<Local> = Local::now();
        let chain_line = match &chain.broken {
            Some((l, why)) => format!("BROKEN at line {l}: {why}"),
            None if chain.head.is_empty() => "no chained records".to_string(),
            None => format!("intact, {} records ({} legacy), head {}", chain.records, chain.legacy, chain.head),
        };

        // Markdown.
        let mut m = format!("# Investigation report — {}\n\n", self.id);
        m += &format!(
            "| | |\n|---|---|\n| Host | {} |\n| Examiner | {} |\n| Case opened | {} |\n| Report generated | {} |\n\n",
            md(&self.host),
            md(&self.examiner),
            self.opened,
            generated.to_rfc3339()
        );
        m += "## Conclusion\n\n";
        m += if self.conclusion.is_empty() { "_No conclusion recorded._\n\n" } else { "" };
        if !self.conclusion.is_empty() {
            m += &format!("{}\n\n", self.conclusion);
        }
        if !extras.summaries.is_empty() {
            m += "## Investigation summary\n\n_Generated from recorded events by fixed rules; every line cites its source. It describes what was observed, not intent._\n\n";
            for b in &extras.summaries {
                m += &format!("### {}\n\nWindow: {}\n\n", md(&b.subject), b.window);
                for (title, list) in [("Observed", &b.observed), ("Detections", &b.detections), ("Evidence", &b.evidence)] {
                    if !list.is_empty() {
                        m += &format!("**{title}**\n\n");
                        for o in list {
                            m += &format!("- {}\n", md(o));
                        }
                        m += "\n";
                    }
                }
                m += &format!("**Assessment:** {}\n\n", b.assessment);
            }
        }
        if !self.bookmarks.is_empty() {
            m += "## Key events (bookmarked)\n\n| Time | Phase | Event | Note |\n|---|---|---|---|\n";
            let mut bm = self.bookmarks.clone();
            bm.sort_by(|a, b| a.time.cmp(&b.time));
            for b in &bm {
                m += &format!("| {} | {} | {} {} | {} |\n", b.time, md(&b.tag), b.event, md(&b.summary), md(&b.note));
            }
            m += "\n";
        }
        m += &format!("## Findings ({})\n\n", self.findings.len());
        if !self.findings.is_empty() {
            m += "| Time | Severity | Finding | Source | Detail |\n|---|---|---|---|---|\n";
            for f in &self.findings {
                m += &format!("| {} | {} | {} | {} | {} |\n", f.time, f.severity, md(&f.title), md(&f.source), md(&f.detail));
            }
            m += "\n";
        }
        if !self.notes.is_empty() {
            m += "## Analyst notes\n\n";
            for n in &self.notes {
                m += &format!("- {} — {}\n", n.time, md(&n.text));
            }
            m += "\n";
        }
        if !extras.persistence.is_empty() {
            m += "## Flagged persistence entries\n\n| Category | Name | Command | Why |\n|---|---|---|---|\n";
            for (c, n, cmd, why) in &extras.persistence {
                m += &format!("| {} | {} | `{}` | {} |\n", md(c), md(n), md(cmd).replace('`', "'"), md(why));
            }
            m += "\n";
        }
        if !extras.network.is_empty() {
            m += "## Network connections at report time\n\n| Process | PID | Endpoints |\n|---|---|---|\n";
            for (p, pid, e) in &extras.network {
                m += &format!("| {} | {pid} | {} |\n", md(p), md(e));
            }
            m += "\n";
        }
        if !extras.detections.is_empty() {
            m += &format!("## Detections ({})\n\n| Severity | Confidence | Rule | ATT&CK | Subject | Evidence | First seen | Last seen | State |\n|---|---|---|---|---|---|---|---|---|\n", extras.detections.len());
            for d in &extras.detections {
                m += &format!(
                    "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                    d.severity, d.confidence, md(&d.rule), d.technique, md(&d.subject), md(&d.evidence), d.first_seen, d.last_seen, d.state
                );
            }
            m += "\n";
        }
        if !extras.alerts.is_empty() {
            m += "## Alerts\n\n";
            for a in &extras.alerts {
                m += &format!("- {}\n", md(a));
            }
            m += "\n";
        }
        if !extras.timeline.is_empty() {
            m += &format!("## Timeline (most recent {} events)\n\n| Time | Source | Event |\n|---|---|---|\n", extras.timeline.len());
            for (t, s, d) in &extras.timeline {
                m += &format!("| {t} | {} | {} |\n", md(s), md(d));
            }
            m += "\n";
        }
        if !extras.health.is_empty() {
            m += "## Collection coverage\n\n_What procwatch could and could not see. Missing data means \"not observed\", never \"did not happen\"._\n\n| Data source | Status | Detail |\n|---|---|---|\n";
            for (a, b, c) in &extras.health {
                m += &format!("| {} | {} | {} |\n", md(a), b, md(c));
            }
            m += "\n";
        }
        if !register.is_empty() {
            m += "## Evidence register\n\n| ID | File | Class | Status | Method | Source | Collected | Problems |\n|---|---|---|---|---|---|---|---|\n";
            for e in &register {
                m += &format!(
                    "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
                    e.id, md(&e.path), e.class.label(), e.status.label(), md(&e.method), md(&e.source), e.collected_at, md(&e.problems.join("; "))
                );
            }
            m += "\n";
        }
        m += &format!("## Evidence ({} files)\n\n", manifest.len());
        if manifest.is_empty() {
            m += "_Evidence has not been sealed; no manifest._\n\n";
        } else {
            m += "| File | Size | SHA-256 |\n|---|---|---|\n";
            for e in &manifest {
                m += &format!("| {} | {} | `{}` |\n", md(&e.path), e.size, e.sha256);
            }
            m += "\n";
        }
        m += &format!("## Chain of custody\n\nChain: {chain_line}\n\n```\n");
        for l in &custody {
            m += l;
            m += "\n";
        }
        m += "```\n";
        fs::write(self.dir.join("report.md"), &m)?;

        // JSON.
        #[derive(Serialize)]
        struct Json<'a> {
            case: &'a Case,
            generated: String,
            evidence: &'a [ManifestEntry],
            custody: &'a [String],
            custody_chain: &'a ChainStatus,
            register: &'a [EvidenceItem],
            extras: &'a ReportExtras,
        }
        fs::write(
            self.dir.join("report.json"),
            serde_json::to_string_pretty(&Json {
                case: self,
                generated: generated.to_rfc3339(),
                evidence: &manifest,
                custody: &custody,
                custody_chain: &chain,
                register: &register,
                extras,
            })?,
        )?;

        // HTML.
        let table = |head: &[&str], rows: Vec<Vec<String>>| -> String {
            let mut t = String::from("<table><tr>");
            for h in head {
                t += &format!("<th>{}</th>", esc(h));
            }
            t += "</tr>";
            for r in rows {
                t += "<tr>";
                for c in r {
                    t += &format!("<td>{}</td>", esc(&c));
                }
                t += "</tr>";
            }
            t + "</table>"
        };
        let mut h = format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>{id}</title><style>\
             body{{font:14px -apple-system,Segoe UI,sans-serif;margin:2em;max-width:1100px;color:#222}}\
             table{{border-collapse:collapse;width:100%;margin:.5em 0 1.5em}}td,th{{border:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top}}\
             th{{background:#f3f3f3}}code,pre{{font:12px ui-monospace,Menlo,monospace}}pre{{background:#f6f6f6;padding:8px;overflow:auto}}\
             .sev-high{{color:#b00;font-weight:bold}}</style></head><body><h1>Investigation report — {id}</h1>",
            id = esc(&self.id)
        );
        h += &table(
            &["Host", "Examiner", "Case opened", "Report generated"],
            vec![vec![self.host.clone(), self.examiner.clone(), self.opened.clone(), generated.to_rfc3339()]],
        );
        h += &format!("<h2>Conclusion</h2><p>{}</p>", if self.conclusion.is_empty() { "<em>No conclusion recorded.</em>".into() } else { esc(&self.conclusion) });
        if !extras.summaries.is_empty() {
            h += "<h2>Investigation summary</h2><p><em>Generated from recorded events by fixed rules; every line cites its source. It describes what was observed, not intent.</em></p>";
            for b in &extras.summaries {
                h += &format!("<h3>{}</h3><p>Window: {}</p>", esc(&b.subject), esc(&b.window));
                for (title, list) in [("Observed", &b.observed), ("Detections", &b.detections), ("Evidence", &b.evidence)] {
                    if !list.is_empty() {
                        h += &format!("<p><b>{title}</b></p><ul>{}</ul>", list.iter().map(|o| format!("<li>{}</li>", esc(o))).collect::<String>());
                    }
                }
                h += &format!("<p><b>Assessment:</b> {}</p>", esc(&b.assessment));
            }
        }
        if !self.bookmarks.is_empty() {
            h += "<h2>Key events (bookmarked)</h2>";
            let mut bm = self.bookmarks.clone();
            bm.sort_by(|a, b| a.time.cmp(&b.time));
            h += &table(&["Time", "Phase", "Event", "Note"], bm.iter().map(|b| vec![b.time.clone(), b.tag.clone(), format!("{} {}", b.event, b.summary), b.note.clone()]).collect());
        }
        h += &format!("<h2>Findings ({})</h2>", self.findings.len());
        h += &table(
            &["Time", "Severity", "Finding", "Source", "Detail"],
            self.findings.iter().map(|f| vec![f.time.clone(), f.severity.clone(), f.title.clone(), f.source.clone(), f.detail.clone()]).collect(),
        );
        if !self.notes.is_empty() {
            h += "<h2>Analyst notes</h2>";
            h += &table(&["Time", "Note"], self.notes.iter().map(|n| vec![n.time.clone(), n.text.clone()]).collect());
        }
        if !extras.persistence.is_empty() {
            h += "<h2>Flagged persistence entries</h2>";
            h += &table(&["Category", "Name", "Command", "Why"], extras.persistence.iter().map(|(a, b, c, d)| vec![a.clone(), b.clone(), c.clone(), d.clone()]).collect());
        }
        if !extras.detections.is_empty() {
            h += &format!("<h2>Detections ({})</h2>", extras.detections.len());
            h += &table(
                &["Severity", "Confidence", "Rule", "ATT&CK", "Subject", "Evidence", "First seen", "Last seen", "State"],
                extras.detections.iter().map(|d| vec![d.severity.clone(), d.confidence.clone(), d.rule.clone(), d.technique.clone(), d.subject.clone(), d.evidence.clone(), d.first_seen.clone(), d.last_seen.clone(), d.state.clone()]).collect(),
            );
        }
        if !extras.health.is_empty() {
            h += "<h2>Collection coverage</h2><p><em>Missing data means \"not observed\", never \"did not happen\".</em></p>";
            h += &table(&["Data source", "Status", "Detail"], extras.health.iter().map(|(a, b, c)| vec![a.clone(), b.clone(), c.clone()]).collect());
        }
        if !extras.timeline.is_empty() {
            h += "<h2>Timeline</h2>";
            h += &table(&["Time", "Source", "Event"], extras.timeline.iter().map(|(a, b, c)| vec![a.clone(), b.clone(), c.clone()]).collect());
        }
        if !register.is_empty() {
            h += "<h2>Evidence register</h2>";
            h += &table(
                &["ID", "File", "Class", "Status", "Method", "Source", "Collected", "SHA-256", "Problems"],
                register.iter().map(|e| vec![e.id.clone(), e.path.clone(), e.class.label().into(), e.status.label().into(), e.method.clone(), e.source.clone(), e.collected_at.clone(), e.sha256.clone(), e.problems.join("; ")]).collect(),
            );
        }
        h += &format!("<h2>Evidence ({} files)</h2>", manifest.len());
        h += &table(&["File", "Size", "SHA-256"], manifest.iter().map(|e| vec![e.path.clone(), e.size.to_string(), e.sha256.clone()]).collect());
        h += &format!("<h2>Chain of custody</h2><p>Chain: {}</p><pre>{}</pre></body></html>", esc(&chain_line), esc(&custody.join("\n")));
        fs::write(self.dir.join("report.html"), h)?;

        let mut ids = Vec::new();
        for f in ["report.md", "report.json", "report.html"] {
            let prov = Provenance { class: Class::Report, ..Provenance::derived("report generated from case data") };
            ids.push(self.enter(Some(&self.dir.join(f)), &prov, Status::Complete)?.id);
        }
        self.log("report exported", &format!("report.md, report.json, report.html ({})", ids.join(", ")))?;
        Ok(self.dir.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collecting_again_keeps_the_earlier_evidence_and_copies_twice() {
        let dir = std::env::temp_dir().join(format!("procwatch-again-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let case = Case::create(&dir).unwrap();
        case.add_text("processes.json", "first").unwrap();
        case.add_text("processes.json", "second").unwrap();
        assert_eq!(fs::read_to_string(case.dir.join("evidence/processes.json")).unwrap(), "second");
        let reg = case.register();
        assert_eq!(reg.len(), 2);
        for item in &reg {
            let p = case.dir.join(&item.path);
            assert_eq!(hash_evidence(&p).unwrap(), item.sha256, "{}", item.path);
        }
        assert!(reg[0].path.contains("earlier"));

        let src = dir.join("tool.bin");
        fs::write(&src, "payload").unwrap();
        let a = case.add_copy(&src).unwrap();
        let b = case.add_copy(&src).unwrap();
        assert_eq!(a, b);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn appending_from_the_tail_matches_the_full_chain() {
        let dir = std::env::temp_dir().join(format!("procwatch-tail-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let case = Case::create(&dir).unwrap();
        // Longer than the tail that is read, with one huge record last.
        for i in 0..400 {
            case.log("action", &format!("{i} {}", "x".repeat(300))).unwrap();
        }
        case.log("big", &"y".repeat(100_000)).unwrap();
        case.log("after", "still chained").unwrap();
        let st = case.chain_status();
        assert!(st.broken.is_none(), "{:?}", st.broken);
        assert_eq!(last_chain(&case.dir.join("custody.log")).unwrap(), st.head);
        assert_eq!(case.chain_status_cached().head, st.head);
        case.log("newer", "").unwrap();
        assert_ne!(case.chain_status_cached().head, st.head, "the cache follows the log");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn case_lifecycle() {
        let parent = std::env::temp_dir().join(format!("pw-case-{}", std::process::id()));
        let mut c = Case::create(&parent).unwrap();
        c.add_text("processes.json", "[]").unwrap();
        let src = parent.join("sample.bin");
        fs::write(&src, b"MZ fake").unwrap();
        c.add_copy(&src).unwrap();
        let q = parent.join("quarantine-me.bin");
        fs::write(&q, b"x").unwrap();
        crate::forensics::contain::quarantine(&c, &q).unwrap();
        c.add_finding("high", "Unsigned launch agent", "Persistence", "/tmp/x").unwrap();
        c.add_note("checked with the user").unwrap();
        c.set_conclusion("Benign test.").unwrap();

        let sealed = c.seal().unwrap();
        assert_eq!(sealed.len(), 4, "text, copy, quarantined file and its record");
        assert!(c.verify().unwrap().iter().all(|(_, s)| *s == Check::Ok));

        // Tamper: change one file, add another.
        let ev = c.dir.join("evidence").join("processes.json");
        fs::write(&ev, "[1]").unwrap();
        fs::write(c.dir.join("evidence").join("late.txt"), "x").unwrap();
        let v = c.verify().unwrap();
        assert!(v.iter().any(|(p, s)| p.ends_with("processes.json") && *s == Check::Modified));
        assert!(v.iter().any(|(p, s)| p.ends_with("late.txt") && *s == Check::Unlisted));

        let dir = c.export_report(&ReportExtras::default()).unwrap();
        let md = fs::read_to_string(dir.join("report.md")).unwrap();
        assert!(md.contains("Unsigned launch agent") && md.contains("Benign test.") && md.contains("Chain of custody"));
        assert!(fs::read_to_string(dir.join("report.html")).unwrap().contains("<table>"));
        let reopened = Case::open(&c.dir).unwrap();
        assert_eq!(reopened.findings.len(), 1);
        assert!(c.custody().len() >= 8);
        let st = c.chain_status();
        assert!(st.broken.is_none() && st.legacy == 0 && !st.head.is_empty(), "{st:?}");
        let reg = c.register();
        assert!(reg.iter().any(|e| e.class == Class::Copy) && reg.iter().any(|e| e.class == Class::Report));
        // Editing an earlier custody record breaks the chain from there on.
        let log = c.dir.join("custody.log");
        let text = fs::read_to_string(&log).unwrap().replacen("case opened", "case 0pened", 1);
        fs::write(&log, text).unwrap();
        assert_eq!(c.chain_status().broken.map(|b| b.0), Some(1));
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn chain_accepts_legacy_prefix_and_rejects_insertions() {
        let legacy = "t | a | old | x\n";
        let b1 = "t | a | new | y";
        let c1 = chain_next(GENESIS, b1);
        let good = format!("{legacy}{b1} | chain={c1}\n");
        let st = verify_chain(&good);
        assert!(st.broken.is_none() && st.legacy == 1 && st.head == c1);
        let bad = format!("{good}t | a | sneaky | z\n");
        assert!(verify_chain(&bad).broken.is_some());
    }

    #[test]
    fn partial_and_failed_collections_are_registered() {
        let parent = std::env::temp_dir().join(format!("pw-case-reg-{}", std::process::id()));
        let c = Case::create(&parent).unwrap();
        let prov = Provenance::live("snapshot").problems(vec!["event log not loaded".into()]);
        let (_, item) = c.add_text_with("system.json", "{}", prov).unwrap();
        assert_eq!(item.status, Status::Partial);
        c.record_failure("memory report", Provenance::live("vmmap").problems(vec!["permission denied".into()])).unwrap();
        let reg = c.register();
        assert_eq!(reg.len(), 2);
        assert_eq!(reg[1].status, Status::Failed);
        assert_eq!(reg[0].id, "E0001");
        let _ = fs::remove_dir_all(parent);
    }
}
