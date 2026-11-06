//! Playbooks and the tamper-evident log behind `procwatch --agent`.
//!
//! A playbook says what to do when a detection appears. The default mode
//! writes down what it would have done, and acting needs `mode: enforce`:
//! a detection can be wrong, and killing the wrong process costs more than
//! a late alert. See `docs/edr.md`.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::enforce::Mode;
use crate::common::model::Severity;
use crate::common::text::glob;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Step {
    /// Write the process's details to the log.
    Collect,
    Suspend,
    Kill,
    /// Refuse traffic from the attacker's address for a while.
    Ban,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct When {
    /// Rule ids or names; empty means any.
    #[serde(default)]
    pub rule: Vec<String>,
    #[serde(default)]
    pub min_severity: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Playbook {
    pub id: String,
    pub when: When,
    #[serde(rename = "do")]
    pub steps: Vec<Step>,
    #[serde(default = "default_cooldown")]
    pub cooldown_seconds: u64,
    #[serde(default = "default_ban")]
    pub ban_seconds: u64,
}

fn default_ban() -> u64 {
    3600
}

fn default_cooldown() -> u64 {
    300
}

fn default_mode() -> Mode {
    Mode::Audit
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicy {
    #[serde(default = "default_mode")]
    pub mode: Mode,
    /// A blocking policy to apply alongside, relative to this file.
    #[serde(default)]
    pub enforce: Option<String>,
    /// Capture file, registry and network activity too.
    #[serde(default)]
    pub activity: bool,
    pub playbooks: Vec<Playbook>,
}

impl AgentPolicy {
    pub fn parse(text: &str) -> Result<AgentPolicy, String> {
        let p: AgentPolicy = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
        p.validate()?;
        Ok(p)
    }

    pub fn load(path: &Path) -> Result<AgentPolicy, String> {
        AgentPolicy::parse(&std::fs::read_to_string(path).map_err(|e| e.to_string())?)
    }

    pub fn enforce_path(&self, policy: &Path) -> Option<PathBuf> {
        self.enforce.as_ref().map(|e| policy.parent().unwrap_or(Path::new("")).join(e))
    }

    fn validate(&self) -> Result<(), String> {
        let mut problems = Vec::new();
        let mut ids = std::collections::HashSet::new();
        for p in &self.playbooks {
            if p.id.is_empty() || !ids.insert(p.id.as_str()) {
                problems.push(format!("playbook id '{}' is empty or used twice", p.id));
            }
            if p.steps.is_empty() {
                problems.push(format!("{}: has no steps", p.id));
            }
            let severity = p.when.min_severity.as_deref().map(Severity::parse);
            if p.when.rule.is_empty() && severity.is_none() {
                problems.push(format!("{}: needs `rule` or `min_severity`: it would answer every detection", p.id));
            }
            // Anything stronger than noting a process must be aimed at
            // something a rule says is bad, not at whatever scores low.
            let acts = p.steps.iter().any(|s| *s != Step::Collect);
            if acts && p.when.rule.is_empty() && severity.is_none_or(|s| s < Severity::High) {
                problems.push(format!("{}: suspend, kill and ban need a named rule or min_severity of high or above", p.id));
            }
            if p.ban_seconds == 0 || p.ban_seconds > 7 * 86_400 {
                problems.push(format!("{}: ban_seconds must be between 1 and a week", p.id));
            }
            if acts && p.when.rule.iter().any(|r| r.trim_matches('*').is_empty()) {
                problems.push(format!("{}: a rule pattern of only wildcards would act on everything", p.id));
            }
        }
        if problems.is_empty() { Ok(()) } else { Err(problems.join("\n")) }
    }

    /// The playbooks a detection triggers.
    pub fn matching(&self, rule_id: &str, rule_name: &str, severity: Severity) -> impl Iterator<Item = &Playbook> {
        let (id, name) = (rule_id.to_string(), rule_name.to_string());
        self.playbooks.iter().filter(move |p| {
            (p.when.rule.is_empty() || p.when.rule.iter().any(|r| glob(r, &id) || glob(r, &name)))
                && p.when.min_severity.as_deref().is_none_or(|m| severity >= Severity::parse(m))
        })
    }
}

/// Answers a playbook once per process until its cooldown ends, so a
/// detection that stays true doesn't repeat every second.
#[derive(Default)]
pub struct Cooldowns(HashMap<(String, u32, u64), Instant>);

impl Cooldowns {
    pub fn ready(&mut self, playbook: &Playbook, pid: u32, start: u64, now: Instant) -> bool {
        const MAX: usize = 100_000;
        let wait = Duration::from_secs(playbook.cooldown_seconds);
        if self.0.len() >= MAX {
            self.0.retain(|_, at| now.duration_since(*at) < Duration::from_secs(3600));
        }
        let key = (playbook.id.clone(), pid, start);
        if self.0.get(&key).is_some_and(|at| now.duration_since(*at) < wait) {
            return false;
        }
        self.0.insert(key, now);
        true
    }
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn link(prev: &str, seq: u64, time: &str, event: &str) -> String {
    let mut h = Sha256::new();
    for part in [prev, &seq.to_string(), time, event] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Serialize, Deserialize)]
struct Entry {
    seq: u64,
    time: String,
    /// Kept as text so the hash covers the exact bytes written.
    event: String,
    prev: String,
    hash: String,
}

/// Most entries' bytes in the current segment before it is sealed.
const SEGMENT: u64 = 64 << 20;

/// Ask the kernel to make a file append-only, so not even its owner can
/// change what is there. Needs CAP_LINUX_IMMUTABLE; without it this does
/// nothing and the hash chain still shows any change.
#[cfg(target_os = "linux")]
fn append_only(file: &std::fs::File, on: bool) -> bool {
    use std::os::fd::AsRawFd;
    const GETFLAGS: libc::c_ulong = 0x8008_6601;
    const SETFLAGS: libc::c_ulong = 0x4008_6602;
    const APPEND: libc::c_long = 0x20;
    let mut flags: libc::c_long = 0;
    unsafe {
        if libc::ioctl(file.as_raw_fd(), GETFLAGS, &mut flags) != 0 {
            return false;
        }
        let next = if on { flags | APPEND } else { flags & !APPEND };
        libc::ioctl(file.as_raw_fd(), SETFLAGS, &next) == 0
    }
}

#[cfg(not(target_os = "linux"))]
fn append_only(_: &std::fs::File, _: bool) -> bool {
    false
}

/// An append-only log where each line carries a hash of everything before
/// it, so editing or removing a line shows. Someone with write access can
/// rebuild a whole chain, which is why the head leaves the machine in the
/// heartbeat. Full segments are sealed; a damaged one is set aside, never
/// discarded, and the chain carries on in a new file.
pub struct ChainLog {
    path: PathBuf,
    file: std::fs::File,
    seq: u64,
    head: String,
    written: u64,
    /// What was found wrong on opening.
    pub damage: Option<String>,
    pub append_only: bool,
}

fn sealed_name(path: &Path, seq: u64) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{seq:012}"));
    PathBuf::from(name)
}

impl ChainLog {
    pub fn open(path: &Path) -> Result<ChainLog, String> {
        let (mut seq, mut head, mut damage) = (0, GENESIS.to_string(), None);
        if path.exists() {
            match verify(path) {
                Ok(v) => {
                    seq = v.lines;
                    head = v.head;
                }
                Err(e) => {
                    let mut aside = path.as_os_str().to_os_string();
                    aside.push(format!(".damaged-{}", chrono::Local::now().format("%Y%m%d%H%M%S")));
                    let _ = std::fs::OpenOptions::new().read(true).open(path).map(|f| append_only(&f, false));
                    std::fs::rename(path, &aside).map_err(|e| format!("{}: {e}", path.display()))?;
                    damage = Some(format!("{e}; kept as {}", PathBuf::from(aside).display()));
                }
            }
        }
        let file = crate::common::paths::private_file().create(true).append(true).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let written = file.metadata().map_or(0, |m| m.len());
        let append = append_only(&file, true);
        Ok(ChainLog { path: path.to_path_buf(), file, seq, head, written, damage, append_only: append })
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        append_only(&self.file, false);
        let sealed = sealed_name(&self.path, self.seq);
        std::fs::rename(&self.path, &sealed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o400))?;
        }
        self.file = crate::common::paths::private_file().create(true).append(true).open(&self.path)?;
        self.written = 0;
        self.append_only = append_only(&self.file, true);
        Ok(())
    }

    pub fn append(&mut self, event: &serde_json::Value) -> std::io::Result<()> {
        if self.written >= SEGMENT {
            self.rotate()?;
        }
        self.seq += 1;
        let time = chrono::Local::now().to_rfc3339();
        let event = event.to_string();
        let hash = link(&self.head, self.seq, &time, &event);
        let entry = Entry { seq: self.seq, time, event, prev: std::mem::take(&mut self.head), hash: hash.clone() };
        self.head = hash;
        let mut line = serde_json::to_string(&entry).map_err(std::io::Error::other)?;
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.sync_data()?;
        self.written += line.len() as u64;
        Ok(())
    }

    /// Whether the file on disk is still at least what was written here.
    pub fn intact(&self) -> bool {
        std::fs::metadata(&self.path).is_ok_and(|m| m.len() >= self.written)
    }

    pub fn head(&self) -> (u64, &str) {
        (self.seq, &self.head)
    }

    /// Points along the chain, for checking elsewhere that history wasn't
    /// rewritten.
    pub fn anchors(&self) -> Vec<(u64, String)> {
        let Ok(file) = std::fs::File::open(&self.path) else { return Vec::new() };
        let all: Vec<(u64, String)> = std::io::BufReader::new(file).lines().map_while(Result::ok).filter_map(|l| serde_json::from_str::<Entry>(&l).ok()).map(|e| (e.seq, e.hash)).collect();
        let step = (all.len() / 32).max(1);
        all.into_iter().step_by(step).collect()
    }
}

/// Delete sealed segments past the limits, oldest first, keeping a record of
/// each one's end: that proves it existed and what its last hash was.
pub fn prune(path: &Path, max_age_days: u64, max_bytes: u64) -> std::io::Result<usize> {
    let (Some(dir), Some(stem)) = (path.parent(), path.file_name().map(|n| n.to_string_lossy().into_owned())) else { return Ok(0) };
    let prefix = format!("{stem}.");
    let mut sealed: Vec<(PathBuf, u64, std::time::SystemTime)> = std::fs::read_dir(dir)?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().strip_prefix(&prefix).is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit())))
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            Some((e.path(), m.len(), m.modified().ok()?))
        })
        .collect();
    sealed.sort_by_key(|s| s.2);
    let mut total: u64 = sealed.iter().map(|s| s.1).sum();
    let mut removed = 0;
    for (file, size, modified) in sealed {
        let old = modified.elapsed().is_ok_and(|a| a.as_secs() > max_age_days.saturating_mul(86_400));
        if !old && total <= max_bytes {
            continue;
        }
        let last = std::fs::read_to_string(&file).ok().and_then(|t| t.lines().next_back().map(str::to_string)).and_then(|l| serde_json::from_str::<Entry>(&l).ok());
        if let Some(e) = last {
            let mut anchors = crate::common::paths::private_file().create(true).append(true).open(dir.join(format!("{stem}.anchors")))?;
            writeln!(anchors, "{}", serde_json::json!({ "v": 1, "seq": e.seq, "hash": e.hash, "time": e.time }))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::remove_file(&file)?;
        total -= size;
        removed += 1;
    }
    Ok(removed)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Verified {
    pub lines: u64,
    pub head: String,
}

/// Check every link. The error names the first bad entry: everything before
/// it can still be trusted. A file may continue a sealed segment, so its
/// first entry's place in the chain is taken from the entry itself.
pub fn verify(path: &Path) -> Result<Verified, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut last: Option<(u64, String)> = None;
    for (i, line) in std::io::BufReader::new(file).lines().enumerate() {
        let n = i + 1;
        let line = line.map_err(|e| format!("line {n}: {e}"))?;
        let e: Entry = serde_json::from_str(&line).map_err(|e| format!("line {n}: not a log entry ({e}): untrusted from here on"))?;
        let (want_seq, want_prev) = last.as_ref().map_or((e.seq, e.prev.as_str()), |(s, h)| (s + 1, h.as_str()));
        if e.seq != want_seq || e.prev != want_prev || link(&e.prev, e.seq, &e.time, &e.event) != e.hash {
            return Err(format!("line {n}: chain broken: the log was edited or a line removed; untrusted from entry {want_seq} on"));
        }
        if last.is_none() && e.seq == 1 && e.prev != GENESIS {
            return Err(format!("line {n}: the chain doesn't start where it should"));
        }
        last = Some((e.seq, e.hash));
    }
    let (lines, head) = last.unwrap_or_else(|| (0, GENESIS.to_string()));
    Ok(Verified { lines, head })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
mode: enforce
playbooks:
  - id: miners
    when: { rule: ["*miner*"] }
    do: [collect, kill]
    cooldown_seconds: 60
  - id: note-all-high
    when: { min_severity: high }
    do: [collect]
"#;

    #[test]
    fn playbooks_match_detections() {
        let p = AgentPolicy::parse(GOOD).unwrap();
        assert_eq!(p.mode, Mode::Enforce);
        let ids = |r, n, s| p.matching(r, n, s).map(|b| b.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids("r1", "Crypto miner", Severity::Low), ["miners"]);
        assert_eq!(ids("r1", "Crypto miner", Severity::High), ["miners", "note-all-high"]);
        assert!(ids("r2", "Other", Severity::Medium).is_empty());
    }

    #[test]
    fn audit_is_the_default_and_loose_playbooks_are_refused() {
        assert_eq!(AgentPolicy::parse("playbooks: []").unwrap().mode, Mode::Audit);
        for bad in [
            "playbooks:\n  - { id: a, when: {}, do: [collect] }\n",
            "playbooks:\n  - { id: a, when: { min_severity: medium }, do: [kill] }\n",
            "playbooks:\n  - { id: a, when: { rule: ['**'] }, do: [kill] }\n",
            "playbooks:\n  - { id: a, when: { rule: [x] }, do: [] }\n",
            "playbooks:\n  - { id: a, when: { rule: [x] }, do: [wipe] }\n",
            "playbooks:\n  - { id: a, when: { rule: [x] }, do: [kill] }\n  - { id: a, when: { rule: [y] }, do: [kill] }\n",
        ] {
            assert!(AgentPolicy::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_detection_is_answered_once_per_cooldown() {
        let p = AgentPolicy::parse(GOOD).unwrap();
        let (mut c, t, b) = (Cooldowns::default(), Instant::now(), &p.playbooks[0]);
        assert!(c.ready(b, 7, 1, t));
        assert!(!c.ready(b, 7, 1, t + Duration::from_secs(59)));
        assert!(c.ready(b, 8, 1, t), "another process");
        assert!(c.ready(b, 7, 1, t + Duration::from_secs(61)));
    }

    #[test]
    fn the_log_shows_edits_and_removals() {
        let dir = crate::common::paths::private_temp_dir("chain").unwrap();
        let path = dir.join("agent.jsonl");
        let mut log = ChainLog::open(&path).unwrap();
        for i in 0..3 {
            log.append(&serde_json::json!({ "n": i })).unwrap();
        }
        assert!(log.intact());
        assert_eq!(verify(&path).unwrap().lines, 3);
        drop(log);
        // It carries on across restarts.
        ChainLog::open(&path).unwrap().append(&serde_json::json!({ "n": 3 })).unwrap();
        assert_eq!(verify(&path).unwrap().lines, 4);
        let good = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, good.replacen("\\\"n\\\":1", "\\\"n\\\":9", 1)).unwrap();
        assert!(verify(&path).unwrap_err().starts_with("line 2"));
        let reopened = ChainLog::open(&path).unwrap();
        assert!(reopened.damage.as_deref().is_some_and(|d| d.contains("line 2")), "the damage is reported and the file kept");
        assert_eq!(reopened.head().0, 0, "a new chain starts");
        drop(reopened);
        let lines: Vec<&str> = good.lines().collect();
        std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(verify(&path).unwrap_err().contains("untrusted from entry 2"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn segments_continue_the_chain_and_pruning_keeps_proof() {
        let dir = crate::common::paths::private_temp_dir("chain").unwrap();
        let path = dir.join("agent.jsonl");
        let mut log = ChainLog::open(&path).unwrap();
        log.append(&serde_json::json!({ "n": 1 })).unwrap();
        log.rotate().unwrap();
        log.append(&serde_json::json!({ "n": 2 })).unwrap();
        assert_eq!(verify(&path).unwrap().lines, 2, "the new file continues numbering");
        assert_eq!(verify(&sealed_name(&path, 1)).unwrap().lines, 1);
        assert_eq!(prune(&path, 3650, 1 << 30).unwrap(), 0, "within limits");
        assert_eq!(prune(&path, 3650, 0).unwrap(), 1);
        assert!(!sealed_name(&path, 1).exists());
        assert!(std::fs::read_to_string(dir.join("agent.jsonl.anchors")).unwrap().contains("\"seq\":1"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
