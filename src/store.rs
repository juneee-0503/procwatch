//! Persistent event history: everything procwatch observes is appended as
//! JSON lines to one file per day, so long sessions don't lose early
//! events to in-memory caps and a session can be replayed later
//! (`procwatch --replay`).
//!
//! Location: `$XDG_DATA_HOME/procwatch/events`, else
//! `~/Library/Application Support/procwatch/events` (macOS),
//! `~/.local/share/procwatch/events` (Linux), `%LOCALAPPDATA%\procwatch\events`
//! (Windows). Kept to `MAX_BYTES` and `MAX_DAYS`, oldest files first. Turn
//! off with `history = off` in the settings file.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

pub const MAX_BYTES: u64 = 256 << 20;
pub const MAX_DAYS: i64 = 14;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcRec {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub start: u64,
    pub name: String,
    pub exe: Option<String>,
    pub cmd: String,
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Rec {
    ProcStart(ProcRec),
    ProcExit { pid: u32, start: u64, name: String, ran: String },
    Net { kind: String, pid: u32, name: String, proto: String, local: String, remote: String, state: String },
    File { kind: String, path: String },
    Deep { kind: String, pid: u32, ppid: Option<u32>, start: u64, path: Option<String>, args: Option<String>, via: String },
    Change { pid: u32, start: u64, kind: String, path: String },
    Detection { rule: String, name: String, severity: String, confidence: String, technique: String, subject: String, pid: Option<u32>, evidence: String },
    Persist { kind: String, category: String, name: String, location: String, target: Option<String>, writer: Option<String> },
    /// Full process table, periodically, so replay has a tree.
    Snapshot { processes: Vec<ProcRec> },
    /// Session marker.
    Session { host: String, version: String, note: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Line {
    /// RFC 3339 with milliseconds.
    pub t: String,
    #[serde(flatten)]
    pub rec: Rec,
}

pub fn default_dir() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
        return Some(PathBuf::from(x).join("procwatch").join("events"));
    }
    #[cfg(target_os = "macos")]
    return std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support/procwatch/events"));
    #[cfg(windows)]
    return std::env::var_os("LOCALAPPDATA").map(|h| PathBuf::from(h).join("procwatch").join("events"));
    #[cfg(not(any(target_os = "macos", windows)))]
    return std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share/procwatch/events"));
}

pub struct Writer {
    dir: PathBuf,
    day: String,
    out: Option<BufWriter<File>>,
    pub written: u64,
    pub error: Option<String>,
}

impl Writer {
    pub fn open(dir: PathBuf) -> Writer {
        let mut w = Writer { dir, day: String::new(), out: None, written: 0, error: None };
        if let Err(e) = fs::create_dir_all(&w.dir) {
            w.error = Some(format!("{}: {e}", w.dir.display()));
        }
        w.prune();
        w
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn file_for(&mut self, t: &DateTime<Local>) -> Option<&mut BufWriter<File>> {
        let day = t.format("%Y%m%d").to_string();
        if day != self.day || self.out.is_none() {
            if let Some(o) = self.out.as_mut() {
                let _ = o.flush();
            }
            let path = self.dir.join(format!("events-{day}.jsonl"));
            match OpenOptions::new().create(true).append(true).open(&path) {
                Ok(f) => {
                    self.out = Some(BufWriter::new(f));
                    self.day = day;
                }
                Err(e) => {
                    self.error = Some(format!("{}: {e}", path.display()));
                    self.out = None;
                }
            }
        }
        self.out.as_mut()
    }

    pub fn write(&mut self, t: DateTime<Local>, rec: Rec) {
        if self.error.is_some() && self.out.is_none() && self.written > 0 {
            return;
        }
        let line = Line { t: t.to_rfc3339_opts(chrono::SecondsFormat::Millis, false), rec };
        let Ok(text) = serde_json::to_string(&line) else { return };
        if let Some(o) = self.file_for(&t) {
            if writeln!(o, "{text}").is_ok() {
                self.written += text.len() as u64 + 1;
            }
        }
    }

    pub fn flush(&mut self) {
        if let Some(o) = self.out.as_mut() {
            if let Err(e) = o.flush() {
                self.error = Some(e.to_string());
            }
        }
    }

    /// Delete the oldest files beyond the size and age limits.
    pub fn prune(&mut self) {
        let mut files: Vec<(PathBuf, u64, String)> = fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let day = name.strip_prefix("events-")?.strip_suffix(".jsonl")?.to_string();
                Some((e.path(), e.metadata().ok()?.len(), day))
            })
            .collect();
        files.sort_by(|a, b| a.2.cmp(&b.2));
        let cutoff = (Local::now() - chrono::Duration::days(MAX_DAYS)).format("%Y%m%d").to_string();
        let mut total: u64 = files.iter().map(|f| f.1).sum();
        for (path, size, day) in &files {
            if (*day < cutoff || total > MAX_BYTES) && *day != self.day {
                if fs::remove_file(path).is_ok() {
                    total -= size;
                }
            }
        }
    }

    pub fn total_bytes(&self) -> u64 {
        fs::read_dir(&self.dir).into_iter().flatten().flatten().filter_map(|e| e.metadata().ok()).map(|m| m.len()).sum()
    }
}

/// Read every stored line in `dir` (or a single file), oldest first,
/// within an optional time window. Malformed lines are counted, not fatal.
pub fn read(path: &Path, from: Option<DateTime<Local>>, to: Option<DateTime<Local>>) -> (Vec<(DateTime<Local>, Rec)>, usize) {
    let mut files: Vec<PathBuf> = if path.is_dir() {
        let mut v: Vec<PathBuf> = fs::read_dir(path)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .collect();
        // A case folder keeps its copy under evidence/.
        if v.is_empty() && path.join("evidence").is_dir() {
            v = fs::read_dir(path.join("evidence")).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "jsonl")).collect();
        }
        v
    } else {
        vec![path.to_path_buf()]
    };
    files.sort();
    let mut out = Vec::new();
    let mut bad = 0;
    for f in files {
        let Ok(file) = File::open(&f) else { continue };
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Line>(&line) {
                Ok(l) => {
                    let Some(t) = DateTime::parse_from_rfc3339(&l.t).ok().map(|t| t.with_timezone(&Local)) else {
                        bad += 1;
                        continue;
                    };
                    if from.is_some_and(|f| t < f) || to.is_some_and(|x| t > x) {
                        continue;
                    }
                    out.push((t, l.rec));
                }
                Err(_) => bad += 1,
            }
        }
    }
    out.sort_by_key(|(t, _)| *t);
    (out, bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_reads_and_prunes() {
        let dir = std::env::temp_dir().join(format!("pw-store-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut w = Writer::open(dir.clone());
        let now = Local::now();
        w.write(now, Rec::File { kind: "created".into(), path: "/tmp/x".into() });
        w.write(now, Rec::ProcExit { pid: 5, start: 1, name: "a".into(), ran: "1s".into() });
        w.flush();
        // An old file beyond the age limit is removed on open.
        fs::write(dir.join("events-20000101.jsonl"), "{}\n").unwrap();
        fs::write(dir.join(format!("events-{}.jsonl", now.format("%Y%m%d"))), {
            let mut t = fs::read_to_string(dir.join(format!("events-{}.jsonl", now.format("%Y%m%d")))).unwrap();
            t.push_str("not json\n");
            t
        })
        .unwrap();
        let w2 = Writer::open(dir.clone());
        assert!(!dir.join("events-20000101.jsonl").exists());
        let (recs, bad) = read(&dir, None, None);
        assert_eq!(recs.len(), 2);
        assert_eq!(bad, 1);
        assert!(matches!(recs[1].1, Rec::ProcExit { pid: 5, .. }));
        assert!(w2.total_bytes() > 0);
        let _ = fs::remove_dir_all(dir);
    }
}
