//! Background intelligence about executables: signature (status, signer,
//! team, platform binary) and, on request, SHA-256. One worker thread
//! works through a queue so hundreds of executables don't stall anything;
//! results are cached by path and invalidated when size or mtime change.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::SystemTime;

use serde::Serialize;

use crate::process::inspect::{self, SignatureStatus};

const WORKERS: usize = 4;

/// Files larger than this aren't hashed automatically.
const MAX_HASH_BYTES: u64 = 512 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum Sig {
    Signed,
    Unsigned,
    Invalid,
    /// Not checked (unsupported platform or file unreadable).
    Unknown,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ExeInfo {
    pub sig: Sig,
    pub signer: String,
    pub team: Option<String>,
    pub platform: bool,
    pub sha256: Option<String>,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub size: u64,
    #[serde(skip)]
    pub mtime: Option<SystemTime>,
    pub exists: bool,
    /// Present but not readable by us (e.g. setuid binaries, root-only
    /// folders): nothing can be concluded about signature or hash.
    pub unreadable: bool,
}

struct Job {
    path: String,
    hash: bool,
}

#[derive(Clone)]
pub struct Intel {
    cache: Arc<Mutex<HashMap<String, ExeInfo>>>,
    queued: Arc<Mutex<HashSet<(String, bool)>>>,
    tx: Sender<Job>,
}

/// (exists, size, mtime, unreadable)
fn stamp(path: &str) -> (bool, u64, Option<SystemTime>, bool) {
    match std::fs::metadata(path) {
        Ok(m) => {
            let unreadable = std::fs::File::open(path).is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied);
            (true, m.len(), m.modified().ok(), unreadable)
        }
        // A folder we may not enter isn't proof the file is gone.
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => (true, 0, None, true),
        Err(_) => (false, 0, None, false),
    }
}

fn examine(path: &str, hash: bool, previous: Option<ExeInfo>) -> ExeInfo {
    let (exists, size, mtime, unreadable) = stamp(path);
    // Same file as before: keep the signature, maybe add the hash.
    if let Some(mut p) = previous.filter(|p| p.exists == exists && p.size == size && p.mtime == mtime) {
        if hash && p.sha256.is_none() && exists && size <= MAX_HASH_BYTES {
            fill_hashes(&mut p, path);
        }
        return p;
    }
    let mut info = ExeInfo {
        sig: Sig::Unknown,
        signer: String::new(),
        team: None,
        platform: false,
        sha256: None,
        md5: None,
        sha1: None,
        size,
        mtime,
        exists,
        unreadable,
    };
    if !exists || unreadable {
        return info;
    }
    if cfg!(any(target_os = "macos", windows)) {
        let (status, details) = inspect::file_signature(path);
        info.sig = match status {
            SignatureStatus::Valid { signer } => {
                info.signer = signer;
                Sig::Signed
            }
            SignatureStatus::Unsigned => Sig::Unsigned,
            SignatureStatus::Invalid { reason } => {
                info.signer = reason;
                Sig::Invalid
            }
            SignatureStatus::Unknown => Sig::Unknown,
        };
        for (k, v) in &details {
            match k.as_str() {
                "Team ID" => info.team = Some(v.clone()),
                "Type" if v.contains("platform") => info.platform = true,
                _ => {}
            }
        }
        // Apple's software-signing chain also marks system binaries.
        if info.signer.contains("Software Signing") {
            info.platform = true;
        }
    }
    if hash && size <= MAX_HASH_BYTES {
        fill_hashes(&mut info, path);
    }
    info
}

/// MD5, SHA-1 and SHA-256 in one read of the file.
fn fill_hashes(info: &mut ExeInfo, path: &str) {
    if let Ok(h) = crate::files::info::hash_file(Path::new(path)) {
        info.sha256 = Some(h.sha256);
        info.md5 = Some(h.md5);
        info.sha1 = Some(h.sha1);
    }
}

impl Intel {
    pub fn new() -> Self {
        let cache: Arc<Mutex<HashMap<String, ExeInfo>>> = Arc::default();
        let queued: Arc<Mutex<HashSet<(String, bool)>>> = Arc::default();
        let (tx, rx) = channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        // A few workers: each signature check spawns a process and mostly
        // waits, so this scales well without hogging the CPU.
        for n in 0..WORKERS {
            let (c, q, rx) = (cache.clone(), queued.clone(), rx.clone());
            let _ = thread::Builder::new().name(format!("intel-{n}")).spawn(move || loop {
            let job = match rx.lock() {
                Ok(r) => r.recv(),
                Err(_) => return,
            };
            let Ok(job) = job else { return };
            {
                let previous = c.lock().ok().and_then(|m| m.get(&job.path).cloned());
                let path = job.path.clone();
                let info = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| examine(&path, job.hash, previous)));
                if let Ok(info) = info {
                    if let Ok(mut m) = c.lock() {
                        m.insert(job.path.clone(), info);
                    }
                }
                if let Ok(mut q) = q.lock() {
                    q.remove(&(job.path, job.hash));
                }
            }
            });
        }
        Intel { cache, queued, tx }
    }

    /// Queue `path` for checking (and hashing when `hash`), unless it's
    /// already known or queued.
    pub fn request(&self, path: &str, hash: bool) {
        if path.is_empty() {
            return;
        }
        let known = self.cache.lock().ok().and_then(|m| m.get(path).map(|i| !hash || i.sha256.is_some() || !i.exists || i.size > MAX_HASH_BYTES));
        if known == Some(true) {
            return;
        }
        if let Ok(mut q) = self.queued.lock() {
            if q.insert((path.to_string(), hash)) {
                let _ = self.tx.send(Job { path: path.to_string(), hash });
            }
        }
    }

    pub fn get(&self, path: &str) -> Option<ExeInfo> {
        self.cache.lock().ok()?.get(path).cloned()
    }

    /// Copy of everything known so far (one lock for a whole snapshot).
    pub fn snapshot(&self) -> HashMap<String, ExeInfo> {
        self.cache.lock().map(|m| m.clone()).unwrap_or_default()
    }

    pub fn pending(&self) -> usize {
        self.queued.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// Forget everything (e.g. after files were replaced).
    pub fn clear(&self) {
        if let Ok(mut m) = self.cache.lock() {
            m.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn checks_and_hashes_in_background() {
        let intel = Intel::new();
        let me = std::env::current_exe().unwrap().display().to_string();
        // Generous: on Windows the signature check starts PowerShell, which
        // takes tens of seconds on a busy CI runner.
        let wait = |done: &dyn Fn() -> bool| {
            for _ in 0..1200 {
                if done() {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
        };
        intel.request(&me, true);
        wait(&|| intel.get(&me).is_some_and(|i| i.sha256.is_some()));
        let info = intel.get(&me).expect("examined");
        assert!(info.exists && info.sha256.as_deref().is_some_and(|h| h.len() == 64));
        intel.request("/nonexistent/procwatch", false);
        wait(&|| intel.get("/nonexistent/procwatch").is_some());
        assert!(!intel.get("/nonexistent/procwatch").unwrap().exists);
    }
}
