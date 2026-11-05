//! File-change monitoring for chosen folders (downloads, temp, autostart
//! locations by default). Events go to the timeline. The OS file-event
//! APIs don't say which process made a change.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Local};
use notify::{EventKind, RecursiveMode, Watcher};
use serde::Serialize;

use crate::common::emit::Emit;

#[derive(Debug, Clone, Serialize)]
pub struct FsEvent {
    #[serde(serialize_with = "ser_time")]
    pub time: DateTime<Local>,
    pub kind: &'static str,
    pub path: String,
    /// The process that did it, when the source knows (fanotify,
    /// fs_usage); plain change notifications don't carry one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

fn ser_time<S: serde::Serializer>(t: &DateTime<Local>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&t.to_rfc3339())
}

const MAX_PER_SECOND: u32 = 2000;
static DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// File events discarded so far because they arrived too fast.
pub fn dropped() -> u64 {
    DROPPED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Folders watched when the user hasn't configured any.
pub fn default_paths() -> Vec<String> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from).unwrap_or_default();
    let mut v: Vec<PathBuf> = vec![home.join("Downloads")];
    if cfg!(target_os = "macos") {
        v.extend([
            PathBuf::from("/private/tmp"),
            home.join("Library/LaunchAgents"),
            PathBuf::from("/Library/LaunchAgents"),
            PathBuf::from("/Library/LaunchDaemons"),
        ]);
    } else if cfg!(windows) {
        if let Some(t) = std::env::var_os("TEMP") {
            v.push(PathBuf::from(t));
        }
        if let Some(a) = std::env::var_os("APPDATA") {
            v.push(PathBuf::from(a).join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
        }
    } else {
        v.extend([PathBuf::from("/tmp"), PathBuf::from("/etc/systemd/system"), PathBuf::from("/etc/cron.d"), home.join(".config/autostart")]);
    }
    v.into_iter().filter(|p| p.is_dir()).map(|p| p.display().to_string()).collect()
}

/// True for paths inside folders that define autostart entries.
pub fn autostart_location(path: &str) -> bool {
    let p = path.to_lowercase().replace('\\', "/");
    ["/launchagents/", "/launchdaemons/", "/etc/systemd/system/", "/etc/cron.", "/var/spool/cron", "/.config/autostart/", "/start menu/programs/startup/", "/etc/init.d/", "/etc/rc.local"]
        .iter()
        .any(|k| p.contains(k))
}

/// Start watching; the returned watcher must be kept alive. Paths that
/// can't be watched are reported back in the error list.
pub fn start(paths: &[String], events: Emit<FsEvent>) -> (Option<notify::RecommendedWatcher>, Vec<String>) {
    let mut errors = Vec::new();
    let (mut window, mut sent) = (std::time::Instant::now(), 0u32);
    let handler = move |res: notify::Result<notify::Event>| {
        let Ok(ev) = res else { return };
        let kind = match ev.kind {
            EventKind::Create(_) => "created",
            EventKind::Modify(notify::event::ModifyKind::Name(_)) => "renamed",
            EventKind::Modify(notify::event::ModifyKind::Metadata(_)) => "attributes",
            EventKind::Modify(_) => "modified",
            EventKind::Remove(_) => "deleted",
            _ => return,
        };
        for p in ev.paths {
            // A build or unpack in a watched folder can emit far more than
            // anyone can read; don't let that bury everything else.
            if window.elapsed() >= std::time::Duration::from_secs(1) {
                (window, sent) = (std::time::Instant::now(), 0);
            }
            sent += 1;
            if sent > MAX_PER_SECOND {
                DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                continue;
            }
            events.send(FsEvent { time: Local::now(), kind, path: p.display().to_string(), pid: None });
        }
    };
    let mut watcher = match notify::recommended_watcher(handler) {
        Ok(w) => w,
        Err(e) => return (None, vec![e.to_string()]),
    };
    for p in paths {
        if let Err(e) = watcher.watch(Path::new(p), RecursiveMode::Recursive) {
            errors.push(format!("{p}: {e}"));
        }
    }
    (Some(watcher), errors)
}
