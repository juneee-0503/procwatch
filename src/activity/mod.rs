//! Per-process activity capture, in the spirit of Process Monitor: file,
//! registry and network operations with the process that performed them.
//!
//! Sources, none of which need a driver:
//! - Windows: ETW Kernel-File, Kernel-Registry and Kernel-Network
//!   (administrator). See `etw.rs`.
//! - Linux: fanotify (root), including create/delete/rename on 5.9+.
//! - macOS: `fs_usage` (root).
//!
//! The volume can be enormous, so repeats are merged per batch and a rate
//! limit drops the excess. Drops are counted and shown: a capture that lost
//! events must say so.

pub mod module;
mod probes;
#[cfg(target_os = "linux")]
use probes::linux;
#[cfg(target_os = "macos")]
use probes::macos;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};

use crate::common::emit::Emit;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    File,
    Registry,
    Network,
}

impl Class {
    pub fn label(self) -> &'static str {
        match self {
            Class::File => "file",
            Class::Registry => "registry",
            Class::Network => "network",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Activity {
    pub time: DateTime<Local>,
    pub pid: u32,
    /// Filled in when it reaches the UI, while the process can still be named.
    pub name: Arc<str>,
    pub class: Class,
    pub op: &'static str,
    pub path: String,
    pub detail: String,
    /// Merged repeats of the same operation on the same target.
    pub count: u32,
    pub bytes: u64,
}

impl Activity {
    pub fn new(pid: u32, class: Class, op: &'static str, path: impl Into<String>) -> Activity {
        Activity { time: Local::now(), pid, name: Arc::from(""), class, op, path: path.into(), detail: String::new(), count: 1, bytes: 0 }
    }

    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    pub fn with_bytes(mut self, bytes: u64) -> Activity {
        self.bytes = bytes;
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Activity {
        self.detail = detail.into();
        self
    }
}

/// More than this per second is dropped rather than queued.
const MAX_PER_SECOND: u32 = 20_000;
const BATCH_EVERY: Duration = Duration::from_millis(250);

static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Events discarded so far because they arrived too fast.
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

/// Collects events from a source thread and hands batches to the UI.
pub struct Batcher {
    out: Emit<Vec<Activity>>,
    items: Vec<Activity>,
    index: HashMap<(u32, &'static str, String), usize>,
    window: Instant,
    in_window: u32,
    me: u32,
}

pub type SharedBatcher = Arc<Mutex<Batcher>>;

impl Batcher {
    pub fn new(out: Emit<Vec<Activity>>) -> Batcher {
        Batcher { out, items: Vec::new(), index: HashMap::new(), window: Instant::now(), in_window: 0, me: std::process::id() }
    }

    pub fn push(&mut self, a: Activity) {
        if a.pid == self.me {
            return; // our own reads would feed back forever
        }
        if self.window.elapsed() >= Duration::from_secs(1) {
            self.window = Instant::now();
            self.in_window = 0;
        }
        let key = (a.pid, a.op, a.path.clone());
        if let Some(i) = self.index.get(&key) {
            let cur = &mut self.items[*i];
            cur.count += 1;
            cur.bytes += a.bytes;
            return;
        }
        self.in_window += 1;
        if self.in_window > MAX_PER_SECOND {
            DROPPED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.index.insert(key, self.items.len());
        self.items.push(a);
    }

    /// False when nobody is listening any more.
    pub fn flush(&mut self) -> bool {
        self.index.clear();
        if self.items.is_empty() {
            return true;
        }
        self.out.send(std::mem::take(&mut self.items))
    }
}

/// Runs for as long as `stop` is unset, delivering batches.
fn spawn_flusher(b: SharedBatcher, stop: Arc<std::sync::atomic::AtomicBool>) {
    let _ = std::thread::Builder::new().name("activity-batch".into()).spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(BATCH_EVERY);
            let alive = b.lock().map(|mut b| b.flush()).unwrap_or(false);
            if !alive {
                return;
            }
        }
    });
}

/// A running capture; stops when dropped.
pub struct Capture {
    stop: Arc<std::sync::atomic::AtomicBool>,
    pub method: &'static str,
    #[cfg(windows)]
    _trace: ferrisetw::trace::UserTrace,
    #[cfg(target_os = "macos")]
    child: std::process::Child,
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        #[cfg(windows)]
        crate::network::traffic::set_connection_sink(None);
        #[cfg(target_os = "macos")]
        {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Start capturing. Err says why it can't run, for the user to see.
pub fn start(out: Emit<Vec<Activity>>) -> Result<Capture, String> {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let batcher: SharedBatcher = Arc::new(Mutex::new(Batcher::new(out)));
    #[cfg(windows)]
    {
        let trace = probes::windows::start_activity(batcher.clone())?;
        let sink = batcher.clone();
        crate::network::traffic::set_connection_sink(Some(Emit::new(move |c: crate::network::traffic::ConnOp| {
            if let Ok(mut b) = sink.lock() {
                b.push(Activity::new(c.pid, Class::Network, c.op, c.remote));
            }
            true
        })));
        spawn_flusher(batcher, stop.clone());
        Ok(Capture { stop, method: "ETW Kernel-File and Kernel-Registry", _trace: trace })
    }
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            return Err("needs root".into());
        }
        let method = linux::start(batcher.clone(), stop.clone())?;
        spawn_flusher(batcher, stop.clone());
        Ok(Capture { stop, method })
    }
    #[cfg(target_os = "macos")]
    {
        if unsafe { libc::geteuid() } != 0 {
            return Err("needs root (fs_usage)".into());
        }
        let child = macos::start(batcher.clone())?;
        spawn_flusher(batcher, stop.clone());
        Ok(Capture { stop, method: "fs_usage", child })
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (batcher, stop);
        Err("not available on this platform".into())
    }
}

/// Windows autostart keys: a write to one is worth a detection, and here
/// the writer is known.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn is_autostart_key(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    ["\\currentversion\\run", "\\currentversion\\policies\\explorer\\run", "\\currentversion\\winlogon", "\\image file execution options\\", "\\services\\", "\\control\\lsa", "\\session manager"]
        .iter()
        .any(|k| p.contains(k))
}

// ── fanotify records (parsing kept portable for tests) ─────────────────

/// One `FAN_EVENT_INFO_TYPE_DFID_NAME` record: the directory's file handle
/// (`handle_bytes`, `handle_type`, data) and the entry's name.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_dfid_name(rec: &[u8]) -> Option<(&[u8], String)> {
    const DFID_NAME: u8 = 2;
    const HEADER: usize = 4;
    const FSID: usize = 8;
    const HANDLE_HEADER: usize = 8;
    if *rec.first()? != DFID_NAME {
        return None;
    }
    let len = u16::from_ne_bytes(rec.get(2..4)?.try_into().ok()?) as usize;
    let rec = rec.get(..len)?;
    let handle = rec.get(HEADER + FSID..)?;
    let bytes = u32::from_ne_bytes(handle.get(..4)?.try_into().ok()?) as usize;
    let total = HANDLE_HEADER.checked_add(bytes)?;
    let name = handle.get(total..)?;
    let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
    Some((handle.get(..total)?, String::from_utf8_lossy(&name[..end]).into_owned()))
}

/// Mount points of real filesystems from `/proc/self/mountinfo`, one per
/// device. Virtual filesystems say nothing about file activity.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn real_mounts(mountinfo: &str) -> Vec<String> {
    const VIRTUAL: &[&str] = &["proc", "sysfs", "cgroup", "cgroup2", "devtmpfs", "devpts", "securityfs", "debugfs", "tracefs", "bpf", "pstore", "mqueue", "hugetlbfs", "configfs", "fusectl", "autofs", "nsfs", "binfmt_misc", "rpc_pipefs", "efivarfs"];
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else { continue };
        let f: Vec<&str> = left.split_whitespace().collect();
        let (Some(dev), Some(point), Some(fstype)) = (f.get(2), f.get(4), right.split_whitespace().next()) else { continue };
        if !VIRTUAL.contains(&fstype) && seen.insert(*dev) {
            out.push(point.replace("\\040", " "));
        }
    }
    out
}



#[cfg(test)]
mod tests {
    use super::*;

    fn batcher() -> (Batcher, std::sync::mpsc::Receiver<Vec<Activity>>) {
        let (out, rx) = Emit::channel();
        (Batcher::new(out), rx)
    }

    #[test]
    fn repeats_merge_and_own_events_are_ignored() {
        let (mut b, rx) = batcher();
        b.push(Activity::new(5, Class::File, "write", "/a").with_bytes(10));
        b.push(Activity::new(5, Class::File, "write", "/a").with_bytes(5));
        b.push(Activity::new(5, Class::File, "read", "/a"));
        b.push(Activity::new(std::process::id(), Class::File, "write", "/a"));
        assert!(b.flush());
        let Ok(v) = rx.try_recv() else { panic!("no batch") };
        assert_eq!(v.len(), 2);
        assert_eq!((v[0].count, v[0].bytes), (2, 15));
        // The next batch starts over.
        b.push(Activity::new(5, Class::File, "write", "/a"));
        assert!(b.flush());
        let Ok(v) = rx.try_recv() else { panic!("no batch") };
        assert_eq!(v[0].count, 1);
    }

    #[test]
    fn floods_are_counted_not_queued() {
        let (mut b, _rx) = batcher();
        let before = dropped();
        for i in 0..(MAX_PER_SECOND + 500) {
            b.push(Activity::new(5, Class::File, "write", format!("/f{i}")));
        }
        assert!(b.items.len() <= MAX_PER_SECOND as usize);
        assert!(dropped() >= before + 500 || b.window.elapsed() >= Duration::from_secs(1));
    }

    #[test]
    fn autostart_keys() {
        assert!(is_autostart_key(r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\x"));
        assert!(is_autostart_key(r"HKLM\SYSTEM\CurrentControlSet\Services\evil\ImagePath"));
        assert!(!is_autostart_key(r"HKLM\SOFTWARE\Vendor\Settings"));
    }

    #[test]
    fn dfid_records_and_garbage() {
        let mut rec = vec![2u8, 0];
        let handle = [1u8, 2, 3, 4];
        let len = 4 + 8 + 8 + handle.len() + 6;
        rec.extend((len as u16).to_ne_bytes());
        rec.extend([9u8; 8]);
        rec.extend((handle.len() as u32).to_ne_bytes());
        rec.extend(1i32.to_ne_bytes());
        rec.extend(handle);
        rec.extend(b"a.txt\0");
        let (h, name) = parse_dfid_name(&rec).unwrap();
        assert_eq!((h.len(), name.as_str()), (12, "a.txt"));
        assert!(parse_dfid_name(&[]).is_none());
        assert!(parse_dfid_name(&[1, 0, 4, 0]).is_none(), "other record type");
        assert!(parse_dfid_name(&[2, 0, 255, 255, 0, 0]).is_none(), "length past the end");
        let mut huge = rec.clone();
        huge[12..16].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(parse_dfid_name(&huge).is_none(), "handle length past the end");
    }

    #[test]
    fn mount_table_keeps_real_filesystems_once() {
        let t = "\
22 1 8:1 / / rw - ext4 /dev/sda1 rw
23 22 0:5 / /proc rw - proc proc rw
24 22 8:1 /home /home rw - ext4 /dev/sda1 rw
25 22 0:30 / /tmp rw - tmpfs tmpfs rw
26 22 0:31 / /my\\040disk rw - xfs /dev/sdb rw
bad line
";
        assert_eq!(real_mounts(t), vec!["/", "/tmp", "/my disk"]);
    }
}
