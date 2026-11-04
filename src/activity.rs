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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};

use crate::sampler::WorkerMsg;

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
    tx: Sender<WorkerMsg>,
    items: Vec<Activity>,
    index: HashMap<(u32, &'static str, String), usize>,
    window: Instant,
    in_window: u32,
    me: u32,
}

pub type SharedBatcher = Arc<Mutex<Batcher>>;

impl Batcher {
    pub fn new(tx: Sender<WorkerMsg>) -> Batcher {
        Batcher { tx, items: Vec::new(), index: HashMap::new(), window: Instant::now(), in_window: 0, me: std::process::id() }
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
        self.tx.send(WorkerMsg::Activity(std::mem::take(&mut self.items))).is_ok()
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
        crate::etw::set_activity_sink(None);
        #[cfg(target_os = "macos")]
        {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Start capturing. Err says why it can't run, for the user to see.
pub fn start(tx: Sender<WorkerMsg>) -> Result<Capture, String> {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let batcher: SharedBatcher = Arc::new(Mutex::new(Batcher::new(tx)));
    #[cfg(windows)]
    {
        let trace = crate::etw::start_activity(batcher.clone())?;
        crate::etw::set_activity_sink(Some(batcher.clone()));
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

/// `\REGISTRY\MACHINE\...` as people write it.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn registry_path(raw: &str) -> String {
    let trimmed = raw.trim_start_matches('\\');
    let upper = trimmed.to_ascii_uppercase();
    for (native, short) in [("REGISTRY\\MACHINE", "HKLM"), ("REGISTRY\\USER", "HKU"), ("REGISTRY\\A", "HKA")] {
        if upper.starts_with(native) {
            // ASCII prefix, so the same byte length in both.
            return format!("{short}{}", &trimmed[native.len()..]);
        }
    }
    raw.to_string()
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

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;

    const FAN_REPORT_DIR_FID: libc::c_uint = 0x0000_0400;
    const FAN_REPORT_NAME: libc::c_uint = 0x0000_0800;
    const FAN_MARK_FILESYSTEM: libc::c_uint = 0x0000_0100;
    const FAN_MOVED_FROM: u64 = 0x40;
    const FAN_MOVED_TO: u64 = 0x80;
    const FAN_CREATE: u64 = 0x100;
    const FAN_DELETE: u64 = 0x200;
    const FAN_OPEN_EVENT: u64 = 0x20;
    const FAN_MODIFY_EVENT: u64 = 0x02;
    const FAN_CLOSE_WRITE_EVENT: u64 = 0x08;
    const FAN_ONDIR: u64 = 0x4000_0000;

    fn group(flags: libc::c_uint, mask: u64, mounts: &[String]) -> Option<libc::c_int> {
        let fd = unsafe { libc::fanotify_init(libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK | flags, (libc::O_RDONLY | libc::O_LARGEFILE) as libc::c_uint) };
        if fd < 0 {
            return None;
        }
        let mut marked = 0;
        for m in mounts {
            let Ok(c) = CString::new(m.as_str()) else { continue };
            if unsafe { libc::fanotify_mark(fd, libc::FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask, libc::AT_FDCWD, c.as_ptr()) } == 0 {
                marked += 1;
            }
        }
        if marked == 0 {
            unsafe { libc::close(fd) };
            return None;
        }
        Some(fd)
    }

    /// Path of a directory given its file handle: the handle is only valid
    /// against its own filesystem, so try each mount.
    fn dir_of(handle: &[u8], mounts: &[libc::c_int]) -> Option<String> {
        // file_handle needs u32 alignment.
        let mut h = vec![0u32; handle.len().div_ceil(4)];
        unsafe { std::ptr::copy_nonoverlapping(handle.as_ptr(), h.as_mut_ptr() as *mut u8, handle.len()) };
        for m in mounts {
            let fd = unsafe { libc::syscall(libc::SYS_open_by_handle_at, *m, h.as_mut_ptr(), libc::O_PATH | libc::O_CLOEXEC) } as libc::c_int;
            if fd >= 0 {
                let p = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok();
                unsafe { libc::close(fd) };
                return p.map(|p| p.display().to_string());
            }
        }
        None
    }

    fn read_events(fd: libc::c_int, mut each: impl FnMut(&libc::fanotify_event_metadata, &[u8])) {
        let mut buf = vec![0u8; 64 * 1024];
        // Bounded so a busy group can't starve the other or the stop flag.
        for _ in 0..16 {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                return;
            }
            let (mut off, n) = (0usize, n as usize);
            let size = std::mem::size_of::<libc::fanotify_event_metadata>();
            while off + size <= n {
                let m: libc::fanotify_event_metadata = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const _) };
                let len = m.event_len as usize;
                if len < size || off + len > n {
                    break;
                }
                each(&m, &buf[off + m.metadata_len as usize..off + len]);
                off += len;
            }
        }
    }

    pub fn start(b: SharedBatcher, stop: Arc<std::sync::atomic::AtomicBool>) -> Result<&'static str, String> {
        let mounts = real_mounts(&std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| e.to_string())?);
        let contents = group(0, FAN_OPEN_EVENT | FAN_MODIFY_EVENT | FAN_CLOSE_WRITE_EVENT, &mounts).ok_or_else(|| format!("fanotify: {}", std::io::Error::last_os_error()))?;
        let names = group(FAN_REPORT_DIR_FID | FAN_REPORT_NAME, FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO | FAN_ONDIR, &mounts);
        let mount_fds: Vec<libc::c_int> = mounts
            .iter()
            .filter_map(|m| CString::new(m.as_str()).ok())
            .map(|c| unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) })
            .filter(|fd| *fd >= 0)
            .collect();
        let method = if names.is_some() { "fanotify (opens, writes, creates, deletes, renames)" } else { "fanotify (opens and writes; creates and deletes need Linux 5.9)" };
        std::thread::Builder::new()
            .name("activity-fanotify".into())
            .spawn(move || {
                let mut polls = vec![libc::pollfd { fd: contents, events: libc::POLLIN, revents: 0 }];
                polls.extend(names.map(|fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 }));
                while !stop.load(Ordering::Relaxed) {
                    if unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, 200) } <= 0 {
                        continue;
                    }
                    read_events(contents, |m, _| {
                        if m.fd < 0 {
                            return;
                        }
                        let path = std::fs::read_link(format!("/proc/self/fd/{}", m.fd)).map(|p| p.display().to_string()).unwrap_or_default();
                        unsafe { libc::close(m.fd) };
                        let op = if m.mask & FAN_MODIFY_EVENT != 0 {
                            "write"
                        } else if m.mask & FAN_CLOSE_WRITE_EVENT != 0 {
                            "close after write"
                        } else {
                            "open"
                        };
                        if let Ok(mut b) = b.lock() {
                            b.push(Activity::new(m.pid as u32, Class::File, op, path));
                        }
                    });
                    if let Some(fd) = names {
                        read_events(fd, |m, info| {
                            let Some((handle, name)) = parse_dfid_name(info) else { return };
                            let dir = dir_of(handle, &mount_fds).unwrap_or_default();
                            let path = if dir.is_empty() { name } else { format!("{}/{name}", dir.trim_end_matches('/')) };
                            let op = if m.mask & FAN_CREATE != 0 {
                                "create"
                            } else if m.mask & FAN_DELETE != 0 {
                                "delete"
                            } else if m.mask & FAN_MOVED_FROM != 0 {
                                "rename from"
                            } else {
                                "rename to"
                            };
                            if let Ok(mut b) = b.lock() {
                                b.push(Activity::new(m.pid as u32, Class::File, op, path));
                            }
                        });
                    }
                }
                unsafe {
                    libc::close(contents);
                    if let Some(fd) = names {
                        libc::close(fd);
                    }
                    for fd in mount_fds {
                        libc::close(fd);
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(method)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::io::BufRead;

    pub fn start(b: SharedBatcher) -> Result<std::process::Child, String> {
        let mut child = std::process::Command::new("/usr/bin/fs_usage")
            .args(["-w", "-f", "filesys"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("fs_usage: {e}"))?;
        let out = child.stdout.take().ok_or("fs_usage: no output")?;
        let _ = std::thread::Builder::new().name("activity-fs_usage".into()).spawn(move || {
            for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
                if let Some((op, path, pid)) = crate::fsattr::parse_fs_usage(&line) {
                    if let Ok(mut b) = b.lock() {
                        b.push(Activity::new(pid, Class::File, op, path));
                    }
                }
            }
        });
        Ok(child)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batcher() -> (Batcher, std::sync::mpsc::Receiver<WorkerMsg>) {
        let (tx, rx) = std::sync::mpsc::channel();
        (Batcher::new(tx), rx)
    }

    #[test]
    fn repeats_merge_and_own_events_are_ignored() {
        let (mut b, rx) = batcher();
        b.push(Activity::new(5, Class::File, "write", "/a").with_bytes(10));
        b.push(Activity::new(5, Class::File, "write", "/a").with_bytes(5));
        b.push(Activity::new(5, Class::File, "read", "/a"));
        b.push(Activity::new(std::process::id(), Class::File, "write", "/a"));
        assert!(b.flush());
        let Ok(WorkerMsg::Activity(v)) = rx.try_recv() else { panic!("no batch") };
        assert_eq!(v.len(), 2);
        assert_eq!((v[0].count, v[0].bytes), (2, 15));
        // The next batch starts over.
        b.push(Activity::new(5, Class::File, "write", "/a"));
        assert!(b.flush());
        let Ok(WorkerMsg::Activity(v)) = rx.try_recv() else { panic!("no batch") };
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
    fn registry_paths_and_autostart_keys() {
        assert_eq!(registry_path(r"\REGISTRY\MACHINE\SOFTWARE\X"), r"HKLM\SOFTWARE\X");
        assert_eq!(registry_path(r"\Registry\User\S-1-5\Software"), r"HKU\S-1-5\Software");
        assert_eq!(registry_path("relative\\key"), "relative\\key");
        assert_eq!(registry_path("\\REGISTRY\\MACHINE\\キー"), "HKLM\\キー");
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
