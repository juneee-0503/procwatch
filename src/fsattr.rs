//! File operations *with the process that performed them*, where the OS
//! offers it to a tool like procwatch:
//!
//! - Linux: fanotify on the mounts of the watched folders (needs root /
//!   CAP_SYS_ADMIN); every open-for-write, modify and close-after-write
//!   carries the pid.
//! - macOS: `fs_usage -w -f filesys` restricted to deep-traced processes
//!   (needs root); writes, creates, renames, deletes and chmods.
//!
//! Events are sent as ordinary `FsEvent`s with `pid` set. Without root the
//! caller falls back to unattributed change notifications.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::mpsc::Sender;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use chrono::Local;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::fswatch::FsEvent;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::sampler::WorkerMsg;

/// Why attribution isn't running (for the health view), or None if it is.
pub fn unavailable_reason() -> Option<String> {
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        return Some("needs root (run procwatch with sudo for per-process file attribution)".into());
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Some("not available on this platform (Windows would need ETW File I/O; not implemented)".into());
    #[allow(unreachable_code)]
    None
}

// ── macOS: fs_usage ────────────────────────────────────────────────────

/// Parse one `fs_usage -w -f filesys` line into (op, path, pid).
/// Example: `23:10:01.123456  open   F=3  (_WC___)  /tmp/x   0.000010   sh.12345`
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_fs_usage(line: &str) -> Option<(&'static str, String, u32)> {
    let mut it = line.split_whitespace();
    let _time = it.next()?;
    let op = it.next()?;
    let rest: Vec<&str> = it.collect();
    let proc_tok = rest.last()?;
    let pid: u32 = proc_tok.rsplit_once('.')?.1.parse().ok()?;
    let flags = rest.iter().find(|t| t.starts_with('(') && t.ends_with(')')).copied().unwrap_or("");
    let kind: &'static str = match op {
        "open" if flags.contains('W') || flags.contains('C') => {
            if flags.contains('C') { "created" } else { "modified" }
        }
        "write" | "WrData" | "WrData[A]" | "WrData[AN]" | "pwrite" | "writev" => "modified",
        "rename" | "renameat" => "renamed",
        "unlink" | "unlinkat" | "rmdir" => "deleted",
        "mkdir" | "mkdirat" => "created",
        "chmod" | "fchmod" | "chmod_extended" | "fchmodat" => "changed",
        _ => return None,
    };
    // The path is the first token that looks like one; paths with spaces
    // run up to the elapsed-time column.
    // Data writes name the disk device first; skip it.
    let start = rest.iter().position(|t| t.starts_with('/') && !t.starts_with("/dev/disk"))?;
    let end = rest.iter().rposition(|t| t.parse::<f64>().is_ok() && t.contains('.')).filter(|e| *e > start).unwrap_or(rest.len() - 1);
    let path = rest[start..end].join(" ");
    Some((kind, path, pid))
}

/// Run fs_usage for `pids` until the returned child is killed.
#[cfg(target_os = "macos")]
pub fn start_fs_usage(pids: &[u32], tx: Sender<WorkerMsg>) -> Option<std::process::Child> {
    use std::io::BufRead;
    if pids.is_empty() || unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let mut cmd = std::process::Command::new("/usr/bin/fs_usage");
    cmd.args(["-w", "-f", "filesys"]);
    cmd.args(pids.iter().map(|p| p.to_string()));
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
    let mut child = cmd.spawn().ok()?;
    let out = child.stdout.take()?;
    let _ = std::thread::Builder::new().name("fs_usage".into()).spawn(move || {
        for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
            if let Some((kind, path, pid)) = parse_fs_usage(&line) {
                if tx.send(WorkerMsg::Fs(FsEvent { time: Local::now(), kind, path, pid: Some(pid) })).is_err() {
                    break;
                }
            }
        }
    });
    Some(child)
}

// ── Linux: fanotify ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub fn start_fanotify(paths: &[String], tx: Sender<WorkerMsg>) -> Result<(), String> {
    use std::ffi::CString;
    let fd = unsafe { libc::fanotify_init(libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC, (libc::O_RDONLY | libc::O_LARGEFILE) as u32) };
    if fd < 0 {
        return Err(format!("fanotify_init: {}", std::io::Error::last_os_error()));
    }
    let mask = libc::FAN_MODIFY | libc::FAN_CLOSE_WRITE;
    let mut marked = 0;
    for p in paths {
        let Ok(c) = CString::new(p.as_str()) else { continue };
        if unsafe { libc::fanotify_mark(fd, libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT, mask, libc::AT_FDCWD, c.as_ptr()) } == 0 {
            marked += 1;
        }
    }
    if marked == 0 {
        unsafe { libc::close(fd) };
        return Err(format!("fanotify_mark: {}", std::io::Error::last_os_error()));
    }
    let watched: Vec<String> = paths.to_vec();
    let me = std::process::id() as i32;
    std::thread::Builder::new()
        .name("fanotify".into())
        .spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n <= 0 {
                    break;
                }
                let mut off = 0usize;
                let size = std::mem::size_of::<libc::fanotify_event_metadata>();
                while off + size <= n as usize {
                    let m: libc::fanotify_event_metadata = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const _) };
                    if m.event_len as usize == 0 {
                        break;
                    }
                    if m.fd >= 0 {
                        let path = std::fs::read_link(format!("/proc/self/fd/{}", m.fd)).map(|p| p.display().to_string()).unwrap_or_default();
                        unsafe { libc::close(m.fd) };
                        if m.pid != me && watched.iter().any(|w| path.starts_with(w.as_str())) {
                            let kind = if m.mask & libc::FAN_CLOSE_WRITE != 0 { "modified" } else { "changed" };
                            let ev = FsEvent { time: Local::now(), kind, path, pid: Some(m.pid as u32) };
                            if tx.send(WorkerMsg::Fs(ev)).is_err() {
                                return;
                            }
                        }
                    }
                    off += m.event_len as usize;
                }
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fs_usage_lines() {
        let l = "23:10:01.123456  open              F=3        (_WC_T______)  /private/tmp/drop.bin                     0.000021   sh.4242";
        assert_eq!(parse_fs_usage(l), Some(("created", "/private/tmp/drop.bin".into(), 4242)));
        let w = "23:10:01.223456  WrData[A]         D=0x000ab  B=0x1000  /dev/disk3s5  /Users/a/Library/LaunchAgents/x y.plist  0.000300 W kernel_task.0";
        assert_eq!(parse_fs_usage(w).map(|x| x.1), Some("/Users/a/Library/LaunchAgents/x y.plist".into()));
        let r = "23:10:02.000001  rename            /tmp/a  /tmp/b      0.000011   mv.77";
        assert_eq!(parse_fs_usage(r).map(|x| (x.0, x.2)), Some(("renamed", 77)));
        assert!(parse_fs_usage("23:10:02.000001  lstat64  /tmp/a  0.000011   ls.5").is_none(), "reads are ignored");
        assert!(parse_fs_usage("garbage").is_none());
    }
}
