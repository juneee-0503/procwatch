use super::super::*;
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
const FAN_Q_OVERFLOW: u64 = 0x4000;

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
            let info = off + m.metadata_len as usize;
            if len < size || off + len > n || info > off + len {
                break;
            }
            // The kernel's queue filled up: events were lost before us.
            if m.mask & FAN_Q_OVERFLOW != 0 {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            } else {
                each(&m, &buf[info..off + len]);
            }
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
        // Not O_PATH: open_by_handle_at refuses such a descriptor.
        .map(|c| unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) })
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
