//! Handles a Windows process holds, like Sysinternals `handle.exe`.
//!
//! Lists the system handle table, duplicates each handle into this process
//! and asks what it refers to. Only the handle is used: the target's memory
//! is never read or written. Other users' processes need administrator
//! rights; protected ones can't be opened at all.
//!
//! Asking for the name of a named pipe can block forever, and such a call
//! can't be cancelled. So files are named only when they are on disk, and
//! each process is worked through on a watched thread: a stall abandons that
//! thread and carries on after the handle that stalled.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{GetFileType, GetFinalPathNameByHandleW, FILE_TYPE_DISK};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessId, OpenProcess, PROCESS_DUP_HANDLE};

use crate::process::inspect::OpenFile;

#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtQueryObject(handle: HANDLE, class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
}

const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
const OBJECT_NAME_INFORMATION: u32 = 1;
const OBJECT_TYPE_INFORMATION: u32 = 2;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const MAX_TABLE: usize = 1 << 30;
/// Silence from the worker for this long means it is stuck.
const STALL: Duration = Duration::from_secs(1);
/// Each stall costs a thread forever, so stop before that adds up.
const MAX_STALLS: usize = 8;

#[repr(C)]
#[derive(Clone, Copy)]
struct Entry {
    object: *mut c_void,
    pid: usize,
    value: usize,
    access: u32,
    backtrace: u16,
    type_index: u16,
    attributes: u32,
    reserved: u32,
}

#[repr(C)]
struct UnicodeString {
    len: u16,
    max: u16,
    buffer: *const u16,
}

/// (handle value, type index) per process.
fn table() -> Result<HashMap<u32, Vec<(usize, u16)>>, String> {
    let mut buf: Vec<u64> = vec![0; 1 << 17];
    loop {
        let bytes = buf.len() * 8;
        let mut ret = 0;
        let status = unsafe { NtQuerySystemInformation(SYSTEM_EXTENDED_HANDLE_INFORMATION, buf.as_mut_ptr() as *mut c_void, bytes as u32, &mut ret) };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            if bytes >= MAX_TABLE {
                return Err("handle table too large".into());
            }
            buf = vec![0; buf.len() * 2];
            continue;
        }
        if status < 0 {
            return Err(format!("NtQuerySystemInformation: {status:#x}"));
        }
        break;
    }
    // Header: count, reserved; entries follow.
    let count = buf[0] as usize;
    let room = (buf.len() - 2) * 8 / size_of::<Entry>();
    let entries = unsafe { std::slice::from_raw_parts(buf.as_ptr().add(2) as *const Entry, count.min(room)) };
    let mut map: HashMap<u32, Vec<(usize, u16)>> = HashMap::new();
    for e in entries {
        map.entry(e.pid as u32).or_default().push((e.value, e.type_index));
    }
    Ok(map)
}

/// The UNICODE_STRING at the start of an NtQueryObject result.
fn query_string(h: HANDLE, class: u32) -> Option<String> {
    let mut buf: Vec<u64> = vec![0; 512];
    let mut ret = 0;
    let status = unsafe { NtQueryObject(h, class, buf.as_mut_ptr() as *mut c_void, (buf.len() * 8) as u32, &mut ret) };
    if status < 0 {
        return None;
    }
    let s = unsafe { &*(buf.as_ptr() as *const UnicodeString) };
    if s.buffer.is_null() || s.len == 0 {
        return None;
    }
    let text = unsafe { std::slice::from_raw_parts(s.buffer, usize::from(s.len) / 2) };
    Some(String::from_utf16_lossy(text))
}

fn disk_path(h: HANDLE) -> Option<String> {
    if unsafe { GetFileType(h) } != FILE_TYPE_DISK {
        return None;
    }
    let mut buf = vec![0u16; 1024];
    let n = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, 0) } as usize;
    (n > 0 && n < buf.len()).then(|| {
        let p = String::from_utf16_lossy(&buf[..n]);
        p.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(p)
    })
}

/// What one handle refers to, or None if it has nothing worth listing.
fn describe(process: HANDLE, value: usize, kind: u16, types: &mut HashMap<u16, String>) -> Option<OpenFile> {
    let mut dup: HANDLE = std::ptr::null_mut();
    let ok = unsafe { DuplicateHandle(process, value as HANDLE, GetCurrentProcess(), &mut dup, 0, 0, DUPLICATE_SAME_ACCESS) };
    if ok == 0 {
        return None;
    }
    let type_name = match types.get(&kind) {
        Some(t) => t.clone(),
        None => {
            let t = query_string(dup, OBJECT_TYPE_INFORMATION).unwrap_or_default();
            types.insert(kind, t.clone());
            t
        }
    };
    let name = match type_name.as_str() {
        "File" => disk_path(dup),
        "Process" => match unsafe { GetProcessId(dup) } {
            0 => None,
            pid => Some(format!("process {pid}")),
        },
        "Key" => query_string(dup, OBJECT_NAME_INFORMATION).map(|n| crate::common::paths::registry_path(&n)),
        "Mutant" | "Section" | "Event" | "Semaphore" | "Directory" | "SymbolicLink" | "Timer" => query_string(dup, OBJECT_NAME_INFORMATION),
        _ => None,
    };
    unsafe { CloseHandle(dup) };
    name.map(|name| OpenFile { fd: format!("{value:#x}"), kind: type_name, name })
}

/// Everything named among `handles`, within `deadline`.
fn enumerate(pid: u32, handles: Vec<(usize, u16)>, deadline: Instant) -> Result<Vec<OpenFile>, String> {
    let process = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) };
    if process.is_null() {
        return Err(format!("can't open the process: {}", std::io::Error::last_os_error()));
    }
    let handles = Arc::new(handles);
    // Raw handles aren't Send; this one stays open until every worker is done.
    let shared = process as isize;
    let (mut start, mut stalls) = (0usize, 0usize);
    let mut finished = false;
    let mut out = Vec::new();
    'all: while start < handles.len() && stalls < MAX_STALLS {
        let (tx, rx) = mpsc::channel();
        let list = handles.clone();
        let begin = start;
        std::thread::Builder::new()
            .name("handles".into())
            .spawn(move || {
                let mut types = HashMap::new();
                for (i, (value, kind)) in list.iter().enumerate().skip(begin) {
                    let item = describe(shared as HANDLE, *value, *kind, &mut types);
                    if tx.send((i, item)).is_err() {
                        return;
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        loop {
            if Instant::now() >= deadline {
                break 'all;
            }
            match rx.recv_timeout(STALL) {
                Ok((i, item)) => {
                    start = i + 1;
                    out.extend(item);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    finished = true;
                    break 'all;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    stalls += 1;
                    start += 1; // past the handle it is stuck on
                    break;
                }
            }
        }
    }
    // Unless the last worker ran to its end, one may still use this handle.
    // Closing it could let the value be reused under that worker, so a
    // leaked handle is the safe outcome of a stall or the deadline.
    if finished && stalls == 0 {
        unsafe { CloseHandle(process) };
    }
    out.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.name.cmp(&b.name)));
    Ok(out)
}

/// Named objects `pid` holds handles to.
pub fn for_process(pid: u32) -> Result<Vec<OpenFile>, String> {
    let mut t = table()?;
    enumerate(pid, t.remove(&pid).unwrap_or_default(), Instant::now() + Duration::from_secs(20))
}

/// Open disk files of every process we may open, for the Files page.
/// Bounded in time: what didn't fit is left out.
pub fn all_files(deadline: Duration) -> Result<Vec<(u32, OpenFile)>, String> {
    let until = Instant::now() + deadline;
    let mut out = Vec::new();
    for (pid, handles) in table()? {
        if Instant::now() >= until {
            break;
        }
        // Protected and system processes refuse; that's normal here.
        if let Ok(items) = enumerate(pid, handles, until) {
            out.extend(items.into_iter().filter(|i| i.kind == "File").map(|i| (pid, i)));
        }
    }
    Ok(out)
}
