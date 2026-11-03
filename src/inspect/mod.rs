//! "Deep inspection" of a single process — the kind of detail panel found
//! in Process Hacker / Process Explorer: threads, open files/handles,
//! environment, loaded modules, code-signing status, owner.
//!
//! Everything here is **read-only enumeration**. Nothing in this module
//! reads or writes another process's memory, nothing dumps process
//! memory to disk, and nothing injects code — by design (see README for
//! why memory-dump support was deliberately left out).

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "linux")]
pub mod linux;

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::process::native::{self, ThreadInfo};

#[derive(Debug, Clone)]
pub struct DeepInfo {
    pub loaded_modules: Vec<String>,
    pub handle_count: Option<u64>,
    pub signature_status: SignatureStatus,
    pub integrity_or_privilege: Option<String>,
    pub working_directory: Option<String>,
    pub notes: Vec<String>, // permission errors, degraded-mode explanations, etc.
    pub threads: Result<Vec<ThreadInfo>, String>,
    pub open_files: Result<Vec<OpenFile>, String>,
    pub environment: Result<Vec<(String, String)>, String>,
    /// Whether the (slow) module listing was part of this inspection.
    pub modules_loaded: bool,
    /// Signer details as label/value pairs (identifier, team, chain…).
    pub signature_details: Vec<(String, String)>,
}

impl Default for DeepInfo {
    fn default() -> Self {
        Self {
            loaded_modules: Vec::new(),
            handle_count: None,
            signature_status: SignatureStatus::Unknown,
            integrity_or_privilege: None,
            working_directory: None,
            notes: Vec::new(),
            threads: Ok(Vec::new()),
            open_files: Err("not collected".into()),
            environment: Ok(Vec::new()),
            modules_loaded: false,
            signature_details: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFile {
    /// fd number (`3`, `cwd`, `txt`, …).
    pub fd: String,
    /// `REG`, `DIR`, `IPv4`, `PIPE`, `unix`, …
    pub kind: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(dead_code)] // the Linux backend only ever reports `Unknown`
pub enum SignatureStatus {
    #[default]
    Unknown,
    Valid { signer: String },
    Invalid { reason: String },
    Unsigned,
}

/// Fetch deep info for `pid`. Dispatches to the platform backend; always
/// succeeds (sections carry their own error text) rather than erroring the
/// whole UI out.
///
/// This can take seconds (it shells out), so callers run it on a worker
/// thread — never on the UI thread. `modules` adds the slow module listing
/// (vmmap / PowerShell), which is only needed for the Modules tab.
pub fn inspect(pid: u32, exe_path: Option<&str>, modules: bool) -> DeepInfo {
    // Threads and environment are platform-neutral at this level; collect
    // them alongside the (slower) platform probes.
    let threads = thread::spawn(move || native::threads(pid).map_err(|e| e.to_string()));
    let env = environment(pid);

    #[cfg(target_os = "windows")]
    let mut info = windows::inspect(pid, exe_path, modules);
    #[cfg(target_os = "macos")]
    let mut info = macos::inspect(pid, exe_path, modules);
    #[cfg(target_os = "linux")]
    let mut info = linux::inspect(pid, exe_path, modules);
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    let mut info = {
        let _ = (exe_path, modules);
        let mut info = DeepInfo::default();
        info.notes.push("deep inspection not implemented on this platform".into());
        info
    };

    info.threads = threads.join().unwrap_or_else(|_| Err("worker panicked".into()));
    info.environment = env;
    info
}

/// Open files of one process, without the rest of the inspection. Used by
/// behavior tracing, which polls this every couple of seconds.
pub fn open_files(pid: u32) -> Result<Vec<OpenFile>, String> {
    #[cfg(target_os = "macos")]
    return macos::open_files(pid).map_err(|e| e.to_string());
    #[cfg(target_os = "linux")]
    return linux::open_files(pid).map_err(|e| e.to_string());
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        Err("open-file listing is not available on this platform".into())
    }
}

/// Mapped executable images (dylibs / shared objects / DLLs) of one
/// process, without the rest of the inspection.
pub fn modules(pid: u32) -> Result<Vec<String>, String> {
    #[cfg(target_os = "macos")]
    return macos::loaded_dylibs(pid).map_err(|e| e.to_string());
    #[cfg(target_os = "linux")]
    return linux::loaded_modules(pid).map_err(|e| e.to_string());
    #[cfg(target_os = "windows")]
    {
        let info = windows::inspect(pid, None, true);
        if info.loaded_modules.is_empty() {
            return Err(info.notes.join("; "));
        }
        Ok(info.loaded_modules)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = pid;
        Err("module listing is not available on this platform".into())
    }
}

/// Thorough signature check for a single file the user is analysing:
/// on macOS this also validates every resource of an app bundle.
pub fn file_signature_thorough(path: &str) -> (SignatureStatus, Vec<(String, String)>) {
    if std::fs::File::open(path).is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) {
        return file_signature(path);
    }
    #[cfg(target_os = "macos")]
    {
        macos::signature_status_with(path, true).unwrap_or_else(|e| (SignatureStatus::Invalid { reason: e.to_string() }, Vec::new()))
    }
    #[cfg(not(target_os = "macos"))]
    {
        file_signature(path)
    }
}

/// Signature status and signer details of any file on disk (fast check,
/// used for background scanning).
pub fn file_signature(path: &str) -> (SignatureStatus, Vec<(String, String)>) {
    if std::fs::File::open(path).is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) {
        return (SignatureStatus::Unknown, vec![("Note".into(), "file is not readable by this user".into())]);
    }
    #[cfg(target_os = "macos")]
    let r = macos::signature_status(path);
    #[cfg(target_os = "windows")]
    let r = windows::file_signature(path);
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let r: anyhow::Result<(SignatureStatus, Vec<(String, String)>)> = {
        let _ = path;
        Ok((SignatureStatus::Unknown, Vec::new()))
    };
    r.unwrap_or_else(|e| (SignatureStatus::Invalid { reason: e.to_string() }, Vec::new()))
}

/// Sample the call stacks of every thread in `pid` for about a second.
/// macOS uses Apple's `sample` tool (same user or root); Linux reports
/// each thread's wait channel and, with root, its kernel stack.
pub fn call_stacks(pid: u32) -> Result<Vec<String>, String> {
    #[cfg(target_os = "macos")]
    return macos::call_stacks(pid);
    #[cfg(target_os = "linux")]
    return linux::call_stacks(pid);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        Err("call stack sampling is not available on this platform (use a debugger such as WinDbg)".into())
    }
}

/// Environment of another process, via sysinfo (KERN_PROCARGS2 on macOS,
/// `/proc/<pid>/environ` on Linux, PEB read on Windows).
fn environment(pid: u32) -> Result<Vec<(String, String)>, String> {
    let mut sys = System::new();
    let target = [Pid::from_u32(pid)];
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&target),
        ProcessRefreshKind::new().with_environ(UpdateKind::Always),
    );
    let proc_ = sys.process(target[0]).ok_or("process exited")?;
    let mut vars: Vec<(String, String)> = proc_
        .environ()
        .iter()
        .map(|kv| {
            let kv = kv.to_string_lossy();
            match kv.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (kv.into_owned(), String::new()),
            }
        })
        .filter(|(k, _)| !k.is_empty())
        .collect();
    if vars.is_empty() {
        return Err("not readable (other users' processes need elevated privileges)".into());
    }
    vars.sort();
    Ok(vars)
}

/// Run an external command with stdin closed, stdout/stderr captured, and a
/// hard timeout. Tools like `vmmap` or PowerShell can occasionally hang on
/// a wedged target process; without a timeout the worker would never
/// return and the panel would show "loading" forever.
///
/// stdout/stderr are drained on separate threads so a chatty child (vmmap
/// easily prints >64 KiB) can't deadlock on a full pipe while we wait.
#[allow(dead_code)] // unused on platforms without a shell-based backend
pub fn run_command(cmd: &mut Command, timeout: Duration) -> anyhow::Result<Output> {
    run_command_capped(cmd, timeout, usize::MAX)
}

/// Like [`run_command`], but stops reading (and kills the child) once
/// stdout exceeds `max_bytes` — for tools like `log show` whose output can
/// run to gigabytes. The output then holds the first `max_bytes`.
#[allow(dead_code)]
pub fn run_command_capped(cmd: &mut Command, timeout: Duration, max_bytes: usize) -> anyhow::Result<Output> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;

    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let capped = Arc::new(AtomicBool::new(false));
    fn drain<R: Read + Send + 'static>(pipe: Option<R>, max: usize, capped: Arc<AtomicBool>) -> thread::JoinHandle<Vec<u8>> {
        thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let mut chunk = [0u8; 64 * 1024];
                loop {
                    match p.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.len() >= max {
                                buf.truncate(max);
                                capped.store(true, Ordering::Relaxed);
                                break;
                            }
                        }
                    }
                }
            }
            buf
        })
    }
    let out_reader = drain(child.stdout.take(), max_bytes, capped.clone());
    let err_reader = drain(child.stderr.take(), 1 << 20, Arc::new(AtomicBool::new(false)));

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if capped.load(Ordering::Relaxed) {
            // Enough output; stop the tool instead of waiting for it.
            let _ = child.kill();
            break child.wait()?;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("timed out after {}s", timeout.as_secs());
        }
        thread::sleep(Duration::from_millis(20));
    };

    Ok(Output {
        status,
        stdout: out_reader.join().unwrap_or_default(),
        stderr: err_reader.join().unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn inspects_own_process() {
        let me = std::process::id();
        let info = super::inspect(me, None, false);
        assert!(info.threads.as_ref().is_ok_and(|t| !t.is_empty()), "{:?}", info.threads);
        assert!(info.environment.as_ref().is_ok_and(|e| !e.is_empty()), "{:?}", info.environment);
        #[cfg(unix)]
        assert!(info.open_files.as_ref().is_ok_and(|f| !f.is_empty()), "{:?}", info.open_files);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod signature_tests {
    use super::*;

    #[test]
    fn fast_check_agrees_on_known_files() {
        // Apple platform binary: must be valid, never a false "invalid".
        assert!(matches!(file_signature("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder").0, SignatureStatus::Valid { .. }));
        // Setuid and not readable by normal users: unknown, not invalid.
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(file_signature("/usr/bin/sudo").0, SignatureStatus::Unknown);
        }
        // A plain script is unsigned.
        let f = std::env::temp_dir().join(format!("pw-unsigned-{}.sh", std::process::id()));
        std::fs::write(&f, "#!/bin/sh\necho hi\n").unwrap();
        assert_eq!(file_signature(f.to_str().unwrap()).0, SignatureStatus::Unsigned);
        let _ = std::fs::remove_file(f);
    }
}
