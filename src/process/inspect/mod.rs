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

use std::thread;

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
    /// Privileges and isolation: integrity level, capabilities, container…
    pub security: Vec<(String, String)>,
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
            security: Vec::new(),
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
    #[cfg(windows)]
    return crate::process::handles::for_process(pid);
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
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
    if !std::path::Path::new(path).is_absolute() {
        return relative_path();
    }
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
/// Paths reach here from autostart entries and the like, and one starting
/// with `-` would be read as an option by the signature tools.
fn relative_path() -> (SignatureStatus, Vec<(String, String)>) {
    (SignatureStatus::Unknown, vec![("Note".into(), "not an absolute path; signature not checked".into())])
}

pub fn file_signature(path: &str) -> (SignatureStatus, Vec<(String, String)>) {
    if !std::path::Path::new(path).is_absolute() {
        return relative_path();
    }
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
        Err("Windows can only show stacks captured with events: start Activity capture with `stacks: true` in capture.yml, then reopen this tab".into())
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

/// Linux capabilities that matter for privilege, by bit number.
const CAPS: &[(u32, &str)] = &[
    (0, "chown"), (1, "dac_override"), (2, "dac_read_search"), (5, "kill"), (6, "setgid"), (7, "setuid"), (8, "setpcap"),
    (12, "net_admin"), (13, "net_raw"), (16, "sys_module"), (17, "sys_rawio"), (18, "sys_chroot"), (19, "sys_ptrace"),
    (21, "sys_admin"), (22, "sys_boot"), (25, "sys_time"), (38, "perfmon"), (39, "bpf"),
];

/// Effective capabilities as text. Everything set reads as "all".
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn capability_names(hex: &str) -> Option<String> {
    let bits = u64::from_str_radix(hex.trim(), 16).ok()?;
    if bits == 0 {
        return Some("none".into());
    }
    // 41 is what every kernel since 5.9 defines.
    if bits & ((1 << 41) - 1) == (1 << 41) - 1 {
        return Some("all".into());
    }
    let names: Vec<&str> = CAPS.iter().filter(|(b, _)| bits & (1 << b) != 0).map(|(_, n)| *n).collect();
    Some(if names.is_empty() { format!("{bits:#x}") } else { names.join(", ") })
}

/// Privilege facts from `/proc/<pid>/status`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn linux_status(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let get = |k: &str| text.lines().find_map(|l| l.strip_prefix(k).map(str::trim));
    if let Some(ids) = get("Uid:").map(|u| u.split_whitespace().collect::<Vec<_>>()) {
        if let [real, effective, ..] = ids[..] {
            out.push(("User IDs".to_string(), format!("real {real}, effective {effective}{}", if real != effective { " (setuid)" } else { "" })));
        }
    }
    if let Some(c) = get("CapEff:").and_then(capability_names) {
        out.push(("Capabilities".into(), c));
    }
    if let Some(m) = get("Seccomp:") {
        out.push(("Seccomp".into(), match m { "0" => "off", "1" => "strict", "2" => "filtered", o => o }.to_string()));
    }
    if get("NoNewPrivs:") == Some("1") {
        out.push(("No new privileges".into(), "set".into()));
    }
    out
}

/// The container a process runs in, from `/proc/<pid>/cgroup`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn linux_container(cgroup: &str) -> Option<String> {
    let id_after = |line: &str, key: &str| -> Option<String> {
        // The id is the first long hexadecimal run after the runtime's name.
        let tail = &line[line.find(key)? + key.len()..];
        tail.split(|c: char| !c.is_ascii_hexdigit()).find(|run| run.len() >= 12).map(|run| run[..12].to_string())
    };
    cgroup.lines().find_map(|l| {
        [("docker", "Docker"), ("kubepods", "Kubernetes"), ("containerd", "containerd"), ("cri-containerd", "containerd"), ("crio", "CRI-O"), ("libpod", "Podman")]
            .iter()
            .find_map(|(key, name)| id_after(l, key).map(|id| format!("{name} {id}")))
            .or_else(|| l.contains("/lxc").then(|| "LXC".to_string()))
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn linux_security_facts() {
        use super::*;
        assert_eq!(capability_names("0000000000000000").as_deref(), Some("none"));
        assert_eq!(capability_names("000001ffffffffff").as_deref(), Some("all"));
        assert_eq!(capability_names("0000000000003000").as_deref(), Some("net_admin, net_raw"));
        assert_eq!(capability_names("xyz"), None);
        let status = "Name:\tx\nUid:\t1000\t0\t0\t0\nCapEff:\t0000000000001000\nSeccomp:\t2\nNoNewPrivs:\t1\n";
        let f = linux_status(status);
        assert!(f.contains(&("User IDs".into(), "real 1000, effective 0 (setuid)".into())), "{f:?}");
        assert!(f.contains(&("Capabilities".into(), "net_admin".into())));
        assert!(f.contains(&("Seccomp".into(), "filtered".into())));
        assert!(f.contains(&("No new privileges".into(), "set".into())));
        assert!(linux_status("garbage").is_empty());
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(linux_container(&format!("0::/system.slice/docker-{id}.scope")).as_deref(), Some("Docker 0123456789ab"));
        assert_eq!(linux_container(&format!("0::/kubepods/burstable/pod1/{id}")).as_deref(), Some("Kubernetes 0123456789ab"));
        assert_eq!(linux_container("0::/user.slice/user-1000.slice/session-2.scope"), None);
    }

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
