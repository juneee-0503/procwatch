//! Blocking, from an explicit policy. Nothing here runs unless asked for
//! with `--enforce`, and the default mode only logs.
//!
//! What can really be prevented without kernel code:
//! - Linux: `exec` and `open`, with fanotify permission events: the kernel
//!   holds the operation until procwatch answers.
//! - Windows: `connect`, with Windows Filtering Platform filters.
//!
//! `start` + `kill`, on every platform, ends a process after it started:
//! that is a response, not prevention, and a short-lived process can finish
//! first.
//!
//! Safety is the point of the design:
//! - a rule that matches anything the OS needs is refused, with no override;
//! - a rule this platform can't enforce stops startup instead of doing
//!   nothing quietly;
//! - everything ends with the process: the fanotify group closes and the
//!   WFP session is dynamic, so no state can outlive procwatch;
//! - fanotify waits forever for an answer, so a watchdog ends procwatch if
//!   the answering thread ever stalls, which releases every waiter.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Audit,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum On {
    Exec,
    Open,
    Connect,
    Start,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Block,
    Kill,
}

fn default_mode() -> Mode {
    Mode::Audit
}

fn default_expiry() -> u64 {
    60
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub on: On,
    pub action: Action,
    pub path: Vec<String>,
    /// Only these process names; empty means any.
    #[serde(default)]
    pub process: Vec<String>,
    #[serde(default)]
    pub except: Vec<String>,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default = "default_mode")]
    pub mode: Mode,
    #[serde(default = "default_expiry")]
    pub expires_minutes: u64,
    pub rules: Vec<Rule>,
}

/// One enforcement outcome.
#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub time: DateTime<Local>,
    pub rule: String,
    /// `blocked`, `killed`, or `would block` / `would kill` in audit mode.
    pub outcome: &'static str,
    pub on: On,
    pub pid: u32,
    pub process: String,
    pub path: String,
}

/// What an operating system can't run without. A rule that matches any of
/// these is refused. Files a real system has at these or similar places;
/// patterns are tested against the paths, so `*`, `/usr/*` and `*.so.6` all
/// fall here.
const ESSENTIAL: &[&str] = &[
    "/bin/sh",
    "/bin/bash",
    "/usr/bin/env",
    "/usr/bin/sudo",
    "/sbin/init",
    "/usr/sbin/sshd",
    "/usr/lib/systemd/systemd",
    "/lib/systemd/systemd",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/lib64/ld-linux-x86-64.so.2",
    "/usr/lib/libc.so.6",
    "/etc/passwd",
    "/etc/ld.so.cache",
    "/etc/resolv.conf",
    "/usr/lib/dyld",
    "/usr/lib/libSystem.B.dylib",
    "/sbin/launchd",
    "/usr/bin/login",
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\kernel32.dll",
    "C:\\Windows\\System32\\ntdll.dll",
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\services.exe",
    "C:\\Windows\\System32\\lsass.exe",
    "C:\\Windows\\System32\\winlogon.exe",
    "C:\\Windows\\System32\\csrss.exe",
    "C:\\Windows\\explorer.exe",
];

/// `*` is any run of characters, `?` one character. Case-insensitive on
/// Windows, where paths are.
pub fn glob(pattern: &str, text: &str) -> bool {
    let fold = |s: &str| -> Vec<char> {
        if cfg!(windows) { s.to_lowercase().chars().collect() } else { s.chars().collect() }
    };
    let (p, t) = (fold(pattern), fold(text));
    let (mut i, mut j) = (0, 0);
    let mut back: Option<(usize, usize)> = None;
    while j < t.len() {
        if i < p.len() && p[i] == '*' {
            back = Some((i, j));
            i += 1;
        } else if i < p.len() && (p[i] == '?' || p[i] == t[j]) {
            i += 1;
            j += 1;
        } else if let Some((bi, bj)) = back {
            // Let the last star take one more character.
            back = Some((bi, bj + 1));
            i = bi + 1;
            j = bj + 1;
        } else {
            return false;
        }
    }
    p[i..].iter().all(|c| *c == '*')
}

fn any(patterns: &[String], text: &str) -> bool {
    patterns.iter().any(|p| glob(p, text))
}

impl Rule {
    pub fn matches(&self, path: &str, process: &str) -> bool {
        any(&self.path, path) && !any(&self.except, path) && (self.process.is_empty() || any(&self.process, process))
    }
}

/// What this platform can do with a rule, or why it can't.
fn support(r: &Rule) -> Result<(), String> {
    match (r.on, r.action) {
        (On::Start, Action::Kill) => Ok(()),
        (On::Start, Action::Block) => Err("`start` happens too late to block: use action: kill, or on: exec on Linux".into()),
        (_, Action::Kill) => Err("`kill` only goes with on: start".into()),
        (On::Exec | On::Open, Action::Block) if cfg!(target_os = "linux") => Ok(()),
        (On::Exec | On::Open, Action::Block) if cfg!(windows) => Err("blocking files on Windows needs a kernel driver: see docs/enforcement.md".into()),
        (On::Exec | On::Open, Action::Block) => Err("blocking files on macOS needs Endpoint Security, which Apple must entitle: see docs/enforcement.md".into()),
        (On::Connect, Action::Block) if cfg!(windows) => {
            if r.path.iter().any(|p| p.contains(['*', '?'])) {
                Err("Windows filters name one executable: `connect` paths can't use wildcards".into())
            } else {
                Ok(())
            }
        }
        (On::Connect, Action::Block) => Err("per-process network blocking is only implemented on Windows".into()),
    }
}

impl Policy {
    pub fn parse(text: &str) -> Result<Policy, String> {
        let p: Policy = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
        p.validate()?;
        Ok(p)
    }

    pub fn load(path: &Path) -> Result<Policy, String> {
        Policy::parse(&std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?)
    }

    /// Every problem, so a file can be fixed in one pass.
    fn validate(&self) -> Result<(), String> {
        let mut problems = Vec::new();
        if self.rules.is_empty() {
            problems.push("no rules".to_string());
        }
        let mut ids = std::collections::HashSet::new();
        let own = std::env::current_exe().ok().map(|p| p.display().to_string());
        for r in &self.rules {
            if r.id.is_empty() || !ids.insert(r.id.as_str()) {
                problems.push(format!("rule id '{}' is empty or used twice", r.id));
            }
            if r.path.is_empty() || r.path.iter().any(String::is_empty) {
                problems.push(format!("{}: needs at least one path", r.id));
            }
            if let Err(e) = support(r) {
                problems.push(format!("{}: {e}", r.id));
            }
            for e in ESSENTIAL.iter().copied().chain(own.as_deref()) {
                if r.path.iter().any(|p| glob(p, e)) && !any(&r.except, e) {
                    problems.push(format!("{}: would also match {e}, which the system needs", r.id));
                    break;
                }
            }
        }
        if problems.is_empty() { Ok(()) } else { Err(problems.join("\n")) }
    }

    pub fn decide(&self, on: On, path: &str, process: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.on == on && r.matches(path, process))
    }

    /// Readable description of what starting this policy will do.
    pub fn plan(&self) -> Vec<String> {
        let verb = |r: &Rule| match (self.mode, r.action) {
            (Mode::Audit, Action::Block) => "log what it would block:",
            (Mode::Audit, Action::Kill) => "log what it would end:",
            (Mode::Enforce, Action::Block) => "BLOCK",
            (Mode::Enforce, Action::Kill) => "END after start",
        };
        self.rules
            .iter()
            .map(|r| format!("{}: {} {:?} of {}{}", r.id, verb(r), r.on, r.path.join(", "), if r.except.is_empty() { String::new() } else { format!(" except {}", r.except.join(", ")) }))
            .collect()
    }
}

fn decision(rule: &Rule, mode: Mode, on: On, pid: u32, process: &str, path: &str) -> Decision {
    let outcome = match (mode, rule.action) {
        (Mode::Audit, Action::Block) => "would block",
        (Mode::Audit, Action::Kill) => "would kill",
        (Mode::Enforce, Action::Block) => "blocked",
        (Mode::Enforce, Action::Kill) => "killed",
    };
    Decision { time: Local::now(), rule: rule.id.clone(), outcome, on, pid, process: process.to_string(), path: path.to_string() }
}

/// A running enforcement; everything it does ends when this is dropped.
pub struct Running {
    stop: Arc<AtomicBool>,
    #[cfg(windows)]
    _filters: Option<wfp::Filters>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

pub fn start(policy: Policy, out: Sender<Decision>) -> Result<Running, String> {
    let stop = Arc::new(AtomicBool::new(false));
    let policy = Arc::new(policy);
    #[cfg(target_os = "linux")]
    if policy.rules.iter().any(|r| matches!(r.on, On::Exec | On::Open)) {
        linux::start(policy.clone(), out.clone(), stop.clone())?;
    }
    #[cfg(windows)]
    let filters = wfp::start(&policy, &out)?;
    if policy.rules.iter().any(|r| r.on == On::Start) {
        spawn_killer(policy.clone(), out, stop.clone())?;
    }
    Ok(Running {
        stop,
        #[cfg(windows)]
        _filters: filters,
    })
}

/// Pids this process mustn't touch: itself and whoever started it.
fn own_line() -> std::collections::HashSet<u32> {
    let me = std::process::id();
    let mut set = std::collections::HashSet::from([me, 0, 1, 4]);
    let m = crate::process::ProcessMonitor::new();
    let parents = m.parents();
    let mut cur = me;
    while let Some(p) = parents.get(&cur).copied() {
        if !set.insert(p) {
            break;
        }
        cur = p;
    }
    set
}

fn spawn_killer(policy: Arc<Policy>, out: Sender<Decision>, stop: Arc<AtomicBool>) -> Result<(), String> {
    use crate::process::actions::{apply_checked, Action as Do, Sig};
    std::thread::Builder::new()
        .name("enforce-start".into())
        .spawn(move || {
            let spared = own_line();
            let mut monitor = crate::process::ProcessMonitor::new();
            let mut seen = std::collections::HashSet::new();
            let mut first = true;
            while !stop.load(Ordering::Relaxed) {
                let (tree, _) = monitor.snapshot();
                let live: std::collections::HashSet<(u32, u64)> = tree.nodes.values().map(|n| (n.info.pid, n.info.start_time_secs)).collect();
                for n in tree.nodes.values() {
                    let i = &n.info;
                    // What ran before we started is not a "start".
                    if !seen.insert((i.pid, i.start_time_secs)) || first || spared.contains(&i.pid) {
                        continue;
                    }
                    let path = i.exe_path.as_deref().unwrap_or("");
                    if path.is_empty() {
                        continue;
                    }
                    if let Some(r) = policy.decide(On::Start, path, &i.name) {
                        let d = decision(r, policy.mode, On::Start, i.pid, &i.name, path);
                        if policy.mode == Mode::Enforce {
                            let _ = apply_checked(i.pid, i.start_time_secs, Do::Signal(Sig::Kill));
                        }
                        let _ = out.send(d);
                    }
                }
                seen.retain(|k| live.contains(k));
                first = false;
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        })
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;
    use std::sync::atomic::AtomicU64;

    const FAN_OPEN_PERM: u64 = 0x0001_0000;
    const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;
    const FAN_ALLOW: u32 = 0x01;
    const FAN_DENY: u32 = 0x02;
    const FAN_MARK_FILESYSTEM: libc::c_uint = 0x0000_0100;
    /// An answer taking this long means the thread is stuck.
    const STALL_MS: u64 = 3000;

    #[repr(C)]
    struct Response {
        fd: i32,
        response: u32,
    }

    /// Since the epoch, for comparing across threads; 0 when idle.
    static BUSY_SINCE: AtomicU64 = AtomicU64::new(0);

    fn now_ms() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(1)
    }

    fn answer(group: libc::c_int, fd: i32, allow: bool) {
        let r = Response { fd, response: if allow { FAN_ALLOW } else { FAN_DENY } };
        // A failed answer leaves the opener waiting until the group closes,
        // which the watchdog below forces if this thread stops working.
        unsafe { libc::write(group, &r as *const _ as *const libc::c_void, std::mem::size_of::<Response>()) };
    }

    pub fn start(policy: Arc<Policy>, out: Sender<Decision>, stop: Arc<AtomicBool>) -> Result<(), String> {
        if unsafe { libc::geteuid() } != 0 {
            return Err("blocking needs root".into());
        }
        let group = unsafe { libc::fanotify_init(libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK, (libc::O_RDONLY | libc::O_LARGEFILE) as libc::c_uint) };
        if group < 0 {
            return Err(format!("fanotify_init: {}", std::io::Error::last_os_error()));
        }
        let wants = |on: On| policy.rules.iter().any(|r| r.on == on);
        let mask = if wants(On::Exec) { FAN_OPEN_EXEC_PERM } else { 0 } | if wants(On::Open) { FAN_OPEN_PERM } else { 0 };
        let mounts = crate::activity::real_mounts(&std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| e.to_string())?);
        let mut marked = 0;
        for m in &mounts {
            let Ok(c) = CString::new(m.as_str()) else { continue };
            if unsafe { libc::fanotify_mark(group, libc::FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask, libc::AT_FDCWD, c.as_ptr()) } == 0 {
                marked += 1;
            }
        }
        if marked == 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(group) };
            return Err(format!("fanotify_mark: {e}"));
        }
        // If answering ever stalls, everything opening a file on the marked
        // filesystems stalls too. Exiting closes the group, and the kernel
        // then lets every waiter through.
        let watch = stop.clone();
        std::thread::Builder::new()
            .name("enforce-watchdog".into())
            .spawn(move || {
                while !watch.load(Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    let since = BUSY_SINCE.load(Ordering::Relaxed);
                    if since != 0 && now_ms().saturating_sub(since) > STALL_MS {
                        eprintln!("enforce: answering stalled; exiting so nothing stays blocked");
                        unsafe { libc::_exit(3) };
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        std::thread::Builder::new()
            .name("enforce-fanotify".into())
            .spawn(move || {
                let me = std::process::id() as i32;
                let mut buf = vec![0u8; 64 * 1024];
                let mut p = libc::pollfd { fd: group, events: libc::POLLIN, revents: 0 };
                while !stop.load(Ordering::Relaxed) {
                    if unsafe { libc::poll(&mut p, 1, 200) } <= 0 {
                        continue;
                    }
                    let n = unsafe { libc::read(group, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                    if n <= 0 {
                        continue;
                    }
                    let (mut off, n) = (0usize, n as usize);
                    let size = std::mem::size_of::<libc::fanotify_event_metadata>();
                    while off + size <= n {
                        let m: libc::fanotify_event_metadata = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const _) };
                        if (m.event_len as usize) < size {
                            break;
                        }
                        off += m.event_len as usize;
                        if m.fd < 0 {
                            continue;
                        }
                        BUSY_SINCE.store(now_ms(), Ordering::Relaxed);
                        let mut allow = true;
                        if m.pid != me {
                            let path = std::fs::read_link(format!("/proc/self/fd/{}", m.fd)).map(|p| p.display().to_string()).unwrap_or_default();
                            let comm = std::fs::read_to_string(format!("/proc/{}/comm", m.pid)).unwrap_or_default();
                            let comm = comm.trim();
                            let on = if m.mask & FAN_OPEN_EXEC_PERM != 0 { On::Exec } else { On::Open };
                            let hit = policy.decide(on, &path, comm).or_else(|| if on == On::Exec { policy.decide(On::Open, &path, comm) } else { None });
                            if let Some(r) = hit {
                                allow = policy.mode == Mode::Audit;
                                let _ = out.send(decision(r, policy.mode, on, m.pid as u32, comm, &path));
                            }
                        }
                        answer(group, m.fd, allow);
                        unsafe { libc::close(m.fd) };
                        BUSY_SINCE.store(0, Ordering::Relaxed);
                    }
                }
                // Waiters are released when the group goes away.
                unsafe { libc::close(group) };
            })
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(windows)]
mod wfp {
    use super::*;
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

    /// Dynamic session: Windows removes the filters when this closes, and
    /// also if procwatch dies.
    pub struct Filters(isize);

    impl Drop for Filters {
        fn drop(&mut self) {
            unsafe { FwpmEngineClose0(self.0 as HANDLE) };
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn start(policy: &Policy, out: &Sender<Decision>) -> Result<Option<Filters>, String> {
        let rules: Vec<&Rule> = policy.rules.iter().filter(|r| r.on == On::Connect).collect();
        if rules.is_empty() {
            return Ok(None);
        }
        if policy.mode == Mode::Audit {
            for r in &rules {
                for p in &r.path {
                    let _ = out.send(decision(r, policy.mode, On::Connect, 0, "", p));
                }
            }
            return Ok(None);
        }
        unsafe {
            let mut session: FWPM_SESSION0 = std::mem::zeroed();
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;
            let mut engine: HANDLE = std::ptr::null_mut();
            let rc = FwpmEngineOpen0(std::ptr::null(), RPC_C_AUTHN_WINNT, std::ptr::null(), &session, &mut engine);
            if rc != 0 {
                return Err(format!("the filter engine refused (administrator needed): {rc:#x}"));
            }
            let filters = Filters(engine as isize);
            for r in rules {
                let mut name = wide(&format!("procwatch {}", r.id));
                for path in &r.path {
                    let file = wide(path);
                    let mut app: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
                    let rc = FwpmGetAppIdFromFileName0(file.as_ptr(), &mut app);
                    if rc != 0 {
                        return Err(format!("{}: {path}: {rc:#x}", r.id));
                    }
                    let mut result = Ok(());
                    for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
                        let mut cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
                        cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                        cond.matchType = FWP_MATCH_EQUAL;
                        cond.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                        cond.conditionValue.Anonymous.byteBlob = app;
                        let mut f: FWPM_FILTER0 = std::mem::zeroed();
                        f.displayData.name = name.as_mut_ptr();
                        f.layerKey = layer;
                        f.action.r#type = FWP_ACTION_BLOCK;
                        f.weight.r#type = FWP_EMPTY;
                        f.numFilterConditions = 1;
                        f.filterCondition = &mut cond;
                        let mut id = 0u64;
                        let rc = FwpmFilterAdd0(engine, &f, std::ptr::null_mut(), &mut id);
                        if rc != 0 {
                            result = Err(format!("{}: filter for {path}: {rc:#x}", r.id));
                            break;
                        }
                    }
                    let mut raw = app as *mut c_void;
                    FwpmFreeMemory0(&mut raw);
                    result?;
                    let _ = out.send(decision(r, policy.mode, On::Connect, 0, "", path));
                }
            }
            Ok(Some(filters))
        }
    }
}

/// `--enforce-check`: show what a policy would do.
pub fn check(path: &Path) -> i32 {
    match Policy::load(path) {
        Ok(p) => {
            println!("{}: {} rules, mode {:?}, {}", path.display(), p.rules.len(), p.mode, if p.expires_minutes == 0 { "no expiry".to_string() } else { format!("ends after {} minutes", p.expires_minutes) });
            for l in p.plan() {
                println!("  {l}");
            }
            0
        }
        Err(e) => {
            eprintln!("{}:\n{e}", path.display());
            1
        }
    }
}

/// `--enforce`: run until the policy expires or procwatch is stopped.
pub fn run(path: &Path, output: Option<&Path>, minutes: Option<u64>) -> i32 {
    use std::io::Write;
    let policy = match Policy::load(path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}:\n{e}", path.display());
            return 1;
        }
    };
    let mut sink: Box<dyn Write> = match output {
        None => Box::new(std::io::stdout()),
        Some(p) => match std::fs::OpenOptions::new().create(true).append(true).open(p) {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("{}: {e}", p.display());
                return 2;
            }
        },
    };
    let expiry = minutes.unwrap_or(policy.expires_minutes);
    eprintln!("enforce: mode {:?}, {}", policy.mode, if expiry == 0 { "until stopped".to_string() } else { format!("for {expiry} minutes") });
    for l in policy.plan() {
        eprintln!("  {l}");
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let running = match start(policy, tx) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("enforce: {e}");
            return 2;
        }
    };
    let end = (expiry > 0).then(|| std::time::Instant::now() + std::time::Duration::from_secs(expiry.saturating_mul(60)));
    while end.is_none_or(|e| std::time::Instant::now() < e) {
        if let Ok(d) = rx.recv_timeout(std::time::Duration::from_millis(500)) {
            let line = serde_json::to_string(&d).unwrap_or_default();
            if writeln!(sink, "{line}").is_err() || sink.flush().is_err() {
                break;
            }
        }
    }
    drop(running);
    eprintln!("enforce: ended; nothing remains in force");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob("/tmp/*", "/tmp/a/b"));
        assert!(glob("*/xmrig", "/opt/x/xmrig"));
        assert!(glob("a?c", "abc"));
        assert!(glob("*", ""));
        assert!(glob("*a*b*", "xxaxxbxx"));
        assert!(!glob("/tmp/*", "/var/tmp/a"));
        assert!(!glob("a?c", "ac"));
        assert!(!glob("abc", "abcd"));
        assert!(glob("/路径/*", "/路径/文件"));
        // Pathological patterns stay linear enough to run on every open.
        let t = std::time::Instant::now();
        assert!(!glob(&"*a".repeat(30), &"a".repeat(10_000)) || t.elapsed().as_secs() < 1);
    }

    fn rule(on: &str, action: &str, paths: &str) -> String {
        format!("rules:\n  - {{ id: r, on: {on}, action: {action}, path: [{paths}] }}\n")
    }

    #[test]
    fn audit_is_the_default_and_expiry_is_on() {
        let p = Policy::parse(&rule("start", "kill", "'/opt/bad/*'")).unwrap();
        assert_eq!((p.mode, p.expires_minutes), (Mode::Audit, 60));
    }

    #[test]
    fn rules_that_would_lock_up_the_system_are_refused() {
        for bad in ["'*'", "'/*'", "'/usr/*'", "'/bin/*'", "'*/sh'", "'*.so.6'", "'/etc/*'", "'C:\\Windows\\*'", "'*.exe'", "'*.dll'"] {
            let e = Policy::parse(&rule("start", "kill", bad)).unwrap_err();
            assert!(e.contains("which the system needs"), "{bad}: {e}");
        }
        assert!(Policy::parse(&rule("start", "kill", "'/opt/bad/*'")).is_ok());
    }

    #[test]
    fn exceptions_decide_and_files_can_name_no_unknown_keys() {
        let text = "rules:\n  - { id: a, on: start, action: kill, path: ['/opt/*'], except: ['/opt/ok/*'], process: ['bad*'] }\n";
        let p = Policy::parse(text).unwrap();
        assert!(p.decide(On::Start, "/opt/x", "badtool").is_some());
        assert!(p.decide(On::Start, "/opt/ok/x", "badtool").is_none());
        assert!(p.decide(On::Start, "/opt/x", "good").is_none());
        assert!(p.decide(On::Exec, "/opt/x", "badtool").is_none());
        assert!(Policy::parse("mode: enforce\nrules:\n  - { id: a, on: start, action: kill, path: ['/opt/*'], typo: 1 }\n").is_err());
        assert!(Policy::parse("rules: []\n").is_err());
        assert!(Policy::parse("mode: blockeverything\nrules: []\n").is_err());
    }

    #[test]
    fn what_a_platform_cannot_do_is_an_error_not_silence() {
        assert!(Policy::parse(&rule("start", "block", "'/opt/x'")).is_err());
        assert!(Policy::parse(&rule("exec", "kill", "'/opt/x'")).is_err());
        let exec = Policy::parse(&rule("exec", "block", "'/opt/x'"));
        assert_eq!(exec.is_ok(), cfg!(target_os = "linux"), "{exec:?}");
        let net = Policy::parse(&rule("connect", "block", "'C:\\Tools\\x.exe'"));
        assert_eq!(net.is_ok(), cfg!(windows), "{net:?}");
    }

    #[test]
    fn audit_decisions_say_so() {
        let p = Policy::parse(&rule("start", "kill", "'/opt/bad/*'")).unwrap();
        assert_eq!(decision(&p.rules[0], Mode::Audit, On::Start, 1, "x", "/opt/bad/x").outcome, "would kill");
        assert_eq!(decision(&p.rules[0], Mode::Enforce, On::Start, 1, "x", "/opt/bad/x").outcome, "killed");
        assert!(p.plan()[0].contains("log what it would end"));
    }

    #[test]
    fn the_example_policy_is_valid_where_it_can_be() {
        let r = Policy::parse(include_str!("../../rules/policy/example.yml"));
        if cfg!(target_os = "linux") {
            assert!(r.is_ok(), "{r:?}");
        } else {
            assert!(r.unwrap_err().contains("no-exec-from-tmp"), "only the Linux rule is refused");
        }
    }
}
