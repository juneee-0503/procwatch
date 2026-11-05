//! Process memory analysis without reading memory contents: the layout of
//! the address space by region type, writable+executable regions (a
//! common sign of injected or unpacked code; JIT engines also use them),
//! and loaded modules that look out of place.
//!
//! Dumping process memory is deliberately not supported (see README).


use serde::Serialize;

use crate::inspect::{self, SignatureStatus};
use crate::common::paths::risky_location;

#[derive(Debug, Clone, Serialize)]
pub struct Region {
    pub kind: String,
    pub virtual_bytes: u64,
    pub resident_bytes: u64,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Report {
    pub regions: Vec<Region>,
    pub summary: Vec<(String, String)>,
    /// Regions currently mapped both writable and executable.
    pub wx_regions: Option<usize>,
    /// (module, reason)
    pub anomalies: Vec<(String, String)>,
    pub notes: Vec<String>,
}

/// `64.0M`, `512K`, `1.6G` → bytes.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_size(s: &str) -> Option<u64> {
    let (num, mult) = match s.chars().last()? {
        'K' => (&s[..s.len() - 1], 1024.0),
        'M' => (&s[..s.len() - 1], 1024.0 * 1024.0),
        'G' => (&s[..s.len() - 1], 1024.0 * 1024.0 * 1024.0),
        c if c.is_ascii_digit() => (s, 1.0),
        _ => return None,
    };
    num.parse::<f64>().ok().map(|n| (n * mult) as u64)
}

pub fn analyze(pid: u32, modules: &[String]) -> Report {
    let mut r = imp::layout(pid);
    module_anomalies(&mut r, modules);
    r
}

/// Modules that are missing on disk, sit in temp/user-writable folders,
/// or (outside the OS directories) aren't signed.
fn module_anomalies(r: &mut Report, modules: &[String]) {
    let system = |m: &str| {
        let l = m.to_lowercase().replace('\\', "/");
        l.starts_with("/system/") || l.starts_with("/usr/lib/") || l.contains("/windows/system32/") || l.contains("/windows/winsxs/")
            || l.starts_with("/lib/") || l.starts_with("/usr/lib64/") || l.starts_with("/lib64/")
    };
    let mut sig_checks = 0;
    for m in modules {
        if m.ends_with(" (deleted)") {
            r.anomalies.push((m.trim_end_matches(" (deleted)").to_string(), "loaded from a file that was deleted".into()));
            continue;
        }
        // macOS system libraries live in the dyld shared cache, not on disk.
        let in_shared_cache = cfg!(target_os = "macos") && system(m);
        if !in_shared_cache && std::fs::metadata(m).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
            r.anomalies.push((m.clone(), "file no longer exists on disk".into()));
            continue;
        }
        if risky_location(m) {
            r.anomalies.push((m.clone(), "loaded from a temporary or user-writable folder".into()));
        }
        if !system(m) && cfg!(any(target_os = "macos", windows)) && sig_checks < 40 {
            sig_checks += 1;
            match inspect::file_signature(m).0 {
                SignatureStatus::Unsigned => r.anomalies.push((m.clone(), "not signed".into())),
                SignatureStatus::Invalid { reason } => r.anomalies.push((m.clone(), format!("invalid signature: {reason}"))),
                _ => {}
            }
        }
    }
    if sig_checks >= 40 {
        r.notes.push("Signature checks were limited to the first 40 non-system modules.".into());
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use crate::common::command::run_command;
    use std::process::Command;
    use std::time::Duration;

    pub fn layout(pid: u32) -> Report {
        let mut r = Report::default();
        match run_command(Command::new("vmmap").args(["--summary", &pid.to_string()]), Duration::from_secs(30)) {
            Ok(o) if o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout);
                let mut in_table = false;
                for line in text.lines() {
                    if line.starts_with("ReadOnly portion") || line.starts_with("Writable regions") || line.starts_with("Physical footprint") {
                        if let Some((k, v)) = line.split_once(':') {
                            r.summary.push((k.trim().into(), v.trim().into()));
                        }
                    }
                    if line.starts_with("===========") {
                        in_table = true;
                        continue;
                    }
                    if !in_table {
                        continue;
                    }
                    if line.trim().is_empty() || line.starts_with("TOTAL") {
                        if line.starts_with("TOTAL") {
                            break;
                        }
                        if !r.regions.is_empty() {
                            break;
                        }
                        continue;
                    }
                    let toks: Vec<&str> = line.split_whitespace().collect();
                    let Some(first_num) = toks.iter().position(|t| parse_size(t).is_some()) else { continue };
                    if first_num == 0 || toks.len() < first_num + 8 {
                        continue;
                    }
                    r.regions.push(Region {
                        kind: toks[..first_num].join(" "),
                        virtual_bytes: parse_size(toks[first_num]).unwrap_or(0),
                        resident_bytes: parse_size(toks[first_num + 1]).unwrap_or(0),
                        count: toks[first_num + 7].parse().unwrap_or(0),
                    });
                }
            }
            Ok(o) => r.notes.push(format!(
                "vmmap: {} (other users' processes need root)",
                String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or("failed").trim()
            )),
            Err(e) => r.notes.push(format!("vmmap: {e}")),
        }
        // Full map for protections: count regions currently rwx.
        if let Ok(o) = run_command(Command::new("vmmap").args(["-w", &pid.to_string()]), Duration::from_secs(30)) {
            if o.status.success() {
                let n = String::from_utf8_lossy(&o.stdout).lines().filter(|l| l.contains(" rwx/")).count();
                r.wx_regions = Some(n);
            }
        }
        r.regions.sort_by_key(|g| std::cmp::Reverse(g.virtual_bytes));
        r
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::collections::BTreeMap;

    pub fn layout(pid: u32) -> Report {
        let mut r = Report::default();
        if let Ok(t) = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup")) {
            for l in t.lines().skip(1) {
                if let Some((k, v)) = l.split_once(':') {
                    r.summary.push((k.trim().into(), v.trim().into()));
                }
            }
        }
        match std::fs::read_to_string(format!("/proc/{pid}/maps")) {
            Ok(t) => {
                let mut groups: BTreeMap<String, (u64, u64)> = BTreeMap::new();
                let mut wx = 0;
                for l in t.lines() {
                    let f: Vec<&str> = l.splitn(6, char::is_whitespace).collect();
                    if f.len() < 5 {
                        continue;
                    }
                    let (start, end) = f[0].split_once('-').unwrap_or(("0", "0"));
                    let size = u64::from_str_radix(end, 16).unwrap_or(0).saturating_sub(u64::from_str_radix(start, 16).unwrap_or(0));
                    if f[1].starts_with("rwx") {
                        wx += 1;
                    }
                    let path = f.get(5).map(|p| p.trim()).unwrap_or("");
                    let kind = match path {
                        "" => "anonymous".to_string(),
                        p if p.starts_with('[') => p.to_string(),
                        p if p.contains(".so") => "shared libraries".to_string(),
                        _ => "mapped files".to_string(),
                    };
                    let e = groups.entry(kind).or_default();
                    e.0 += size;
                    e.1 += 1;
                }
                r.wx_regions = Some(wx);
                r.regions = groups.into_iter().map(|(k, (v, c))| Region { kind: k, virtual_bytes: v, resident_bytes: 0, count: c }).collect();
                r.regions.sort_by_key(|g| std::cmp::Reverse(g.virtual_bytes));
            }
            Err(e) => r.notes.push(format!("/proc/{pid}/maps: {e}")),
        }
        r
    }
}

#[cfg(target_os = "windows")]
mod imp {
    use super::*;
    use crate::common::command::run_command;
    use std::process::Command;
    use std::time::Duration;

    pub fn layout(pid: u32) -> Report {
        let mut r = Report::default();
        let script = format!(
            "$p = Get-Process -Id {pid} -ErrorAction Stop; \
             'Working set|' + $p.WorkingSet64; 'Peak working set|' + $p.PeakWorkingSet64; \
             'Private bytes|' + $p.PrivateMemorySize64; 'Virtual size|' + $p.VirtualMemorySize64; \
             'Paged pool|' + $p.PagedMemorySize64"
        );
        match run_command(Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]), Duration::from_secs(15)) {
            Ok(o) => {
                for l in String::from_utf8_lossy(&o.stdout).lines() {
                    if let Some((k, v)) = l.split_once('|') {
                        let v = v.trim().parse::<u64>().map(crate::process::human_bytes).unwrap_or_else(|_| v.trim().to_string());
                        r.summary.push((k.into(), v));
                    }
                }
            }
            Err(e) => r.notes.push(e.to_string()),
        }
        regions(pid, &mut r);
        r
    }

    /// Walk the address space with VirtualQueryEx: region metadata only,
    /// no memory contents are read.
    fn regions(pid: u32, r: &mut Report) {
        use std::collections::BTreeMap;
        use std::mem::{size_of, zeroed};
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE};
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

        const EXEC: u32 = 0x10 | 0x20 | 0x40 | 0x80; // PAGE_EXECUTE*
        const WX: u32 = 0x40 | 0x80; // PAGE_EXECUTE_READWRITE / WRITECOPY
        let h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid) };
        if h.is_null() {
            r.notes.push(format!("region walk: {} (needs administrator for other users' processes)", std::io::Error::last_os_error()));
            return;
        }
        let mut groups: BTreeMap<&'static str, (u64, u64)> = BTreeMap::new();
        let (mut wx, mut private_exec) = (0usize, 0usize);
        let mut addr: usize = 0;
        loop {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
            let n = unsafe { VirtualQueryEx(h, addr as *const _, &mut mbi, size_of::<MEMORY_BASIC_INFORMATION>()) };
            if n == 0 {
                break;
            }
            if mbi.State == MEM_COMMIT {
                let kind = match mbi.Type {
                    MEM_IMAGE => "image (exe/dll)",
                    MEM_MAPPED => "mapped files",
                    MEM_PRIVATE => "private",
                    _ => "other",
                };
                let g = groups.entry(kind).or_default();
                g.0 += mbi.RegionSize as u64;
                g.1 += 1;
                if mbi.Protect & WX != 0 {
                    wx += 1;
                }
                // Executable memory that isn't backed by a file on disk is
                // where injected code usually lives.
                if mbi.Type == MEM_PRIVATE && mbi.Protect & EXEC != 0 {
                    private_exec += 1;
                }
            }
            let next = (mbi.BaseAddress as usize).checked_add(mbi.RegionSize);
            match next {
                Some(n) if n > addr => addr = n,
                _ => break,
            }
        }
        unsafe { CloseHandle(h) };
        r.wx_regions = Some(wx);
        if private_exec > 0 {
            r.summary.push(("Private executable regions".into(), format!("{private_exec} (code not backed by a file — normal for JIT, suspicious otherwise)")));
        }
        r.regions = groups.into_iter().map(|(k, (v, c))| Region { kind: k.into(), virtual_bytes: v, resident_bytes: 0, count: c }).collect();
        r.regions.sort_by_key(|g| std::cmp::Reverse(g.virtual_bytes));
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
mod imp {
    use super::*;
    pub fn layout(_pid: u32) -> Report {
        Report { notes: vec!["not supported on this platform".into()], ..Report::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_own_process() {
        assert_eq!(parse_size("512K"), Some(512 * 1024));
        assert_eq!(parse_size("1.5M"), Some(1572864));
        assert_eq!(parse_size("abc"), None);
        let mut r = Report::default();
        module_anomalies(&mut r, &["/nonexistent/libevil.dylib".into(), "/tmp/x.so (deleted)".into()]);
        assert_eq!(r.anomalies.len(), 2);
        let me = analyze(std::process::id(), &[]);
        assert!(!me.regions.is_empty() || !me.notes.is_empty());
    }
}
