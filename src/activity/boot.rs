//! Activity from early boot, on Windows: an ETW AutoLogger session starts
//! with the kernel, before services and logon, and records to a file that
//! is read afterwards.
//!
//! It records until stopped or until its file is full, so `read` stops it.
//! Reads and writes are left out: boot produces far too many.

#![cfg_attr(not(windows), allow(dead_code))]

use std::path::{Path, PathBuf};

pub const SESSION: &str = "procwatch-boot";

/// File: CREATE, OP_END, DELETE_PATH, RENAME, CREATE_NEW_FILE.
pub const BOOT_FILE_KEYWORDS: u64 = 0x40 | 0x80 | 0x400 | 0x800 | 0x1000;
pub const BOOT_MAX_MB: u32 = 512;

/// Where the AutoLogger writes.
pub fn default_log() -> PathBuf {
    let root = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from("C:\\Windows"), PathBuf::from);
    root.join("System32").join("LogFiles").join("WMI").join(format!("{SESSION}.etl"))
}

/// The newest log: Windows numbers files it starts while one exists.
pub fn newest_log(wanted: &Path) -> Option<PathBuf> {
    let dir = wanted.parent()?;
    let stem = wanted.file_stem()?.to_string_lossy().to_lowercase();
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().to_lowercase().starts_with(&stem))
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok())
        .map(|e| e.path())
}

#[cfg(windows)]
mod windows_side {
    use super::*;
    use crate::activity::probes::windows::{read_etl, KERNEL_FILE, KERNEL_PROCESS, KERNEL_REGISTRY};
    use crate::common::command::tool;

    const KEY: &str = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\procwatch-boot";
    const SESSION_GUID: &str = "{5c6f6e9a-3b1d-4f57-9d55-7a1e7c6f0b21}";

    fn reg(args: &[&str]) -> Result<(), String> {
        let out = tool("reg").args(args).args(["/f"]).output().map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!("reg {}: {} (needs administrator)", args[0], String::from_utf8_lossy(&out.stderr).trim()))
        }
    }

    fn set(key: &str, name: &str, kind: &str, value: &str) -> Result<(), String> {
        reg(&["add", key, "/v", name, "/t", kind, "/d", value])
    }

    pub fn enable() -> Result<(), String> {
        let log = default_log().to_string_lossy().into_owned();
        set(KEY, "Start", "REG_DWORD", "1")?;
        set(KEY, "Guid", "REG_SZ", SESSION_GUID)?;
        set(KEY, "FileName", "REG_SZ", &log)?;
        set(KEY, "MaxFileSize", "REG_DWORD", &BOOT_MAX_MB.to_string())?;
        set(KEY, "BufferSize", "REG_DWORD", "256")?;
        set(KEY, "MinimumBuffers", "REG_DWORD", "64")?;
        set(KEY, "MaximumBuffers", "REG_DWORD", "256")?;
        set(KEY, "LogFileMode", "REG_DWORD", "1")?; // sequential, stops when full
        for (guid, keywords) in [(KERNEL_FILE, BOOT_FILE_KEYWORDS), (KERNEL_REGISTRY, u64::MAX), (KERNEL_PROCESS, 0x10)] {
            let key = format!("{KEY}\\{{{guid}}}");
            set(&key, "Enabled", "REG_DWORD", "1")?;
            set(&key, "EnableLevel", "REG_DWORD", "4")?;
            set(&key, "MatchAnyKeyword", "REG_QWORD", &format!("{keywords:#x}"))?;
        }
        Ok(())
    }

    pub fn disable() -> Result<(), String> {
        let _ = ferrisetw::trace::stop_trace_by_name(SESSION);
        if tool("reg").args(["query", KEY]).output().is_ok_and(|o| o.status.success()) {
            reg(&["delete", KEY])?;
        }
        Ok(())
    }

    pub fn status() -> Vec<String> {
        let configured = tool("reg").args(["query", KEY]).output().is_ok_and(|o| o.status.success());
        let running = crate::common::etw::session_stats(SESSION);
        let mut lines = vec![format!("configured for next boot: {}", if configured { "yes" } else { "no" })];
        lines.push(match running {
            Some(s) => format!("recording now: yes ({} events lost, {} buffers lost)", s.events_lost, s.buffers_lost),
            None => "recording now: no".to_string(),
        });
        lines.push(match newest_log(&default_log()) {
            Some(p) => format!("log: {} ({} MB)", p.display(), std::fs::metadata(&p).map_or(0, |m| m.len()) >> 20),
            None => "log: none yet".to_string(),
        });
        lines
    }

    pub fn read(path: &Path, json: bool) -> Result<(), String> {
        // A session still writing would hide the end of the file.
        if path == default_log() || path.starts_with(default_log().parent().unwrap_or(Path::new(""))) {
            let _ = ferrisetw::trace::stop_trace_by_name(SESSION);
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let names = read_etl(path, crate::common::emit::Emit::new(move |batch| tx.send(batch).is_ok()))?;
        let mut count = 0u64;
        for batch in rx {
            for a in batch {
                count += 1;
                let name = names.get(&a.pid).map_or("?", String::as_str);
                if json {
                    crate::safe_println!(
                        "{}",
                        serde_json::json!({ "time": a.time.to_rfc3339(), "pid": a.pid, "process": name, "class": a.class.label(), "operation": a.op, "target": a.path, "result": a.status, "detail": a.detail })
                    );
                } else {
                    crate::safe_println!(
                        "{} {:>6} {:<24} {:<8} {:<12} {:<18} {}",
                        a.time.format("%H:%M:%S%.3f"),
                        a.pid,
                        crate::common::text::truncate(name, 24),
                        a.class.label(),
                        a.op,
                        a.status.as_deref().unwrap_or(""),
                        a.path
                    );
                }
            }
        }
        eprintln!("{count} operations from {}", path.display());
        Ok(())
    }
}

/// `--boot-log enable|disable|status|read [FILE] [--json]`.
pub fn run(action: &str, file: Option<&Path>, json: bool) -> i32 {
    #[cfg(windows)]
    {
        use windows_side::*;
        let done = match action {
            "enable" => enable().map(|()| println!("Boot logging starts at the next restart and writes to {}.\nRead it with --boot-log read; turn it off with --boot-log disable.", default_log().display())),
            "disable" => disable().map(|()| println!("Boot logging is off.")),
            "status" => {
                status().iter().for_each(|l| println!("{l}"));
                Ok(())
            }
            "read" => match file.map(Path::to_path_buf).or_else(|| newest_log(&default_log())) {
                Some(p) => read(&p, json),
                None => Err("no boot log yet: enable it and restart".to_string()),
            },
            other => Err(format!("unknown action {other}: enable, disable, status or read")),
        };
        match done {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("procwatch: {e}");
                2
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (action, file, json);
        eprintln!("--boot-log is for Windows. On Linux start `procwatch --monitor --activity` from a systemd unit ordered before multi-user.target; see docs/activity-capture.md.");
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_newest_numbered_log() {
        let dir = crate::common::paths::private_temp_dir("bootlog").unwrap();
        std::fs::write(dir.join("other.etl"), "x").unwrap();
        std::fs::write(dir.join("procwatch-boot.etl.001"), "x").unwrap();
        let found = newest_log(&dir.join("procwatch-boot.etl")).unwrap();
        assert!(found.to_string_lossy().ends_with(".001"));
        assert!(newest_log(&dir.join("absent.etl")).is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
