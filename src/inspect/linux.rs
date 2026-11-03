//! Linux backend — not one of your two target platforms, but included so
//! the whole project can be compiled and smoke-tested on any dev machine
//! (including the sandbox this was written in) rather than taking the
//! Windows/macOS code on faith. Uses `/proc`, which is the same source
//! `htop`/`ps`/`lsof` read from on Linux.

use super::{DeepInfo, OpenFile, SignatureStatus};
use std::fs;

pub fn inspect(pid: u32, _exe_path: Option<&str>, _modules: bool) -> DeepInfo {
    // /proc/<pid>/maps is cheap, so modules are always read.
    let mut info = DeepInfo { modules_loaded: true, ..DeepInfo::default() };

    match loaded_modules(pid) {
        Ok(mods) => info.loaded_modules = mods,
        Err(e) => info.notes.push(format!("modules (/proc/{pid}/maps): {e}")),
    }

    info.open_files = open_files(pid).map_err(|e| format!("/proc/{pid}/fd: {e}"));
    info.handle_count = info.open_files.as_ref().ok().map(|f| f.len() as u64);

    // Linux has no Authenticode/codesign equivalent in the base OS.
    info.signature_status = SignatureStatus::Unknown;
    info.notes.push("code-signing checks are not a standard Linux concept".to_string());

    info.working_directory = fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .map(|p| p.display().to_string());

    info
}

pub fn loaded_modules(pid: u32) -> std::io::Result<Vec<String>> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    // The pathname is the 6th column and may contain spaces, so take the
    // remainder after the first five fields instead of the last token.
    let mut libs: Vec<String> = maps
        .lines()
        .filter_map(|l| l.splitn(6, char::is_whitespace).nth(5))
        .map(str::trim)
        .filter(|p| p.ends_with(".so") || p.contains(".so."))
        .map(str::to_string)
        .collect();
    libs.sort();
    libs.dedup();
    Ok(libs)
}

pub fn open_files(pid: u32) -> std::io::Result<Vec<OpenFile>> {
    let mut files: Vec<OpenFile> = fs::read_dir(format!("/proc/{pid}/fd"))?
        .filter_map(Result::ok)
        .map(|e| {
            let fd = e.file_name().to_string_lossy().into_owned();
            let name = fs::read_link(e.path()).map(|p| p.display().to_string()).unwrap_or_default();
            let kind = if name.starts_with("socket:") {
                "SOCK"
            } else if name.starts_with("pipe:") {
                "PIPE"
            } else if name.starts_with("anon_inode:") {
                "ANON"
            } else if name.starts_with("/dev/") {
                "CHR"
            } else {
                "REG"
            };
            OpenFile { fd, kind: kind.to_string(), name }
        })
        .collect();
    files.sort_by_key(|f| f.fd.parse::<u64>().unwrap_or(u64::MAX));
    Ok(files)
}

pub fn call_stacks(pid: u32) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let tasks = fs::read_dir(format!("/proc/{pid}/task")).map_err(|e| e.to_string())?;
    let mut tids: Vec<u64> = tasks.flatten().filter_map(|e| e.file_name().to_string_lossy().parse().ok()).collect();
    tids.sort_unstable();
    for tid in tids {
        let base = format!("/proc/{pid}/task/{tid}");
        let comm = fs::read_to_string(format!("{base}/comm")).unwrap_or_default();
        let wchan = fs::read_to_string(format!("{base}/wchan")).unwrap_or_default();
        let wchan = if wchan.trim().is_empty() || wchan.trim() == "0" { "running".to_string() } else { format!("waiting in {}", wchan.trim()) };
        lines.push(format!("Thread {tid}  {}  — {wchan}", comm.trim()));
        match fs::read_to_string(format!("{base}/stack")) {
            Ok(stack) => lines.extend(stack.lines().map(|l| format!("    {}", l.trim()))),
            Err(_) => lines.push("    (kernel stack needs root)".into()),
        }
    }
    Ok(lines)
}
