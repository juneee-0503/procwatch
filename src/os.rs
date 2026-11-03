//! Small OS integrations: clipboard, "reveal in file manager", and finding
//! which processes have a given file open.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Copy `text` to the system clipboard. Uses the platform tool when
/// present, otherwise the OSC 52 terminal escape (works over SSH in most
/// modern terminals).
pub fn copy_to_clipboard(text: &str) -> anyhow::Result<&'static str> {
    #[cfg(target_os = "macos")]
    let tools: &[(&str, &[&str])] = &[("pbcopy", &[])];
    #[cfg(target_os = "windows")]
    let tools: &[(&str, &[&str])] = &[("clip", &[])];
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let tools: &[(&str, &[&str])] = &[("wl-copy", &[]), ("xclip", &["-selection", "clipboard"]), ("xsel", &["-b", "-i"])];

    for (tool, args) in tools {
        let child = Command::new(tool)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if let Ok(mut child) = child {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if child.wait().map(|s| s.success()).unwrap_or(false) {
                return Ok("clipboard");
            }
        }
    }

    // OSC 52: ESC ] 52 ; c ; <base64> BEL
    let mut out = std::io::stdout();
    write!(out, "\x1b]52;c;{}\x07", base64(text.as_bytes()))?;
    out.flush()?;
    Ok("terminal clipboard")
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                s.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// Fire-and-forget desktop notification (macOS Notification Center,
/// `notify-send` on Linux). Silently does nothing where unavailable.
pub fn notify(title: &str, body: &str) {
    #[cfg(target_os = "macos")]
    {
        let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!("display notification \"{}\" with title \"{}\"", esc(body), esc(title));
        let _ = Command::new("osascript").args(["-e", &script]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = Command::new("notify-send").args([title, body]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
    }
    #[cfg(windows)]
    {
        let _ = (title, body);
    }
}

/// Show `path` selected in Finder / Explorer, or open its folder on Linux.
pub fn reveal(path: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = Command::new("open");
        c.args(["-R", path]);
        c
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = Command::new("explorer");
        c.arg(format!("/select,{path}"));
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut cmd = {
        let dir = std::path::Path::new(path).parent().map(|p| p.display().to_string()).unwrap_or_else(|| "/".into());
        let mut c = Command::new("xdg-open");
        c.arg(dir);
        c
    };
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    Ok(())
}

/// One process holding a matching file.
#[derive(Debug, Clone)]
pub struct Hit {
    pub pid: u32,
    pub command: String,
    pub fd: String,
    /// `REG`, `DIR`, `IPv4`, `PIPE`, … (empty when unknown).
    pub kind: String,
    pub path: String,
}

/// Processes with an open file whose path contains `query`
/// (case-insensitive). Scans every process, so it runs on a worker.
pub fn find_open_file(query: &str) -> anyhow::Result<Vec<Hit>> {
    let q = query.to_lowercase();
    let mut hits: Vec<Hit> = list_open_files()?.into_iter().filter(|h| h.path.to_lowercase().contains(&q)).collect();
    hits.truncate(2000);
    Ok(hits)
}

/// Every open file of every process we're allowed to inspect, sorted by
/// process name. Scans the whole system (seconds on a busy machine).
pub fn list_open_files() -> anyhow::Result<Vec<Hit>> {
    let mut hits = imp::scan()?;
    hits.sort_by(|a, b| a.command.to_lowercase().cmp(&b.command.to_lowercase()).then(a.pid.cmp(&b.pid)));
    Ok(hits)
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use crate::inspect::run_command;

    pub fn scan() -> anyhow::Result<Vec<Hit>> {
        // One lsof for the whole system: p = pid, c = command, f = fd,
        // t = type, n = name. Only processes we may inspect are listed.
        let out = run_command(Command::new("lsof").args(["-n", "-P", "-F", "pcftn"]), Duration::from_secs(60))?;
        let text = String::from_utf8_lossy(&out.stdout);
        let (mut pid, mut command) = (0u32, String::new());
        let mut hits: Vec<Hit> = Vec::new();
        for line in text.lines() {
            let (tag, value) = line.split_at(line.len().min(1));
            match tag {
                "p" => pid = value.parse().unwrap_or(0),
                "c" => command = value.to_string(),
                "f" => hits.push(Hit { pid, command: command.clone(), fd: value.to_string(), kind: String::new(), path: String::new() }),
                "t" => {
                    if let Some(h) = hits.last_mut() {
                        h.kind = value.to_string();
                    }
                }
                "n" => {
                    if let Some(h) = hits.last_mut() {
                        h.path = value.to_string();
                    }
                }
                _ => {}
            }
        }
        Ok(hits)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::fs;

    pub fn scan() -> anyhow::Result<Vec<Hit>> {
        let mut hits = Vec::new();
        for entry in fs::read_dir("/proc")?.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
            let Ok(fds) = fs::read_dir(entry.path().join("fd")) else { continue };
            let command = fs::read_to_string(entry.path().join("comm")).unwrap_or_default().trim().to_string();
            for fd in fds.flatten() {
                let Ok(target) = fs::read_link(fd.path()) else { continue };
                let path = target.display().to_string();
                let kind = if path.starts_with("socket:") {
                    "SOCK"
                } else if path.starts_with("pipe:") {
                    "PIPE"
                } else if path.starts_with("anon_inode:") {
                    "ANON"
                } else if path.starts_with("/dev/") {
                    "CHR"
                } else {
                    "REG"
                };
                hits.push(Hit { pid, command: command.clone(), fd: fd.file_name().to_string_lossy().into_owned(), kind: kind.into(), path });
            }
        }
        let _ = Duration::ZERO;
        Ok(hits)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    use super::*;

    pub fn scan() -> anyhow::Result<Vec<Hit>> {
        let _ = Duration::ZERO;
        anyhow::bail!("listing open files needs Sysinternals handle.exe on Windows; ports can still be searched")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(super::base64(b""), "");
        assert_eq!(super::base64(b"f"), "Zg==");
        assert_eq!(super::base64(b"fo"), "Zm8=");
        assert_eq!(super::base64(b"foo"), "Zm9v");
        assert_eq!(super::base64(b"foobar"), "Zm9vYmFy");
    }

    #[cfg(unix)]
    #[test]
    fn finds_own_cwd() {
        let cwd = std::env::current_dir().unwrap().display().to_string();
        let name = cwd.rsplit('/').next().unwrap().to_string();
        let hits = super::find_open_file(&name).unwrap();
        assert!(hits.iter().any(|h| h.pid == std::process::id()), "own cwd not found");
    }
}
