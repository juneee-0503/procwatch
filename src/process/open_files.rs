//! Who has what open, across all processes: `lsof` on macOS, `/proc` on
//! Linux, the handle table on Windows.
use std::time::Duration;

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
    use crate::common::command::run_command;

    pub fn scan() -> anyhow::Result<Vec<Hit>> {
        // One lsof for the whole system: p = pid, c = command, f = fd,
        // t = type, n = name. Only processes we may inspect are listed.
        let out = run_command(crate::common::command::tool("lsof").args(["-n", "-P", "-F", "pcftn"]), Duration::from_secs(60))?;
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
            // Like lsof: the working directory and executable count too.
            for (link, fd, kind) in [("cwd", "cwd", "DIR"), ("exe", "txt", "REG")] {
                if let Ok(t) = fs::read_link(entry.path().join(link)) {
                    hits.push(Hit { pid, command: command.clone(), fd: fd.into(), kind: kind.into(), path: t.display().to_string() });
                }
            }
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

#[cfg(windows)]
mod imp {
    use super::*;

    pub fn scan() -> anyhow::Result<Vec<Hit>> {
        let names = crate::process::ProcessMonitor::new().names();
        let files = crate::process::handles::all_files(Duration::from_secs(45)).map_err(anyhow::Error::msg)?;
        Ok(files
            .into_iter()
            .map(|(pid, f)| Hit { pid, command: names.get(&pid).cloned().unwrap_or_else(|| format!("pid {pid}")), fd: f.fd, kind: "REG".into(), path: f.name })
            .collect())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod imp {
    use super::*;

    pub fn scan() -> anyhow::Result<Vec<Hit>> {
        let _ = Duration::ZERO;
        anyhow::bail!("listing open files is not available on this platform; ports can still be searched")
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn finds_own_cwd() {
        let cwd = std::env::current_dir().unwrap().display().to_string();
        let name = cwd.rsplit('/').next().unwrap().to_string();
        let hits = super::find_open_file(&name).unwrap();
        assert!(hits.iter().any(|h| h.pid == std::process::id()), "own cwd not found");
    }
}
