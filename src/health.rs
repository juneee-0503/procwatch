//! Collection health: which data sources procwatch can see right now, which
//! are partial or blocked, and what that means for conclusions. "Nothing
//! detected" is only as good as the data behind it.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Available,
    Partial,
    Denied,
    Missing,
    NotLoaded,
    /// Deliberately not collected, or not available to this tool.
    NotUsed,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Available => "available",
            Status::Partial => "partial",
            Status::Denied => "access denied",
            Status::Missing => "not present",
            Status::NotLoaded => "not loaded yet",
            Status::NotUsed => "not collected",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Source {
    pub name: String,
    pub status: Status,
    pub detail: String,
}

impl Source {
    pub fn new(name: &str, status: Status, detail: impl Into<String>) -> Source {
        Source { name: name.into(), status, detail: detail.into() }
    }
}

pub fn elevated() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // Reading the Prefetch folder needs an elevated token.
        std::fs::read_dir(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()) + "\\Prefetch").is_ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Platform facts that don't depend on app state.
pub fn platform() -> Vec<Source> {
    let (os, how) = crate::selftest::platform_status();
    let mut v = vec![Source::new(
        "This build on this OS",
        if cfg!(target_os = "macos") { Status::Available } else { Status::Partial },
        format!("{os}: {how} — run procwatch --selftest for measured capture rates"),
    )];
    #[cfg(target_os = "macos")]
    {
        let tcc = std::env::var("HOME").map(|h| format!("{h}/Library/Application Support/com.apple.TCC/TCC.db")).unwrap_or_default();
        let fda = std::fs::File::open(&tcc).is_ok();
        v.push(Source::new(
            "Full Disk Access",
            if fda { Status::Available } else { Status::Partial },
            if fda {
                "granted to this terminal".to_string()
            } else {
                "not granted to this terminal: protected folders (Mail, Messages, Safari, TCC database, other users) are unreadable".to_string()
            },
        ));
        v.push(Source::new(
            "Endpoint Security events",
            Status::NotUsed,
            "needs a signed system extension; process, file and network events are sampled, so very short-lived activity can be missed",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        v.push(Source::new("eBPF / audit events", Status::NotUsed, "not used; process and network events are sampled from /proc"));
        let (status, detail) = journal();
        v.push(Source::new("systemd journal", status, detail));
    }
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let sysmon = ["Sysmon64.exe", "Sysmon.exe"].iter().any(|f| std::path::Path::new(&format!("{root}\\{f}")).exists());
        v.push(Source::new(
            "Sysmon",
            if sysmon { Status::Available } else { Status::Missing },
            if sysmon { "installed — its Operational log is read with the event logs" } else { "not installed: no process-creation hashes, network or file-create events from Sysmon" },
        ));
        v.push(Source::new("ETW", Status::NotUsed, "not used; process and network events are sampled"));
    }
    v.push(Source::new("Process memory contents", Status::NotUsed, "never read or dumped, by design; use a dedicated acquisition tool and analyse the image offline"));
    v
}

/// Checked once, in the background: this list is rebuilt on every draw of
/// the health page, and a tool must not run there.
#[cfg(target_os = "linux")]
fn journal() -> (Status, &'static str) {
    use std::sync::{Once, OnceLock};
    static RESULT: OnceLock<(Status, &'static str)> = OnceLock::new();
    static START: Once = Once::new();
    START.call_once(|| {
        std::thread::spawn(|| {
            let r = crate::inspect::run_command(std::process::Command::new("journalctl").args(["-n", "1", "-q"]), std::time::Duration::from_secs(10));
            let _ = RESULT.set(match r {
                Ok(o) if o.status.success() => (Status::Available, "readable"),
                Ok(_) => (Status::Partial, "only your own entries (add to the systemd-journal group or run as root)"),
                Err(_) => (Status::Missing, "journalctl not found or not responding"),
            });
        });
    });
    RESULT.get().copied().unwrap_or((Status::NotLoaded, "checking…"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_lists_memory_policy() {
        assert!(platform().iter().any(|s| s.name == "Process memory contents" && s.status == Status::NotUsed));
        assert_eq!(Status::Denied.label(), "access denied");
    }
}
