//! System services, and the processes a system can't run without.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceState {
    Running,
    /// Failed, or meant to be running and isn't.
    Failed,
    Stopped,
    Other,
}

impl ServiceState {
    pub fn label(self) -> &'static str {
        match self {
            ServiceState::Running => "running",
            ServiceState::Failed => "failed",
            ServiceState::Stopped => "stopped",
            ServiceState::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Service {
    pub name: String,
    pub state: ServiceState,
    pub pid: Option<u32>,
    pub detail: String,
}

/// Processes whose absence or failure means the system is in trouble.
pub const CRITICAL: &[&str] = if cfg!(windows) {
    &["System", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe"]
} else if cfg!(target_os = "macos") {
    &["launchd", "kernel_task", "WindowServer", "loginwindow", "configd", "opendirectoryd", "securityd", "syslogd", "coreaudiod", "mds"]
} else {
    &["systemd", "systemd-journald", "systemd-logind", "systemd-udevd", "dbus-daemon", "sshd", "cron", "NetworkManager", "rsyslogd"]
};

/// Run a listing tool and parse what it prints.
pub fn run(cmd: &mut std::process::Command, parse: fn(&str) -> Vec<Service>) -> Result<Vec<Service>, String> {
    let out = crate::common::command::run_command(cmd, std::time::Duration::from_secs(20)).map_err(|e| e.to_string())?;
    let mut list = parse(&String::from_utf8_lossy(&out.stdout));
    if list.is_empty() {
        return Err(String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("no services reported").to_string());
    }
    list.sort_by(|a, b| (a.state != ServiceState::Failed).cmp(&(b.state != ServiceState::Failed)).then_with(|| a.name.cmp(&b.name)));
    Ok(list)
}
