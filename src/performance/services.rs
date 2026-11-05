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

/// The service list, or why there isn't one.
pub fn collect() -> Result<Vec<Service>, String> {
    use crate::common::command::tool;
    use std::time::Duration;
    const TIMEOUT: Duration = Duration::from_secs(20);
    #[cfg(target_os = "linux")]
    let (mut cmd, parse): (_, fn(&str) -> Vec<Service>) = {
        let mut c = tool("systemctl");
        c.args(["list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager"]);
        (c, super::parse::systemctl)
    };
    #[cfg(target_os = "macos")]
    let (mut cmd, parse): (_, fn(&str) -> Vec<Service>) = {
        let mut c = tool("launchctl");
        c.arg("list");
        (c, super::parse::launchctl)
    };
    #[cfg(windows)]
    let (mut cmd, parse): (_, fn(&str) -> Vec<Service>) = {
        let mut c = tool("powershell");
        c.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-CimInstance Win32_Service | ForEach-Object { \"$($_.Name)|$($_.State)|$($_.StartMode)|$($_.ProcessId)|$($_.DisplayName)\" }",
        ]);
        (c, super::parse::windows_services)
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    return Err("not available on this platform".into());
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        let out = crate::common::command::run_command(&mut cmd, TIMEOUT).map_err(|e| e.to_string())?;
        let mut list = parse(&String::from_utf8_lossy(&out.stdout));
        if list.is_empty() {
            return Err(String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("no services reported").to_string());
        }
        list.sort_by(|a, b| (a.state != ServiceState::Failed).cmp(&(b.state != ServiceState::Failed)).then_with(|| a.name.cmp(&b.name)));
        Ok(list)
    }
}
