//! System event logs: macOS unified log, systemd journal, Windows event
//! log. Read-only queries over a recent time window.

#[cfg(target_os = "macos")]
use std::process::Command;
use std::time::Duration;

use chrono::{DateTime, Local};
use serde::Serialize;

#[allow(unused_imports)]
use crate::common::command::{run_command, run_command_capped};

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    #[serde(serialize_with = "ser_time")]
    pub time: DateTime<Local>,
    pub source: String,
    pub level: String,
    pub process: String,
    pub pid: Option<u32>,
    pub message: String,
    /// Identical consecutive messages collapsed into this one.
    pub repeats: usize,
    /// Windows event ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<u32>,
}

fn ser_time<S: serde::Serializer>(t: &DateTime<Local>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&t.to_rfc3339())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Errors, faults, warnings and authentication / security sources.
    Important,
    /// Everything (capped).
    All,
}

pub const MAX: usize = 5000;

/// Fetch entries from the last `minutes`, newest first.
pub fn fetch(minutes: u32, scope: Scope) -> Result<Vec<Entry>, String> {
    let mut v = imp::fetch(minutes, scope)?;
    v.sort_by_key(|e| std::cmp::Reverse(e.time));
    // Noisy sources repeat the same line thousands of times; keep one
    // row with a count so the rest of the window stays visible.
    let mut out: Vec<Entry> = Vec::with_capacity(v.len().min(MAX));
    for e in v {
        match out.last_mut() {
            Some(last) if last.process == e.process && last.message == e.message && last.level == e.level => last.repeats += 1,
            _ => out.push(e),
        }
        if out.len() >= MAX {
            break;
        }
    }
    Ok(out)
}

#[cfg_attr(windows, allow(dead_code))]
fn first_line(s: &str) -> String {
    s.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim()
        .chars()
        .filter(|c| !c.is_control() && *c != '\u{fffd}')
        .take(400)
        .collect()
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    pub fn fetch(minutes: u32, scope: Scope) -> Result<Vec<Entry>, String> {
        let mut cmd = Command::new("/usr/bin/log");
        cmd.args(["show", "--last", &format!("{minutes}m"), "--style", "ndjson"]);
        if scope == Scope::Important {
            cmd.args([
                "--predicate",
                "messageType == error OR messageType == fault OR process == \"sudo\" OR process == \"sshd\" \
                 OR process == \"authd\" OR process == \"loginwindow\" OR process == \"securityd\" \
                 OR process == \"syspolicyd\" OR process == \"XProtect\" OR subsystem == \"com.apple.TCC\" \
                 OR subsystem == \"com.apple.xpc.launchd\" AND eventMessage CONTAINS[c] \"exited\"",
            ]);
        }
        // Busy machines log hundreds of MB per hour; read at most 96 MB.
        let out = run_command_capped(&mut cmd, Duration::from_secs(90), 96 << 20).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&out.stdout);
        // Output is oldest-first; keep the newest lines.
        let lines: Vec<&str> = text.lines().collect();
        let mut v = Vec::new();
        for line in lines.iter().skip(lines.len().saturating_sub(MAX * 4)) {
            let Ok(j) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            let s = |k: &str| j.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            let Some(time) = j
                .get("timestamp")
                .and_then(|t| t.as_str())
                .and_then(|t| DateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S%.f%z").ok())
                .map(|t| t.with_timezone(&Local))
            else {
                continue;
            };
            let process = s("processImagePath").rsplit('/').next().unwrap_or("").to_string();
            let subsystem = s("subsystem");
            v.push(Entry {
                time,
                source: if subsystem.is_empty() { "unified log".into() } else { subsystem },
                level: s("messageType").to_lowercase(),
                process,
                pid: j.get("processID").and_then(|p| p.as_u64()).map(|p| p as u32),
                message: first_line(&s("eventMessage")),
                repeats: 0,
                event_id: None,
            });
        }
        if v.is_empty() && !out.status.success() {
            return Err(first_line(&String::from_utf8_lossy(&out.stderr)));
        }
        if out.stdout.len() >= 96 << 20 {
            if let Some(oldest) = v.first().map(|e| e.time) {
                v.push(Entry {
                    time: oldest,
                    source: "procwatch".into(),
                    level: "note".into(),
                    process: "procwatch".into(),
                    pid: None,
                    message: "The log was too large to read in full; only the earliest part of the window is shown. Pick a shorter window (w).".into(),
                    repeats: 0,
                    event_id: None,
                });
            }
        }
        Ok(v)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use chrono::TimeZone;

    pub fn fetch(minutes: u32, scope: Scope) -> Result<Vec<Entry>, String> {
        let since = format!("-{minutes}min");
        let mut cmd = crate::common::command::tool("journalctl");
        cmd.args(["--since", &since, "-o", "json", "--no-pager", "-n", &MAX.to_string()]);
        if scope == Scope::Important {
            cmd.args(["-p", "warning"]);
        }
        let out = run_command(&mut cmd, Duration::from_secs(60)).map_err(|e| format!("journalctl: {e}"))?;
        let mut v = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let Ok(j) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            let s = |k: &str| j.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            let Some(us) = s("__REALTIME_TIMESTAMP").parse::<i64>().ok() else { continue };
            let Some(time) = Local.timestamp_micros(us).single() else { continue };
            let level = match s("PRIORITY").as_str() {
                "0" | "1" | "2" => "critical",
                "3" => "error",
                "4" => "warning",
                "5" | "6" => "info",
                _ => "debug",
            };
            let process = if s("_COMM").is_empty() { s("SYSLOG_IDENTIFIER") } else { s("_COMM") };
            v.push(Entry {
                time,
                source: if s("_SYSTEMD_UNIT").is_empty() { "journal".into() } else { s("_SYSTEMD_UNIT") },
                level: level.into(),
                process,
                pid: s("_PID").parse().ok(),
                message: first_line(&s("MESSAGE")),
                repeats: 0,
                event_id: None,
            });
        }
        if v.is_empty() && !out.status.success() {
            return Err(first_line(&String::from_utf8_lossy(&out.stderr)));
        }
        Ok(v)
    }
}

#[cfg(target_os = "windows")]
mod imp {
    use super::*;

    pub fn fetch(minutes: u32, scope: Scope) -> Result<Vec<Entry>, String> {
        let level = if scope == Scope::Important { "Level=1,2,3;" } else { "" };
        let _ = level;
        // Security-relevant channels are read in full; System/Application
        // only errors and warnings when scope is "important".
        let filter = if scope == Scope::Important { "$f.Level=@(1,2,3)" } else { "" };
        let script = format!(
            r#"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$logs = @('System','Application','Security',
  'Microsoft-Windows-Windows Defender/Operational',
  'Microsoft-Windows-PowerShell/Operational',
  'Microsoft-Windows-Sysmon/Operational',
  'Microsoft-Windows-TaskScheduler/Operational')
foreach ($log in $logs) {{
  try {{
    $f = @{{LogName=$log; StartTime=(Get-Date).AddMinutes(-{minutes})}}
    if ($log -in @('System','Application')) {{ {filter} }}
    Get-WinEvent -FilterHashtable $f -MaxEvents 2000 -ErrorAction Stop | ForEach-Object {{
      $lines = ($_.Message -split "`r?`n") | Where-Object {{ $_.Trim() }}
      # Sysmon fields are needed whole (DNS queries, hashes); others: first lines.
      if ($log -like '*Sysmon*') {{ $m = ($lines -join ' | ') }} else {{ $m = ($lines | Select-Object -First 3) -join ' ' }}
      if ($m.Length -gt 2000) {{ $m = $m.Substring(0, 2000) }}
      Write-Output ("{{0}}`t{{1}}`t{{2}}`t{{3}}`t{{4}}`t{{5}}`t{{6}}" -f $_.TimeCreated.ToString('o'), $log, $_.LevelDisplayName, $_.ProviderName, $_.ProcessId, $_.Id, $m)
    }}
  }} catch {{
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {{ Write-Output ("ERR`t" + $log + "`t" + $_.Exception.Message) }}
  }}
}}"#
        );
        let out = run_command(crate::common::command::tool("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]), Duration::from_secs(90))
            .map_err(|e| e.to_string())?;
        let mut v = Vec::new();
        let mut problems = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(rest) = line.strip_prefix("ERR\t") {
                let (log, why) = rest.split_once('\t').unwrap_or((rest, ""));
                // Channels that simply don't exist (no Sysmon) are noted
                // by the health panel; access problems matter here.
                problems.push(format!("{log}: {}", first_line(why)));
                continue;
            }
            let f: Vec<&str> = line.splitn(7, '\t').collect();
            if f.len() < 7 {
                continue;
            }
            let Some(time) = DateTime::parse_from_rfc3339(f[0]).ok().map(|t| t.with_timezone(&Local)) else { continue };
            v.push(Entry {
                time,
                source: f[1].into(),
                level: f[2].to_lowercase(),
                process: f[3].into(),
                pid: f[4].parse().ok().filter(|p| *p != 0),
                message: first_line(f[6]),
                repeats: 0,
                event_id: f[5].parse().ok(),
            });
        }
        let oldest = v.iter().map(|e| e.time).min().unwrap_or_else(Local::now);
        for p in problems {
            v.push(Entry {
                time: oldest,
                source: "procwatch".into(),
                level: "note".into(),
                process: "procwatch".into(),
                pid: None,
                message: format!("Couldn't read {p}"),
                repeats: 0,
                event_id: None,
            });
        }
        Ok(v)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
mod imp {
    use super::*;
    pub fn fetch(_minutes: u32, _scope: Scope) -> Result<Vec<Entry>, String> {
        Err("event logs are not supported on this platform".into())
    }
}
