use super::super::*;
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
