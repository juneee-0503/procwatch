use super::super::*;

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
