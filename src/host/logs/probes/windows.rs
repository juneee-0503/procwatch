use super::super::*;

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
