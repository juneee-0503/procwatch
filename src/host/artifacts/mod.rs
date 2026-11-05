//! Execution and activity artifacts: what ran (or may have run) before
//! procwatch was started. Each kind documents what its timestamp means and
//! what it can and cannot support, because these differ a lot — a
//! ShimCache entry, for example, does not prove a program ever ran.
//!
//! Parsers are pure functions over bytes so they work on files copied off
//! another machine (`procwatch --offline CASE --artifacts DIR`) as well as
//! on the live system.

pub mod evtx;
pub mod hives;
pub mod prefetch;
pub mod regf;
pub mod shimcache;
pub mod xpress;

use std::path::{Path, PathBuf};

use chrono::{DateTime, Local};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Artifact {
    pub kind: &'static str,
    #[serde(serialize_with = "ser_time")]
    pub time: Option<DateTime<Local>>,
    /// Program path, command or record summary.
    pub subject: String,
    pub detail: String,
    /// File (or registry location) it came from.
    pub source: String,
    pub user: Option<String>,
}

fn ser_time<S: serde::Serializer>(t: &Option<DateTime<Local>>, s: S) -> Result<S::Ok, S::Error> {
    match t {
        Some(t) => s.serialize_str(&t.to_rfc3339()),
        None => s.serialize_none(),
    }
}

/// What an artifact kind is and how far it can be trusted.
pub struct KindInfo {
    pub kind: &'static str,
    pub source: &'static str,
    pub platforms: &'static str,
    pub time_meaning: &'static str,
    pub limits: &'static str,
    pub supports: &'static str,
}

pub static KINDS: &[KindInfo] = &[
    KindInfo {
        kind: "prefetch",
        source: r"C:\Windows\Prefetch\*.pf (needs administrator)",
        platforms: "Windows XP – 11 (format 17/23/26/30/31; Win10+ files are Xpress-Huffman compressed)",
        time_meaning: "last run times recorded by the prefetcher (up to 8 on Windows 8+)",
        limits: "Disabled on many servers and some SSD setups; ~10 s of activity after start; old entries are evicted (128/1024 files).",
        supports: "The program ran, how often, when last, and which files/volumes it touched at start.",
    },
    KindInfo {
        kind: "shimcache",
        source: r"HKLM\SYSTEM\…\Session Manager\AppCompatCache (written at shutdown)",
        platforms: "Windows 10 / 11 (\"10ts\" entries)",
        time_meaning: "the file's last-modified time — NOT when it ran",
        limits: "Entries reach the registry only at shutdown/reboot; on Windows 10+ presence does not prove execution.",
        supports: "The file existed at that path and was seen by the compatibility layer; order is most-recent-first.",
    },
    KindInfo {
        kind: "bam",
        source: r"HKLM\SYSTEM\…\Services\bam\State\UserSettings\<SID>",
        platforms: "Windows 10 1709+ / 11",
        time_meaning: "last execution time per user, as recorded by the Background Activity Moderator",
        limits: "Roughly the last week only; GUI/console programs, not services; needs administrator to read.",
        supports: "That user ran the program, and when last.",
    },
    KindInfo {
        kind: "amcache",
        source: r"C:\Windows\appcompat\Programs\Amcache.hve (locked while Windows runs: copy it with a forensic tool)",
        platforms: "Windows 10 1709+ / 11 (InventoryApplicationFile layout)",
        time_meaning: "the inventory entry's last-write time — usually when the file was first seen or last updated by Program Inventory, not a run time",
        limits: "Presence shows the file existed and was inventoried; it does not by itself prove execution. Transaction logs are not replayed.",
        supports: "Full path, SHA-1 (first 31 MB), publisher, version and link date of programs that were on the system.",
    },
    KindInfo {
        kind: "defender",
        source: "Get-MpThreatDetection (Microsoft Defender)",
        platforms: "Windows with Microsoft Defender",
        time_meaning: "initial detection time",
        limits: "Only what Defender detected; history is trimmed by Defender itself.",
        supports: "A detection, the affected resources and the action taken.",
    },
    KindInfo {
        kind: "evtx",
        source: "Windows event log files (.evtx), live or copied",
        platforms: "Windows Vista+ format (parsed on any OS)",
        time_meaning: "the record's TimeCreated",
        limits: "Only what auditing was configured to log; logs roll over; process creation (4688) needs auditing enabled, command lines need a separate policy.",
        supports: "Logons, service/task creation, process creation, script blocks, Defender and Sysmon events, as logged.",
    },
    KindInfo {
        kind: "shell history",
        source: "~/.zsh_history, ~/.bash_history, fish_history",
        platforms: "macOS, Linux",
        time_meaning: "when the command was entered (zsh extended history, bash with HISTTIMEFORMAT, fish); otherwise none",
        limits: "Written when the shell exits; users can disable, edit or delete it; commands that start with a space may be skipped.",
        supports: "That a command was typed in an interactive shell — not that it succeeded.",
    },
];

pub fn info(kind: &str) -> Option<&'static KindInfo> {
    KINDS.iter().find(|k| k.kind == kind)
}

#[derive(Debug, Default)]
pub struct Scan {
    pub items: Vec<Artifact>,
    /// Problems and skipped sources ("Prefetch: access denied").
    pub notes: Vec<String>,
    /// Parsed Windows event records, for Sigma.
    pub records: Vec<evtx::WinRecord>,
}

pub fn filetime(ft: u64) -> Option<DateTime<Local>> {
    // 100 ns ticks since 1601-01-01; 0 and absurd values mean "unset".
    if ft == 0 || ft > 0x01F0_0000_0000_0000 {
        return None;
    }
    let secs = (ft / 10_000_000) as i64 - 11_644_473_600;
    let nanos = ((ft % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos).map(|t| t.with_timezone(&Local))
}

pub fn utf16z(b: &[u8]) -> String {
    let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).take_while(|u| *u != 0).collect();
    String::from_utf16_lossy(&units)
}

pub fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
pub fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
pub fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap_or([0; 8])))
}

/// Standard base64 (for registry values exported by PowerShell).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let clean: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=').collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let mut acc = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            acc |= val(*c)? << (18 - 6 * i);
        }
        let n = match chunk.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            _ => return None,
        };
        for i in 0..n {
            out.push((acc >> (16 - 8 * i)) as u8);
        }
    }
    Some(out)
}

// ── shell history ──────────────────────────────────────────────────────

/// zsh stores non-ASCII bytes "metafied": 0x83 then the byte XOR 0x20.
fn unmetafy(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut it = b.iter();
    while let Some(c) = it.next() {
        if *c == 0x83 {
            if let Some(n) = it.next() {
                out.push(n ^ 0x20);
            }
        } else {
            out.push(*c);
        }
    }
    out
}

const MAX_HISTORY: usize = 3000;

pub fn parse_history(path: &Path, bytes: &[u8], user: Option<String>) -> Vec<Artifact> {
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let text = String::from_utf8_lossy(&unmetafy(bytes)).into_owned();
    let mut out = Vec::new();
    let mut push = |time: Option<DateTime<Local>>, cmd: &str| {
        let cmd = cmd.trim();
        if !cmd.is_empty() {
            out.push(Artifact {
                kind: "shell history",
                time,
                subject: cmd.chars().take(400).collect(),
                detail: name.clone(),
                source: path.display().to_string(),
                user: user.clone(),
            });
        }
    };
    let ts = |s: &str| s.trim().parse::<i64>().ok().and_then(|t| DateTime::from_timestamp(t, 0)).map(|t| t.with_timezone(&Local));
    if name.contains("fish") {
        let mut cmd: Option<String> = None;
        for line in text.lines() {
            if let Some(c) = line.strip_prefix("- cmd: ") {
                if let Some(prev) = cmd.take() {
                    push(None, &prev);
                }
                cmd = Some(c.replace("\\n", "\n"));
            } else if let Some(t) = line.trim_start().strip_prefix("when: ") {
                if let Some(c) = cmd.take() {
                    push(ts(t), &c);
                }
            }
        }
        if let Some(c) = cmd {
            push(None, &c);
        }
    } else {
        let mut pending_time = None;
        for line in text.lines() {
            // zsh extended: ": 1700000000:0;command"
            if let Some(rest) = line.strip_prefix(": ") {
                if let Some((meta, cmd)) = rest.split_once(';') {
                    push(ts(meta.split(':').next().unwrap_or("")), cmd);
                    continue;
                }
            }
            // bash with HISTTIMEFORMAT: "#1700000000" before the command
            if let Some(t) = line.strip_prefix('#').filter(|t| t.len() >= 9 && t.chars().all(|c| c.is_ascii_digit())) {
                pending_time = ts(t);
                continue;
            }
            push(pending_time.take(), line);
        }
    }
    let skip = out.len().saturating_sub(MAX_HISTORY);
    out.drain(..skip);
    // The file is oldest-first; newest first matches every other list.
    out.reverse();
    out
}

#[cfg(unix)]
fn history_files(home: &Path) -> Vec<PathBuf> {
    [".zsh_history", ".bash_history", ".sh_history", ".local/share/fish/fish_history"].iter().map(|f| home.join(f)).filter(|p| p.is_file()).collect()
}

#[cfg(unix)]
fn homes() -> Vec<(PathBuf, Option<String>)> {
    let me = std::env::var("HOME").map(PathBuf::from).ok();
    let mut v: Vec<(PathBuf, Option<String>)> = me.iter().map(|h| (h.clone(), std::env::var("USER").ok())).collect();
    // As root, every user's history is readable.
    if unsafe { libc::geteuid() } == 0 {
        for base in ["/Users", "/home"] {
            if let Ok(rd) = std::fs::read_dir(base) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() && Some(&p) != me.as_ref() {
                        v.push((p.clone(), p.file_name().map(|n| n.to_string_lossy().into_owned())));
                    }
                }
            }
        }
        for r in ["/root", "/var/root"] {
            if Path::new(r).is_dir() && me.as_deref() != Some(Path::new(r)) {
                v.push((r.into(), Some("root".into())));
            }
        }
    }
    v
}

// ── collection ─────────────────────────────────────────────────────────

/// Artifacts on the running system.
pub fn collect_live() -> Scan {
    let mut scan = Scan::default();
    #[cfg(unix)]
    {
        for (home, user) in homes() {
            for f in history_files(&home) {
                match read_capped(&f) {
                    Ok(b) => scan.items.extend(parse_history(&f, &b, user.clone())),
                    Err(e) => scan.notes.push(format!("{}: {e}", f.display())),
                }
            }
        }
        if unsafe { libc::geteuid() } != 0 {
            scan.notes.push("Shell history: only your own account (run with sudo to include every user).".into());
        }
    }
    #[cfg(windows)]
    windows::collect(&mut scan);
    sort_newest_first(&mut scan.items);
    scan
}

/// Timed entries newest first, then untimed ones in their own order.
pub fn sort_newest_first(items: &mut [Artifact]) {
    items.sort_by_key(|a| (a.time.is_none(), std::cmp::Reverse(a.time)));
}

/// Artifacts in a folder copied from another machine: *.pf, *.evtx,
/// shell history files, and raw AppCompatCache values (*.appcompat /
/// appcompatcache.bin).
pub fn collect_dir(dir: &Path) -> Scan {
    let mut scan = Scan::default();
    let mut stack = vec![dir.to_path_buf()];
    let mut files = 0usize;
    while let Some(d) = stack.pop() {
        let rd = match std::fs::read_dir(&d) {
            Ok(rd) => rd,
            Err(e) => {
                scan.notes.push(format!("{}: {e}", d.display()));
                continue;
            }
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            files += 1;
            if files > 20_000 {
                scan.notes.push("Stopped after 20,000 files.".into());
                return scan;
            }
            let name = p.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
            let ext = p.extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
            if ext == "pf" {
                match read_capped(&p).map_err(|e| e.to_string()).and_then(|b| prefetch::parse(&b)) {
                    Ok(pf) => scan.items.extend(pf.artifacts(&p.display().to_string())),
                    Err(e) => scan.notes.push(format!("{}: {e}", p.display())),
                }
            } else if ext == "evtx" {
                match evtx::parse_file(&p) {
                    Ok((records, problems)) => {
                        scan.items.extend(records.iter().filter_map(|r| r.artifact(&p.display().to_string())));
                        scan.records.extend(records);
                        scan.notes.extend(problems.into_iter().map(|e| format!("{}: {e}", p.display())));
                    }
                    Err(e) => scan.notes.push(format!("{}: {e}", p.display())),
                }
            } else if name.ends_with("history") || name == "fish_history" {
                if let Ok(b) = read_capped(&p) {
                    scan.items.extend(parse_history(&p, &b, None));
                }
            } else if name == "amcache.hve" || name == "system" || ext == "hve" || name.ends_with(".hiv") {
                let parsed = read_capped(&p).map_err(|e| e.to_string()).and_then(regf::Hive::parse);
                match parsed {
                    Ok(h) if name.contains("amcache") => match hives::amcache(&h, &p.display().to_string()) {
                        Ok(v) => scan.items.extend(v),
                        Err(e) => scan.notes.push(format!("{}: {e}", p.display())),
                    },
                    Ok(h) => {
                        let (v, notes) = hives::system(&h, &p.display().to_string());
                        scan.items.extend(v);
                        scan.notes.extend(notes.into_iter().map(|n| format!("{}: {n}", p.display())));
                    }
                    Err(e) => scan.notes.push(format!("{}: {e}", p.display())),
                }
            } else if ext == "appcompat" || name == "appcompatcache.bin" {
                match read_capped(&p).map_err(|e| e.to_string()).and_then(|b| shimcache::parse(&b)) {
                    Ok(v) => scan.items.extend(v.into_iter().map(|e| e.artifact(&p.display().to_string()))),
                    Err(e) => scan.notes.push(format!("{}: {e}", p.display())),
                }
            }
        }
    }
    sort_newest_first(&mut scan.items);
    scan
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::common::command::run_command_capped;
    use std::time::Duration;

    fn ps(script: &str) -> Result<String, String> {
        let out = run_command_capped(
            crate::common::command::tool("powershell").args(["-NoProfile", "-NonInteractive", "-Command", script]),
            Duration::from_secs(60),
            64 << 20,
        )
        .map_err(|e| e.to_string())?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    pub fn collect(scan: &mut Scan) {
        // Prefetch.
        let dir = std::env::var("SystemRoot").map(|r| PathBuf::from(r).join("Prefetch")).unwrap_or_else(|_| PathBuf::from(r"C:\Windows\Prefetch"));
        match std::fs::read_dir(&dir) {
            Ok(rd) => {
                let mut n = 0;
                for e in rd.flatten().filter(|e| e.path().extension().is_some_and(|x| x.eq_ignore_ascii_case("pf"))) {
                    n += 1;
                    match read_capped(e.path()).map_err(|e| e.to_string()).and_then(|b| prefetch::parse(&b)) {
                        Ok(pf) => scan.items.extend(pf.artifacts(&e.path().display().to_string())),
                        Err(err) => scan.notes.push(format!("{}: {err}", e.path().display())),
                    }
                }
                if n == 0 {
                    scan.notes.push("Prefetch folder is empty (prefetching may be disabled).".into());
                }
            }
            Err(e) => scan.notes.push(format!("Prefetch: {e} (run as administrator)")),
        }
        // Amcache: locked while Windows runs; read it if we can.
        let am = std::env::var("SystemRoot").map(|r| PathBuf::from(r).join(r"appcompat\Programs\Amcache.hve")).unwrap_or_default();
        match read_capped(&am).map_err(|e| e.to_string()).and_then(regf::Hive::parse) {
            Ok(h) => match hives::amcache(&h, &am.display().to_string()) {
                Ok(v) => scan.items.extend(v),
                Err(e) => scan.notes.push(format!("Amcache: {e}")),
            },
            Err(e) => scan.notes.push(format!(
                "Amcache: {e} — it is locked while Windows runs; copy it (and its .LOG files) with a forensic collection tool and import the folder (A)"
            )),
        }
        // ShimCache (raw registry value, parsed here).
        match ps("$v=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache' -ErrorAction Stop).AppCompatCache; [Convert]::ToBase64String($v)") {
            Ok(b64) => match base64_decode(b64.trim()).ok_or_else(|| "unreadable value".to_string()).and_then(|b| shimcache::parse(&b)) {
                Ok(v) => scan.items.extend(v.into_iter().map(|e| e.artifact("AppCompatCache"))),
                Err(e) => scan.notes.push(format!("ShimCache: {e}")),
            },
            Err(e) => scan.notes.push(format!("ShimCache: {e}")),
        }
        // BAM.
        let bam = r#"
$roots = @('HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings','HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings')
foreach ($r in $roots) { if (Test-Path $r) {
  Get-ChildItem $r -ErrorAction Stop | ForEach-Object {
    $sid = $_.PSChildName; $k = Get-Item $_.PSPath
    foreach ($n in $k.GetValueNames()) { $v = $k.GetValue($n)
      if ($v -is [byte[]] -and $v.Length -ge 8) { Write-Output ("{0}`t{1}`t{2}" -f $sid, [BitConverter]::ToInt64($v,0), $n) } } }
  break } }"#;
        match ps(bam) {
            Ok(out) => {
                let mut n = 0;
                for line in out.lines() {
                    let f: Vec<&str> = line.splitn(3, '\t').collect();
                    if f.len() == 3 {
                        n += 1;
                        scan.items.push(Artifact {
                            kind: "bam",
                            time: f[1].parse::<u64>().ok().and_then(filetime),
                            subject: f[2].to_string(),
                            detail: "last run (Background Activity Moderator)".into(),
                            source: "bam\\State\\UserSettings".into(),
                            user: Some(f[0].to_string()),
                        });
                    }
                }
                if n == 0 {
                    scan.notes.push("BAM: no entries readable (needs administrator; Windows 10 1709+).".into());
                }
            }
            Err(e) => scan.notes.push(format!("BAM: {e}")),
        }
        // Defender detections.
        let def = r#"
try { Get-MpThreatDetection -ErrorAction Stop | ForEach-Object {
  Write-Output ("{0}`t{1}`t{2}`t{3}`t{4}" -f $_.InitialDetectionTime.ToString('o'), $_.ThreatID, $_.ActionSuccess, ($_.Resources -join ' ; '), $_.ProcessName) }
} catch { Write-Output ("ERR`t" + $_.Exception.Message) }"#;
        match ps(def) {
            Ok(out) => {
                for line in out.lines() {
                    if let Some(e) = line.strip_prefix("ERR\t") {
                        scan.notes.push(format!("Defender: {e}"));
                        continue;
                    }
                    let f: Vec<&str> = line.splitn(5, '\t').collect();
                    if f.len() == 5 {
                        scan.items.push(Artifact {
                            kind: "defender",
                            time: DateTime::parse_from_rfc3339(f[0]).ok().map(|t| t.with_timezone(&Local)),
                            subject: f[3].to_string(),
                            detail: format!("threat {} · action {} · process {}", f[1], if f[2] == "True" { "succeeded" } else { "FAILED" }, f[4]),
                            source: "Get-MpThreatDetection".into(),
                            user: None,
                        });
                    }
                }
            }
            Err(e) => scan.notes.push(format!("Defender: {e}")),
        }
    }
}

/// Whole-file parsers work in memory; a folder from elsewhere can hold
/// anything, so refuse what can't be an artifact instead of exhausting RAM.
fn read_capped(path: impl AsRef<Path>) -> std::io::Result<Vec<u8>> {
    const MAX: u64 = 1 << 30;
    let path = path.as_ref();
    crate::files::info::require_regular(path)?;
    if std::fs::metadata(path)?.len() > MAX {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "larger than 1 GB"));
    }
    std::fs::read(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histories() {
        let z = parse_history(Path::new("/h/.zsh_history"), b": 1700000000:0;curl x | sh\n: 1700000100:0;ls\nplain\n", Some("a".into()));
        assert_eq!(z.len(), 3);
        assert_eq!(z[2].time.unwrap().timestamp(), 1_700_000_000, "newest first");
        assert!(z[0].time.is_none());
        let b = parse_history(Path::new("/h/.bash_history"), b"#1700000000\nwhoami\nid\n", None);
        assert_eq!(b[1].time.unwrap().timestamp(), 1_700_000_000);
        assert!(b[0].time.is_none());
        let f = parse_history(Path::new("/h/fish_history"), b"- cmd: echo hi\n  when: 1700000000\n- cmd: ls\n", None);
        assert_eq!(f.len(), 2);
        assert_eq!(f[1].time.unwrap().timestamp(), 1_700_000_000);
        // zsh metafied UTF-8: "é" = c3 a9 → c3 83 89
        let m = parse_history(Path::new("/h/.zsh_history"), &[b'e', b'c', b'h', b'o', b' ', 0xc3, 0x83, 0x89], None);
        assert_eq!(m[0].subject, "echo é");
    }

    #[test]
    fn helpers() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("YQ").unwrap(), b"a");
        assert!(base64_decode("@@@@").is_none());
        // 2020-01-01T00:00:00Z
        assert_eq!(filetime(132_223_104_000_000_000).unwrap().timestamp(), 1_577_836_800);
        assert!(filetime(0).is_none());
        assert_eq!(utf16z(&[b'a', 0, b'b', 0, 0, 0, b'c', 0]), "ab");
    }
}
