//! IOC sweep: match a list of indicators of compromise against everything
//! procwatch can observe. Indicator file format — one per line, type
//! detected automatically, `#` starts a comment:
//!
//! ```text
//! 44d88612fea8a8f36de82e1278abb02f      # MD5 / SHA-1 / SHA-256
//! 203.0.113.7                            # IP address
//! evil.example                           # domain (matches subdomains)
//! /tmp/.hidden/agent                     # path (substring)
//! "Invoke-Mimikatz"                      # quoted = free text
//! ```

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Kind {
    Md5,
    Sha1,
    Sha256,
    Ip,
    Domain,
    Path,
    Text,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Md5 => "md5",
            Kind::Sha1 => "sha1",
            Kind::Sha256 => "sha256",
            Kind::Ip => "ip",
            Kind::Domain => "domain",
            Kind::Path => "path",
            Kind::Text => "text",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Ioc {
    pub kind: Kind,
    pub value: String,
    pub note: String,
}

/// Something observed on the system, from any source.
#[derive(Debug, Clone, Default)]
pub struct Obs {
    pub source: &'static str,
    pub pid: Option<u32>,
    pub name: String,
    pub sha256: Option<String>,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub ip: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    /// Free text searched by text/domain/ip/path indicators.
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub ioc: String,
    pub kind: Kind,
    pub note: String,
    pub source: String,
    pub pid: Option<u32>,
    pub name: String,
    pub detail: String,
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_domain(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        && labels.last().is_some_and(|t| t.len() >= 2 && t.chars().all(|c| c.is_ascii_alphabetic()))
}

/// Parse an indicator file. Returns indicators and per-line problems.
pub fn parse(text: &str) -> (Vec<Ioc>, Vec<String>) {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let (body, note) = match raw.split_once('#') {
            Some((b, c)) if !b.trim_end().ends_with('"') || b.matches('"').count() % 2 == 0 => (b.trim(), c.trim()),
            _ => (raw.trim(), ""),
        };
        if body.is_empty() {
            continue;
        }
        // Defanged forms people paste from reports: hxxp, [.], (.)
        let cleaned = body.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http");
        let v = cleaned.trim().trim_end_matches(',');
        let (kind, value) = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
            (Kind::Text, v[1..v.len() - 1].to_string())
        } else if is_hex(v) && v.len() == 32 {
            (Kind::Md5, v.to_lowercase())
        } else if is_hex(v) && v.len() == 40 {
            (Kind::Sha1, v.to_lowercase())
        } else if is_hex(v) && v.len() == 64 {
            (Kind::Sha256, v.to_lowercase())
        } else if v.parse::<std::net::IpAddr>().is_ok() {
            (Kind::Ip, v.to_lowercase())
        } else if let Some(host) = v.strip_prefix("http://").or_else(|| v.strip_prefix("https://")) {
            let host = host.split(['/', ':']).next().unwrap_or("").to_lowercase();
            if host.parse::<std::net::IpAddr>().is_ok() {
                (Kind::Ip, host)
            } else if is_domain(&host) {
                (Kind::Domain, host)
            } else {
                errors.push(format!("line {}: can't read URL host in '{v}'", n + 1));
                continue;
            }
        } else if v.contains('/') || v.contains('\\') {
            (Kind::Path, v.to_lowercase())
        } else if is_domain(&v.to_lowercase()) {
            (Kind::Domain, v.to_lowercase())
        } else if v.len() >= 4 {
            (Kind::Text, v.to_string())
        } else {
            errors.push(format!("line {}: '{v}' is too short to match safely", n + 1));
            continue;
        };
        out.push(Ioc { kind, value, note: note.to_string() });
    }
    (out, errors)
}

fn host_matches(host: &str, domain: &str) -> bool {
    let h = host.to_lowercase();
    h == domain || h.ends_with(&format!(".{domain}"))
}

/// Match every indicator against every observation.
pub fn sweep(iocs: &[Ioc], obs: &[Obs]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for o in obs {
        let text = o.text.to_lowercase();
        let path = o.path.as_deref().map(str::to_lowercase);
        for i in iocs {
            let matched = match i.kind {
                Kind::Sha256 => o.sha256.as_deref() == Some(i.value.as_str()),
                Kind::Md5 => o.md5.as_deref() == Some(i.value.as_str()),
                Kind::Sha1 => o.sha1.as_deref() == Some(i.value.as_str()),
                Kind::Ip => {
                    o.ip.as_deref().is_some_and(|ip| ip.trim_matches(['[', ']']).eq_ignore_ascii_case(&i.value))
                        || text.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':')).any(|t| t == i.value)
                }
                Kind::Domain => o.host.as_deref().is_some_and(|h| host_matches(h, &i.value)) || text.contains(&i.value),
                Kind::Path => path.as_deref().is_some_and(|p| p.contains(&i.value)) || text.contains(&i.value),
                Kind::Text => text.contains(&i.value.to_lowercase()),
            };
            if matched {
                hits.push(Hit {
                    ioc: i.value.clone(),
                    kind: i.kind,
                    note: i.note.clone(),
                    source: o.source.to_string(),
                    pid: o.pid,
                    name: o.name.clone(),
                    detail: o.path.clone().or_else(|| o.ip.clone()).unwrap_or_else(|| o.text.chars().take(160).collect()),
                });
            }
        }
    }
    hits.sort_by(|a, b| a.kind.label().cmp(b.kind.label()).then(a.ioc.cmp(&b.ioc)).then(a.source.cmp(&b.source)));
    hits.dedup_by(|a, b| a.ioc == b.ioc && a.source == b.source && a.pid == b.pid && a.detail == b.detail);
    hits
}

/// Default indicator file: next to the settings file.
pub fn default_path() -> Option<std::path::PathBuf> {
    crate::config::path().map(|p| p.with_file_name("iocs.txt"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_matches() {
        let (iocs, errs) = parse(
            "# list\n\
             ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  # abc\n\
             203.0.113.7\n\
             hxxp://bad[.]example/x\n\
             /tmp/.hidden/\n\
             \"Invoke-Mimikatz\"\n\
             ab\n",
        );
        assert_eq!(iocs.len(), 5, "{iocs:?}");
        assert_eq!(errs.len(), 1);
        assert_eq!(iocs[2].kind, Kind::Domain);
        assert_eq!(iocs[2].value, "bad.example");

        let obs = vec![
            Obs { source: "process", pid: Some(9), name: "agent".into(), sha256: Some(iocs[0].value.clone()), path: Some("/tmp/.hidden/agent".into()), ..Default::default() },
            Obs { source: "network", pid: Some(9), ip: Some("203.0.113.7".into()), host: Some("cdn.bad.example".into()), ..Default::default() },
            Obs { source: "log", text: "powershell Invoke-Mimikatz -DumpCreds".into(), ..Default::default() },
            Obs { source: "network", ip: Some("203.0.113.70".into()), ..Default::default() },
        ];
        let hits = sweep(&iocs, &obs);
        let kinds: Vec<Kind> = hits.iter().map(|h| h.kind).collect();
        assert!(kinds.contains(&Kind::Sha256) && kinds.contains(&Kind::Ip) && kinds.contains(&Kind::Domain));
        assert!(kinds.contains(&Kind::Path) && kinds.contains(&Kind::Text));
        assert!(!hits.iter().any(|h| h.detail.contains("203.0.113.70")), "ip must match exactly");
    }
}
