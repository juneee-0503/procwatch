//! Standard exchange formats, so results go straight into other tools:
//! a STIX 2.1 bundle and a MISP event with the indicators an investigation
//! produced, and the timeline as ECS-style JSON lines for a SIEM.

use std::collections::BTreeSet;

use chrono::{DateTime, Local, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// An indicator worth sharing, with why.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Indicator {
    Sha256 { value: String, why: String },
    Ip { value: String, why: String },
    Domain { value: String, why: String },
    Path { value: String, why: String },
}

impl Indicator {
    fn why(&self) -> &str {
        match self {
            Indicator::Sha256 { why, .. } | Indicator::Ip { why, .. } | Indicator::Domain { why, .. } | Indicator::Path { why, .. } => why,
        }
    }
    fn value(&self) -> &str {
        match self {
            Indicator::Sha256 { value, .. } | Indicator::Ip { value, .. } | Indicator::Domain { value, .. } | Indicator::Path { value, .. } => value,
        }
    }
}

/// Deterministic UUID (version 5 layout) from content, so re-exports keep
/// the same STIX ids.
fn uuid(kind: &str, value: &str) -> String {
    let h = Sha256::digest(format!("procwatch|{kind}|{value}").as_bytes());
    let mut b: [u8; 16] = h[..16].try_into().unwrap_or([0; 16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

fn stix_escape(v: &str) -> String {
    v.replace('\\', "\\\\").replace('\'', "\\'")
}

pub fn stix_bundle(case_id: &str, indicators: &[Indicator], now: DateTime<Local>) -> Value {
    let ts = now.with_timezone(&Utc).format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let identity_id = format!("identity--{}", uuid("identity", "procwatch"));
    let mut objects = vec![json!({
        "type": "identity", "spec_version": "2.1", "id": identity_id, "created": ts, "modified": ts,
        "name": "procwatch", "identity_class": "system"
    })];
    for i in indicators {
        let (pattern, name) = match i {
            Indicator::Sha256 { value, .. } => (format!("[file:hashes.'SHA-256' = '{}']", stix_escape(value)), format!("File SHA-256 {value}")),
            Indicator::Ip { value, .. } => {
                let kind = if value.contains(':') { "ipv6-addr" } else { "ipv4-addr" };
                (format!("[{kind}:value = '{}']", stix_escape(value)), format!("Address {value}"))
            }
            Indicator::Domain { value, .. } => (format!("[domain-name:value = '{}']", stix_escape(value)), format!("Domain {value}")),
            Indicator::Path { value, .. } => (format!("[file:name = '{}']", stix_escape(value.rsplit(['/', '\\']).next().unwrap_or(value))), format!("File {value}")),
        };
        objects.push(json!({
            "type": "indicator", "spec_version": "2.1",
            "id": format!("indicator--{}", uuid("indicator", &pattern)),
            "created_by_ref": identity_id, "created": ts, "modified": ts,
            "name": name, "description": i.why(),
            "indicator_types": ["anomalous-activity"],
            "pattern": pattern, "pattern_type": "stix", "valid_from": ts,
            "labels": [format!("procwatch-case:{case_id}")]
        }));
    }
    json!({ "type": "bundle", "id": format!("bundle--{}", uuid("bundle", &format!("{case_id}{ts}"))), "objects": objects })
}

pub fn misp_event(case_id: &str, indicators: &[Indicator], now: DateTime<Local>) -> Value {
    let attrs: Vec<Value> = indicators
        .iter()
        .map(|i| {
            let (t, cat) = match i {
                Indicator::Sha256 { .. } => ("sha256", "Payload delivery"),
                Indicator::Ip { .. } => ("ip-dst", "Network activity"),
                Indicator::Domain { .. } => ("domain", "Network activity"),
                Indicator::Path { .. } => ("filename", "Artifacts dropped"),
            };
            json!({ "type": t, "category": cat, "value": i.value(), "to_ids": matches!(i, Indicator::Sha256 { .. }), "comment": i.why() })
        })
        .collect();
    json!({ "Event": {
        "info": format!("procwatch investigation {case_id}"),
        "date": now.format("%Y-%m-%d").to_string(),
        "threat_level_id": "2", "analysis": "1", "distribution": "0",
        "Tag": [{ "name": "tool:procwatch" }],
        "Attribute": attrs
    }})
}

/// One timeline row in Elastic Common Schema field names.
#[allow(clippy::too_many_arguments)]
pub fn ecs_event(
    time: DateTime<Local>,
    id: &str,
    source: &str,
    kind: &str,
    pid: Option<u32>,
    name: &str,
    detail: &str,
    exe: Option<&str>,
    remote: Option<(&str, &str)>,
    path: Option<&str>,
    host: &str,
) -> Value {
    let (category, etype, ekind): (&str, &str, &str) = match (source, kind) {
        ("process" | "deep", "started" | "spawn" | "exec") => ("process", "start", "event"),
        ("process" | "deep", "exited" | "exit") => ("process", "end", "event"),
        ("network", "connect" | "accept") => ("network", "connection", "event"),
        ("network", "listen") => ("network", "start", "event"),
        ("network", _) => ("network", "end", "event"),
        ("file", "deleted" | "delete") => ("file", "deletion", "event"),
        ("file", "created" | "create") => ("file", "creation", "event"),
        ("file", "open" | "read") => ("file", "access", "event"),
        ("registry", _) => ("registry", "change", "event"),
        ("file", _) => ("file", "change", "event"),
        ("persist", _) => ("configuration", "change", "event"),
        ("detect" | "alert", _) => ("intrusion_detection", "info", "alert"),
        ("log", _) => ("host", "info", "event"),
        _ => ("host", "info", "event"),
    };
    let mut v = json!({
        "@timestamp": time.with_timezone(&Utc).to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "event": { "kind": ekind, "category": [category], "type": [etype], "action": kind, "provider": "procwatch", "dataset": format!("procwatch.{source}"), "id": id },
        "host": { "name": host },
        "message": detail,
    });
    if let Some(p) = pid {
        v["process"] = json!({ "pid": p, "name": name });
        if let Some(e) = exe {
            v["process"]["executable"] = json!(e);
        }
        if category == "process" && !detail.is_empty() {
            v["process"]["command_line"] = json!(detail.split(" · parent").next().unwrap_or(detail));
        }
    }
    if let Some((ip, port)) = remote {
        v["destination"] = json!({ "ip": ip, "port": port.parse::<u16>().ok() });
    }
    if let Some(p) = path {
        v["file"] = json!({ "path": p });
    }
    if category == "intrusion_detection" {
        let rule = kind.split_whitespace().last().unwrap_or(kind);
        v["rule"] = json!({ "id": rule, "name": detail.split(" — ").next().unwrap_or(detail) });
    }
    v
}

/// Deduplicate and sort.
pub fn unique(mut v: Vec<Indicator>) -> Vec<Indicator> {
    let mut seen = BTreeSet::new();
    let kind = |i: &Indicator| match i {
        Indicator::Sha256 { .. } => 0,
        Indicator::Ip { .. } => 1,
        Indicator::Domain { .. } => 2,
        Indicator::Path { .. } => 3,
    };
    v.retain(|i| seen.insert((kind(i), i.value().to_lowercase())));
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stix_misp_and_ecs_shapes() {
        let now = Local::now();
        let ind = unique(vec![
            Indicator::Sha256 { value: "ab".repeat(32), why: "PW-001 on x".into() },
            Indicator::Ip { value: "203.0.113.9".into(), why: "beaconing".into() },
            Indicator::Ip { value: "203.0.113.9".into(), why: "dup".into() },
            Indicator::Domain { value: "evil.example".into(), why: "queried".into() },
        ]);
        assert_eq!(ind.len(), 3);
        let b = stix_bundle("case-1", &ind, now);
        assert_eq!(b["type"], "bundle");
        let objs = b["objects"].as_array().unwrap();
        assert_eq!(objs.len(), 4, "identity + 3 indicators");
        assert!(objs.iter().any(|o| o["pattern"] == format!("[file:hashes.'SHA-256' = '{}']", "ab".repeat(32))));
        assert!(objs.iter().any(|o| o["pattern"] == "[ipv4-addr:value = '203.0.113.9']"));
        // Stable ids across exports.
        assert_eq!(stix_bundle("case-1", &ind, now)["objects"][1]["id"], objs[1]["id"]);
        let id = objs[1]["id"].as_str().unwrap();
        assert_eq!(id.len(), "indicator--".len() + 36);
        let m = misp_event("case-1", &ind, now);
        assert_eq!(m["Event"]["Attribute"].as_array().unwrap().len(), 3);
        let e = ecs_event(now, "T-1", "network", "connect", Some(5), "curl", "TCP a → b", Some("/usr/bin/curl"), Some(("203.0.113.9", "443")), None, "h");
        assert_eq!(e["event"]["category"][0], "network");
        assert_eq!(e["destination"]["port"], 443);
        assert_eq!(e["process"]["executable"], "/usr/bin/curl");
    }
}

#[cfg(test)]
mod dump {
    /// Writes a sample bundle for external validation when PW_STIX_DUMP is set.
    #[test]
    fn dump_stix() {
        let Ok(path) = std::env::var("PW_STIX_DUMP") else { return };
        let ind = vec![
            super::Indicator::Sha256 { value: "ab".repeat(32), why: "PW-001 on x".into() },
            super::Indicator::Ip { value: "203.0.113.9".into(), why: "beaconing".into() },
            super::Indicator::Ip { value: "2001:db8::1".into(), why: "v6".into() },
            super::Indicator::Domain { value: "evil.example".into(), why: "queried".into() },
            super::Indicator::Path { value: "C:\\Users\\a\\it's.exe".into(), why: "quote".into() },
        ];
        std::fs::write(path, serde_json::to_string_pretty(&super::stix_bundle("case-1", &ind, chrono::Local::now())).unwrap()).unwrap();
    }
}
