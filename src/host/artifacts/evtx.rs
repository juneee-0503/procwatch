//! Windows event log (.evtx) files, parsed with the `evtx` crate on any
//! OS, flattened into records with named fields for Sigma and summarised
//! for the artifact list.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Local};
use serde::Serialize;
use serde_json::Value;

use super::Artifact;

#[derive(Debug, Clone, Serialize)]
pub struct WinRecord {
    #[serde(serialize_with = "ser_time")]
    pub time: DateTime<Local>,
    pub channel: String,
    pub provider: String,
    pub event_id: u32,
    pub record_id: u64,
    pub computer: String,
    pub data: BTreeMap<String, String>,
}

fn ser_time<S: serde::Serializer>(t: &DateTime<Local>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&t.to_rfc3339())
}

const MAX_RECORDS: usize = 200_000;

fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Object(o) => o.get("#text").and_then(text),
        Value::Array(a) => Some(a.iter().filter_map(text).collect::<Vec<_>>().join(", ")),
        Value::Null => None,
    }
}

fn attr<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.get("#attributes").and_then(|a| a.get(key))
}

/// Flatten EventData / UserData into name → value.
fn flatten(v: &Value, out: &mut BTreeMap<String, String>) {
    let Value::Object(o) = v else { return };
    for (k, val) in o {
        if k == "#attributes" {
            continue;
        }
        match val {
            // Unnamed <Data> elements come out as an array.
            Value::Array(items) if k == "Data" => {
                for (i, it) in items.iter().enumerate() {
                    if let Some(t) = text(it) {
                        out.insert(format!("Data{i}"), t);
                    }
                }
            }
            // UserData wraps its fields in one more element.
            Value::Object(inner) if !inner.contains_key("#text") => flatten(val, out),
            _ => {
                if let Some(t) = text(val) {
                    out.insert(k.clone(), t);
                }
            }
        }
    }
}

pub fn from_json(v: &Value, fallback_time: Option<DateTime<Local>>, record_id: u64) -> Option<WinRecord> {
    let ev = v.get("Event")?;
    let sys = ev.get("System")?;
    let event_id = sys.get("EventID").and_then(text).and_then(|t| t.parse().ok())?;
    let time = sys
        .get("TimeCreated")
        .and_then(|t| attr(t, "SystemTime"))
        .and_then(Value::as_str)
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&Local))
        .or(fallback_time)?;
    let mut data = BTreeMap::new();
    for section in ["EventData", "UserData"] {
        if let Some(d) = ev.get(section) {
            flatten(d, &mut data);
        }
    }
    Some(WinRecord {
        time,
        channel: sys.get("Channel").and_then(text).unwrap_or_default(),
        provider: sys.get("Provider").and_then(|p| attr(p, "Name")).and_then(text).unwrap_or_default(),
        event_id,
        record_id,
        computer: sys.get("Computer").and_then(text).unwrap_or_default(),
        data,
    })
}

/// Parse a whole file. Returns records plus per-record problems (capped).
pub fn parse_file(path: &Path) -> Result<(Vec<WinRecord>, Vec<String>), String> {
    let mut parser = evtx::EvtxParser::from_path(path).map_err(|e| e.to_string())?;
    let mut records = Vec::new();
    let mut problems = Vec::new();
    let mut bad = 0usize;
    for r in parser.records_json_value() {
        match r {
            Ok(rec) => {
                let fallback = DateTime::parse_from_rfc3339(&rec.timestamp.to_string()).ok().map(|t| t.with_timezone(&Local));
                match from_json(&rec.data, fallback, rec.event_record_id) {
                    Some(w) => records.push(w),
                    None => bad += 1,
                }
            }
            Err(e) => {
                bad += 1;
                if problems.len() < 5 {
                    problems.push(e.to_string());
                }
            }
        }
        if records.len() >= MAX_RECORDS {
            problems.push(format!("stopped after {MAX_RECORDS} records"));
            break;
        }
    }
    if bad > 0 {
        problems.push(format!("{bad} record(s) could not be read"));
    }
    Ok((records, problems))
}

impl WinRecord {
    fn get(&self, k: &str) -> &str {
        self.data.get(k).map(String::as_str).unwrap_or("")
    }

    /// The Sigma view of this record.
    pub fn sigma_event(&self) -> crate::detection::sigma::Event {
        crate::detection::sigma::map::windows_record(&self.channel, &self.provider, self.event_id, &self.data)
    }

    /// A one-line summary for well-known, investigation-relevant events;
    /// everything else is still available to Sigma rules.
    pub fn artifact(&self, source: &str) -> Option<Artifact> {
        let svc = crate::detection::sigma::map::service_of(&self.channel);
        let (subject, detail) = match (svc.as_str(), self.event_id) {
            ("security", 4688) => (self.get("NewProcessName").to_string(), format!("process created by {} · {}", self.get("SubjectUserName"), self.get("CommandLine"))),
            ("security", 4624) => (format!("{}\\{}", self.get("TargetDomainName"), self.get("TargetUserName")), format!("logon type {} from {} {}", self.get("LogonType"), self.get("IpAddress"), self.get("WorkstationName"))),
            ("security", 4625) => (format!("{}\\{}", self.get("TargetDomainName"), self.get("TargetUserName")), format!("FAILED logon type {} from {}", self.get("LogonType"), self.get("IpAddress"))),
            ("security", 4720) => (self.get("TargetUserName").to_string(), format!("user account created by {}", self.get("SubjectUserName"))),
            ("security", 4698) => (self.get("TaskName").to_string(), format!("scheduled task created by {}", self.get("SubjectUserName"))),
            ("security", 1102) | ("system", 104) => ("event log".into(), format!("log cleared ({})", self.channel)),
            ("system", 7045) => (self.get("ImagePath").to_string(), format!("service installed: {} ({})", self.get("ServiceName"), self.get("AccountName"))),
            ("powershell", 4104) => ("PowerShell script block".into(), self.get("ScriptBlockText").chars().take(300).collect()),
            ("sysmon", 1) => (self.get("Image").to_string(), format!("process created · {}", self.get("CommandLine"))),
            ("sysmon", 3) => (self.get("Image").to_string(), format!("connection to {}:{}", self.get("DestinationIp"), self.get("DestinationPort"))),
            ("sysmon", 11) => (self.get("TargetFilename").to_string(), format!("file created by {}", self.get("Image"))),
            ("windefend", 1116 | 1117) => (self.get("Path").to_string(), format!("Defender: {} ({})", self.get("Threat Name"), self.get("Action Name"))),
            _ => return None,
        };
        Some(Artifact {
            kind: "evtx",
            time: Some(self.time),
            subject,
            detail: format!("{} {} · {detail}", self.channel, self.event_id),
            source: source.into(),
            user: Some(self.get("SubjectUserName").to_string()).filter(|u| !u.is_empty()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_crate_json() {
        let v: Value = serde_json::from_str(
            r##"{"Event":{"#attributes":{"xmlns":"x"},"System":{
                "Provider":{"#attributes":{"Name":"Microsoft-Windows-Security-Auditing"}},
                "EventID":4688,"Channel":"Security","Computer":"WS1",
                "TimeCreated":{"#attributes":{"SystemTime":"2024-05-01T10:00:00.123Z"}}},
              "EventData":{"SubjectUserName":"alice","NewProcessName":"C:\\Windows\\System32\\cmd.exe","CommandLine":"cmd /c whoami"}}}"##,
        )
        .unwrap();
        let r = from_json(&v, None, 7).unwrap();
        assert_eq!(r.event_id, 4688);
        assert_eq!(r.provider, "Microsoft-Windows-Security-Auditing");
        assert_eq!(r.time.timestamp(), 1_714_557_600);
        let a = r.artifact("Security.evtx").unwrap();
        assert!(a.detail.contains("cmd /c whoami"));
        assert_eq!(r.sigma_event().category, "process_creation");

        let q: Value = serde_json::from_str(
            r##"{"Event":{"System":{"EventID":{"#attributes":{"Qualifiers":16384},"#text":7045},"Channel":"System",
              "TimeCreated":{"#attributes":{"SystemTime":"2024-05-01T10:00:00Z"}}},
              "EventData":{"Data":["a","b"]},"UserData":{"Wrapper":{"ServiceName":"svc"}}}}"##,
        )
        .unwrap();
        let r = from_json(&q, None, 1).unwrap();
        assert_eq!(r.event_id, 7045);
        assert_eq!(r.data.get("Data1").map(String::as_str), Some("b"));
        assert_eq!(r.data.get("ServiceName").map(String::as_str), Some("svc"));
    }
}
