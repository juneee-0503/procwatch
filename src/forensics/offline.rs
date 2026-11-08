//! Offline analysis of a saved case: re-run the host rules, Sigma rules,
//! IOC matching and artifact parsing over collected evidence and imported
//! artifact folders, without access to the machine they came from.
//!
//! The original evidence is only read. Results are written into the case
//! as a new *derived* evidence item and logged in the custody chain.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::Local;
use serde::Serialize;
use serde_json::Value;

use crate::forensics::case::{Case, Provenance};
use crate::files::intel::ExeInfo;
use crate::common::model::Severity;
use crate::network::{ConnState, Connection};
use crate::process::ProcessInfo;

pub struct Options {
    pub case: PathBuf,
    pub iocs: Option<PathBuf>,
    pub sigma: Option<PathBuf>,
    pub artifacts: Vec<PathBuf>,
    pub yara: Option<PathBuf>,
    pub json: bool,
}

#[derive(Serialize, Clone)]
pub struct Hit {
    pub engine: &'static str,
    pub rule: String,
    pub name: String,
    pub severity: Severity,
    pub confidence: crate::common::model::Confidence,
    pub technique: String,
    pub subject: String,
    pub evidence: String,
    pub time: Option<String>,
}

#[derive(Serialize)]
pub struct Analysis {
    pub case: String,
    pub analysed_at: String,
    pub inputs: Vec<String>,
    pub gaps: Vec<String>,
    pub processes: usize,
    pub connections: usize,
    pub event_records: usize,
    pub artifacts: usize,
    pub sigma_rules: usize,
    pub sigma_rejected: Vec<String>,
    pub hits: Vec<Hit>,
    pub ioc_hits: Vec<crate::detection::ioc::Hit>,
}

fn load(case: &Case, name: &str, inputs: &mut Vec<String>, gaps: &mut Vec<String>) -> Option<Value> {
    let p = case.dir.join("evidence").join(name);
    match std::fs::read_to_string(&p) {
        Ok(t) => match serde_json::from_str(&t) {
            Ok(v) => {
                let id = case.register().into_iter().rfind(|i| i.path.ends_with(name)).map(|i| format!(" ({})", i.id)).unwrap_or_default();
                inputs.push(format!("evidence/{name}{id}"));
                Some(v)
            }
            Err(e) => {
                gaps.push(format!("{name}: unreadable JSON ({e})"));
                None
            }
        },
        Err(_) => {
            gaps.push(format!("{name}: not in the case"));
            None
        }
    }
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn state(label: &str) -> ConnState {
    match label {
        "LISTEN" => ConnState::Listen,
        "ESTABLISHED" => ConnState::Established,
        "SYN" => ConnState::Opening,
        "" => ConnState::Stateless,
        _ => ConnState::Other,
    }
}

pub fn analyse(o: &Options) -> anyhow::Result<(Analysis, Case)> {
    let case = Case::open(&o.case)?;
    let mut inputs = Vec::new();
    let mut gaps = Vec::new();
    // Gaps the live collection already recorded.
    for item in case.register() {
        if !item.problems.is_empty() {
            gaps.push(format!("{} {}: {}", item.id, item.path, item.problems.join("; ")));
        }
    }
    let procs_v = load(&case, "processes.json", &mut inputs, &mut gaps).unwrap_or(Value::Array(vec![]));
    let exes: HashMap<String, ExeInfo> =
        load(&case, "executables.json", &mut inputs, &mut gaps).and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
    let conns_v = load(&case, "connections.json", &mut inputs, &mut gaps).unwrap_or(Value::Array(vec![]));
    let fs_v = load(&case, "file-changes.json", &mut inputs, &mut gaps).unwrap_or(Value::Array(vec![]));
    let logs_v = load(&case, "event-log.json", &mut inputs, &mut gaps).unwrap_or(Value::Array(vec![]));
    let persist_v = load(&case, "persistence.json", &mut inputs, &mut gaps).unwrap_or(Value::Array(vec![]));

    let mut procs: HashMap<u32, ProcessInfo> = HashMap::new();
    for p in procs_v.as_array().into_iter().flatten() {
        let Some(pid) = p.get("pid").and_then(Value::as_u64) else { continue };
        let mut i = ProcessInfo::bare(pid as u32, p.get("ppid").and_then(Value::as_u64).map(|x| x as u32), s(p, "name"));
        i.exe_path = Some(s(p, "exe")).filter(|e| !e.is_empty());
        i.user = Some(s(p, "user")).filter(|e| !e.is_empty());
        let cmd = s(p, "command_line");
        i.cmd = if cmd.is_empty() { vec![] } else { vec![cmd] };
        i.start_time_secs = p.get("start_time_unix").and_then(Value::as_u64).unwrap_or(0);
        procs.insert(i.pid, i);
    }
    let mut conns: HashMap<u32, Vec<Connection>> = HashMap::new();
    for c in conns_v.as_array().into_iter().flatten() {
        let Some(pid) = c.get("pid").and_then(Value::as_u64) else { continue };
        let protocol = if s(c, "proto").eq_ignore_ascii_case("udp") { "UDP" } else { "TCP" };
        conns.entry(pid as u32).or_default().push(Connection { protocol, local: s(c, "local"), remote: s(c, "remote"), state: state(&s(c, "state")) });
    }

    // Imported artifacts (EVTX, Prefetch…), and anything under the case's
    // own artifacts/ folder.
    let mut art_dirs = o.artifacts.clone();
    if case.dir.join("artifacts").is_dir() {
        art_dirs.push(case.dir.join("artifacts"));
    }
    let mut artifacts = Vec::new();
    let mut records = Vec::new();
    for d in &art_dirs {
        let scan = crate::host::artifacts::collect_dir(d);
        inputs.push(format!("{} ({} artifacts, {} event records)", d.display(), scan.items.len(), scan.records.len()));
        gaps.extend(scan.notes.into_iter().map(|n| format!("{}: {n}", d.display())));
        artifacts.extend(scan.items);
        records.extend(scan.records);
    }

    // Rules.
    let mut sigma = crate::detection::sigma::builtin();
    let mut rejected = Vec::new();
    if let Some(dir) = o.sigma.clone().or_else(crate::detection::sigma::default_dir).filter(|d| d.exists()) {
        let (user, errs) = crate::detection::sigma::load_dir(&dir);
        sigma.retain(|b| !user.iter().any(|u| u.id == b.id));
        sigma.extend(user);
        rejected = errs;
    }
    let suppressions = crate::detection::engine::load();
    let suppressed = |rule: &str, i: Option<&ProcessInfo>, path: &str| {
        let cmd = i.map(|i| i.cmd.join(" ")).unwrap_or_default();
        let facts = crate::detection::engine::Facts {
            name: i.map_or("", |i| i.name.as_str()),
            path: i.and_then(|i| i.exe_path.as_deref()).unwrap_or(path),
            user: i.and_then(|i| i.user.as_deref()).unwrap_or(""),
            cmd: &cmd,
            team: "",
        };
        crate::detection::engine::suppressed(&suppressions, rule, &facts).is_some()
    };

    let mut hits = Vec::new();
    let empty = Vec::new();
    let collected = procs.values().map(|p| p.start_time_secs).max().unwrap_or(0) + 3600;
    for p in procs.values() {
        let parent = p.ppid.and_then(|pp| procs.get(&pp));
        let exe = p.exe_path.as_deref().and_then(|e| exes.get(e));
        let a = crate::detection::triage::assess(p, parent, conns.get(&p.pid).unwrap_or(&empty), exe, collected);
        let label = format!("{} ({})", p.name, p.pid);
        for h in a.hits {
            if !suppressed(&h.id, Some(p), "") {
                hits.push(Hit { engine: "host rule", rule: h.id, name: h.name, severity: h.severity, confidence: h.confidence, technique: h.technique, subject: label.clone(), evidence: h.evidence, time: None });
            }
        }
        let ev = crate::detection::sigma::map::process(p, parent, exe.and_then(|e| e.sha256.as_deref()), exe.and_then(|e| e.md5.as_deref()));
        for r in crate::detection::sigma::evaluate(&sigma, &ev) {
            if !suppressed(&r.id, Some(p), "") {
                hits.push(sigma_hit(r, &ev, label.clone(), None));
            }
        }
        for c in conns.get(&p.pid).into_iter().flatten() {
            let ev = crate::detection::sigma::map::connection(p.exe_path.as_deref().unwrap_or(&p.name), p.pid, c.protocol, &c.local, &c.remote, c.state == ConnState::Listen);
            for r in crate::detection::sigma::evaluate(&sigma, &ev) {
                if !suppressed(&r.id, Some(p), "") {
                    hits.push(sigma_hit(r, &ev, label.clone(), None));
                }
            }
        }
    }
    for f in fs_v.as_array().into_iter().flatten() {
        let ev = crate::detection::sigma::map::file(&s(f, "kind"), &s(f, "path"));
        for r in crate::detection::sigma::evaluate(&sigma, &ev) {
            hits.push(sigma_hit(r, &ev, s(f, "path"), Some(s(f, "time"))));
        }
    }
    for l in logs_v.as_array().into_iter().flatten() {
        let pid = l.get("pid").and_then(Value::as_u64).map(|p| p as u32);
        let ev = crate::detection::sigma::map::log_line(&s(l, "source"), &s(l, "process"), pid, &s(l, "level"), &s(l, "message"), l.get("event_id").and_then(Value::as_u64).map(|x| x as u32));
        for r in crate::detection::sigma::evaluate(&sigma, &ev) {
            hits.push(sigma_hit(r, &ev, format!("{} (log)", s(l, "process")), Some(s(l, "time"))));
        }
    }
    for rec in &records {
        let ev = crate::detection::sigma::map::record_event(rec);
        for r in crate::detection::sigma::evaluate(&sigma, &ev) {
            hits.push(sigma_hit(r, &ev, format!("{} {} on {}", rec.channel, rec.event_id, rec.computer), Some(rec.time.to_rfc3339())));
        }
    }
    // Content rules over file copies kept in the case.
    let files_dir = case.dir.join("evidence").join("files");
    if files_dir.is_dir() {
        let (yrules, yerrs) = crate::files::yara::load(o.yara.as_deref());
        gaps.extend(yerrs.into_iter().map(|e| format!("YARA rule skipped: {e}")));
        let mut n = 0;
        for e in std::fs::read_dir(&files_dir).into_iter().flatten().flatten() {
            n += 1;
            match crate::files::yara::scan_file(&yrules, &e.path()) {
                Ok((ms, truncated)) => {
                    if truncated {
                        gaps.push(format!("{}: only the first {} scanned", e.path().display(), crate::process::human_bytes(crate::files::yara::MAX_SCAN)));
                    }
                    for m in ms {
                        hits.push(Hit {
                            engine: "yara",
                            rule: format!("YARA:{}", m.rule),
                            name: if m.description.is_empty() { m.rule.clone() } else { m.description.clone() },
                            severity: m.severity,
                            confidence: m.confidence,
                            technique: String::new(),
                            subject: format!("evidence/files/{}", e.file_name().to_string_lossy()),
                            evidence: m.strings.iter().map(|(id, off, _)| format!("{id}@{off:#x}")).collect::<Vec<_>>().join(" "),
                            time: None,
                        });
                    }
                }
                Err(err) => gaps.push(format!("{}: {err}", e.path().display())),
            }
        }
        inputs.push(format!("evidence/files ({n} copied files, YARA)"));
    }
    hits.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.confidence.cmp(&a.confidence)).then(a.rule.cmp(&b.rule)));

    // IOC sweep.
    let mut ioc_hits = Vec::new();
    if let Some(f) = &o.iocs {
        let text = std::fs::read_to_string(f).map_err(|e| anyhow::anyhow!("{}: {e}", f.display()))?;
        let (iocs, errs) = crate::detection::ioc::parse(&text);
        inputs.push(format!("{} ({} indicators)", f.display(), iocs.len()));
        gaps.extend(errs.into_iter().map(|e| format!("{}: {e}", f.display())));
        let mut obs = Vec::new();
        for p in procs.values() {
            let exe = p.exe_path.as_deref().and_then(|e| exes.get(e));
            obs.push(crate::detection::ioc::Obs {
                source: "process",
                pid: Some(p.pid),
                name: p.name.clone(),
                sha256: exe.and_then(|e| e.sha256.clone()),
                md5: exe.and_then(|e| e.md5.clone()),
                sha1: exe.and_then(|e| e.sha1.clone()),
                path: p.exe_path.clone(),
                text: p.cmd.join(" "),
                ..Default::default()
            });
            for c in conns.get(&p.pid).into_iter().flatten() {
                obs.push(crate::detection::ioc::Obs { source: "network", pid: Some(p.pid), name: p.name.clone(), ip: Some(crate::common::filter::split_endpoint(&c.remote).0), ..Default::default() });
            }
        }
        for it in persist_v.as_array().into_iter().flatten() {
            obs.push(crate::detection::ioc::Obs {
                source: "persistence",
                name: s(it, "name"),
                sha256: Some(s(it, "sha256")).filter(|x| !x.is_empty()),
                path: Some(s(it, "target")).filter(|x| !x.is_empty()),
                text: format!("{} {}", s(it, "command"), s(it, "location")),
                ..Default::default()
            });
        }
        for l in logs_v.as_array().into_iter().flatten() {
            obs.push(crate::detection::ioc::Obs { source: "log", name: s(l, "process"), text: s(l, "message"), ..Default::default() });
        }
        for a in &artifacts {
            obs.push(crate::detection::ioc::Obs { source: "artifact", name: a.kind.into(), path: Some(a.subject.clone()), text: format!("{} {}", a.subject, a.detail), ..Default::default() });
        }
        for r in &records {
            obs.push(crate::detection::ioc::Obs { source: "evtx", name: format!("{} {}", r.channel, r.event_id), text: r.data.values().cloned().collect::<Vec<_>>().join(" "), ..Default::default() });
        }
        ioc_hits = crate::detection::ioc::sweep(&iocs, &obs);
    }

    let a = Analysis {
        case: case.id.clone(),
        analysed_at: Local::now().to_rfc3339(),
        inputs,
        gaps,
        processes: procs.len(),
        connections: conns.values().map(Vec::len).sum(),
        event_records: records.len(),
        artifacts: artifacts.len(),
        sigma_rules: sigma.len(),
        sigma_rejected: rejected,
        hits,
        ioc_hits,
    };
    Ok((a, case))
}

fn sigma_hit(r: &crate::detection::sigma::Rule, ev: &crate::detection::sigma::Event, subject: String, time: Option<String>) -> Hit {
    Hit {
        engine: "sigma",
        rule: r.id.clone(),
        name: r.title.clone(),
        severity: r.level,
        confidence: r.confidence,
        technique: r.technique(),
        subject,
        evidence: r.evidence(ev),
        time,
    }
}

/// CLI entry point. Returns the process exit code.
pub fn run(o: Options) -> i32 {
    let (a, case) = match analyse(&o) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("procwatch: offline analysis failed: {e}");
            return 2;
        }
    };
    let json = serde_json::to_string_pretty(&a).unwrap_or_default();
    let name = format!("offline-analysis-{}.json", Local::now().format("%Y%m%d-%H%M%S"));
    let prov = Provenance::derived("procwatch --offline: host rules, Sigma and IOC matching over collected evidence").problems(a.gaps.clone());
    let saved = case.add_text_with(&name, &json, prov).map(|(p, i)| format!("{} ({})", case.rel(&p), i.id));
    if o.json {
        crate::safe_println!("{json}");
    } else {
        print_text(&a);
        match &saved {
            Ok(p) => crate::safe_println!("\nSaved to the case as {p}."),
            Err(e) => crate::safe_println!("\nCouldn't save into the case: {e}"),
        }
    }
    let notable = a.hits.iter().any(|h| h.severity >= Severity::Medium) || !a.ioc_hits.is_empty();
    i32::from(notable)
}

fn print_text(a: &Analysis) {
    crate::safe_println!("Offline analysis of {} ({})", a.case, a.analysed_at);
    println!(
        "  {} processes, {} connections, {} event records, {} artifacts · {} Sigma rules{}",
        a.processes,
        a.connections,
        a.event_records,
        a.artifacts,
        a.sigma_rules,
        if a.sigma_rejected.is_empty() { String::new() } else { format!(" ({} rejected)", a.sigma_rejected.len()) }
    );
    crate::safe_println!("\nInputs:");
    for i in &a.inputs {
        crate::safe_println!("  {i}");
    }
    if !a.gaps.is_empty() {
        crate::safe_println!("\nGaps (data that was missing or partial — absence of a hit is not proof):");
        for g in &a.gaps {
            crate::safe_println!("  ! {g}");
        }
    }
    crate::safe_println!("\nDetections ({}):", a.hits.len());
    for h in a.hits.iter().take(200) {
        println!(
            "  {:<8} {:<6} {:<14} {} — {}{}\n           {}",
            h.severity.label(),
            h.confidence.label(),
            h.rule,
            h.name,
            h.subject,
            h.time.as_deref().map(|t| format!(" @ {t}")).unwrap_or_default(),
            h.evidence
        );
    }
    if !a.ioc_hits.is_empty() {
        crate::safe_println!("\nIndicator matches ({}):", a.ioc_hits.len());
        for h in &a.ioc_hits {
            crate::safe_println!("  {:<7} {:<40} {:<12} {} {}", h.kind.label(), h.ioc, h.source, h.name, h.detail);
        }
    }
}

/// Folder argument helper: accepts a case folder or its case.json.
pub fn case_dir(arg: &str) -> PathBuf {
    let p = Path::new(arg);
    if p.file_name().is_some_and(|n| n == "case.json") {
        p.parent().map(Path::to_path_buf).unwrap_or_default()
    } else {
        p.to_path_buf()
    }
}

