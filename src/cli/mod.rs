//! Command-line entry points. Each mode is a thin caller of the modules
//! below; the interactive one lives in `ui::terminal`.

pub mod agent;
pub mod coverage;
pub mod metrics;
pub mod modules;
pub mod monitor;
pub mod selftest;
pub mod soak;

use crate::common;
use crate::detection::{ioc, sigma};
use crate::files::yara;
use crate::forensics::{baseline, offline};
use crate::response::enforce;
use crate::{network, process};

const USAGE: &str = "procwatch — terminal process analyzer

Usage:
  procwatch                         interactive monitor (press ? for help)
  procwatch --snapshot FILE         save programs + listening ports as a baseline (FILE or - for stdout)
  procwatch --diff FILE [--json]    compare now with a baseline; exit status 1 if anything changed
  procwatch --case DIR              resume an existing investigation case
  procwatch --sigma DIR             use Sigma rules from DIR (default: sigma/ next to the settings file)
  procwatch --run -- PROGRAM [ARGS…]
                                    ANALYSIS VMs ONLY: start PROGRAM held at its first instruction, attach
                                    deep trace, then run it; output and evidence go to a new case
  procwatch --replay [PATH] [--from WHEN] [--to WHEN]
                                    open a recorded session (event history folder, a case folder or an
                                    events.jsonl file; default: this machine's history) without touching
                                    the live system. WHEN: 2026-11-03T14:00, \"2026-11-03 14:00\" or 14:00
  procwatch --sweep IOCFILE [--json]  sweep processes, connections and autostart entries for indicators;
                                    exit status 1 if anything matched
  procwatch --offline CASE [--iocs FILE] [--sigma DIR] [--yara DIR] [--artifacts DIR]... [--json]
                                    re-analyse a saved case (and copied .evtx/.pf/history files) without
                                    the original machine; results are added to the case as derived evidence;
                                    exit status 1 if anything of medium severity or an indicator matched
  procwatch --check-rules [DIR]     parse Sigma rules and list the ones that can't be used, and why
  procwatch --soak MINUTES          run the full pipeline headless under a churn workload and report
                                    memory/CPU/buffer sizes; exit status 1 on leaks or worker panics
  procwatch --selftest [--json]     measure process-capture rates, PID-reuse protection, file-event latency
                                    and own overhead on this machine (harmless workloads only)
  procwatch --scan PATH... [--yara DIR] [--json]
                                    match files (folders recursively) against YARA content rules;
                                    exit status 1 if anything matched
  procwatch --monitor [--output FILE] [--minutes N] [--activity]
                                    run without a screen and stream new events as ECS JSON lines;
                                    --activity adds file, registry and network operations
                                    (administrator / root)
  procwatch --enforce-check POLICY  show what a blocking policy would do, and refuse unsafe ones
  procwatch --enforce POLICY [--output FILE] [--minutes N]
                                    apply a policy (audit mode only logs); needs root/administrator.
                                    Everything ends when procwatch exits. See docs/enforcement.md
  procwatch --agent POLICY [--output FILE] [--minutes N]
                                    EDR agent: detections, playbooks, blocking and a tamper-evident
                                    log, restarted if it dies. Audit mode only logs. See docs/edr.md
  procwatch --agent-check POLICY    show what an agent policy would do, and refuse unsafe ones
  procwatch --agent-verify [FILE]   check an agent log's hash chain; exit status 1 if it was changed
  procwatch --capture-check [FILE]  check capture.yml, the filter for activity capture
  procwatch --capture-packets FILE [--seconds N] [--interface IF] [--max-mb N] [--snaplen N]
                                    save packets for Wireshark: pcap on Linux and macOS, pcapng on
                                    Windows; needs root/administrator (default 60 s, 100 MB)
  procwatch --boot-log enable|disable|status|read [FILE] [--json]
                                    Windows: record file, registry and process activity from early
                                    boot, and read it back; needs administrator
  procwatch --defense-check [FILE]  check defense.yml and show what is watched
  procwatch --alarm-test            send a test alarm to every configured destination
  procwatch --unban-all             lift every address the agent banned
  procwatch --history [METRIC] [--hours N] [--json]
                                    metrics kept on disk; no metric lists what is recorded
  procwatch --modules [--json]      list modules and what each supports on this system
  procwatch --module-enable NAME    run a module from the next start
  procwatch --module-disable NAME   leave a module out from the next start
  procwatch --metrics [--json]      one reading of scheduling, memory, disks, network, sensors, services
  procwatch --coverage [--json]     list the MITRE ATT&CK techniques the rules look for
  procwatch --help";

pub fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("-h" | "--help") => {
            crate::safe_println!("{USAGE}");
            if let Some(p) = common::paths::config_path() {
                crate::safe_println!("\nSettings file: {}", p.display());
            }
            return Ok(());
        }
        Some("--snapshot") => {
            let Some(target) = args.get(1) else {
                eprintln!("--snapshot needs a file name (or - for stdout)\n\n{USAGE}");
                std::process::exit(2);
            };
            let base = headless_capture();
            if target == "-" {
                crate::safe_println!("{}", serde_json::to_string_pretty(&base)?);
            } else {
                base.save(std::path::Path::new(target))?;
                eprintln!("Saved {} programs and {} listening ports to {target}", base.programs.len(), base.listeners.len());
            }
            return Ok(());
        }
        Some("--diff") => {
            let Some(file) = args.get(1) else {
                eprintln!("--diff needs a baseline file\n\n{USAGE}");
                std::process::exit(2);
            };
            let base = match baseline::Baseline::load(std::path::Path::new(file)) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Couldn't read baseline {file}: {e}");
                    std::process::exit(2);
                }
            };
            let changes = base.diff(&headless_capture());
            if args.iter().any(|a| a == "--json") {
                crate::safe_println!("{}", serde_json::to_string_pretty(&changes)?);
            } else {
                print!("{}", crate::common::text::printable(&baseline::render_text(&base, &changes)));
            }
            std::process::exit(if changes.is_empty() { 0 } else { 1 });
        }
        Some("--case" | "--sigma") if args.len() >= 2 => {}
        Some("--replay") => {}
        Some("--run") => {
            if args.len() < 2 {
                eprintln!("--run needs a program: procwatch --run -- PROGRAM [ARGS…]\n\n{USAGE}");
                std::process::exit(2);
            }
        }
        Some("--offline") => {
            let Some(dir) = args.get(1) else {
                eprintln!("--offline needs a case folder\n\n{USAGE}");
                std::process::exit(2);
            };
            let value = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).map(std::path::PathBuf::from);
            let artifacts = args.windows(2).filter(|w| w[0] == "--artifacts").map(|w| std::path::PathBuf::from(&w[1])).collect();
            std::process::exit(offline::run(offline::Options {
                case: offline::case_dir(dir),
                iocs: value("--iocs"),
                sigma: value("--sigma"),
                yara: value("--yara"),
                artifacts,
                json: args.iter().any(|a| a == "--json"),
            }));
        }
        Some("--scan") => {
            let value = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
            let yara_dir = value("--yara");
            let paths: Vec<&String> = args[1..].iter().filter(|a| !a.starts_with("--") && Some(*a) != yara_dir.as_ref()).collect();
            if paths.is_empty() {
                eprintln!("--scan needs at least one file or folder\n\n{USAGE}");
                std::process::exit(2);
            }
            std::process::exit(headless_scan(&paths, yara_dir.as_deref(), args.iter().any(|a| a == "--json")));
        }
        Some("--soak") => {
            let minutes = args.get(1).and_then(|m| m.parse().ok()).unwrap_or(10);
            std::process::exit(soak::run(minutes));
        }
        Some("--selftest") => std::process::exit(selftest::run(args.iter().any(|a| a == "--json"))),
        Some("--enforce-check") => {
            let Some(file) = args.get(1) else {
                eprintln!("--enforce-check needs a policy file\n\n{USAGE}");
                std::process::exit(2);
            };
            std::process::exit(enforce::check(std::path::Path::new(file)));
        }
        Some("--enforce") => {
            let Some(file) = args.get(1) else {
                eprintln!("--enforce needs a policy file\n\n{USAGE}");
                std::process::exit(2);
            };
            let value = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1));
            let minutes = value("--minutes").map(|m| m.parse::<u64>());
            if matches!(minutes, Some(Err(_))) {
                eprintln!("--minutes needs a number\n\n{USAGE}");
                std::process::exit(2);
            }
            std::process::exit(enforce::run(std::path::Path::new(file), value("--output").map(std::path::Path::new), minutes.and_then(Result::ok)));
        }
        Some("--agent" | "--agent-worker" | "--agent-check") => {
            let Some(file) = args.get(1) else {
                eprintln!("{} needs a policy file\n\n{USAGE}", args[0]);
                std::process::exit(2);
            };
            let value = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
            let path = std::path::Path::new(file);
            let minutes = match value("--minutes").map(|m| m.parse::<u64>()) {
                None => None,
                Some(Ok(m)) => Some(m),
                Some(Err(_)) => {
                    eprintln!("--minutes needs a number\n\n{USAGE}");
                    std::process::exit(2);
                }
            };
            let output = value("--output").map(std::path::PathBuf::from);
            std::process::exit(match args[0].as_str() {
                "--agent-check" => agent::check(path),
                "--agent" => agent::run(path, output.as_deref(), minutes),
                _ => agent::worker(path, output.as_deref(), minutes),
            });
        }
        Some("--agent-verify") => std::process::exit(agent::verify_log(args.get(1).map(std::path::Path::new))),
        Some("--capture-check") => {
            let path = args.get(1).map(std::path::PathBuf::from).or_else(|| crate::common::paths::config_path().map(|p| p.with_file_name("capture.yml")));
            let parsed = match &path {
                Some(p) if p.exists() => crate::activity::filter::CaptureConfig::load_from(p),
                _ => Err("no capture.yml: everything is kept".to_string()),
            };
            match parsed {
                Ok(c) => {
                    println!("registry reads: {}\ncall stacks: {}\n{} rules", c.registry_reads, c.stacks, c.rules.len());
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }
        Some("--capture-packets") => {
            let Some(file) = args.get(1).filter(|a| !a.starts_with("--")) else {
                eprintln!("--capture-packets needs a file name\n\n{USAGE}");
                std::process::exit(2);
            };
            let value = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
            let mut o = network::pcap::Options { interface: value("--interface"), ..Default::default() };
            for (flag, slot, scale) in [("--seconds", &mut o.seconds, 1u64), ("--max-mb", &mut o.max_bytes, 1 << 20)] {
                if let Some(v) = value(flag) {
                    let Ok(n) = v.parse::<u64>() else {
                        eprintln!("{flag} needs a number\n\n{USAGE}");
                        std::process::exit(2);
                    };
                    *slot = n.saturating_mul(scale);
                }
            }
            if let Some(v) = value("--snaplen") {
                let Ok(n) = v.parse::<u32>() else {
                    eprintln!("--snaplen needs a number\n\n{USAGE}");
                    std::process::exit(2);
                };
                o.snaplen = n.clamp(64, 262_144);
            }
            std::process::exit(network::pcap::run(std::path::Path::new(file), &o));
        }
        Some("--boot-log") => {
            let Some(action) = args.get(1) else {
                eprintln!("--boot-log needs enable, disable, status or read\n\n{USAGE}");
                std::process::exit(2);
            };
            let file = args.get(2).filter(|a| !a.starts_with("--")).map(std::path::Path::new);
            std::process::exit(crate::activity::boot::run(action, file, args.iter().any(|a| a == "--json")));
        }
        Some("--defense-check") => std::process::exit(defense_check(args.get(1).map(std::path::Path::new))),
        Some("--alarm-test") => std::process::exit(alarm_test()),
        Some("--unban-all") => match crate::defense::ban::clear() {
            Ok(()) => {
                println!("No addresses are banned.");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("procwatch: {e}");
                std::process::exit(2);
            }
        },
        Some("--history") => {
            let metric = args.get(1).filter(|a| !a.starts_with("--")).map(String::as_str);
            let hours = args.iter().position(|a| a == "--hours").and_then(|i| args.get(i + 1)).map_or(Ok(24), |h| h.parse::<u64>());
            let Ok(hours) = hours else {
                eprintln!("--hours needs a number\n\n{USAGE}");
                std::process::exit(2);
            };
            std::process::exit(crate::performance::history::run(metric, hours, args.iter().any(|a| a == "--json")));
        }
        Some("--modules") => std::process::exit(modules::list(args.iter().any(|a| a == "--json"))),
        Some(flag @ ("--module-enable" | "--module-disable")) => {
            let Some(name) = args.get(1) else {
                eprintln!("{flag} needs a module name\n\n{USAGE}");
                std::process::exit(2);
            };
            std::process::exit(modules::set(name, flag == "--module-enable"));
        }
        Some("--metrics") => std::process::exit(metrics::run(args.iter().any(|a| a == "--json"))),
        Some("--coverage") => std::process::exit(coverage::run(args.iter().any(|a| a == "--json"))),
        Some("--monitor") => {
            let value = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1));
            let minutes = match value("--minutes").map(|m| m.parse::<u64>()) {
                None => None,
                Some(Ok(m)) => Some(m),
                Some(Err(_)) => {
                    eprintln!("--minutes needs a number\n\n{USAGE}");
                    std::process::exit(2);
                }
            };
            std::process::exit(monitor::run(value("--output").map(std::path::Path::new), minutes, args.iter().any(|a| a == "--activity")));
        }
        Some("--check-rules") => {
            let dir = args.get(1).map(std::path::PathBuf::from).or_else(sigma::default_dir);
            let builtin = sigma::builtin();
            crate::safe_println!("{} built-in rules", builtin.len());
            match dir.filter(|d| d.exists()) {
                Some(d) => {
                    let (rules, errors) = sigma::load_dir(&d);
                    crate::safe_println!("{}: {} usable rules, {} rejected", d.display(), rules.len(), errors.len());
                    for e in &errors {
                        crate::safe_println!("  ✗ {e}");
                    }
                    std::process::exit(i32::from(!errors.is_empty()));
                }
                None => crate::safe_println!("no rule folder (create {} or pass one)", sigma::default_dir().map(|d| d.display().to_string()).unwrap_or_default()),
            }
            return Ok(());
        }
        Some("--sweep") => {
            let Some(file) = args.get(1) else {
                eprintln!("--sweep needs an indicator file\n\n{USAGE}");
                std::process::exit(2);
            };
            std::process::exit(headless_sweep(file, args.iter().any(|a| a == "--json")));
        }
        Some(other) => {
            eprintln!("Unknown option {other}\n\n{USAGE}");
            std::process::exit(2);
        }
        None => {}
    }

    crate::ui::terminal::run_interactive()
}

/// `--sweep`: match indicators against processes (with executable
/// hashes), connections and persistence entries without the UI.
fn defense_config(file: Option<&std::path::Path>) -> Result<crate::defense::config::DefenseConfig, String> {
    use crate::defense::config::DefenseConfig;
    match file {
        Some(p) => DefenseConfig::load_from(p),
        None => DefenseConfig::load(),
    }
}

fn defense_check(file: Option<&std::path::Path>) -> i32 {
    match defense_config(file) {
        Err(e) => {
            eprintln!("{e}");
            1
        }
        Ok(c) => {
            println!("authentication logs: {}", if c.auth_logs.is_empty() { "usual places, or the journal".to_string() } else { format!("{:?}", c.auth_logs) });
            println!("web logs: {}", if c.web_logs.is_empty() { "usual nginx and Apache places".to_string() } else { format!("{:?}", c.web_logs) });
            println!("never reported: {:?}", c.allow);
            println!("repeats quiet for {} s", c.quiet_seconds);
            println!("metrics endpoint: {}", if c.exporter.listen.is_empty() { "off" } else { &c.exporter.listen });
            if c.alarms.is_empty() {
                println!("alarms: none, findings stay on this machine");
            }
            for a in &c.alarms {
                println!("alarm: {}", a.describe());
            }
            0
        }
    }
}

fn alarm_test() -> i32 {
    use crate::common::model::Severity;
    use crate::defense::alarm::{send, Notice};
    let config = match defense_config(None) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    if config.alarms.is_empty() {
        eprintln!("no alarm destinations in defense.yml");
        return 1;
    }
    let host = sysinfo::System::host_name().unwrap_or_default();
    let notice = Notice { severity: Severity::Critical, rule: "alarm-test".into(), title: "Test alarm from procwatch: nothing is wrong".into(), source: None, detail: String::new(), host };
    let mut failed = 0;
    for d in &config.alarms {
        match send(d, &notice) {
            Ok(()) => println!("{}: sent", d.describe()),
            Err(e) => {
                failed += 1;
                println!("{}: FAILED: {e}", d.describe());
            }
        }
    }
    i32::from(failed > 0)
}

fn headless_sweep(file: &str, json: bool) -> i32 {
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Couldn't read {file}: {e}");
            return 2;
        }
    };
    let (iocs, errors) = ioc::parse(&text);
    for e in &errors {
        eprintln!("skipped {e}");
    }
    if iocs.is_empty() {
        eprintln!("No usable indicators in {file}");
        return 2;
    }
    eprintln!("Collecting processes, connections and autostart entries…");
    let mut monitor = process::ProcessMonitor::new();
    let (tree, _) = monitor.snapshot();
    let conns = network::connections_by_pid();
    let persistence = crate::host::persistence::scan();
    let mut hashes: std::collections::HashMap<String, Option<crate::files::info::Hashes>> = std::collections::HashMap::new();
    let mut obs = Vec::new();
    let total = tree.nodes.len();
    for (i, n) in tree.nodes.values().enumerate() {
        let info = &n.info;
        let h = info.exe_path.as_ref().and_then(|p| {
            hashes
                .entry(p.clone())
                .or_insert_with(|| {
                    let meta = std::fs::metadata(p).ok()?;
                    (meta.len() <= 512 << 20).then(|| crate::files::info::hash_file(std::path::Path::new(p)).ok()).flatten()
                })
                .clone()
        });
        if i % 100 == 0 {
            eprint!("\rhashing executables {i}/{total}");
        }
        obs.push(ioc::Obs {
            source: "process",
            pid: Some(info.pid),
            name: info.name.clone(),
            sha256: h.as_ref().map(|h| h.sha256.clone()),
            md5: h.as_ref().map(|h| h.md5.clone()),
            sha1: h.as_ref().map(|h| h.sha1.clone()),
            path: info.exe_path.clone(),
            text: format!("{} {}", info.name, info.cmd.join(" ")),
            ..Default::default()
        });
    }
    eprintln!("\rhashed {} executables          ", hashes.len());
    for (pid, cs) in &conns {
        let name = tree.get(*pid).map(|n| n.info.name.clone()).unwrap_or_default();
        for c in cs {
            let ip = crate::common::filter::split_endpoint(&c.remote).0;
            obs.push(ioc::Obs { source: "network", pid: Some(*pid), name: name.clone(), ip: Some(ip), text: format!("{} {}", c.local, c.remote), ..Default::default() });
        }
    }
    for it in &persistence.items {
        obs.push(ioc::Obs {
            source: "persistence",
            name: format!("{}: {}", it.category, it.name),
            sha256: it.sha256.clone(),
            path: it.target.clone(),
            text: format!("{} {}", it.command, it.location),
            ..Default::default()
        });
    }
    let hits = ioc::sweep(&iocs, &obs);
    if json {
        crate::safe_println!("{}", serde_json::to_string_pretty(&hits).unwrap_or_default());
    } else if hits.is_empty() {
        crate::safe_println!("No matches for {} indicators across {} observations.", iocs.len(), obs.len());
    } else {
        for h in &hits {
            let pid = h.pid.map(|p| format!(" pid {p}")).unwrap_or_default();
            crate::safe_println!("MATCH {:<7} {:<40} {:<12} {}{pid}  {}", h.kind.label(), h.ioc, h.source, h.name, h.detail);
        }
    }
    if hits.is_empty() { 0 } else { 1 }
}

/// One-shot capture for the command-line modes (no terminal UI).
fn headless_capture() -> baseline::Baseline {
    let mut monitor = process::ProcessMonitor::new();
    let (tree, _) = monitor.snapshot();
    let conns = network::connections_by_pid();
    baseline::Baseline::capture(&tree, &conns)
}

/// `--scan`: YARA rules over files and folders.
fn headless_scan(paths: &[&String], yara_dir: Option<&str>, json: bool) -> i32 {
    let (rules, errors) = yara::load(yara_dir.map(std::path::Path::new));
    for e in &errors {
        eprintln!("skipped rule: {e}");
    }
    let mut files: Vec<String> = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = paths.iter().map(std::path::PathBuf::from).collect();
    let given = stack.len();
    let mut seen = 0;
    while let Some(p) = stack.pop() {
        seen += 1;
        // Links below the given paths aren't followed: they can loop.
        let Ok(meta) = (if seen <= given { std::fs::metadata(&p) } else { std::fs::symlink_metadata(&p) }) else { continue };
        if meta.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                stack.extend(rd.flatten().map(|e| e.path()));
            }
        } else if meta.is_file() {
            files.push(p.display().to_string());
        }
    }
    // procwatch's own binary contains the built-in rules as text.
    if let Some(me) = std::env::current_exe().ok().and_then(|p| std::fs::canonicalize(p).ok()) {
        files.retain(|f| std::fs::canonicalize(f).ok().as_ref() != Some(&me));
    }
    let scanned = files.len();
    let (hits, failed) = yara::scan_files(&rules, &files);
    for f in &failed {
        eprintln!("{f}");
    }
    let mut results: Vec<serde_json::Value> = hits.into_iter().map(|(p, m)| serde_json::json!({"path": p, "matches": m})).collect();
    results.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    if json {
        crate::safe_println!("{}", serde_json::to_string_pretty(&results).unwrap_or_default());
    } else {
        crate::safe_println!("{} files scanned with {} rules, {} matched", scanned, rules.len(), results.len());
        for r in &results {
            crate::safe_println!("{}", r["path"].as_str().unwrap_or(""));
            for m in r["matches"].as_array().into_iter().flatten() {
                crate::safe_println!("  {}  {}", m["rule"].as_str().unwrap_or(""), m["description"].as_str().unwrap_or(""));
            }
        }
    }
    i32::from(!results.is_empty())
}

