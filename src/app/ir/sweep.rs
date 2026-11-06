//! IOC sweeps.

use super::*;

impl App {
    // ── IOC sweep ──────────────────────────────────────────────────────

    pub fn open_sweep_dialog(&mut self) {
        let default = self
            .ir
            .sweep
            .as_ref()
            .map(|s| s.file.clone())
            .or_else(|| crate::detection::ioc::default_path().map(|p| p.display().to_string()))
            .unwrap_or_default();
        self.mode = Mode::Input { purpose: InputPurpose::IocFile, input: default, error: None };
    }

    /// Everything procwatch can currently see, as sweep observations.
    pub(crate) fn observations(&mut self) -> Vec<crate::detection::ioc::Obs> {
        use crate::detection::ioc::Obs;
        let mut obs = Vec::new();
        for n in self.tree.nodes.values() {
            if let Some(p) = n.info.exe_path.as_deref() {
                self.ir.intel.request(p, true);
            }
        }
        let intel = self.ir.intel.snapshot();
        for n in self.tree.nodes.values() {
            let i = &n.info;
            let e = i.exe_path.as_deref().and_then(|p| intel.get(p));
            obs.push(Obs {
                source: "process",
                pid: Some(i.pid),
                name: i.name.clone(),
                sha256: e.and_then(|e| e.sha256.clone()),
                md5: e.and_then(|e| e.md5.clone()),
                sha1: e.and_then(|e| e.sha1.clone()),
                path: i.exe_path.clone(),
                text: format!("{} {}", i.name, i.cmd.join(" ")),
                ..Default::default()
            });
        }
        for (pid, cs) in &self.connections {
            let name = self.name_of(*pid);
            for c in cs {
                let ip = split_endpoint(&c.remote).0;
                let host = self.ir.resolver.name(&ip);
                obs.push(Obs { source: "network", pid: Some(*pid), name: name.clone(), ip: Some(ip), host, text: format!("{} {}", c.local, c.remote), ..Default::default() });
            }
        }
        for (ip, host) in self.ir.resolver.known() {
            obs.push(Obs { source: "dns", ip: Some(ip), host: Some(host), ..Default::default() });
        }
        if let Some(Ok(cache)) = &self.ir.dns_cache {
            for (name, data) in cache {
                obs.push(Obs { source: "dns cache", host: Some(name.clone()), ip: Some(data.clone()), ..Default::default() });
            }
        }
        for it in self.persist_items() {
            obs.push(Obs {
                source: "persistence",
                name: format!("{}: {}", it.category, it.name),
                sha256: it.sha256.clone(),
                path: it.target.clone(),
                text: format!("{} {}", it.command, it.location),
                ..Default::default()
            });
        }
        if let Some(Ok(files)) = self.files.as_ref().map(|f| &f.result) {
            for h in files {
                obs.push(Obs { source: "open file", pid: Some(h.pid), name: h.command.clone(), path: Some(h.path.clone()), ..Default::default() });
            }
        }
        for e in &self.ir.fs_events {
            obs.push(Obs { source: "file change", path: Some(e.path.clone()), ..Default::default() });
        }
        for e in self.log_entries() {
            obs.push(Obs { source: "event log", pid: e.pid, name: e.process.clone(), text: e.message.clone(), ..Default::default() });
        }
        if let Some(t) = &self.trace {
            for e in &t.events {
                obs.push(Obs { source: "trace", pid: Some(e.pid), name: e.process.clone(), text: e.detail.clone(), ..Default::default() });
            }
        }
        if let Some(Ok(r)) = self.ir.file_report.as_ref().map(|f| &f.result) {
            if let Some(h) = &r.hashes {
                obs.push(Obs {
                    source: "analyzed file",
                    sha256: Some(h.sha256.clone()),
                    md5: Some(h.md5.clone()),
                    sha1: Some(h.sha1.clone()),
                    path: Some(r.path.clone()),
                    text: r.deep.indicators.iter().map(|(_, v)| v.as_str()).collect::<Vec<_>>().join(" "),
                    ..Default::default()
                });
            }
        }
        obs
    }

    pub fn run_sweep(&mut self, file: &str) {
        let file = file.trim().to_string();
        let text = match std::fs::read_to_string(&file) {
            Ok(t) => t,
            Err(e) => {
                self.mode = Mode::Input { purpose: InputPurpose::IocFile, input: file, error: Some(format!("can't read: {e}")) };
                return;
            }
        };
        let (iocs, errors) = crate::detection::ioc::parse(&text);
        if iocs.is_empty() {
            self.mode = Mode::Input { purpose: InputPurpose::IocFile, input: file, error: Some("no usable indicators in that file".into()) };
            return;
        }
        let obs = self.observations();
        let hits = crate::detection::ioc::sweep(&iocs, &obs);
        let hashing = self.ir.intel.pending();
        self.set_status(
            if hits.is_empty() { StatusLevel::Success } else { StatusLevel::Error },
            format!("IOC sweep: {} indicators, {} hits across {} observations", iocs.len(), hits.len(), obs.len()),
        );
        if let Some(c) = &self.ir.case {
            let _ = c.log("ioc sweep", &format!("{file}: {} indicators, {} hits", iocs.len(), hits.len()));
        }
        self.ir.sweep = Some(SweepState { file, indicators: iocs.len(), errors, hits, hashing, at: Local::now() });
        self.record_ioc_hits();
        self.ir.sweep_selected = 0;
        self.mode = Mode::Sweep;
    }

    pub fn rerun_sweep(&mut self) {
        if let Some(f) = self.ir.sweep.as_ref().map(|s| s.file.clone()) {
            self.run_sweep(&f);
        }
    }

    /// Record every sweep hit as a high-severity finding.
    pub fn sweep_to_findings(&mut self) {
        if !self.require("case") {
            return;
        }
        let Some(hits) = self.ir.sweep.as_ref().map(|s| s.hits.clone()) else { return };
        if hits.is_empty() {
            return;
        }
        let Some(case) = self.ensure_case() else { return };
        let mut n = 0;
        for h in &hits {
            let who = match h.pid {
                Some(p) => format!(" in {} ({p})", h.name),
                None if !h.name.is_empty() => format!(" in {}", h.name),
                None => String::new(),
            };
            let title = format!("IOC match: {} {}{who}", h.kind.label(), h.ioc);
            let detail = format!("{} · {}{}", h.source, h.detail, if h.note.is_empty() { String::new() } else { format!(" · {}", h.note) });
            if case.add_finding("high", &title, "ioc sweep", &detail).is_ok() {
                n += 1;
            }
        }
        self.set_status(StatusLevel::Success, format!("Recorded {n} findings from the sweep"));
    }
}
