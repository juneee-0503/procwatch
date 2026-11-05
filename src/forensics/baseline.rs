//! Baseline snapshots: record which programs run and which ports are
//! listening, then report what is new or gone compared to now. Saved as
//! JSON so it can be diffed from scripts (`procwatch --diff FILE`).

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::network::{ConnState, Connection};
use crate::process::ProcessTree;

const VERSION: u32 = 1;

/// A program, identified by executable path (or name when the path isn't
/// readable) and the account it runs as.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Program {
    pub name: String,
    pub exe: Option<String>,
    pub user: Option<String>,
    /// Number of instances when the snapshot was taken.
    pub count: usize,
    pub command: String,
}

impl Program {
    fn key(&self) -> (String, Option<String>) {
        (self.exe.clone().unwrap_or_else(|| self.name.clone()), self.user.clone())
    }
}

/// A listening socket and the program that owns it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Listener {
    pub protocol: String,
    pub address: String,
    pub process: String,
    pub exe: Option<String>,
}

impl Listener {
    fn key(&self) -> (String, String, String) {
        (self.protocol.clone(), self.address.clone(), self.exe.clone().unwrap_or_else(|| self.process.clone()))
    }

    /// Whether the socket accepts connections from other machines.
    pub fn exposed(&self) -> bool {
        let host = self.address.rsplit_once(':').map(|(h, _)| h).unwrap_or("");
        !(host.starts_with("127.") || host == "[::1]" || host == "localhost")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub taken: String,
    pub host: String,
    pub programs: Vec<Program>,
    pub listeners: Vec<Listener>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ChangeKind {
    NewProgram,
    GoneProgram,
    NewListener,
    GoneListener,
}

impl ChangeKind {
    pub fn label(self) -> &'static str {
        match self {
            ChangeKind::NewProgram => "new program",
            ChangeKind::GoneProgram => "not running",
            ChangeKind::NewListener => "new port",
            ChangeKind::GoneListener => "port closed",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub kind: ChangeKind,
    pub name: String,
    pub user: Option<String>,
    /// Executable path, or the listening address for port changes.
    pub detail: String,
    /// Listening on a non-loopback address.
    pub exposed: bool,
}

fn host_name() -> String {
    sysinfo::System::host_name().unwrap_or_else(|| "unknown".into())
}

impl Baseline {
    pub fn capture(tree: &ProcessTree, conns: &HashMap<u32, Vec<Connection>>) -> Self {
        let mut programs: BTreeMap<(String, Option<String>), Program> = BTreeMap::new();
        for node in tree.nodes.values() {
            let i = &node.info;
            let p = Program { name: i.name.clone(), exe: i.exe_path.clone(), user: i.user.clone(), count: 1, command: i.cmd.join(" ") };
            programs.entry(p.key()).and_modify(|e| e.count += 1).or_insert(p);
        }
        let mut listeners: Vec<Listener> = conns
            .iter()
            .flat_map(|(pid, cs)| {
                let (name, exe) = tree
                    .get(*pid)
                    .map(|n| (n.info.name.clone(), n.info.exe_path.clone()))
                    .unwrap_or_else(|| (pid.to_string(), None));
                cs.iter()
                    .filter(|c| c.state == ConnState::Listen)
                    .map(move |c| Listener { protocol: c.protocol.into(), address: c.local.clone(), process: name.clone(), exe: exe.clone() })
            })
            .collect();
        listeners.sort();
        listeners.dedup();
        Baseline {
            version: VERSION,
            taken: Local::now().to_rfc3339(),
            host: host_name(),
            programs: programs.into_values().collect(),
            listeners,
        }
    }

    pub fn taken_at(&self) -> Option<DateTime<Local>> {
        DateTime::parse_from_rfc3339(&self.taken).ok().map(|t| t.with_timezone(&Local))
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let b: Baseline = serde_json::from_str(&fs::read_to_string(path)?)?;
        if b.version != VERSION {
            anyhow::bail!("unsupported baseline version {}", b.version);
        }
        Ok(b)
    }

    /// Write atomically; the previous file is kept as `*.prev.json`.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        if path.exists() {
            let _ = fs::copy(path, path.with_extension("prev.json"));
        }
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_string_pretty(self)?)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// What differs in `now` compared to this baseline: exposed ports and
    /// new programs first.
    pub fn diff(&self, now: &Baseline) -> Vec<Change> {
        let old_p: HashMap<_, &Program> = self.programs.iter().map(|p| (p.key(), p)).collect();
        let new_p: HashMap<_, &Program> = now.programs.iter().map(|p| (p.key(), p)).collect();
        let old_l: HashMap<_, &Listener> = self.listeners.iter().map(|l| (l.key(), l)).collect();
        let new_l: HashMap<_, &Listener> = now.listeners.iter().map(|l| (l.key(), l)).collect();

        let prog = |kind, p: &Program| Change {
            kind,
            name: p.name.clone(),
            user: p.user.clone(),
            detail: p.exe.clone().unwrap_or_else(|| p.command.clone()),
            exposed: false,
        };
        let lis = |kind, l: &Listener| Change {
            kind,
            name: l.process.clone(),
            user: None,
            detail: format!("{} {}", l.protocol, l.address),
            exposed: l.exposed(),
        };

        let mut out: Vec<Change> = Vec::new();
        out.extend(new_l.iter().filter(|(k, _)| !old_l.contains_key(*k)).map(|(_, l)| lis(ChangeKind::NewListener, l)));
        out.extend(new_p.iter().filter(|(k, _)| !old_p.contains_key(*k)).map(|(_, p)| prog(ChangeKind::NewProgram, p)));
        out.extend(old_l.iter().filter(|(k, _)| !new_l.contains_key(*k)).map(|(_, l)| lis(ChangeKind::GoneListener, l)));
        out.extend(old_p.iter().filter(|(k, _)| !new_p.contains_key(*k)).map(|(_, p)| prog(ChangeKind::GoneProgram, p)));
        let rank = |c: &Change| match c.kind {
            ChangeKind::NewListener => 0,
            ChangeKind::NewProgram => 1,
            ChangeKind::GoneListener => 2,
            ChangeKind::GoneProgram => 3,
        };
        out.sort_by(|a, b| {
            rank(a)
                .cmp(&rank(b))
                .then(b.exposed.cmp(&a.exposed))
                .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then(a.detail.cmp(&b.detail))
        });
        out
    }
}

/// Default location: next to the settings file.
pub fn default_path() -> Option<PathBuf> {
    crate::common::paths::config_path().map(|p| p.with_file_name("baseline.json"))
}

/// Plain-text rendering for the command line.
pub fn render_text(base: &Baseline, changes: &[Change]) -> String {
    let mut s = format!("Compared with baseline taken {} on {}\n", base.taken, base.host);
    if changes.is_empty() {
        s.push_str("No changes.\n");
        return s;
    }
    for c in changes {
        let sign = match c.kind {
            ChangeKind::NewProgram | ChangeKind::NewListener => '+',
            _ => '-',
        };
        let exposed = if c.exposed { "  [reachable from network]" } else { "" };
        let user = c.user.as_deref().map(|u| format!(" ({u})")).unwrap_or_default();
        s.push_str(&format!("{sign} {:<12} {}{user}  {}{exposed}\n", c.kind.label(), c.name, c.detail));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::tests::sample;

    fn listen(addr: &str) -> Connection {
        Connection { protocol: "TCP", local: addr.into(), remote: "*:*".into(), state: ConnState::Listen }
    }

    #[test]
    fn diff_reports_new_and_gone() {
        let mut tree = sample();
        let mut conns = HashMap::new();
        conns.insert(1, vec![listen("127.0.0.1:8080")]);
        let base = Baseline::capture(&tree, &conns);

        tree.nodes.remove(&3);
        let mut info = crate::process::tests::info(9, Some(1));
        info.name = "newcomer".into();
        tree.nodes.insert(9, crate::process::TreeNode { info, children: vec![] });
        conns.insert(9, vec![listen("*:4444")]);
        conns.insert(1, vec![]);
        let now = Baseline::capture(&tree, &conns);

        let d = base.diff(&now);
        let kinds: Vec<ChangeKind> = d.iter().map(|c| c.kind).collect();
        assert_eq!(kinds, vec![ChangeKind::NewListener, ChangeKind::NewProgram, ChangeKind::GoneListener, ChangeKind::GoneProgram]);
        assert!(d[0].exposed, "*:4444 is reachable from the network");
        assert!(!d[2].exposed, "127.0.0.1 is loopback only");
        assert!(base.diff(&base).is_empty());
    }

    #[test]
    fn saves_and_loads() {
        let dir = std::env::temp_dir().join(format!("procwatch-test-{}", std::process::id()));
        let path = dir.join("baseline.json");
        let b = Baseline::capture(&sample(), &HashMap::new());
        b.save(&path).unwrap();
        b.save(&path).unwrap();
        assert!(path.with_extension("prev.json").exists());
        let loaded = Baseline::load(&path).unwrap();
        assert_eq!(loaded.programs, b.programs);
        let _ = fs::remove_dir_all(dir);
    }
}
