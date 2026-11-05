//! Signs of compromise on the host itself. Everything reads under `root`,
//! so tests can build a fake system; in use it is `/`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::netattack::{parse_tcp, ESTABLISHED};
use super::{Stage, Threat};
use crate::common::model::Severity;

const INTERPRETERS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash", "fish", "busybox", "python", "python3", "perl", "ruby", "php", "lua"];
const TEMP_DIRS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];
/// Most files hashed in one pass, and the largest.
const MAX_FILES: usize = 5000;
const MAX_FILE: u64 = 4 << 20;

struct Watched {
    path: &'static str,
    /// Every file directly inside rather than the path itself.
    folder: bool,
    rule: &'static str,
    what: &'static str,
    severity: Severity,
    stage: Stage,
}

const fn file(path: &'static str, rule: &'static str, what: &'static str, severity: Severity, stage: Stage) -> Watched {
    Watched { path, folder: false, rule, what, severity, stage }
}

const fn dir(path: &'static str, rule: &'static str, what: &'static str, severity: Severity, stage: Stage) -> Watched {
    Watched { path, folder: true, rule, what, severity, stage }
}

const WATCHED: &[Watched] = &[
    file("etc/ld.so.preload", "ld-preload-changed", "Library preload list", Severity::Critical, Stage::Persistence),
    file("etc/passwd", "passwd-changed", "Account list", Severity::Low, Stage::Persistence),
    file("etc/shadow", "shadow-changed", "Password file", Severity::Medium, Stage::Persistence),
    file("etc/sudoers", "sudoers-changed", "sudo rules", Severity::High, Stage::Privilege),
    dir("etc/sudoers.d", "sudoers-changed", "sudo rules", Severity::High, Stage::Privilege),
    file("etc/ssh/sshd_config", "sshd-config-changed", "SSH server settings", Severity::High, Stage::Persistence),
    dir("etc/pam.d", "pam-changed", "Login modules", Severity::High, Stage::Persistence),
    file("etc/crontab", "cron-changed", "Scheduled task", Severity::Medium, Stage::Persistence),
    dir("etc/cron.d", "cron-changed", "Scheduled task", Severity::Medium, Stage::Persistence),
    dir("etc/cron.hourly", "cron-changed", "Scheduled task", Severity::Medium, Stage::Persistence),
    dir("etc/cron.daily", "cron-changed", "Scheduled task", Severity::Medium, Stage::Persistence),
    dir("var/spool/cron", "cron-changed", "Scheduled task", Severity::Medium, Stage::Persistence),
    dir("var/spool/cron/crontabs", "cron-changed", "Scheduled task", Severity::Medium, Stage::Persistence),
    dir("etc/systemd/system", "service-changed", "System service", Severity::Medium, Stage::Persistence),
    file("etc/rc.local", "service-changed", "Startup script", Severity::Medium, Stage::Persistence),
    dir("etc/profile.d", "shell-startup-changed", "Shell startup script", Severity::Medium, Stage::Persistence),
    file("root/.ssh/authorized_keys", "ssh-key-changed", "SSH keys of root", Severity::High, Stage::Persistence),
];

fn sha256(path: &Path) -> Option<String> {
    use std::io::Read;
    let f = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    f.take(MAX_FILE).read_to_end(&mut bytes).ok()?;
    Some(Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect())
}

/// What was true last time. Saved, so changes made while procwatch wasn't
/// running are still found.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Saved {
    pub files: BTreeMap<String, String>,
    pub accounts: Vec<String>,
    pub modules: Vec<String>,
    #[serde(default)]
    pub logins: HashMap<String, HashSet<IpAddr>>,
}

pub struct Host {
    root: PathBuf,
    pub saved: Saved,
    first: bool,
    include_loopback: bool,
}

impl Host {
    pub fn new(root: &Path, saved: Option<Saved>, include_loopback: bool) -> Host {
        Host { root: root.to_path_buf(), first: saved.is_none(), saved: saved.unwrap_or_default(), include_loopback }
    }

    fn read(&self, relative: &str) -> Option<String> {
        std::fs::read_to_string(self.root.join(relative)).ok()
    }

    /// Hash of every watched file, by path, with what its change means.
    fn survey(&self) -> Vec<(String, String, &'static Watched)> {
        let mut out = Vec::new();
        let mut add = |rel: String, w: &'static Watched| {
            if out.len() < MAX_FILES {
                if let Some(h) = sha256(&self.root.join(&rel)) {
                    out.push((rel, h, w));
                }
            }
        };
        for w in WATCHED {
            if w.folder {
                for e in std::fs::read_dir(self.root.join(w.path)).into_iter().flatten().flatten() {
                    if e.file_type().is_ok_and(|t| t.is_file()) {
                        add(format!("{}/{}", w.path, e.file_name().to_string_lossy()), w);
                    }
                }
            } else {
                add(w.path.to_string(), w);
            }
        }
        const USER_KEYS: Watched = file("", "ssh-key-changed", "SSH keys of a user", Severity::High, Stage::Persistence);
        static USER: Watched = USER_KEYS;
        for e in std::fs::read_dir(self.root.join("home")).into_iter().flatten().flatten() {
            add(format!("home/{}/.ssh/authorized_keys", e.file_name().to_string_lossy()), &USER);
        }
        out
    }

    fn files(&mut self, now: DateTime<Local>, out: &mut Vec<Threat>) {
        let found = self.survey();
        let current: BTreeMap<String, String> = found.iter().map(|(p, h, _)| (p.clone(), h.clone())).collect();
        for (path, hash, w) in &found {
            let change = match self.saved.files.get(path) {
                None => "appeared",
                Some(old) if old != hash => "changed",
                _ => continue,
            };
            if !self.first {
                out.push(Threat::new(now, w.rule, w.severity, w.stage, format!("{} {change}: /{path}", w.what)).with_evidence(format!("sha256 {hash}")));
            }
        }
        for path in self.saved.files.keys().filter(|p| !current.contains_key(*p)) {
            out.push(Threat::new(now, "watched-file-removed", Severity::Medium, Stage::Persistence, format!("Removed: /{path}")));
        }
        self.saved.files = current;
        // A preload list is rare enough to matter even on the first look.
        if self.read("etc/ld.so.preload").is_some_and(|t| t.lines().any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))) {
            out.push(Threat::new(now, "ld-preload-active", Severity::Critical, Stage::Persistence, "/etc/ld.so.preload loads a library into every program".into()));
        }
    }

    fn accounts(&mut self, now: DateTime<Local>, out: &mut Vec<Threat>) {
        let Some(text) = self.read("etc/passwd") else { return };
        let mut names = Vec::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split(':').collect();
            let (Some(name), Some(uid), Some(shell)) = (f.first(), f.get(2), f.get(6)) else { continue };
            names.push(name.to_string());
            if *uid == "0" && *name != "root" {
                out.push(Threat::new(now, "uid0-account", Severity::Critical, Stage::Privilege, format!("{name} has the same rights as root")).of_user(name));
            }
            let can_log_in = !shell.ends_with("nologin") && !shell.ends_with("false");
            if can_log_in && !self.first && !self.saved.accounts.iter().any(|a| a == name) {
                out.push(Threat::new(now, "account-appeared", Severity::High, Stage::Persistence, format!("New login account: {name}")).of_user(name));
            }
        }
        self.saved.accounts = names;
    }

    fn modules(&mut self, now: DateTime<Local>, out: &mut Vec<Threat>) {
        let Some(text) = self.read("proc/modules") else { return };
        let listed: Vec<String> = text.lines().filter_map(|l| l.split_whitespace().next()).map(str::to_string).collect();
        for name in listed.iter().filter(|m| !self.first && !self.saved.modules.contains(m)) {
            out.push(Threat::new(now, "kernel-module-loaded", Severity::Medium, Stage::Persistence, format!("Kernel module loaded: {name}")));
        }
        // Loadable modules have `initstate`; built-in ones don't.
        for e in std::fs::read_dir(self.root.join("sys/module")).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if e.path().join("initstate").exists() && !listed.contains(&name) {
                out.push(Threat::new(now, "hidden-module", Severity::Critical, Stage::Persistence, format!("Kernel module {name} is hidden from the module list")).with_evidence("present in /sys/module, missing from /proc/modules; a known rootkit technique"));
            }
        }
        self.saved.modules = listed;
    }

    fn sockets(&self) -> HashMap<u64, IpAddr> {
        ["proc/net/tcp", "proc/net/tcp6"]
            .iter()
            .filter_map(|p| self.read(p))
            .flat_map(|t| parse_tcp(&t))
            .filter(|s| s.state == ESTABLISHED && (self.include_loopback || !s.remote.is_loopback()))
            .map(|s| (s.inode, s.remote))
            .collect()
    }

    fn processes(&self, now: DateTime<Local>, out: &mut Vec<Threat>) {
        let sockets = self.sockets();
        for e in std::fs::read_dir(self.root.join("proc")).into_iter().flatten().flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
            let Ok(exe) = std::fs::read_link(e.path().join("exe")) else { continue };
            let exe = exe.to_string_lossy().into_owned();
            let path = exe.strip_suffix(" (deleted)").unwrap_or(&exe);
            let name = path.rsplit('/').next().unwrap_or("");
            let base = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
            if exe.starts_with("/memfd:") {
                out.push(Threat::new(now, "fileless-execution", Severity::Critical, Stage::Execution, format!("Process {pid} runs from memory, with no file on disk")).of_pid(pid).with_evidence(&exe));
            } else if exe.ends_with(" (deleted)") && TEMP_DIRS.iter().any(|d| path.starts_with(d)) {
                out.push(Threat::new(now, "deleted-binary-running", Severity::High, Stage::Execution, format!("Process {pid} runs a deleted program from a temporary folder")).of_pid(pid).with_evidence(&exe));
            }
            if !INTERPRETERS.contains(&name) && !INTERPRETERS.contains(&base) {
                continue;
            }
            // A shell's input is a terminal or pipe; a network socket means
            // whoever is at the other end is typing into it.
            let stream = |fd: u32| -> Option<IpAddr> {
                let link = std::fs::read_link(e.path().join("fd").join(fd.to_string())).ok()?;
                let text = link.to_string_lossy().into_owned();
                let inode = text.strip_prefix("socket:[")?.strip_suffix(']')?.parse::<u64>().ok()?;
                sockets.get(&inode).copied()
            };
            if let Some(ip) = stream(0).or_else(|| stream(1)) {
                out.push(Threat::new(now, "reverse-shell", Severity::Critical, Stage::Execution, format!("{name} ({pid}) is driven over the network by {ip}")).of_pid(pid).source_ip(ip).with_evidence(&exe));
            }
        }
    }

    /// Everything but the hidden-process search, which is slower.
    pub fn check(&mut self, now: DateTime<Local>) -> Vec<Threat> {
        let mut out = Vec::new();
        self.files(now, &mut out);
        self.accounts(now, &mut out);
        self.modules(now, &mut out);
        self.processes(now, &mut out);
        self.first = false;
        out
    }

    /// Processes that exist but that listing `/proc` doesn't show, which is
    /// how a rootkit hides them. Threads answer too, so each candidate's
    /// `Tgid` must be itself, and it's checked twice to skip ones that exit.
    pub fn hidden_processes(&self, now: DateTime<Local>, upto: u32) -> Vec<Threat> {
        let proc = self.root.join("proc");
        let listed: HashSet<u32> = std::fs::read_dir(&proc).into_iter().flatten().flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect();
        let leader = |pid: u32| -> Option<()> {
            let status = std::fs::read_to_string(proc.join(pid.to_string()).join("status")).ok()?;
            let tgid: u32 = status.lines().find_map(|l| l.strip_prefix("Tgid:"))?.trim().parse().ok()?;
            (tgid == pid).then_some(())
        };
        let mut out = Vec::new();
        for pid in 1..upto {
            if listed.contains(&pid) || leader(pid).is_none() {
                continue;
            }
            let shown: HashSet<u32> = std::fs::read_dir(&proc).into_iter().flatten().flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect();
            if !shown.contains(&pid) && leader(pid).is_some() {
                out.push(Threat::new(now, "hidden-process", Severity::Critical, Stage::Persistence, format!("Process {pid} exists but is hidden from the process list")).of_pid(pid).with_evidence("reachable by number, missing from the /proc listing; a known rootkit technique"));
            }
        }
        out
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn write(root: &Path, rel: &str, text: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    fn rules(t: &[Threat]) -> Vec<&'static str> {
        t.iter().map(|x| x.rule).collect()
    }

    fn system() -> PathBuf {
        let r = crate::common::paths::private_temp_dir("hostcheck").unwrap();
        write(&r, "etc/passwd", "root:x:0:0::/root:/bin/bash\nbin:x:2:2::/:/usr/sbin/nologin\n");
        write(&r, "proc/modules", "ext4 1 0 - Live 0x0\n");
        write(&r, "root/.ssh/authorized_keys", "ssh-ed25519 AAA me\n");
        std::fs::create_dir_all(r.join("home/alice/.ssh")).unwrap();
        r
    }

    #[test]
    fn the_first_look_only_records() {
        let r = system();
        let mut h = Host::new(&r, None, false);
        assert_eq!(h.check(Local::now()).len(), 0);
        assert_eq!(h.check(Local::now()).len(), 0);
        std::fs::remove_dir_all(r).unwrap();
    }

    #[test]
    fn persistence_changes_are_found() {
        let r = system();
        let mut h = Host::new(&r, None, false);
        h.check(Local::now());
        write(&r, "root/.ssh/authorized_keys", "ssh-ed25519 AAA me\nssh-rsa BBB attacker\n");
        write(&r, "home/alice/.ssh/authorized_keys", "ssh-rsa CCC\n");
        write(&r, "etc/cron.d/backup", "* * * * * root /tmp/x\n");
        write(&r, "etc/passwd", "root:x:0:0::/root:/bin/bash\nbin:x:2:2::/:/usr/sbin/nologin\ntoor:x:0:0::/root:/bin/bash\nd:x:3:3::/:/usr/sbin/nologin\n");
        write(&r, "etc/ld.so.preload", "/lib/evil.so\n");
        let t = h.check(Local::now());
        let got = rules(&t);
        for want in ["ssh-key-changed", "cron-changed", "uid0-account", "account-appeared", "ld-preload-changed", "ld-preload-active", "passwd-changed"] {
            assert!(got.contains(&want), "{want} missing from {got:?}");
        }
        assert_eq!(t.iter().filter(|x| x.rule == "ssh-key-changed").count(), 2);
        assert_eq!(t.iter().filter(|x| x.rule == "account-appeared").count(), 1, "nologin accounts are package noise");
        std::fs::remove_dir_all(r).unwrap();
    }

    /// The state outlives the program: a change made while it was off counts.
    #[test]
    fn changes_while_stopped_are_found() {
        let r = system();
        let mut h = Host::new(&r, None, false);
        h.check(Local::now());
        let saved = serde_json::to_string(&h.saved).unwrap();
        write(&r, "root/.ssh/authorized_keys", "attacker\n");
        std::fs::remove_file(r.join("etc/passwd")).unwrap();
        let mut again = Host::new(&r, Some(serde_json::from_str(&saved).unwrap()), false);
        let got = rules(&again.check(Local::now()).clone());
        assert!(got.contains(&"ssh-key-changed") && got.contains(&"watched-file-removed"), "{got:?}");
        std::fs::remove_dir_all(r).unwrap();
    }

    #[test]
    fn hidden_and_new_kernel_modules() {
        let r = system();
        let mut h = Host::new(&r, None, false);
        h.check(Local::now());
        write(&r, "proc/modules", "ext4 1 0 - Live 0x0\nnewmod 1 0 - Live 0x0\n");
        write(&r, "sys/module/ext4/initstate", "live\n");
        write(&r, "sys/module/diamorphine/initstate", "live\n");
        write(&r, "sys/module/builtin/parameters/x", "1\n");
        let got = rules(&h.check(Local::now()).clone());
        assert_eq!(got, ["kernel-module-loaded", "hidden-module"]);
        std::fs::remove_dir_all(r).unwrap();
    }

    fn process(root: &Path, pid: u32, exe: &str, stdin: Option<&str>) {
        let dir = root.join("proc").join(pid.to_string());
        std::fs::create_dir_all(dir.join("fd")).unwrap();
        symlink(exe, dir.join("exe")).unwrap();
        if let Some(s) = stdin {
            symlink(s, dir.join("fd/0")).unwrap();
        }
    }

    #[test]
    fn hostile_processes_are_found() {
        let r = system();
        write(&r, "proc/net/tcp", "header\n 0: 0100000A:0016 0571000B:1F90 01 0 0 0 0 0 555\n 1: 0100007F:0016 0100007F:1F90 01 0 0 0 0 0 556\n");
        process(&r, 10, "/usr/bin/bash", Some("socket:[555]"));
        process(&r, 11, "/usr/bin/bash", Some("/dev/pts/1"));
        process(&r, 12, "/usr/bin/bash", Some("socket:[556]"));
        process(&r, 13, "/usr/bin/python3.11", Some("socket:[555]"));
        process(&r, 14, "/usr/sbin/nginx", Some("socket:[555]"));
        process(&r, 20, "/memfd:payload (deleted)", None);
        process(&r, 21, "/tmp/.x/miner (deleted)", None);
        process(&r, 22, "/usr/lib/old (deleted)", None);
        let mut h = Host::new(&r, None, false);
        let t = h.check(Local::now());
        let mut shells: Vec<u32> = t.iter().filter(|x| x.rule == "reverse-shell").filter_map(|x| x.pid).collect();
        shells.sort_unstable();
        assert_eq!(shells, [10, 13], "not a terminal, loopback or a non-shell");
        assert_eq!(t.iter().find(|x| x.pid == Some(10)).unwrap().source.unwrap().to_string(), "11.0.113.5");
        let got = rules(&t);
        assert!(got.contains(&"fileless-execution") && got.contains(&"deleted-binary-running"));
        assert_eq!(t.iter().filter(|x| x.rule == "deleted-binary-running").count(), 1, "upgrades leave deleted programs too");
        std::fs::remove_dir_all(r).unwrap();
    }
}
