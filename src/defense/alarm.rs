//! Getting alarms to people. Nothing is sent unless `defense.yml` says where.
//! Delivery runs on its own thread: a slow webhook must never delay
//! detection, and a burst must never become a storm of notifications.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::kernel::alarm::{AlarmEvent, Hub, Phase, Priority};
pub use crate::kernel::decide::Notice;
use crate::kernel::decide::Decider;
use crate::kernel::module::Importance;
use crate::kernel::{Capability, Context, Module};

/// Most notifications a destination gets a minute; the rest become a count.
const PER_MINUTE: usize = 12;
const SEND_TIMEOUT: Duration = Duration::from_secs(15);
const RETRIES: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    #[default]
    Json,
    Slack,
    Dingtalk,
    Feishu,
    Wecom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "lowercase")]
pub enum Kind {
    Webhook {
        url: String,
        #[serde(default)]
        format: Format,
    },
    Syslog,
    File {
        path: std::path::PathBuf,
    },
    /// Runs with no shell; the alarm arrives as JSON on standard input.
    Command {
        argv: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Destination {
    #[serde(flatten)]
    pub kind: Kind,
    #[serde(default)]
    pub min_severity: Option<String>,
}

impl Destination {
    pub fn validate(&self) -> Result<(), String> {
        match &self.kind {
            Kind::Webhook { url, .. } if !url.starts_with("https://") && !url.starts_with("http://") => Err("a webhook needs an http or https address".into()),
            Kind::Webhook { url, .. } if url.contains(['\n', '"', '\\']) => Err("a webhook address can't contain quotes or line breaks".into()),
            Kind::Command { argv } if argv.is_empty() => Err("a command alarm needs argv".into()),
            _ => Ok(()),
        }
    }

    fn wants(&self, priority: Priority) -> bool {
        self.min_severity.as_deref().and_then(Priority::parse).map_or(priority >= Priority::High, |m| priority >= m)
    }

    /// Where it goes, without any token in the address.
    pub fn describe(&self) -> String {
        match &self.kind {
            Kind::Webhook { url, .. } => format!("webhook {}", url.split('/').take(3).collect::<Vec<_>>().join("/")),
            Kind::Syslog => "syslog".to_string(),
            Kind::File { path } => format!("file {}", path.display()),
            Kind::Command { argv } => format!("command {}", argv[0]),
        }
    }
}

fn host() -> String {
    crate::kernel::model::identity().host.to_string()
}

fn heading(n: &Notice) -> String {
    format!("[{}] {}: {}", n.priority.label().to_uppercase(), host(), n.title)
}

/// The body for a chat service.
pub fn body(format: Format, n: &Notice) -> String {
    let text = if n.detail.is_empty() { heading(n) } else { format!("{}\n{}", heading(n), n.detail) };
    let v = match format {
        Format::Json => serde_json::json!({ "v": 1, "host": host(), "instance": &*crate::kernel::model::identity().instance, "priority": n.priority, "title": n.title, "detail": n.detail, "rule": n.rule, "source": n.source }),
        Format::Slack => serde_json::json!({ "text": text }),
        Format::Dingtalk | Format::Wecom => serde_json::json!({ "msgtype": "text", "text": { "content": text } }),
        Format::Feishu => serde_json::json!({ "msg_type": "text", "content": { "text": text } }),
    };
    v.to_string()
}

fn curl_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A curl configuration. It goes over standard input rather than the command
/// line, where any local user could read the token in the address.
pub fn curl_config(url: &str, body: &str) -> String {
    format!(
        "url = {}\nrequest = \"POST\"\nheader = \"Content-Type: application/json\"\ndata-binary = {}\nsilent\nshow-error\nfail\nmax-time = 10\nmax-redirs = 0\n",
        curl_quote(url),
        curl_quote(body)
    )
}

fn webhook(url: &str, format: Format, n: &Notice) -> Result<(), String> {
    let mut child = crate::common::command::tool("curl")
        .args(["--config", "-", "--output", "/dev/null"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("curl: {e}"))?;
    let config = curl_config(url, &body(format, n));
    if let Some(mut input) = child.stdin.take() {
        input.write_all(config.as_bytes()).map_err(|e| e.to_string())?;
    }
    let began = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return if status.success() { Ok(()) } else { Err(format!("curl exited with {status}")) };
        }
        if began.elapsed() >= SEND_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err("timed out".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
fn syslog(n: &Notice) -> Result<(), String> {
    use std::os::unix::net::UnixDatagram;
    let level = match n.priority {
        Priority::High => 2,
        Priority::Medium => 4,
        Priority::Low => 6,
    };
    let auth_facility = 10 * 8;
    let line = format!("<{}>procwatch: {}", auth_facility + level, crate::common::text::printable(&heading(n)));
    let s = UnixDatagram::unbound().map_err(|e| e.to_string())?;
    let path = ["/dev/log", "/var/run/syslog"].into_iter().find(|p| std::path::Path::new(p).exists()).ok_or("no syslog socket")?;
    s.send_to(line.as_bytes(), path).map(|_| ()).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn syslog(_: &Notice) -> Result<(), String> {
    Err("syslog isn't available on this platform".into())
}

fn command(argv: &[String], n: &Notice) -> Result<(), String> {
    let mut child = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("{}: {e}", argv[0]))?;
    if let Some(mut input) = child.stdin.take() {
        let _ = input.write_all(body(Format::Json, n).as_bytes());
    }
    let began = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return if status.success() { Ok(()) } else { Err(format!("exited with {status}")) };
        }
        if began.elapsed() >= SEND_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err("timed out".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Deliver to one destination, once.
pub fn send(d: &Destination, n: &Notice) -> Result<(), String> {
    match &d.kind {
        Kind::Webhook { url, format } => webhook(url, *format, n),
        Kind::Syslog => syslog(n),
        Kind::File { path } => {
            let mut f = crate::common::paths::private_file().create(true).append(true).open(path).map_err(|e| e.to_string())?;
            writeln!(f, "{}", body(Format::Json, n)).map_err(|e| e.to_string())
        }
        Kind::Command { argv } => command(argv, n),
    }
}

/// Spreads notifications over time: at most `PER_MINUTE`, with a count of
/// what was held back.
#[derive(Default)]
pub struct Limiter {
    sent: VecDeque<Instant>,
    held: usize,
}

impl Limiter {
    /// Whether this one may go, and how many were held back before it.
    pub fn allow(&mut self, priority: Priority, now: Instant) -> Option<usize> {
        while self.sent.front().is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60)) {
            self.sent.pop_front();
        }
        // High priority gets a little more room than the rest.
        let room = if priority >= Priority::High { PER_MINUTE * 2 } else { PER_MINUTE };
        if self.sent.len() >= room {
            self.held += 1;
            return None;
        }
        self.sent.push_back(now);
        Some(std::mem::take(&mut self.held))
    }
}

fn deliver(destinations: Vec<Destination>, rx: Receiver<Notice>, hub: Hub, problems: SyncSender<String>) {
    let mut limits: Vec<Limiter> = destinations.iter().map(|_| Limiter::default()).collect();
    for notice in rx {
        for (d, limit) in destinations.iter().zip(&mut limits) {
            if !d.wants(notice.priority) {
                continue;
            }
            let Some(held) = limit.allow(notice.priority, Instant::now()) else { continue };
            let mut n = notice.clone();
            if held > 0 {
                n.title = format!("{} (+{held} more held back)", n.title);
            }
            let mut result = send(d, &n);
            for attempt in 1..RETRIES {
                if result.is_ok() {
                    break;
                }
                std::thread::sleep(Duration::from_secs(u64::from(attempt) * 2));
                result = send(d, &n);
            }
            match result {
                Ok(()) => {
                    hub.stats().notified.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    hub.stats().notify_failed.fetch_add(1, Ordering::Relaxed);
                    let _ = problems.try_send(format!("alarm to {} failed: {e}", d.describe()));
                }
            }
        }
    }
}

pub const PROBLEM: &str = "alarm.problem";

/// The last stage of the alarm path: decides, then hands to a thread of its
/// own, because sending is the part most likely to hang.
pub struct AlarmModule {
    destinations: Vec<Destination>,
    decider: Decider,
    events: Option<Receiver<AlarmEvent>>,
    tx: Option<Sender<Notice>>,
    problems: Option<Receiver<String>>,
}

impl AlarmModule {
    pub fn new(destinations: Vec<Destination>) -> AlarmModule {
        AlarmModule { destinations, decider: Decider::default(), events: None, tx: None, problems: None }
    }

    /// A module's signal is gone: what it provided can't be trusted.
    fn track_signal(&mut self, e: &AlarmEvent) {
        if e.rule != "module-lost" {
            return;
        }
        let provides = e.detail.rsplit("provides: ").next().unwrap_or("");
        for prefix in provides.split(", ").filter(|p| !p.is_empty()) {
            match e.phase {
                Phase::Recovered => self.decider.unsilence(prefix),
                _ => self.decider.silence(prefix),
            }
        }
    }
}

impl Module for AlarmModule {
    fn capabilities(&self) -> Vec<Capability> {
        vec![if self.destinations.is_empty() {
            Capability::no("alarm delivery", "no destinations in defense.yml: alarms stay on this screen")
        } else {
            Capability::yes("alarm delivery")
        }]
    }

    fn importance(&self) -> Importance {
        Importance::Core
    }

    fn interval(&self) -> Option<Duration> {
        Some(Duration::from_secs(1))
    }

    fn start(&mut self, ctx: &Context) -> Result<(), String> {
        if self.destinations.is_empty() {
            return Err("no alarm destinations configured".into());
        }
        let (tx, rx) = channel();
        let (ptx, prx) = sync_channel(64);
        let list = self.destinations.clone();
        let hub = ctx.alarms().clone();
        self.events = Some(hub.subscribe());
        std::thread::Builder::new().name("alarm".into()).spawn(move || deliver(list, rx, hub, ptx)).map_err(|e| e.to_string())?;
        self.tx = Some(tx);
        self.problems = Some(prx);
        Ok(())
    }

    fn tick(&mut self, ctx: &Context) {
        let now = Instant::now();
        self.decider.maintenance(crate::common::maintenance::remaining().map(|left| now + left));
        let events: Vec<AlarmEvent> = self.events.as_ref().map(|rx| rx.try_iter().collect()).unwrap_or_default();
        let mut notices = Vec::new();
        for e in &events {
            self.track_signal(e);
            notices.extend(self.decider.on_event(e, now));
        }
        notices.extend(self.decider.tick(now));
        if let Some(tx) = &self.tx {
            notices.into_iter().for_each(|n| {
                let _ = tx.send(n);
            });
        }
        if let Some(rx) = &self.problems {
            while let Ok(p) = rx.try_recv() {
                ctx.publish(PROBLEM, p);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(priority: Priority) -> Notice {
        Notice { priority, rule: "r".into(), title: "SSH \"attack\" (source 203.0.113.1)".into(), source: "defense".into(), detail: "line".into() }
    }

    #[test]
    fn each_service_gets_its_own_shape() {
        let n = notice(Priority::High);
        let get = |f| serde_json::from_str::<serde_json::Value>(&body(f, &n)).unwrap();
        assert!(get(Format::Slack)["text"].as_str().unwrap().ends_with("SSH \"attack\" (source 203.0.113.1)\nline"));
        assert_eq!(get(Format::Dingtalk)["msgtype"], "text");
        assert!(get(Format::Wecom)["text"]["content"].is_string());
        assert!(get(Format::Feishu)["content"]["text"].is_string());
        assert_eq!((get(Format::Json)["priority"].as_str(), get(Format::Json)["v"].as_u64()), (Some("high"), Some(1)));
    }

    #[test]
    fn quoting_cannot_add_curl_options() {
        let c = curl_config("https://x.example/hook", "a\"\nurl = \"https://evil.example\\");
        assert_eq!(c.lines().filter(|l| l.starts_with("url")).count(), 1);
        assert!(c.contains("max-redirs = 0"));
    }

    #[test]
    fn destinations_are_checked_and_tokens_stay_out_of_messages() {
        let d = |k| Destination { kind: k, min_severity: None };
        assert!(d(Kind::Webhook { url: "ftp://x".into(), format: Format::Json }).validate().is_err());
        assert!(d(Kind::Command { argv: vec![] }).validate().is_err());
        let w = d(Kind::Webhook { url: "https://hooks.example/services/SECRET".into(), format: Format::Slack });
        assert!(w.validate().is_ok());
        assert_eq!(w.describe(), "webhook https://hooks.example");
        assert!(!w.wants(Priority::Medium), "the default is high");
        assert!(w.wants(Priority::High));
    }

    #[test]
    fn bursts_are_limited_and_counted() {
        let (mut l, t) = (Limiter::default(), Instant::now());
        assert!((0..PER_MINUTE).all(|_| l.allow(Priority::Medium, t) == Some(0)));
        assert_eq!(l.allow(Priority::Medium, t), None);
        assert_eq!(l.allow(Priority::Medium, t), None);
        assert_eq!(l.allow(Priority::High, t), Some(2), "high gets through, with the count");
        assert_eq!(l.allow(Priority::Medium, t + Duration::from_secs(61)), Some(0));
    }

    #[test]
    fn file_and_command_destinations_deliver() {
        let dir = crate::common::paths::private_temp_dir("alarm").unwrap();
        let path = dir.join("alarms.jsonl");
        let d = Destination { kind: Kind::File { path: path.clone() }, min_severity: None };
        send(&d, &notice(Priority::High)).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains("203.0.113.1"));
        #[cfg(unix)]
        {
            let c = Destination { kind: Kind::Command { argv: vec!["/bin/sh".into(), "-c".into(), "cat > /dev/null".into()] }, min_severity: None };
            send(&c, &notice(Priority::High)).unwrap();
            let bad = Destination { kind: Kind::Command { argv: vec!["/bin/sh".into(), "-c".into(), "exit 3".into()] }, min_severity: None };
            assert!(send(&bad, &notice(Priority::High)).is_err());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
