//! Telling another machine we are alive and intact. Everything local shares
//! the fate of what it protects, so the proof must leave the machine:
//! silence is the alarm, and it is raised elsewhere.
//!
//! A beat carries the program hash, configuration hash and log chain head.
//! Each is signed with a shared key and numbered, so beats can't be forged
//! by anyone without the key, or replayed. Whoever holds the key can still
//! forge them: that risk is accepted and documented.

use std::collections::{BTreeMap, HashMap};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The current heartbeat protocol. Unknown fields are ignored.
pub const PROTOCOL: u32 = 1;
/// Beats missed before saying so.
const MISSED: u32 = 3;
const MAX_BODY: usize = 256 * 1024;
const MAX_ANCHORS: usize = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    /// Where to send beats; empty leaves them off.
    pub url: String,
    pub key_file: String,
    pub interval_seconds: u64,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { url: String::new(), key_file: String::new(), interval_seconds: 15 }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SyncSettings {
    /// Where to copy the alarm and audit log; empty leaves it off.
    pub url: String,
}

/// HMAC-SHA-256, RFC 2104.
pub fn hmac(key: &[u8], message: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| k.iter().map(|b| b ^ byte).collect::<Vec<u8>>();
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(message).finalize();
    let outer = Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize();
    outer.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compares without showing where the difference lies.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct Beat {
    pub v: u32,
    pub host: String,
    pub instance: String,
    pub seq: u64,
    pub time: String,
    pub health: String,
    pub program: String,
    pub config: String,
    pub chain_seq: u64,
    pub chain_head: String,
    /// Older points on the chain, sent at start: rewritten history shows here.
    pub anchors: Vec<(u64, String)>,
    /// Seconds of maintenance left.
    pub maintenance: Option<u64>,
    /// Sent once, on the way out.
    pub last_words: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Signed {
    body: String,
    mac: String,
}

/// Log lines on their way to safekeeping.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Lines {
    pub v: u32,
    pub host: String,
    pub lines: Vec<String>,
}

pub fn seal<T: Serialize>(message: &T, key: &[u8]) -> Result<String, String> {
    let body = serde_json::to_string(message).map_err(|e| e.to_string())?;
    let mac = hmac(key, body.as_bytes());
    serde_json::to_string(&Signed { body, mac }).map_err(|e| e.to_string())
}

pub fn open<T: serde::de::DeserializeOwned>(text: &str, key: &[u8]) -> Result<T, String> {
    let s: Signed = serde_json::from_str(text).map_err(|_| "not a heartbeat".to_string())?;
    if !same(&s.mac, &hmac(key, s.body.as_bytes())) {
        return Err("bad signature".into());
    }
    serde_json::from_str(&s.body).map_err(|e| e.to_string())
}

pub fn read_key(path: &str) -> Result<Vec<u8>, String> {
    let key = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    if key.len() < 16 {
        return Err(format!("{path}: a key needs at least 16 bytes"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = std::fs::metadata(path).map_err(|e| e.to_string())?.mode();
        if mode & 0o077 != 0 {
            return Err(format!("{path}: other users can read the key"));
        }
    }
    Ok(key.trim_ascii_end().to_vec())
}

/// Posts without blocking the caller's loop for long.
pub fn post(url: &str, body: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = crate::common::command::tool("curl").args(["--config", "-"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e| format!("curl: {e}"))?;
    if let Some(mut input) = child.stdin.take() {
        input.write_all(crate::defense::alarm::curl_config(url, body).as_bytes()).map_err(|e| e.to_string())?;
    }
    let s = child.wait().map_err(|e| e.to_string())?;
    if s.success() { Ok(()) } else { Err(format!("curl exited with {s}")) }
}

/// What the receiving end concludes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub host: String,
    pub kind: &'static str,
    pub detail: String,
}

struct Peer {
    instance: String,
    seq: u64,
    last: Instant,
    program: String,
    config: String,
    period: Duration,
    lost: bool,
    quiet_until: Option<Instant>,
    anchors: BTreeMap<u64, String>,
    said_goodbye: bool,
}

/// The receiving end's reasoning, kept free of any network code.
#[derive(Default)]
pub struct Watcher {
    peers: HashMap<String, Peer>,
    pub period: Duration,
}

impl Watcher {
    pub fn new(period: Duration) -> Watcher {
        Watcher { peers: HashMap::new(), period }
    }

    pub fn accept(&mut self, b: &Beat, now: Instant) -> Vec<Finding> {
        let mut out = Vec::new();
        let mut note = |kind, detail: String| out.push(Finding { host: b.host.clone(), kind, detail });
        let period = self.period;
        let quiet = b.maintenance.map(|s| now + Duration::from_secs(s));
        let Some(p) = self.peers.get_mut(&b.host) else {
            note("first contact", format!("program {}", b.program));
            let anchors = b.anchors.iter().cloned().chain(std::iter::once((b.chain_seq, b.chain_head.clone()))).collect();
            self.peers.insert(b.host.clone(), Peer { instance: b.instance.clone(), seq: b.seq, last: now, program: b.program.clone(), config: b.config.clone(), period, lost: false, quiet_until: quiet, anchors, said_goodbye: b.last_words.is_some() });
            return out;
        };
        if b.instance == p.instance && b.seq <= p.seq {
            note("replay", format!("sequence {} after {}", b.seq, p.seq));
            return out;
        }
        if b.instance != p.instance {
            note("restarted", format!("new instance {}", b.instance));
        }
        if p.lost {
            note("back", "beats resumed".to_string());
        }
        if b.program != p.program {
            note("program changed", format!("was {}, now {}", p.program, b.program));
            p.program = b.program.clone();
        }
        if b.config != p.config {
            note("configuration changed", format!("was {}, now {}", p.config, b.config));
            p.config = b.config.clone();
        }
        if b.chain_seq < p.anchors.keys().next_back().copied().unwrap_or(0) {
            note("log shortened", format!("chain at {}, had reached {}", b.chain_seq, p.anchors.keys().next_back().copied().unwrap_or(0)));
        }
        for (seq, head) in b.anchors.iter().chain(std::iter::once(&(b.chain_seq, b.chain_head.clone()))) {
            match p.anchors.get(seq) {
                Some(known) if known != head => note("log rewritten", format!("entry {seq} no longer matches what was recorded here")),
                Some(_) => {}
                None if p.anchors.len() < MAX_ANCHORS => {
                    p.anchors.insert(*seq, head.clone());
                }
                None => {}
            }
        }
        if let Some(words) = &b.last_words {
            note("last words", words.clone());
            p.said_goodbye = true;
        } else {
            p.said_goodbye = false;
        }
        p.instance = b.instance.clone();
        p.seq = b.seq;
        p.last = now;
        p.lost = false;
        p.quiet_until = quiet;
        out
    }

    /// Who has gone silent. This needs a person: a lost link looks the same.
    pub fn tick(&mut self, now: Instant) -> Vec<Finding> {
        let mut out = Vec::new();
        for (host, p) in &mut self.peers {
            let maintenance = p.quiet_until.is_some_and(|t| now < t);
            if !p.lost && !maintenance && now.duration_since(p.last) >= p.period * MISSED {
                p.lost = true;
                let why = if p.said_goodbye { "after saying it was stopping" } else { "with no warning" };
                out.push(Finding { host: host.clone(), kind: "lost contact", detail: format!("silent for {} beats, {why}: confirm by hand; it could be the network", MISSED) });
            }
        }
        out
    }
}

/// Store log lines, one file per host. Host names come from the sender, so
/// they are reduced to what is safe in a file name.
fn store(lines: &Lines, dir: &std::path::Path) -> Result<(), String> {
    use std::io::Write;
    let name: String = lines.host.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.')).filter(|c| *c != '.').take(64).collect();
    crate::common::paths::ensure_private_dir(dir).map_err(|e| e.to_string())?;
    let mut f = crate::common::paths::private_file().create(true).append(true).open(dir.join(format!("{name}.jsonl"))).map_err(|e| e.to_string())?;
    lines.lines.iter().try_for_each(|l| writeln!(f, "{l}")).map_err(|e| e.to_string())
}

fn serve(mut s: TcpStream, key: &[u8], watcher: &mut Watcher, dir: Option<&std::path::Path>) -> Vec<Finding> {
    use std::io::{Read, Write};
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let mut request = Vec::new();
    let mut chunk = [0u8; 4096];
    let body_at = loop {
        if let Some(at) = memchr::memmem::find(&request, b"\r\n\r\n") {
            break Some(at + 4);
        }
        match s.read(&mut chunk) {
            Ok(n) if n > 0 && request.len() < MAX_BODY => request.extend_from_slice(&chunk[..n]),
            _ => break None,
        }
    };
    let mut found = Vec::new();
    let mut status = "400 Bad Request";
    if let Some(at) = body_at {
        let head = String::from_utf8_lossy(&request[..at]).to_ascii_lowercase();
        let want = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(0).min(MAX_BODY);
        while request.len() - at < want {
            match s.read(&mut chunk) {
                Ok(n) if n > 0 => request.extend_from_slice(&chunk[..n]),
                _ => break,
            }
        }
        let body = String::from_utf8_lossy(&request[at..]);
        if head.starts_with("post /logs") {
            let saved = open::<Lines>(&body, key).and_then(|l| dir.map_or(Ok(()), |d| store(&l, d)));
            if saved.is_ok() {
                status = "200 OK";
            }
            let _ = write!(s, "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            return found;
        }
        match open::<Beat>(&body, key) {
            Ok(b) if b.v >= 1 => {
                status = "200 OK";
                found = watcher.accept(&b, Instant::now());
            }
            Ok(_) => {}
            Err(e) => found.push(Finding { host: s.peer_addr().map_or_else(|_| "?".to_string(), |a| a.ip().to_string()), kind: "refused beat", detail: e }),
        }
    }
    let _ = write!(s, "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    found
}

fn report(f: &Finding, destinations: &[crate::defense::alarm::Destination]) {
    use crate::kernel::alarm::Priority;
    crate::safe_println!("{}", serde_json::to_string(f).unwrap_or_default());
    let routine = matches!(f.kind, "first contact" | "back");
    let notice = crate::defense::alarm::Notice { priority: if routine { Priority::Low } else { Priority::High }, title: format!("{}: {}", f.host, f.kind), detail: f.detail.clone(), source: "heartbeat".into(), rule: f.kind.to_string() };
    for d in destinations {
        let _ = crate::defense::alarm::send(d, &notice);
    }
}

/// `--heartbeat-receiver`: run on another machine.
pub fn receive(addr: &str, key_file: &str, period: Duration, store_dir: Option<&std::path::Path>) -> i32 {
    let run = || -> Result<(), String> {
        let key = read_key(key_file)?;
        let addr: SocketAddr = addr.parse().map_err(|_| format!("{addr}: not an address and port"))?;
        let listener = TcpListener::bind(addr).map_err(|e| format!("{addr}: {e}"))?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let destinations = crate::defense::config::DefenseConfig::load().map(|c| c.alarms).unwrap_or_default();
        let mut watcher = Watcher::new(period);
        eprintln!("receiver: listening on {addr}, a host is lost after {MISSED} missed beats");
        loop {
            let mut found = match listener.accept() {
                Ok((s, _)) => {
                    let _ = s.set_nonblocking(false);
                    serve(s, &key, &mut watcher, store_dir)
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(100));
                    Vec::new()
                }
            };
            found.extend(watcher.tick(Instant::now()));
            found.iter().for_each(|f| report(f, &destinations));
        }
    };
    match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("procwatch: {e}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"a test key of sufficient length";

    fn beat(instance: &str, seq: u64) -> Beat {
        Beat { v: PROTOCOL, host: "web1".into(), instance: instance.into(), seq, program: "p1".into(), config: "c1".into(), chain_seq: seq, chain_head: format!("h{seq}"), ..Default::default() }
    }

    fn kinds(f: &[Finding]) -> Vec<&'static str> {
        f.iter().map(|x| x.kind).collect()
    }

    #[test]
    fn hmac_matches_the_published_vectors() {
        // RFC 4231, test case 2.
        assert_eq!(hmac(b"Jefe", b"what do ya want for nothing?"), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        // Test case 6: a key longer than the block.
        assert_eq!(hmac(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First"), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    #[test]
    fn beats_are_signed() {
        let text = seal(&beat("a", 1), KEY).unwrap();
        assert_eq!(open::<Beat>(&text, KEY).unwrap().seq, 1);
        assert_eq!(open::<Beat>(&text, b"another key").unwrap_err(), "bad signature");
        assert!(open::<Beat>(&text.replace("web1", "web2"), KEY).is_err(), "edited");
        assert!(open::<Beat>("garbage", KEY).is_err());
    }

    #[test]
    fn stored_logs_stay_in_their_folder() {
        let dir = crate::common::paths::private_temp_dir("store").unwrap();
        store(&Lines { v: 1, host: "../../etc/evil".into(), lines: vec!["x".into()] }, &dir).unwrap();
        assert!(dir.join("etcevil.jsonl").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn replays_are_refused_and_restarts_recognised() {
        let (mut w, t) = (Watcher::new(Duration::from_secs(10)), Instant::now());
        assert_eq!(kinds(&w.accept(&beat("a", 5), t)), ["first contact"]);
        assert!(w.accept(&beat("a", 6), t).is_empty());
        assert_eq!(kinds(&w.accept(&beat("a", 6), t)), ["replay"]);
        assert_eq!(kinds(&w.accept(&beat("a", 2), t)), ["replay"]);
        assert_eq!(kinds(&w.accept(&beat("b", 7), t)), ["restarted"]);
    }

    #[test]
    fn silence_is_the_alarm() {
        let (mut w, t) = (Watcher::new(Duration::from_secs(10)), Instant::now());
        w.accept(&beat("a", 1), t);
        assert!(w.tick(t + Duration::from_secs(29)).is_empty());
        assert_eq!(kinds(&w.tick(t + Duration::from_secs(30))), ["lost contact"]);
        assert!(w.tick(t + Duration::from_secs(40)).is_empty(), "said once");
        assert!(kinds(&w.accept(&beat("a", 2), t + Duration::from_secs(41))).contains(&"back"));
    }

    #[test]
    fn maintenance_holds_the_alarm_until_it_ends() {
        let (mut w, t) = (Watcher::new(Duration::from_secs(10)), Instant::now());
        w.accept(&Beat { maintenance: Some(100), ..beat("a", 1) }, t);
        assert!(w.tick(t + Duration::from_secs(99)).is_empty());
        assert_eq!(kinds(&w.tick(t + Duration::from_secs(100))), ["lost contact"]);
    }

    #[test]
    fn last_words_arrive_and_are_recalled() {
        let (mut w, t) = (Watcher::new(Duration::from_secs(10)), Instant::now());
        w.accept(&beat("a", 1), t);
        assert_eq!(kinds(&w.accept(&Beat { last_words: Some("SIGTERM".into()), ..beat("a", 2) }, t)), ["last words"]);
        assert!(w.tick(t + Duration::from_secs(30))[0].detail.contains("saying it was stopping"));
    }

    #[test]
    fn hashes_are_compared_on_this_side() {
        let (mut w, t) = (Watcher::new(Duration::from_secs(10)), Instant::now());
        w.accept(&beat("a", 1), t);
        assert_eq!(kinds(&w.accept(&Beat { program: "evil".into(), ..beat("a", 2) }, t)), ["program changed"]);
        assert_eq!(kinds(&w.accept(&Beat { program: "evil".into(), config: "c2".into(), ..beat("a", 3) }, t)), ["configuration changed"]);
    }

    /// T-09: a rebuilt chain is self-consistent, but not with what left the
    /// machine before the rewrite.
    #[test]
    fn a_rewritten_log_disagrees_with_the_anchors() {
        let (mut w, t) = (Watcher::new(Duration::from_secs(10)), Instant::now());
        w.accept(&beat("a", 10), t);
        w.accept(&beat("a", 11), t);
        let rebuilt = Beat { anchors: vec![(10, "forged".into())], ..beat("b", 12) };
        assert!(kinds(&w.accept(&rebuilt, t)).contains(&"log rewritten"));
        assert!(kinds(&w.accept(&Beat { chain_seq: 3, ..beat("c", 13) }, t)).contains(&"log shortened"));
    }
}
