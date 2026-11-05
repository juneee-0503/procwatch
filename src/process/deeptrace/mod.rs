//! Deep trace: event-driven lifecycle tracking for chosen processes and
//! everything they start.
//!
//! - macOS: kqueue `EVFILT_PROC` notifications (fork, exec, exit) for each
//!   watched process. On a fork the new children are listed immediately
//!   and watched in turn, so short-lived children are seen even when they
//!   live far less than one refresh. No special entitlement is needed.
//! - Linux: `/proc/PID/task/*/children` and `/proc/PID/exe` polled every
//!   20 ms for watched processes only, so children that live less than
//!   that can be missed (`--selftest` measures it).
//! - Windows: a ToolHelp process snapshot every 100 ms, filtered to
//!   children of watched processes.
//!
//! Every event carries a millisecond timestamp taken when it was noticed,
//! and the watcher reports how it observed it, so the timeline can say how
//! precise each entry is.

mod probes;
use probes as imp;

use crate::common::emit::Emit;
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{Receiver, Sender};
#[cfg(any(test, target_os = "linux", target_os = "windows"))]
use std::time::Duration;

use chrono::{DateTime, Local};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DtKind {
    Spawn,
    Exec,
    Exit,
}

impl DtKind {
    pub fn label(self) -> &'static str {
        match self {
            DtKind::Spawn => "spawn",
            DtKind::Exec => "exec",
            DtKind::Exit => "exit",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DtEvent {
    #[serde(serialize_with = "ser_time")]
    pub at: DateTime<Local>,
    pub kind: DtKind,
    pub pid: u32,
    pub ppid: Option<u32>,
    /// Process start time (s), 0 if it was gone before it could be read.
    pub start: u64,
    pub path: Option<String>,
    pub args: Option<String>,
    /// "kqueue", "procfs poll 50ms", "toolhelp poll 100ms".
    pub via: &'static str,
}

fn ser_time<S: serde::Serializer>(t: &DateTime<Local>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&t.to_rfc3339_opts(chrono::SecondsFormat::Millis, false))
}

pub enum Cmd {
    Watch(u32),
    /// Watch and confirm (true = registered) before returning.
    WatchSync(u32, Sender<bool>),
    Unwatch(u32),
}

/// Handle to the watcher thread.
pub struct Watcher {
    tx: Sender<Cmd>,
}

/// How processes are being watched here.
pub fn method() -> &'static str {
    imp::method()
}

/// Where the watcher reports.
#[derive(Clone)]
pub struct Output {
    pub events: Emit<Vec<DtEvent>>,
    pub errors: Emit<String>,
}

impl Watcher {
    /// Start the watcher; events are delivered through `out` in batches.
    pub fn start(out: Output) -> Option<Watcher> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("deeptrace".into())
            .spawn(move || {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| imp::run(rx, &out)));
                if let Err(e) = r {
                    out.errors.send(format!("deep trace stopped: {}", crate::common::panic_text(&e)));
                }
            })
            .ok()?;
        #[cfg(target_os = "linux")]
        imp::wait_ready();
        Some(Watcher { tx })
    }

    /// What is in use right now; Linux picks once its thread has started.
    pub fn method(&self) -> &'static str {
        method()
    }

    pub fn watch(&self, pid: u32) {
        let _ = self.tx.send(Cmd::Watch(pid));
    }

    /// Watch `pid` and wait until the watcher has it (used before letting
    /// a stopped, freshly launched program continue).
    pub fn watch_sync(&self, pid: u32) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        if self.tx.send(Cmd::WatchSync(pid, tx)).is_err() {
            return false;
        }
        rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap_or(false)
    }

    pub fn unwatch(&self, pid: u32) {
        let _ = self.tx.send(Cmd::Unwatch(pid));
    }
}

/// Shared bookkeeping for the polling implementations.
#[allow(dead_code)]
struct Book {
    watched: HashSet<u32>,
    exe: HashMap<u32, Option<String>>,
}

#[allow(dead_code)]
fn send(out: &Output, batch: &mut Vec<DtEvent>) -> bool {
    if batch.is_empty() {
        return true;
    }
    out.events.send(std::mem::take(batch))
}

#[allow(dead_code)]
fn drain(rx: &Receiver<Cmd>, mut f: impl FnMut(Cmd)) -> bool {
    loop {
        match rx.try_recv() {
            Ok(c) => f(c),
            Err(std::sync::mpsc::TryRecvError::Empty) => return true,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return false,
        }
    }
}


/// The kernel's process event connector (`cn_proc`), as it appears on a
/// netlink socket. Parsing is kept apart from the socket so it can be
/// tested on any platform.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod cn_proc {
    #[derive(Debug, PartialEq, Eq)]
    pub enum Ev {
        Fork { parent: u32, child: u32 },
        Exec { pid: u32 },
        Exit { pid: u32 },
    }

    const NLMSG_HDR: usize = 16;
    const CN_MSG: usize = 20;
    const EVENT_HDR: usize = 16;
    const FORK: u32 = 0x0000_0001;
    const EXEC: u32 = 0x0000_0002;
    const EXIT: u32 = 0x8000_0000;

    fn u32_at(b: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
    }

    /// Every process event in one datagram. Threads are dropped: only
    /// events where the thread is its group's leader describe a process.
    pub fn parse(mut buf: &[u8]) -> Vec<Ev> {
        let mut out = Vec::new();
        while let Some(len) = u32_at(buf, 0).map(|l| l as usize) {
            if len < NLMSG_HDR || len > buf.len() {
                break;
            }
            let msg = &buf[..len];
            let at = NLMSG_HDR + CN_MSG;
            let data = at + EVENT_HDR;
            match u32_at(msg, at) {
                Some(FORK) => {
                    if let (Some(tgid), Some(child), Some(leader)) = (u32_at(msg, data + 4), u32_at(msg, data + 8), u32_at(msg, data + 12)) {
                        if child == leader {
                            out.push(Ev::Fork { parent: tgid, child });
                        }
                    }
                }
                Some(EXEC) => {
                    if let Some(tgid) = u32_at(msg, data + 4) {
                        out.push(Ev::Exec { pid: tgid });
                    }
                }
                Some(EXIT) => {
                    if let (Some(pid), Some(tgid)) = (u32_at(msg, data), u32_at(msg, data + 4)) {
                        if pid == tgid {
                            out.push(Ev::Exit { pid });
                        }
                    }
                }
                _ => {}
            }
            let next = (len + 3) & !3;
            if next >= buf.len() {
                break;
            }
            buf = &buf[next..];
        }
        out
    }

    /// The message that subscribes a socket to process events.
    pub fn listen_message() -> Vec<u8> {
        const NLMSG_DONE: u16 = 3;
        const CN_IDX_PROC: u32 = 1;
        const CN_VAL_PROC: u32 = 1;
        const MCAST_LISTEN: u32 = 1;
        let total = (NLMSG_HDR + CN_MSG + 4) as u32;
        let mut m = Vec::with_capacity(total as usize);
        m.extend(total.to_ne_bytes());
        m.extend(NLMSG_DONE.to_ne_bytes());
        m.extend(0u16.to_ne_bytes()); // flags
        m.extend(0u32.to_ne_bytes()); // seq
        m.extend(0u32.to_ne_bytes()); // pid: assigned by the kernel
        m.extend(CN_IDX_PROC.to_ne_bytes());
        m.extend(CN_VAL_PROC.to_ne_bytes());
        m.extend(0u32.to_ne_bytes()); // seq
        m.extend(0u32.to_ne_bytes()); // ack
        m.extend(4u16.to_ne_bytes()); // payload length
        m.extend(0u16.to_ne_bytes()); // flags
        m.extend(MCAST_LISTEN.to_ne_bytes());
        m
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn event(what: u32, fields: [u32; 4]) -> Vec<u8> {
            let mut m = vec![0u8; NLMSG_HDR + CN_MSG];
            let len = (NLMSG_HDR + CN_MSG + EVENT_HDR + 16 + 2) as u32;
            m[..4].copy_from_slice(&len.to_ne_bytes());
            m.extend(what.to_ne_bytes());
            m.extend([0u8; 12]);
            fields.iter().for_each(|f| m.extend(f.to_ne_bytes()));
            m.extend([0u8; 2]);
            m
        }

        #[test]
        fn parses_process_events_and_skips_threads() {
            assert_eq!(parse(&event(FORK, [10, 10, 20, 20])), vec![Ev::Fork { parent: 10, child: 20 }]);
            assert_eq!(parse(&event(FORK, [10, 10, 21, 10])), vec![], "a new thread");
            assert_eq!(parse(&event(EXEC, [20, 20, 0, 0])), vec![Ev::Exec { pid: 20 }]);
            assert_eq!(parse(&event(EXIT, [20, 20, 0, 0])), vec![Ev::Exit { pid: 20 }]);
            assert_eq!(parse(&event(EXIT, [21, 20, 0, 0])), vec![], "a thread ended");
            assert_eq!(parse(&event(0x40, [1, 2, 3, 4])), vec![], "other events");
        }

        #[test]
        fn several_messages_and_garbage() {
            let mut two = event(EXEC, [5, 5, 0, 0]);
            while !two.len().is_multiple_of(4) {
                two.push(0);
            }
            two.extend(event(EXIT, [5, 5, 0, 0]));
            assert_eq!(parse(&two), vec![Ev::Exec { pid: 5 }, Ev::Exit { pid: 5 }]);
            assert_eq!(parse(&[]), vec![]);
            assert_eq!(parse(&[1, 2, 3]), vec![]);
            assert_eq!(parse(&u32::MAX.to_ne_bytes()), vec![]);
            let truncated = event(FORK, [1, 2, 3, 4]);
            assert_eq!(parse(&truncated[..30]), vec![]);
            assert_eq!(listen_message().len(), 40);
        }
    }
}




#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Start a shell that spawns short-lived children; the watcher must see
    /// them although each lives far less than a refresh. kqueue catches
    /// millisecond lifetimes; polling needs them longer than its interval.
    #[test]
    fn sees_short_lived_children() {
        let (events, rx) = Emit::channel();
        let w = Watcher::start(Output { events, errors: Emit::new(|_| true) }).expect("watcher");
        let mut sh = std::process::Command::new("/bin/sh")
            .args(["-c", if cfg!(target_os = "macos") { "sleep 0.3; for i in 1 2 3 4 5; do /usr/bin/true; done; sleep 0.3" } else { "sleep 0.3; for i in 1 2 3 4 5; do sleep 0.1; done; sleep 0.3" }])
            .spawn()
            .unwrap();
        w.watch(sh.id());
        let _ = sh.wait();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut spawns = 0;
        let mut exits = 0;
        while std::time::Instant::now() < deadline {
            if let Ok(evs) = rx.recv_timeout(Duration::from_millis(200)) {
                spawns += evs.iter().filter(|e| e.kind == DtKind::Spawn).count();
                exits += evs.iter().filter(|e| e.kind == DtKind::Exit && e.pid == sh.id()).count();
            }
            if exits > 0 && spawns >= 6 {
                break;
            }
        }
        // sleep + 5 short ones + sleep = 7 children; allow a miss or two on
        // a loaded machine, but far more than sampling would catch.
        assert!(spawns >= 5, "saw {spawns} spawns");
        assert_eq!(exits, 1, "parent exit seen exactly once");
    }
}
