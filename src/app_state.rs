//! "What did the system look like at time T?" — reconstructed from the
//! live tree, recorded start/exit events, socket events and persistence
//! definition times. Every row says whether it was observed (procwatch
//! was sampling at T) or inferred from timestamps (T before procwatch
//! started). A child module of `app`.

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Local};

use super::*;

#[derive(Debug, Clone)]
pub struct StateRow {
    pub what: String,
    pub detail: String,
    pub basis: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct StateAt {
    pub time: Option<DateTime<Local>>,
    pub processes: Vec<StateRow>,
    pub sockets: Vec<StateRow>,
    pub persistence: Vec<StateRow>,
    /// Entries whose definition was written *after* T.
    pub persistence_later: Vec<StateRow>,
    pub notes: Vec<String>,
}

impl App {
    pub fn state_at(&self, t: DateTime<Local>) -> StateAt {
        let mut st = StateAt { time: Some(t), ..Default::default() };
        let watched = t >= self.ir.watch_start;
        let basis = if watched { "observed" } else { "inferred" };
        let ts = |secs: u64| chrono::DateTime::from_timestamp(secs as i64, 0).map(|x| x.with_timezone(&Local));

        // Processes: (pid, start) → (name, start, exit, cmd)
        // (pid, start) → (name, start, exit, command line)
        type Known = (String, Option<DateTime<Local>>, Option<DateTime<Local>>, String);
        let mut procs: BTreeMap<(u32, u64), Known> = BTreeMap::new();
        for n in self.tree.nodes.values() {
            let i = &n.info;
            procs.insert((i.pid, i.start_time_secs), (i.name.clone(), ts(i.start_time_secs).filter(|_| i.start_time_secs > 0), None, i.cmd.join(" ")));
        }
        for e in &self.events {
            let entry = procs.entry((e.pid, e.start)).or_insert((e.name.clone(), ts(e.start).filter(|_| e.start > 0), None, String::new()));
            match e.kind {
                EventKind::Exited => entry.2 = Some(e.at),
                EventKind::Started if entry.3.is_empty() => entry.3 = e.detail.clone(),
                _ => {}
            }
        }
        // Most recently started first; unknown start times last.
        let mut ordered: Vec<(&(u32, u64), &Known)> = procs.iter().collect();
        ordered.sort_by_key(|(_, (_, start, _, _))| (start.is_none(), std::cmp::Reverse(*start)));
        for ((pid, _), (name, start, exit, cmd)) in ordered {
            let started = match start {
                Some(s) => *s <= t,
                // Unknown start: only claim it if we saw it running then.
                None => watched,
            };
            let alive = exit.is_none_or(|x| x > t);
            if started && alive {
                let since = start.map(|s| format!("since {}", s.format("%m-%d %H:%M:%S"))).unwrap_or_else(|| "start time unknown".into());
                let until = exit.map(|x| format!(" · exited ~{}", x.format("%H:%M:%S"))).unwrap_or_else(|| " · still running".into());
                st.processes.push(StateRow {
                    what: format!("{name} ({pid})"),
                    detail: format!("{since}{until} · {}", cmd.chars().take(120).collect::<String>()),
                    basis,
                });
            }
        }
        if !watched {
            st.notes.push(format!(
                "T is before procwatch started ({}): processes that started and ended before then are unknown; the list is inferred from start times.",
                self.ir.watch_start.format("%H:%M:%S")
            ));
        }
        if self.events.len() >= 2000 {
            st.notes.push("Older process start/exit events were dropped (history is capped at 2000); early exits may be missing.".into());
        }

        // Sockets: replay connect/close events per (pid, socket).
        if watched {
            let mut last: HashMap<(u32, &crate::network::Connection), (&str, DateTime<Local>)> = HashMap::new();
            let mut first: HashMap<(u32, &crate::network::Connection), &str> = HashMap::new();
            for e in &self.ir.net_events {
                first.entry((e.pid, &e.conn)).or_insert(e.kind);
                if e.time <= t {
                    last.insert((e.pid, &e.conn), (e.kind, e.time));
                }
            }
            let mut open: Vec<(u32, &crate::network::Connection, String)> = Vec::new();
            for ((pid, c), (kind, at)) in &last {
                if matches!(*kind, "connect" | "listen") {
                    open.push((*pid, c, format!("opened ~{}", at.format("%H:%M:%S"))));
                }
            }
            // Present from the first sample: first event is a close, or
            // still open now without any event.
            for ((pid, c), kind) in &first {
                if matches!(*kind, "close" | "unlisten") && !last.contains_key(&(*pid, *c)) {
                    open.push((*pid, c, "open when procwatch started".into()));
                }
            }
            for ((pid, c), seen) in &self.ir.conn_first_seen {
                if *seen <= t && !first.contains_key(&(*pid, c)) {
                    open.push((*pid, c, "open since procwatch started".into()));
                }
            }
            open.sort_by_key(|a| a.0);
            for (pid, c, how) in open {
                st.sockets.push(StateRow {
                    what: format!("{} ({pid})", self.name_of(pid)),
                    detail: format!("{} {} → {} {} · {how}", c.protocol, c.local, c.remote, c.state.label()),
                    basis: "observed",
                });
            }
        } else {
            st.notes.push("Sockets before procwatch started are unknown.".into());
        }

        // Persistence: definition files written before / after T.
        if self.ir.persistence.is_none() {
            st.notes.push("Persistence hasn't been scanned (open the Persistence page) — autostart state is unknown.".into());
        }
        for p in self.persist_items() {
            let Some(d) = p.defined.as_deref().and_then(|d| DateTime::parse_from_rfc3339(d).ok()).map(|d| d.with_timezone(&Local)) else { continue };
            let row = StateRow {
                what: format!("{}: {}", p.category, p.name),
                detail: format!("written {} · {}", d.format("%Y-%m-%d %H:%M:%S"), p.command.chars().take(100).collect::<String>()),
                basis: "inferred",
            };
            if d <= t {
                st.persistence.push(row);
            } else {
                st.persistence_later.push(row);
            }
        }
        st.persistence_later.sort_by(|a, b| a.detail.cmp(&b.detail));
        if !st.persistence.is_empty() || !st.persistence_later.is_empty() {
            st.notes.push("Persistence is inferred from definition-file times: an entry rewritten after T counts as \"added or changed after T\"; entries deleted before the scan are not visible.".into());
        }
        st
    }

    /// Open the state view at the selected timeline event's time.
    pub fn open_state_at(&mut self) {
        let Some(t) = self.visible_timeline().get(self.ir.tl_selected).map(|i| self.ir.timeline[*i].time) else { return };
        self.ir.state_at = Some(self.state_at(t));
        self.ir.state_scroll = 0;
        self.mode = Mode::StateAt;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconstructs_processes_and_flags_later_persistence() {
        let mut app = crate::app::tests_support::app();
        let now = Local::now();
        app.ir.watch_start = now - chrono::Duration::seconds(600);
        // Every sample process started 1000 s ago (start time is known).
        let start = (now.timestamp() - 1000) as u64;
        for n in app.tree.nodes.values_mut() {
            n.info.start_time_secs = start;
        }
        // A process that started 500 s ago and exited 100 s ago.
        app.events.push_front(Event {
            at: now - chrono::Duration::seconds(100),
            kind: EventKind::Exited,
            pid: 9999,
            name: "dropper".into(),
            parent: String::new(),
            user: String::new(),
            detail: String::new(),
            start: (now.timestamp() - 500) as u64,
            ppid: None,
            exe: None,
        });
        let live = app.tree.nodes.len();
        let at = |s: i64| app.state_at(now - chrono::Duration::seconds(s));
        assert_eq!(at(300).processes.len(), live + 1, "dropper was running 300 s ago");
        assert_eq!(at(50).processes.len(), live, "…and gone 50 s ago");
        assert_eq!(at(700).processes.len(), live, "before it started");
        assert!(at(700).notes.iter().any(|n| n.contains("before procwatch started")));
        assert_eq!(at(300).processes.iter().filter(|r| r.basis == "observed").count(), live + 1);
    }
}
