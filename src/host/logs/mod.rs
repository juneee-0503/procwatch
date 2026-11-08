//! System event logs: macOS unified log, systemd journal, Windows event
//! log. Read-only queries over a recent time window.

#[cfg(target_os = "macos")]
use std::process::Command;
use std::time::Duration;

pub mod module;
mod probes;
use probes as imp;

use chrono::{DateTime, Local};
use serde::Serialize;

#[allow(unused_imports)]
use crate::common::command::{run_command, run_command_capped};

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    #[serde(serialize_with = "ser_time")]
    pub time: DateTime<Local>,
    pub source: String,
    pub level: String,
    pub process: String,
    pub pid: Option<u32>,
    pub message: String,
    /// Identical consecutive messages collapsed into this one.
    pub repeats: usize,
    /// Windows event ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<u32>,
}

fn ser_time<S: serde::Serializer>(t: &DateTime<Local>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&t.to_rfc3339())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Errors, faults, warnings and authentication / security sources.
    Important,
    /// Everything (capped).
    All,
}

pub const MAX: usize = 5000;

/// Fetch entries from the last `minutes`, newest first.
pub fn fetch(minutes: u32, scope: Scope) -> Result<Vec<Entry>, String> {
    let mut v = imp::fetch(minutes, scope)?;
    v.sort_by_key(|e| std::cmp::Reverse(e.time));
    // Noisy sources repeat the same line thousands of times; keep one
    // row with a count so the rest of the window stays visible.
    let mut out: Vec<Entry> = Vec::with_capacity(v.len().min(MAX));
    for e in v {
        match out.last_mut() {
            Some(last) if last.process == e.process && last.message == e.message && last.level == e.level => last.repeats += 1,
            _ => out.push(e),
        }
        if out.len() >= MAX {
            break;
        }
    }
    Ok(out)
}

#[cfg_attr(windows, allow(dead_code))]
fn first_line(s: &str) -> String {
    s.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim()
        .chars()
        .filter(|c| !c.is_control() && *c != '\u{fffd}')
        .take(400)
        .collect()
}




