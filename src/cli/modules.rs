//! `procwatch --modules`: what is registered and what it supports here, and
//! turning modules on and off for future runs.

use std::sync::Arc;

use crate::common::pacing::SamplerCtl;
use crate::kernel::{Support, supervisor::Registry};

fn registry() -> Registry {
    crate::engine::registry(Arc::new(SamplerCtl::default()), Vec::new())
}

pub fn list(json: bool) -> i32 {
    let statuses = registry().statuses();
    let config = crate::engine::load_config();
    if json {
        println!("{}", serde_json::to_string_pretty(&statuses).unwrap_or_default());
        return 0;
    }
    for s in &statuses {
        println!("{:<13} {:<9} {}", s.name, if config.disabled.contains(s.name) { "disabled" } else { "enabled" }, s.description);
        for c in &s.capabilities {
            let why = match &c.support {
                Support::Yes => String::new(),
                Support::Partly(w) | Support::No(w) => format!(" — {w}"),
            };
            println!("    {:<34} {}{why}", c.name, c.support.label());
        }
    }
    for p in &config.problems {
        println!("modules.conf: {p}");
    }
    0
}

pub fn set(name: &str, enabled: bool) -> i32 {
    if !registry().statuses().iter().any(|s| s.name == name) {
        eprintln!("No module named {name}; --modules lists them");
        return 2;
    }
    let mut c = crate::engine::load_config();
    if enabled {
        c.disabled.remove(name);
    } else {
        c.disabled.insert(name.to_string());
    }
    match crate::engine::save_config(&c) {
        Ok(()) => {
            println!("{name} {} from the next start", if enabled { "enabled" } else { "disabled" });
            0
        }
        Err(e) => {
            eprintln!("Couldn't save: {e}");
            2
        }
    }
}
