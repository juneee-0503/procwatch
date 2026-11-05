//! `procwatch --metrics`: one reading of the system's health figures.

use crate::common::text::printable;
use crate::performance::metrics::{Collector, INTERVAL};
use crate::performance::services::{self, ServiceState};
use crate::process::{human_bytes, human_rate};

pub fn run(json: bool) -> i32 {
    let mut c = Collector::new();
    let _ = c.sample();
    // Rates need two samples.
    std::thread::sleep(INTERVAL.min(std::time::Duration::from_secs(2)));
    let m = c.sample();
    let list = services::collect();
    if json {
        let v = serde_json::json!({ "metrics": m, "services": list.as_ref().ok(), "services_error": list.as_ref().err() });
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return 0;
    }
    let f = |v: Option<f64>| v.map(|v| format!("{v:.0}")).unwrap_or_else(|| "n/a".into());
    let b = |v: Option<u64>| v.map(human_bytes).unwrap_or_else(|| "n/a".into());
    let p = |v: Option<f32>| v.map(|v| format!("{v:.1}%")).unwrap_or_else(|| "n/a".into());
    println!("Context switches/s {}   interrupts/s {}   run queue {}   blocked {}", f(m.context_switches_per_sec), f(m.interrupts_per_sec), f(m.run_queue), f(m.blocked));
    println!("Memory available {} of {}   swap {} of {}", b(m.available_memory), b(m.total_memory), b(m.swap_used), b(m.swap_total));
    println!("Page faults/s {}   swap in/out pages/s {} / {}", f(m.page_faults_per_sec), f(m.swap_in_pages_per_sec), f(m.swap_out_pages_per_sec));
    println!("Pressure cpu {}   memory {}   io {}", p(m.cpu_pressure), p(m.memory_pressure), p(m.io_pressure));
    println!("TCP retransmits/s {}", f(m.retransmits_per_sec));
    for d in &m.disks {
        let o = |v: Option<f64>| v.map(|v| format!("{v:.1}")).unwrap_or_else(|| "n/a".into());
        crate::safe_println!("Disk {:<14} read {:>10} write {:>10} IOPS {:>6.0} queue {:>5} busy {:>5}% await {:>6} ms", d.name, human_rate(d.read_rate), human_rate(d.write_rate), d.iops, o(d.queue_depth), o(d.busy_pct), o(d.await_ms));
    }
    for n in &m.nics {
        crate::safe_println!("Net  {:<14} in {:>10} out {:>10} errors {} drops {}", n.name, human_rate(n.rx_rate), human_rate(n.tx_rate), n.errors_total, n.drops_total);
    }
    for t in &m.temperatures {
        crate::safe_println!("Temp {:<30} {:.0} °C", t.label, t.value);
    }
    for w in &m.power {
        crate::safe_println!("Power {:<29} {:.1} W", w.label, w.value);
    }
    match &list {
        Ok(l) => {
            let failed: Vec<&str> = l.iter().filter(|s| s.state == ServiceState::Failed).map(|s| s.name.as_str()).collect();
            println!("Services: {} total, {} running, {} failed", l.len(), l.iter().filter(|s| s.state == ServiceState::Running).count(), failed.len());
            for name in failed.iter().take(20) {
                println!("  failed: {}", printable(name));
            }
        }
        Err(e) => println!("Services: unavailable ({})", printable(e)),
    }
    for n in &m.notes {
        println!("note: {n}");
    }
    0
}
