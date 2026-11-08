//! Seeing system calls as they happen, with eBPF, instead of sampling the
//! process table: a shell that lives for ten milliseconds is seen, with the
//! exact arguments it was given and the process that started it.
//!
//! Needs Linux 5.8 or later and root. Elsewhere, or when loading fails,
//! detection carries on with the slower checks in `host`.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub mod asm;
pub mod event;
#[cfg(target_os = "linux")]
pub mod loader;
pub mod program;
pub mod realtime;

#[cfg(target_os = "linux")]
pub use loader::Sensor;

/// `--ebpf-check`.
#[cfg(not(target_os = "linux"))]
pub fn check() -> i32 {
    eprintln!("eBPF needs Linux 5.8 or later.");
    2
}

/// Run a program pinned to each CPU in turn: on some kernels probes only
/// fire on some of them, and this shows which.
#[cfg(target_os = "linux")]
fn per_cpu(sensor: &Sensor) -> bool {
    use std::time::Duration;
    let cpus = std::thread::available_parallelism().map_or(1, usize::from).min(64);
    let mut all = true;
    for cpu in 0..cpus {
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::CPU_SET(cpu, &mut set);
            libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set);
        }
        let _ = sensor.rx.try_iter().count();
        for _ in 0..5 {
            let _ = std::process::Command::new("/bin/true").status();
        }
        std::thread::sleep(Duration::from_millis(400));
        let seen = sensor.rx.try_iter().filter(|e| e.kind == program::Kind::Exec && e.path == "/bin/true").count();
        println!("  cpu {cpu}: saw {seen} of 5");
        all &= seen == 5;
    }
    all
}

/// `--ebpf-check`: load everything, watch a real process start, and report.
#[cfg(target_os = "linux")]
pub fn check() -> i32 {
    use std::time::{Duration, Instant};
    let sensor = match Sensor::start() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("procwatch: {e}");
            return 1;
        }
    };
    println!("attached: {}", sensor.attached.join(", "));
    if !sensor.missing.is_empty() {
        println!("not on this kernel: {}", sensor.missing.join(", "));
    }
    for p in &sensor.partly {
        println!("failed: {p}");
    }
    let mark = "/bin/true";
    // Attaching takes effect at once on some kernels and not on others.
    std::thread::sleep(Duration::from_millis(300));
    for _ in 0..3 {
        let _ = std::process::Command::new(mark).status();
    }
    let until = Instant::now() + Duration::from_secs(2);
    let (mut seen, mut execs, mut samples) = (0, 0, Vec::new());
    while Instant::now() < until {
        if let Ok(e) = sensor.rx.recv_timeout(Duration::from_millis(100)) {
            if e.kind == program::Kind::Exec {
                execs += 1;
                seen += u32::from(e.path == mark);
                if samples.len() < 5 {
                    samples.push(format!("{:?} by {} args {:?}", e.path, e.comm, e.args));
                }
            }
        }
    }
    println!("saw {seen} of 3 test programs start; {} records read, {execs} execs, {} lost", sensor.seen.load(std::sync::atomic::Ordering::Relaxed), sensor.lost());
    samples.iter().for_each(|s| println!("  {s}"));
    let every_cpu = per_cpu(&sensor);
    i32::from(seen != 3 || !every_cpu || !sensor.partly.is_empty())
}
