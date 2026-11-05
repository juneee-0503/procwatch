//! Loading the programs and reading their ring buffer, with the raw system
//! calls. Everything is held by file descriptors, so all of it leaves the
//! kernel when procwatch exits, however it exits.

use std::ffi::c_void;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver};
use std::sync::Arc;

use super::event::{decode, Event};
use super::program::{self, Kind, Maps, RECORD};

const MAP_CREATE: i32 = 0;
const MAP_LOOKUP: i32 = 1;
const PROG_LOAD: i32 = 5;
const MAP_ARRAY: u32 = 2;
const MAP_RINGBUF: u32 = 27;
const PROG_TRACEPOINT: u32 = 5;
const PERF_TYPE_TRACEPOINT: u32 = 2;
const PERF_ATTR_SIZE: u32 = 128;
const PERF_SET_BPF: libc::c_ulong = 0x4004_2408;
const PERF_ENABLE: libc::c_ulong = 0x2400;
const PERF_FLAG_CLOEXEC: libc::c_ulong = 8;
const RING_SIZE: usize = 16 << 20;
const BUSY: u32 = 1 << 31;
const DISCARD: u32 = 1 << 30;
const HEADER: usize = 8;
const LICENSE: &[u8] = b"Dual MIT/GPL\0";

fn bpf(cmd: i32, attr: &mut [u64; 16]) -> std::io::Result<i64> {
    let r = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr.as_mut_ptr(), std::mem::size_of_val(attr)) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(r)
}

fn fd(n: i64) -> OwnedFd {
    unsafe { OwnedFd::from_raw_fd(n as i32) }
}

fn map(kind: u32, key: u32, value: u32, entries: u32) -> std::io::Result<OwnedFd> {
    let mut attr = [0u64; 16];
    attr[0] = u64::from(kind) | u64::from(key) << 32;
    attr[1] = u64::from(value) | u64::from(entries) << 32;
    bpf(MAP_CREATE, &mut attr).map(fd)
}

fn load(name: &str, code: &[u8]) -> Result<OwnedFd, String> {
    let attempt = |log: Option<&mut Vec<u8>>| {
        let mut attr = [0u64; 16];
        attr[0] = u64::from(PROG_TRACEPOINT) | ((code.len() / 8) as u64) << 32;
        attr[1] = code.as_ptr() as u64;
        attr[2] = LICENSE.as_ptr() as u64;
        if let Some(buffer) = log {
            attr[3] = 1 | (buffer.len() as u64) << 32;
            attr[4] = buffer.as_mut_ptr() as u64;
        }
        bpf(PROG_LOAD, &mut attr).map(fd)
    };
    if let Ok(p) = attempt(None) {
        return Ok(p);
    }
    // Only a failure is worth the verifier's full account.
    let mut log = vec![0u8; 1 << 20];
    let result = attempt(Some(&mut log));
    match result {
        Ok(p) => Ok(p),
        Err(e) => {
            let end = log.iter().position(|b| *b == 0).unwrap_or(log.len());
            let text = String::from_utf8_lossy(&log[..end]);
            let tail: Vec<&str> = text.lines().rev().take(24).collect();
            Err(format!("{name}: {e}\n{}", tail.into_iter().rev().collect::<Vec<_>>().join("\n")))
        }
    }
}

/// The tracepoint's number, if this kernel has it.
fn tracepoint(name: &str) -> Option<u64> {
    ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"].iter().find_map(|root| std::fs::read_to_string(format!("{root}/events/syscalls/{name}/id")).ok()?.trim().parse().ok())
}

fn attach(id: u64, program: &OwnedFd) -> std::io::Result<OwnedFd> {
    let mut attr = [0u64; 16];
    attr[0] = u64::from(PERF_TYPE_TRACEPOINT) | u64::from(PERF_ATTR_SIZE) << 32;
    attr[1] = id;
    attr[2] = 1; // sample period
    // One event is enough: the program belongs to the tracepoint, on every CPU.
    let n = unsafe { libc::syscall(libc::SYS_perf_event_open, attr.as_ptr(), -1, 0, -1, PERF_FLAG_CLOEXEC) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let event = fd(n);
    unsafe {
        if libc::ioctl(event.as_raw_fd(), PERF_SET_BPF, program.as_raw_fd()) != 0 || libc::ioctl(event.as_raw_fd(), PERF_ENABLE, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(event)
}

/// The shared memory of a ring buffer.
struct Ring {
    map: OwnedFd,
    consumer: *mut c_void,
    producer: *mut c_void,
    page: usize,
}

// The mappings live as long as the Ring and are read with atomics.
unsafe impl Send for Ring {}

impl Ring {
    fn new(map: OwnedFd) -> std::io::Result<Ring> {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let fail = |p: *mut c_void| p == libc::MAP_FAILED;
        unsafe {
            let consumer = libc::mmap(std::ptr::null_mut(), page, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, map.as_raw_fd(), 0);
            if fail(consumer) {
                return Err(std::io::Error::last_os_error());
            }
            // The data is mapped twice in a row, so a record that wraps
            // reads as one piece.
            let producer = libc::mmap(std::ptr::null_mut(), page + 2 * RING_SIZE, libc::PROT_READ, libc::MAP_SHARED, map.as_raw_fd(), page as i64);
            if fail(producer) {
                let e = std::io::Error::last_os_error();
                libc::munmap(consumer, page);
                return Err(e);
            }
            Ok(Ring { map, consumer, producer, page })
        }
    }

    fn drain(&mut self, mut each: impl FnMut(&[u8])) {
        let consumer = unsafe { &*self.consumer.cast::<AtomicU64>() };
        let producer = unsafe { &*self.producer.cast::<AtomicU64>() };
        let data = unsafe { self.producer.cast::<u8>().add(self.page) };
        let mut at = consumer.load(Ordering::Acquire);
        let end = producer.load(Ordering::Acquire);
        while at < end {
            let offset = at as usize & (RING_SIZE - 1);
            let header = unsafe { &*data.add(offset).cast::<AtomicU32>() }.load(Ordering::Acquire);
            if header & BUSY != 0 {
                break;
            }
            let len = (header & !(BUSY | DISCARD)) as usize;
            if len > RING_SIZE - HEADER {
                break;
            }
            if header & DISCARD == 0 {
                each(unsafe { std::slice::from_raw_parts(data.add(offset + HEADER), len) });
            }
            at += ((len + HEADER + 7) & !7) as u64;
            consumer.store(at, Ordering::Release);
        }
    }

    fn wait(&self, ms: i32) {
        let mut p = libc::pollfd { fd: self.map.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        unsafe { libc::poll(&raw mut p, 1, ms) };
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.consumer, self.page);
            libc::munmap(self.producer, self.page + 2 * RING_SIZE);
        }
    }
}

pub struct Sensor {
    pub rx: Receiver<Event>,
    pub attached: Vec<&'static str>,
    pub missing: Vec<&'static str>,
    pub dropped: Arc<AtomicU64>,
    pub seen: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    lost_map: OwnedFd,
    _programs: Vec<OwnedFd>,
    _events: Vec<OwnedFd>,
}

impl Drop for Sensor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Sensor {
    pub fn start() -> Result<Sensor, String> {
        let hint = "needs root and Linux 5.8 or later";
        let ring = map(MAP_RINGBUF, 0, 0, RING_SIZE as u32).map_err(|e| format!("ring buffer: {e} ({hint})"))?;
        let lost_map = map(MAP_ARRAY, 4, 8, 1).map_err(|e| format!("counter: {e} ({hint})"))?;
        let maps = Maps { ring: ring.as_raw_fd(), lost: lost_map.as_raw_fd() };
        let (mut programs, mut events, mut attached, mut missing) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for (name, code) in program::all(maps)? {
            let Some(id) = tracepoint(name) else {
                missing.push(name);
                continue;
            };
            let p = load(name, &code)?;
            events.push(attach(id, &p).map_err(|e| format!("{name}: {e}"))?);
            programs.push(p);
            attached.push(name);
        }
        if attached.is_empty() {
            return Err(format!("no system call tracepoints found: is tracefs mounted? ({hint})"));
        }
        let mut ring = Ring::new(ring).map_err(|e| format!("mapping the ring buffer: {e}"))?;
        let (tx, rx) = sync_channel(65_536);
        let (stop, dropped, seen) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let (halt, full, count) = (stop.clone(), dropped.clone(), seen.clone());
        std::thread::Builder::new()
            .name("ebpf".into())
            .spawn(move || {
                while !halt.load(Ordering::Relaxed) {
                    ring.drain(|record| {
                        let Some(mut e) = decode(record) else { return };
                        count.fetch_add(1, Ordering::Relaxed);
                        // The descriptors must be read now, while they exist.
                        if e.kind == Kind::Exec {
                            e.peer = crate::defense::host::stream_peer(std::path::Path::new("/"), e.pid, false);
                        }
                        if tx.try_send(e).is_err() {
                            full.fetch_add(1, Ordering::Relaxed);
                        }
                    });
                    ring.wait(100);
                }
            })
            .map_err(|e| e.to_string())?;
        debug_assert_eq!(RECORD % 8, 0);
        Ok(Sensor { rx, attached, missing, dropped, seen, stop, lost_map, _programs: programs, _events: events })
    }

    /// Records lost because the ring or queue was full.
    pub fn lost(&self) -> u64 {
        let (key, mut value) = (0u32, 0u64);
        let mut attr = [0u64; 16];
        attr[0] = self.lost_map.as_raw_fd() as u64;
        attr[1] = (&raw const key) as u64;
        attr[2] = (&raw mut value) as u64;
        let _ = bpf(MAP_LOOKUP, &mut attr);
        value + self.dropped.load(Ordering::Relaxed)
    }
}
