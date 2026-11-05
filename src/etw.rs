//! ETW sessions for activity and traffic. Observation only: these are the
//! same public providers Windows' own tools consume, and need administrator
//! rights but no driver.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, OnceLock};

use ferrisetw::parser::{Parser, Pointer};
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;

use crate::activity::{registry_path, Activity, Class, SharedBatcher};
use crate::netio::Totals;
use crate::sampler::WorkerMsg;

const KERNEL_FILE: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";
const KERNEL_REGISTRY: &str = "70EB4F03-C1DE-4F73-A051-33D13D5413BD";
const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";

/// Kernel-File keywords: FILEIO (for close), CREATE, READ, WRITE,
/// DELETE_PATH, RENAME_SETLINK_PATH, CREATE_NEW_FILE.
const FILE_KEYWORDS: u64 = 0x20 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000;
/// Kernel-Network keywords: IPv4 and IPv6.
const NET_KEYWORDS: u64 = 0x10 | 0x20;

/// Open objects remembered for naming later events; a session that misses
/// closes must not grow without limit.
const MAX_OBJECTS: usize = 200_000;

const MAX_TRAFFIC_PIDS: usize = 16_384;

/// Where network events go while an activity capture runs.
static SINK: Mutex<Option<SharedBatcher>> = Mutex::new(None);

pub fn set_activity_sink(b: Option<SharedBatcher>) {
    if let Ok(mut s) = SINK.lock() {
        *s = b;
    }
}

/// Volume device names and their drive letters.
fn drives() -> &'static [(String, char)] {
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    static DRIVES: OnceLock<Vec<(String, char)>> = OnceLock::new();
    DRIVES.get_or_init(|| {
        (b'A'..=b'Z')
            .filter_map(|letter| {
                let drive: Vec<u16> = format!("{}:", letter as char).encode_utf16().chain(std::iter::once(0)).collect();
                let mut buf = [0u16; 512];
                let n = unsafe { QueryDosDeviceW(drive.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
                (n > 0).then(|| (String::from_utf16_lossy(&buf[..buf.iter().position(|c| *c == 0).unwrap_or(0)]), letter as char))
            })
            .filter(|(dev, _)| !dev.is_empty())
            .collect()
    })
}

/// ETW file names are NT device paths; show the drive letter.
pub fn dos_path(nt: &str) -> String {
    if nt.starts_with("\\Device\\") {
        for (dev, letter) in drives() {
            if let Some(rest) = nt.strip_prefix(dev.as_str()) {
                return format!("{letter}:{rest}");
            }
        }
    }
    nt.to_string()
}

/// First of `names` that holds non-empty text: field names vary by build.
fn text(p: &Parser, names: &[&str]) -> String {
    names.iter().find_map(|n| p.try_parse::<String>(n).ok().filter(|s| !s.is_empty())).unwrap_or_default()
}

fn pointer(p: &Parser, name: &str) -> Option<u64> {
    p.try_parse::<Pointer>(name).ok().map(|v| *v as u64)
}

fn start(name: &str, providers: Vec<Provider>) -> Result<UserTrace, String> {
    // A stale session from a crashed run would block the name.
    let _ = ferrisetw::trace::stop_trace_by_name(name);
    let mut b = UserTrace::new().named(name.to_string());
    for p in providers {
        b = b.enable(p);
    }
    b.start_and_process().map_err(|e| format!("ETW needs administrator rights ({e:?})"))
}

pub fn start_traffic(tx: Sender<WorkerMsg>, stop: Arc<AtomicBool>) -> Result<UserTrace, String> {
    let totals: Arc<Mutex<Totals>> = Arc::default();
    let shared = totals.clone();
    let provider = Provider::by_guid(KERNEL_NETWORK)
        .any(NET_KEYWORDS)
        .add_callback(move |r: &EventRecord, sl: &SchemaLocator| {
            // The event says which process; the header is often System.
            let id = r.event_id();
            let (received, sent, op) = match id {
                11 | 27 | 43 | 59 => (true, false, ""),
                10 | 26 | 42 | 58 => (false, true, ""),
                12 | 28 => (false, false, "connect"),
                15 | 31 => (false, false, "accept"),
                13 | 29 => (false, false, "disconnect"),
                _ => return,
            };
            let Ok(schema) = sl.event_schema(r) else { return };
            let p = Parser::create(r, &schema);
            let Ok(pid) = p.try_parse::<u32>("PID") else { return };
            if received || sent {
                let size = u64::from(p.try_parse::<u32>("size").unwrap_or(0));
                if let Ok(mut t) = shared.lock() {
                    let e = t.entry(pid).or_default();
                    if received {
                        e.0 += size;
                    } else {
                        e.1 += size;
                    }
                }
                return;
            }
            if let Ok(s) = SINK.lock() {
                if let Some(b) = s.as_ref() {
                    let ip = p.try_parse::<IpAddr>("daddr").map(|a| a.to_string()).unwrap_or_default();
                    // Network byte order, whatever the schema says.
                    let port = p.try_parse::<u16>("dport").map(u16::swap_bytes).unwrap_or(0);
                    if let Ok(mut b) = b.lock() {
                        b.push(Activity::new(pid, Class::Network, op, format!("{ip}:{port}")));
                    }
                }
            }
        })
        .build();
    let trace = start("procwatch-traffic", vec![provider])?;
    let _ = std::thread::Builder::new().name("traffic".into()).spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let now = totals
                .lock()
                .map(|mut t| {
                    // Exited processes' entries; rates only need the live ones.
                    if t.len() > MAX_TRAFFIC_PIDS {
                        t.clear();
                    }
                    t.clone()
                })
                .unwrap_or_default();
            if !now.is_empty() && tx.send(WorkerMsg::Traffic(now)).is_err() {
                return;
            }
        }
    });
    Ok(trace)
}

pub fn start_activity(batcher: SharedBatcher) -> Result<UserTrace, String> {
    let files = batcher.clone();
    let mut open_files: HashMap<u64, String> = HashMap::new();
    let file = Provider::by_guid(KERNEL_FILE)
        .any(FILE_KEYWORDS)
        .add_callback(move |r: &EventRecord, sl: &SchemaLocator| {
            let id = r.event_id();
            if !matches!(id, 12 | 14 | 15 | 16 | 17 | 26 | 27 | 30) {
                return;
            }
            let Ok(schema) = sl.event_schema(r) else { return };
            let p = Parser::create(r, &schema);
            let pid = r.process_id();
            let event = match id {
                12 | 30 => {
                    let name = dos_path(&text(&p, &["FileName", "OpenPath"]));
                    if open_files.len() >= MAX_OBJECTS {
                        open_files.clear();
                    }
                    if let Some(obj) = pointer(&p, "FileObject") {
                        open_files.insert(obj, name.clone());
                    }
                    Activity::new(pid, Class::File, if id == 30 { "create" } else { "open" }, name)
                }
                14 => {
                    if let Some(obj) = pointer(&p, "FileObject") {
                        open_files.remove(&obj);
                    }
                    return;
                }
                15 | 16 => {
                    let Some(name) = pointer(&p, "FileObject").and_then(|o| open_files.get(&o)) else { return };
                    let size = u64::from(p.try_parse::<u32>("IOSize").unwrap_or(0));
                    Activity::new(pid, Class::File, if id == 15 { "read" } else { "write" }, name.clone()).with_bytes(size)
                }
                17 => {
                    // SetInformation: only the delete dispositions matter.
                    if !matches!(p.try_parse::<u32>("InfoClass"), Ok(13 | 64)) {
                        return;
                    }
                    let Some(name) = pointer(&p, "FileObject").and_then(|o| open_files.get(&o)) else { return };
                    Activity::new(pid, Class::File, "delete", name.clone())
                }
                _ => {
                    // Some builds leave the path out; the object still has one.
                    let given = dos_path(&text(&p, &["FilePath", "FileName"]));
                    let name = if given.is_empty() { pointer(&p, "FileObject").and_then(|o| open_files.get(&o).cloned()).unwrap_or_default() } else { given };
                    Activity::new(pid, Class::File, if id == 26 { "delete" } else { "rename" }, name)
                }
            };
            if let Ok(mut b) = files.lock() {
                b.push(event);
            }
        })
        .build();
    let mut keys: HashMap<u64, String> = HashMap::new();
    let registry = Provider::by_guid(KERNEL_REGISTRY)
        .add_callback(move |r: &EventRecord, sl: &SchemaLocator| {
            let id = r.event_id();
            if !matches!(id, 1 | 2 | 3 | 5 | 6) {
                return;
            }
            let Ok(schema) = sl.event_schema(r) else { return };
            let p = Parser::create(r, &schema);
            let pid = r.process_id();
            let key = pointer(&p, "KeyObject");
            let event = match id {
                1 | 2 => {
                    // Some builds name a key only when it is opened.
                    let name = text(&p, &["RelativeName", "KeyName"]);
                    if keys.len() >= MAX_OBJECTS {
                        keys.clear();
                    }
                    if let Some(k) = key {
                        keys.insert(k, name.clone());
                    }
                    // 1 is REG_CREATED_NEW_KEY; anything else opened an old one.
                    if id == 2 || p.try_parse::<u32>("Disposition").unwrap_or(0) != 1 {
                        return;
                    }
                    Activity::new(pid, Class::Registry, "create key", registry_path(&name))
                }
                _ => {
                    let named = text(&p, &["KeyName"]);
                    let name = if named.is_empty() { key.and_then(|k| keys.get(&k).cloned()).unwrap_or_default() } else { named };
                    let path = registry_path(&name);
                    match id {
                        3 => Activity::new(pid, Class::Registry, "delete key", path),
                        5 => Activity::new(pid, Class::Registry, "set value", format!("{path}\\{}", text(&p, &["ValueName"]))).with_bytes(u64::from(p.try_parse::<u32>("DataSize").unwrap_or(0))),
                        _ => Activity::new(pid, Class::Registry, "delete value", format!("{path}\\{}", text(&p, &["ValueName"]))),
                    }
                }
            };
            if let Ok(mut b) = batcher.lock() {
                b.push(event);
            }
        })
        .build();
    start("procwatch-activity", vec![file, registry])
}
