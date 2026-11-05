//! ETW sources for activity capture: Kernel-File and Kernel-Registry.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrisetw::native::ExtendedDataItem;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{Provider, TraceFlags};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;

use crate::activity::filter::CaptureConfig;
use crate::activity::{ntstatus, Activity, Class, SharedBatcher};
use crate::common::etw::{dos_path, pointer, start, text};
use crate::common::paths::registry_path;
use crate::files::symbols::Symbolizer;

pub const KERNEL_FILE: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";
pub const KERNEL_REGISTRY: &str = "70EB4F03-C1DE-4F73-A051-33D13D5413BD";
pub const KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";

/// Kernel-File keywords: FILEIO (for close), OP_END (status), CREATE, READ, WRITE,
/// DELETE_PATH, RENAME_SETLINK_PATH, CREATE_NEW_FILE.
const FILE_KEYWORDS: u64 = 0x20 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000;

/// Open objects remembered for naming later events; a session that misses
/// closes must not grow without limit.
const MAX_OBJECTS: usize = 200_000;

/// How long an operation waits for its result. Asynchronous requests can
/// outlive this, and a build may not report some at all: the operation is
/// still worth showing without one.
const RESULT_WAIT: Duration = Duration::from_secs(2);

/// The call stack the kernel attached to an event, if any.
fn stack_of(r: &EventRecord) -> Option<Vec<u64>> {
    r.extended_data().iter().find_map(|d| match d.to_extended_data_item() {
        ExtendedDataItem::StackTrace64(s) => Some(s.addresses().to_vec()),
        _ => None,
    })
}

/// An ETW time as local time.
fn stamp(r: &EventRecord) -> chrono::DateTime<chrono::Local> {
    const UNIX_FROM_1601: i64 = 11_644_473_600 * 10_000_000;
    let ticks = r.raw_timestamp() - UNIX_FROM_1601;
    chrono::DateTime::from_timestamp(ticks.div_euclid(10_000_000), (ticks.rem_euclid(10_000_000) * 100) as u32)
        .map_or_else(chrono::Local::now, |t| t.with_timezone(&chrono::Local))
}

type Pending = Arc<Mutex<HashMap<u64, (Instant, Activity)>>>;

fn file_events(files: SharedBatcher, pending: Pending, want_stacks: bool) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    let mut open_files: HashMap<u64, String> = HashMap::new();
    let mut swept = Instant::now();
    let mut file_symbols = Symbolizer::default();
    move |r: &EventRecord, sl: &SchemaLocator| {
            let id = r.event_id();
            if !matches!(id, 12 | 14 | 15 | 16 | 17 | 24 | 26 | 27 | 30) {
                return;
            }
            let Ok(schema) = sl.event_schema(r) else { return };
            let p = Parser::create(r, &schema);
            let pid = r.process_id();
            let Ok(mut pending) = pending.lock() else { return };
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
                24 => {
                    // OperationEnd: the result of a request we're holding.
                    let Some((_, mut event)) = pointer(&p, "Irp").and_then(|i| pending.remove(&i)) else { return };
                    event.status = p.try_parse::<u32>("Status").ok().map(ntstatus);
                    if let Ok(mut b) = files.lock() {
                        b.push(event);
                    }
                    return;
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
            let mut event = event;
            event.time = stamp(r);
            if want_stacks {
                event.stack = stack_of(r).map(|s| Arc::new(file_symbols.resolve(pid, &s)));
            }
            let now = Instant::now();
            // Late results and unanswered requests still get shown.
            let mut ready = Vec::new();
            if pending.len() >= MAX_OBJECTS || now.duration_since(swept) >= RESULT_WAIT / 2 {
                swept = now;
                let full = pending.len() >= MAX_OBJECTS;
                ready.extend(pending.extract_if(|_, held| full || now.duration_since(held.0) >= RESULT_WAIT).map(|(_, held)| held.1));
            }
            match pointer(&p, "Irp").filter(|i| *i != 0) {
                Some(irp) => {
                    if let Some((_, older)) = pending.insert(irp, (now, event)) {
                        ready.push(older);
                    }
                }
                None => ready.push(event),
            }
            if ready.is_empty() {
                return;
            }
            if let Ok(mut b) = files.lock() {
                ready.into_iter().for_each(|e| b.push(e));
            }
    }
}

fn registry_events(batcher: SharedBatcher, want_stacks: bool, reads: bool) -> impl FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    let mut keys: HashMap<u64, String> = HashMap::new();
    let mut reg_symbols = Symbolizer::default();
    move |r: &EventRecord, sl: &SchemaLocator| {
            let id = r.event_id();
            let read = matches!(id, 4 | 7);
            if !matches!(id, 1 | 2 | 3 | 5 | 6) && !(reads && read) {
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
                    let created = id == 1 && p.try_parse::<u32>("Disposition").unwrap_or(0) == 1;
                    if !created && !(reads && id == 2) {
                        return;
                    }
                    if !created {
                        let mut e = Activity::new(pid, Class::Registry, "open key", registry_path(&name));
                        e.time = stamp(r);
                        e.status = p.try_parse::<u32>("Status").ok().map(ntstatus);
                        if let Ok(mut b) = batcher.lock() {
                            b.push(e);
                        }
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
                        4 => Activity::new(pid, Class::Registry, "query key", path),
                        7 => Activity::new(pid, Class::Registry, "query value", format!("{path}\\{}", text(&p, &["ValueName"]))),
                        5 => Activity::new(pid, Class::Registry, "set value", format!("{path}\\{}", text(&p, &["ValueName"]))).with_bytes(u64::from(p.try_parse::<u32>("DataSize").unwrap_or(0))),
                        _ => Activity::new(pid, Class::Registry, "delete value", format!("{path}\\{}", text(&p, &["ValueName"]))),
                    }
                }
            };
            let mut event = event;
            event.time = stamp(r);
            event.status = p.try_parse::<u32>("Status").ok().map(ntstatus);
            if want_stacks {
                event.stack = stack_of(r).map(|s| Arc::new(reg_symbols.resolve(pid, &s)));
            }
            if let Ok(mut b) = batcher.lock() {
                b.push(event);
            }
    }
}

pub fn start_activity(batcher: SharedBatcher, config: &CaptureConfig) -> Result<UserTrace, String> {
    let flags = if config.stacks { TraceFlags::EVENT_ENABLE_PROPERTY_STACK_TRACE } else { TraceFlags::empty() };
    let pending = Pending::default();
    let file = Provider::by_guid(KERNEL_FILE).any(FILE_KEYWORDS).trace_flags(flags).add_callback(file_events(batcher.clone(), pending, config.stacks)).build();
    let registry = Provider::by_guid(KERNEL_REGISTRY).trace_flags(flags).add_callback(registry_events(batcher, config.stacks, config.registry_reads)).build();
    start("procwatch-activity", vec![file, registry])
}

/// Everything in an ETL file, as activity; returns process names by pid.
pub fn read_etl(path: &std::path::Path, out: crate::common::emit::Emit<Vec<Activity>>) -> Result<HashMap<u32, String>, String> {
    use ferrisetw::trace::FileTrace;
    use ferrisetw::GUID;
    let batcher: SharedBatcher = Arc::new(Mutex::new(crate::activity::Batcher::offline(out)));
    let pending = Pending::default();
    let (mut files, mut registry) = (file_events(batcher.clone(), pending.clone(), false), registry_events(batcher.clone(), false, true));
    let (file_id, reg_id, proc_id) = (GUID::from(KERNEL_FILE), GUID::from(KERNEL_REGISTRY), GUID::from(KERNEL_PROCESS));
    let names = Arc::new(Mutex::new(HashMap::new()));
    let seen = names.clone();
    let starts = batcher.clone();
    FileTrace::new(path.to_path_buf(), move |r: &EventRecord, sl: &SchemaLocator| {
        let id = r.provider_id();
        if id == file_id {
            files(r, sl);
        } else if id == reg_id {
            registry(r, sl);
        } else if id == proc_id && r.event_id() == 1 {
            let Ok(schema) = sl.event_schema(r) else { return };
            let p = Parser::create(r, &schema);
            let Ok(pid) = p.try_parse::<u32>("ProcessID") else { return };
            let image = dos_path(&text(&p, &["ImageName"]));
            let name = image.rsplit('\\').next().unwrap_or("").to_string();
            let mut started = Activity::new(pid, Class::Process, "start", image);
            started.time = stamp(r);
            if let (Ok(mut n), Ok(mut b)) = (seen.lock(), starts.lock()) {
                n.insert(pid, name);
                b.push(started);
            }
        }
    })
    .start_and_process()
    .map_err(|e| format!("{}: {e:?}", path.display()))?;
    if let Ok(mut b) = batcher.lock() {
        pending.lock().map(|mut p| p.drain().for_each(|(_, held)| b.push(held.1))).ok();
        b.flush();
    }
    let names = names.lock().map(|n| n.clone()).unwrap_or_default();
    Ok(names)
}
