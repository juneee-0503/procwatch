//! ETW sources for activity capture: Kernel-File and Kernel-Registry.

use std::collections::HashMap;

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;

use crate::activity::{Activity, Class, SharedBatcher};
use crate::common::etw::{dos_path, pointer, start, text};
use crate::common::paths::registry_path;

const KERNEL_FILE: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";
const KERNEL_REGISTRY: &str = "70EB4F03-C1DE-4F73-A051-33D13D5413BD";

/// Kernel-File keywords: FILEIO (for close), CREATE, READ, WRITE,
/// DELETE_PATH, RENAME_SETLINK_PATH, CREATE_NEW_FILE.
const FILE_KEYWORDS: u64 = 0x20 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000;

/// Open objects remembered for naming later events; a session that misses
/// closes must not grow without limit.
const MAX_OBJECTS: usize = 200_000;

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
