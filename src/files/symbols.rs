//! Turning code addresses into `module!function+offset`, on Windows.
//!
//! Addresses come from the kernel (ETW stack walks). Names come from each
//! module's export table in the file on disk: no target memory is read.
//! Exports only name a DLL's public functions, so internal code resolves to
//! the nearest export before it, or to `module+offset`. Full names would
//! need symbol files from a symbol server.

#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::HashMap;
use std::sync::Arc;

use crate::files::binfmt::pe_exports;

/// Above this a 64-bit address is kernel space.
const KERNEL: u64 = 0xffff_0000_0000_0000;

/// Sorted by address within one module.
type Exports = Arc<Vec<(u32, String)>>;

#[derive(Clone)]
struct Module {
    base: u64,
    size: u64,
    name: String,
    path: String,
}

/// Format `address`, given the modules of its process.
fn describe(address: u64, modules: &[Module], exports: &mut HashMap<String, Exports>) -> String {
    if address >= KERNEL {
        return format!("kernel!{address:#x}");
    }
    let Some(m) = modules.iter().find(|m| address >= m.base && address - m.base < m.size) else {
        // Code outside any loaded file is worth seeing as such.
        return format!("<unbacked>!{address:#x}");
    };
    let rva = (address - m.base) as u32;
    let table = exports.entry(m.path.clone()).or_insert_with(|| Arc::new(read_exports(&m.path))).clone();
    match table.partition_point(|(a, _)| *a <= rva).checked_sub(1).and_then(|i| table.get(i)) {
        Some((at, name)) => format!("{}!{name}+{:#x}", m.name, rva - at),
        None => format!("{}+{rva:#x}", m.name),
    }
}

fn read_exports(path: &str) -> Vec<(u32, String)> {
    const MAX: u64 = 256 << 20;
    if std::fs::metadata(path).map_or(true, |m| m.len() > MAX) {
        return Vec::new();
    }
    std::fs::read(path).map(|b| pe_exports(&b)).unwrap_or_default()
}

/// Resolves stacks, remembering modules per process and exports per file.
#[derive(Default)]
pub struct Symbolizer {
    modules: HashMap<u32, Vec<Module>>,
    exports: HashMap<String, Exports>,
}

impl Symbolizer {
    pub fn resolve(&mut self, pid: u32, stack: &[u64]) -> Vec<String> {
        if !self.modules.contains_key(&pid) {
            if self.modules.len() >= 4096 {
                self.modules.clear();
            }
            self.modules.insert(pid, modules_of(pid));
        }
        let modules = self.modules.get(&pid).cloned().unwrap_or_default();
        stack.iter().map(|a| describe(*a, &modules, &mut self.exports)).collect()
    }
}

#[cfg(windows)]
fn modules_of(pid: u32) -> Vec<Module> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32};
    let text = |w: &[u16]| String::from_utf16_lossy(&w[..w.iter().position(|c| *c == 0).unwrap_or(w.len())]);
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: MODULEENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        let mut ok = Module32FirstW(snap, &mut e);
        while ok != 0 {
            out.push(Module { base: e.modBaseAddr as u64, size: u64::from(e.modBaseSize), name: text(&e.szModule), path: text(&e.szExePath) });
            ok = Module32NextW(snap, &mut e);
        }
        CloseHandle(snap);
    }
    out
}

#[cfg(not(windows))]
fn modules_of(_pid: u32) -> Vec<Module> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_become_names() {
        let modules = vec![Module { base: 0x1000_0000, size: 0x10000, name: "a.dll".into(), path: "a".into() }];
        let mut e: HashMap<String, Exports> = HashMap::new();
        e.insert("a".into(), Arc::new(vec![(0x100, "First".into()), (0x200, "Second".into())]));
        assert_eq!(describe(0x1000_0210, &modules, &mut e), "a.dll!Second+0x10");
        assert_eq!(describe(0x1000_0100, &modules, &mut e), "a.dll!First+0x0");
        assert_eq!(describe(0x1000_0050, &modules, &mut e), "a.dll+0x50", "before any export");
        assert_eq!(describe(0x2000_0000, &modules, &mut e), "<unbacked>!0x20000000");
        assert!(describe(0xffff_f800_0000_0000, &modules, &mut e).starts_with("kernel!"));
    }
}
