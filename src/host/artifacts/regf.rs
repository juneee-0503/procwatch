//! Read-only parser for Windows registry hive files ("regf"), enough to
//! walk keys and read values from offline copies of SYSTEM, SOFTWARE,
//! NTUSER.DAT or Amcache.hve on any OS.
//!
//! Limits: transaction logs (.LOG1/.LOG2) are not replayed, so a hive
//! copied from a running system may miss its most recent changes; deleted
//! keys are not recovered.

use chrono::{DateTime, Local};

use super::{filetime, u16_at, u32_at, u64_at};

const HBIN_START: usize = 4096;
const MAX_DEPTH: usize = 64;

pub struct Hive {
    data: Vec<u8>,
    root: usize,
}

#[derive(Clone, Copy)]
pub struct Key<'a> {
    hive: &'a Hive,
    /// Offset of the nk cell's data in the file.
    at: usize,
}

pub struct Value {
    pub name: String,
    pub kind: u32,
    pub data: Vec<u8>,
}

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_DWORD: u32 = 4;
pub const REG_QWORD: u32 = 11;

impl Hive {
    pub fn parse(data: Vec<u8>) -> Result<Hive, String> {
        if data.get(0..4) != Some(b"regf") {
            return Err("not a registry hive (no regf signature)".into());
        }
        let root_off = u32_at(&data, 0x24).ok_or("truncated header")? as usize;
        let h = Hive { root: 0, data };
        let root = h.cell(root_off).ok_or("root key is outside the file")?;
        if h.data.get(root..root + 2) != Some(b"nk") {
            return Err("root cell is not a key".into());
        }
        Ok(Hive { root, ..h })
    }

    /// File offset of a cell's data, from a hive-relative cell offset.
    fn cell(&self, off: usize) -> Option<usize> {
        if off == 0 || off == 0xFFFF_FFFF {
            return None;
        }
        let at = HBIN_START.checked_add(off)?;
        let size = u32_at(&self.data, at)? as i32;
        let len = size.unsigned_abs() as usize;
        (len >= 4 && at + len <= self.data.len()).then_some(at + 4)
    }

    fn cell_len(&self, data_at: usize) -> usize {
        u32_at(&self.data, data_at - 4).map_or(0, |s| (s as i32).unsigned_abs() as usize).saturating_sub(4)
    }

    pub fn root(&self) -> Key<'_> {
        Key { hive: self, at: self.root }
    }

    /// Key by backslash path from the root ("ControlSet001\\Services\\bam").
    pub fn key(&self, path: &str) -> Option<Key<'_>> {
        let mut k = self.root();
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            k = k.subkey(part)?;
        }
        Some(k)
    }
}

fn utf16(b: &[u8]) -> String {
    String::from_utf16_lossy(&b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect::<Vec<_>>())
}

impl<'a> Key<'a> {
    fn d(&self) -> &'a [u8] {
        &self.hive.data
    }

    pub fn name(&self) -> String {
        let len = u16_at(self.d(), self.at + 0x48).unwrap_or(0) as usize;
        let flags = u16_at(self.d(), self.at + 2).unwrap_or(0);
        let raw = self.d().get(self.at + 0x4c..self.at + 0x4c + len).unwrap_or(&[]);
        if flags & 0x20 != 0 {
            raw.iter().map(|b| *b as char).collect()
        } else {
            utf16(raw)
        }
    }

    pub fn last_write(&self) -> Option<DateTime<Local>> {
        u64_at(self.d(), self.at + 4).and_then(filetime)
    }

    pub fn subkeys(&self) -> Vec<Key<'a>> {
        let mut out = Vec::new();
        if u32_at(self.d(), self.at + 0x14).unwrap_or(0) == 0 {
            return out;
        }
        if let Some(list) = u32_at(self.d(), self.at + 0x1c).and_then(|o| self.hive.cell(o as usize)) {
            self.collect_list(list, &mut out, 0);
        }
        out
    }

    fn collect_list(&self, list: usize, out: &mut Vec<Key<'a>>, depth: usize) {
        if depth > MAX_DEPTH || out.len() > 100_000 {
            return;
        }
        let d = self.d();
        let n = u16_at(d, list + 2).unwrap_or(0) as usize;
        let push = |off: u32, out: &mut Vec<Key<'a>>| {
            if let Some(at) = self.hive.cell(off as usize).filter(|at| d.get(*at..*at + 2) == Some(b"nk")) {
                out.push(Key { hive: self.hive, at });
            }
        };
        match d.get(list..list + 2) {
            Some(b"lf") | Some(b"lh") => (0..n).filter_map(|i| u32_at(d, list + 4 + i * 8)).for_each(|o| push(o, out)),
            Some(b"li") => (0..n).filter_map(|i| u32_at(d, list + 4 + i * 4)).for_each(|o| push(o, out)),
            Some(b"ri") => {
                for o in (0..n).filter_map(|i| u32_at(d, list + 4 + i * 4)) {
                    if let Some(sub) = self.hive.cell(o as usize) {
                        self.collect_list(sub, out, depth + 1);
                    }
                }
            }
            _ => {}
        }
    }

    pub fn subkey(&self, name: &str) -> Option<Key<'a>> {
        self.subkeys().into_iter().find(|k| k.name().eq_ignore_ascii_case(name))
    }

    pub fn values(&self) -> Vec<Value> {
        let d = self.d();
        let count = u32_at(d, self.at + 0x24).unwrap_or(0) as usize;
        let Some(list) = u32_at(d, self.at + 0x28).and_then(|o| self.hive.cell(o as usize)) else { return Vec::new() };
        (0..count.min(65_536))
            .filter_map(|i| u32_at(d, list + i * 4))
            .filter_map(|o| self.hive.cell(o as usize))
            .filter(|at| d.get(*at..*at + 2) == Some(b"vk"))
            .map(|at| self.value_at(at))
            .collect()
    }

    fn value_at(&self, at: usize) -> Value {
        let d = self.d();
        let name_len = u16_at(d, at + 2).unwrap_or(0) as usize;
        let size_raw = u32_at(d, at + 4).unwrap_or(0);
        let data_off = u32_at(d, at + 8).unwrap_or(0);
        let kind = u32_at(d, at + 12).unwrap_or(0);
        let flags = u16_at(d, at + 16).unwrap_or(0);
        let raw_name = d.get(at + 20..at + 20 + name_len).unwrap_or(&[]);
        let name = if flags & 1 != 0 { raw_name.iter().map(|b| *b as char).collect() } else { utf16(raw_name) };
        let size = (size_raw & 0x7FFF_FFFF) as usize;
        let data = if size_raw & 0x8000_0000 != 0 {
            // Small data lives in the offset field itself.
            data_off.to_le_bytes()[..size.min(4)].to_vec()
        } else {
            self.read_data(data_off as usize, size)
        };
        Value { name, kind, data }
    }

    fn read_data(&self, off: usize, size: usize) -> Vec<u8> {
        let d = self.d();
        let Some(at) = self.hive.cell(off) else { return Vec::new() };
        if d.get(at..at + 2) == Some(b"db") && size > 16344 {
            // Big data: a list of segments.
            let n = u16_at(d, at + 2).unwrap_or(0) as usize;
            let Some(list) = u32_at(d, at + 4).and_then(|o| self.hive.cell(o as usize)) else { return Vec::new() };
            let mut out = Vec::with_capacity(size);
            for seg in (0..n).filter_map(|i| u32_at(d, list + i * 4)).filter_map(|o| self.hive.cell(o as usize)) {
                let take = self.hive.cell_len(seg).min(16344).min(size - out.len());
                out.extend_from_slice(d.get(seg..seg + take).unwrap_or(&[]));
                if out.len() >= size {
                    break;
                }
            }
            return out;
        }
        d.get(at..at + size.min(self.hive.cell_len(at))).unwrap_or(&[]).to_vec()
    }

    pub fn value(&self, name: &str) -> Option<Value> {
        self.values().into_iter().find(|v| v.name.eq_ignore_ascii_case(name))
    }

    /// A value as text (REG_SZ / REG_EXPAND_SZ / numbers).
    pub fn text(&self, name: &str) -> Option<String> {
        self.value(name).map(|v| v.text())
    }
}

impl Value {
    pub fn text(&self) -> String {
        match self.kind {
            REG_SZ | REG_EXPAND_SZ => utf16(&self.data).trim_end_matches('\0').to_string(),
            REG_DWORD => u32_at(&self.data, 0).map(|v| v.to_string()).unwrap_or_default(),
            REG_QWORD => u64_at(&self.data, 0).map(|v| v.to_string()).unwrap_or_default(),
            _ => self.data.iter().map(|b| format!("{b:02x}")).collect(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds small hives for tests: cells are appended to one hbin.
    pub struct Builder {
        pub cells: Vec<u8>,
    }

    impl Builder {
        pub fn new() -> Builder {
            Builder { cells: Vec::new() }
        }
        /// Append a cell, return its hive-relative offset (after the
        /// 32-byte hbin header).
        pub fn cell(&mut self, data: &[u8]) -> u32 {
            let off = 32 + self.cells.len();
            let len = (data.len() + 4).div_ceil(8) * 8;
            self.cells.extend(&(-(len as i32)).to_le_bytes());
            self.cells.extend(data);
            self.cells.resize(self.cells.len() + len - 4 - data.len(), 0);
            off as u32
        }
        pub fn value(&mut self, name: &str, kind: u32, data: &[u8]) -> u32 {
            let (size, off) = if data.len() <= 4 {
                let mut b = [0u8; 4];
                b[..data.len()].copy_from_slice(data);
                (data.len() as u32 | 0x8000_0000, u32::from_le_bytes(b))
            } else {
                (data.len() as u32, self.cell(data))
            };
            let mut vk = b"vk".to_vec();
            vk.extend((name.len() as u16).to_le_bytes());
            vk.extend(size.to_le_bytes());
            vk.extend(off.to_le_bytes());
            vk.extend(kind.to_le_bytes());
            vk.extend(1u16.to_le_bytes());
            vk.extend([0, 0]);
            vk.extend(name.as_bytes());
            self.cell(&vk)
        }
        /// Reserve a cell now (e.g. the root, which Windows places first)
        /// and fill it later with `key_into`.
        pub fn reserve(&mut self, len: usize) -> u32 {
            self.cell(&vec![0u8; len])
        }
        pub fn key_into(&mut self, slot: u32, name: &str, written: u64, subkeys: &[u32], values: &[u32]) -> u32 {
            let tmp = self.key(name, written, subkeys, values);
            let src = tmp as usize - 32;
            let len = (-i32::from_le_bytes(self.cells[src..src + 4].try_into().unwrap())) as usize;
            let data = self.cells[src + 4..src + len].to_vec();
            let dst = slot as usize - 32 + 4;
            self.cells[dst..dst + data.len()].copy_from_slice(&data);
            slot
        }
        pub fn key(&mut self, name: &str, written: u64, subkeys: &[u32], values: &[u32]) -> u32 {
            let list = if subkeys.is_empty() {
                0xFFFF_FFFF
            } else {
                let mut lf = b"lf".to_vec();
                lf.extend((subkeys.len() as u16).to_le_bytes());
                for s in subkeys {
                    lf.extend(s.to_le_bytes());
                    lf.extend([0u8; 4]);
                }
                self.cell(&lf)
            };
            let vlist = if values.is_empty() { 0xFFFF_FFFF } else { self.cell(&values.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>()) };
            let mut nk = vec![0u8; 0x4c];
            nk[0..2].copy_from_slice(b"nk");
            nk[2..4].copy_from_slice(&0x20u16.to_le_bytes());
            nk[4..12].copy_from_slice(&written.to_le_bytes());
            nk[0x14..0x18].copy_from_slice(&(subkeys.len() as u32).to_le_bytes());
            nk[0x1c..0x20].copy_from_slice(&list.to_le_bytes());
            nk[0x24..0x28].copy_from_slice(&(values.len() as u32).to_le_bytes());
            nk[0x28..0x2c].copy_from_slice(&vlist.to_le_bytes());
            nk[0x48..0x4a].copy_from_slice(&(name.len() as u16).to_le_bytes());
            nk.extend(name.as_bytes());
            self.cell(&nk)
        }
        pub fn finish(self, root: u32) -> Vec<u8> {
            let mut f = vec![0u8; HBIN_START];
            f[0..4].copy_from_slice(b"regf");
            f[0x24..0x28].copy_from_slice(&root.to_le_bytes());
            let mut hbin = vec![0u8; 32];
            hbin[0..4].copy_from_slice(b"hbin");
            hbin.extend(self.cells);
            let size = hbin.len().div_ceil(4096) * 4096;
            hbin.resize(size, 0);
            hbin[8..12].copy_from_slice(&(size as u32).to_le_bytes());
            f.extend(hbin);
            f
        }
    }

    pub fn wide(s: &str) -> Vec<u8> {
        s.encode_utf16().chain(std::iter::once(0)).flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn walks_keys_and_values() {
        let mut b = Builder::new();
        let v1 = b.value("Path", REG_SZ, &wide("C:\\x.exe"));
        let v2 = b.value("Count", REG_DWORD, &7u32.to_le_bytes());
        let child = b.key("Child", 132_223_104_000_000_000, &[], &[v1, v2]);
        let mid = b.key("Mid", 0, &[child], &[]);
        let root = b.key("ROOT", 0, &[mid], &[]);
        let h = Hive::parse(b.finish(root)).unwrap();
        let k = h.key("mid\\CHILD").unwrap();
        assert_eq!(k.name(), "Child");
        assert_eq!(k.text("path").as_deref(), Some("C:\\x.exe"));
        assert_eq!(k.text("Count").as_deref(), Some("7"));
        assert_eq!(k.last_write().unwrap().timestamp(), 1_577_836_800);
        assert!(h.key("Mid\\Nope").is_none());
        assert!(Hive::parse(vec![0; 10]).is_err());
    }
}
