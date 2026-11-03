//! AppCompatCache ("ShimCache") parser for Windows 10 / 11, where every
//! entry starts with the signature "10ts".
//!
//! The timestamp is the file's last-modified time from when it was seen,
//! not an execution time, and on Windows 10+ an entry alone does not prove
//! that the program ran.

use chrono::{DateTime, Local};

use super::{filetime, u16_at, u32_at, u64_at, utf16z, Artifact};

#[derive(Debug, Clone)]
pub struct Entry {
    /// 0 = most recently added.
    pub position: usize,
    pub path: String,
    pub modified: Option<DateTime<Local>>,
}

const MAX_ENTRIES: usize = 4096;

pub fn parse(b: &[u8]) -> Result<Vec<Entry>, String> {
    let header = u32_at(b, 0).ok_or("value is empty")? as usize;
    if !(header == 0x30 || header == 0x34) {
        return Err(format!("unsupported AppCompatCache layout (header size {header:#x}; Windows 10/11 expected)"));
    }
    let mut out = Vec::new();
    let mut off = header;
    while off + 12 <= b.len() && out.len() < MAX_ENTRIES {
        if b.get(off..off + 4) != Some(b"10ts") {
            break;
        }
        let entry_size = u32_at(b, off + 8).ok_or("truncated entry")? as usize;
        let path_len = u16_at(b, off + 12).ok_or("truncated entry")? as usize;
        let path = utf16z(b.get(off + 14..off + 14 + path_len).ok_or("truncated path")?);
        let modified = u64_at(b, off + 14 + path_len).and_then(filetime);
        out.push(Entry { position: out.len(), path, modified });
        let next = off + 12 + entry_size;
        if next <= off {
            break;
        }
        off = next;
    }
    Ok(out)
}

impl Entry {
    pub fn artifact(&self, source: &str) -> Artifact {
        Artifact {
            kind: "shimcache",
            time: self.modified,
            subject: self.path.clone(),
            detail: format!("position {} (0 = most recent) · time is the file's mtime, not a run time", self.position),
            source: source.into(),
            user: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, ft: u64) -> Vec<u8> {
        let p: Vec<u8> = path.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut body = Vec::new();
        body.extend((p.len() as u16).to_le_bytes());
        body.extend(&p);
        body.extend(ft.to_le_bytes());
        body.extend(2u32.to_le_bytes());
        body.extend([0xAA, 0xBB]);
        let mut e = b"10ts".to_vec();
        e.extend(0u32.to_le_bytes());
        e.extend((body.len() as u32).to_le_bytes());
        e.extend(body);
        e
    }

    #[test]
    fn parses_win10_entries() {
        let mut v = vec![0u8; 0x34];
        v[0..4].copy_from_slice(&0x34u32.to_le_bytes());
        v.extend(entry("C:\\Users\\a\\evil.exe", 132_223_104_000_000_000));
        v.extend(entry("C:\\Windows\\notepad.exe", 0));
        let e = parse(&v).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].path, "C:\\Users\\a\\evil.exe");
        assert_eq!(e[0].modified.unwrap().timestamp(), 1_577_836_800);
        assert!(e[1].modified.is_none());
        assert!(parse(&[1, 0, 0, 0]).is_err());
    }
}
