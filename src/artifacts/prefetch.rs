//! Windows Prefetch (.pf) parser: formats 17 (XP/2003), 23 (Vista/7),
//! 26 (8/8.1), 30 and 31 (10/11), including the compressed "MAM"
//! container used since Windows 10.

use chrono::{DateTime, Local};

use super::{filetime, u32_at, u64_at, utf16z, xpress, Artifact};

#[derive(Debug, Clone)]
pub struct Volume {
    pub device: String,
    pub serial: u32,
    pub created: Option<DateTime<Local>>,
}

#[derive(Debug, Clone)]
pub struct Prefetch {
    pub version: u32,
    pub exe: String,
    pub hash: u32,
    pub run_count: u32,
    /// Most recent first.
    pub last_runs: Vec<DateTime<Local>>,
    /// Files referenced in the first seconds of execution.
    pub files: Vec<String>,
    pub volumes: Vec<Volume>,
}

const MAX_FILES: usize = 4096;

pub fn decompress(data: &[u8]) -> Result<Vec<u8>, String> {
    if !data.starts_with(b"MAM") {
        return Ok(data.to_vec());
    }
    let size = u32_at(data, 4).ok_or("truncated MAM header")? as usize;
    // 0x84 variant carries a CRC32 before the payload.
    let payload = if data.get(3).is_some_and(|b| b & 0x80 != 0) { data.get(12..) } else { data.get(8..) }.ok_or("truncated MAM header")?;
    xpress::decompress(payload, size)
}

pub fn parse(raw: &[u8]) -> Result<Prefetch, String> {
    let d = decompress(raw)?;
    if d.get(4..8) != Some(b"SCCA") {
        return Err("not a prefetch file (no SCCA signature)".into());
    }
    let version = u32_at(&d, 0).ok_or("truncated")?;
    if ![17, 23, 26, 30, 31].contains(&version) {
        return Err(format!("unsupported prefetch version {version}"));
    }
    let exe = utf16z(d.get(16..76).ok_or("truncated")?);
    let hash = u32_at(&d, 76).unwrap_or(0);
    let metrics_off = u32_at(&d, 84).unwrap_or(0);
    let names_off = u32_at(&d, 100).unwrap_or(0) as usize;
    let names_size = u32_at(&d, 104).unwrap_or(0) as usize;
    let vol_off = u32_at(&d, 108).unwrap_or(0) as usize;
    let vol_count = u32_at(&d, 112).unwrap_or(0) as usize;
    let (times_at, n_times, count_at) = match version {
        17 => (120, 1, 144),
        23 => (128, 1, 152),
        26 => (128, 8, 208),
        // Two layouts exist for 30: the newer has a smaller header.
        _ => (128, 8, if metrics_off == 0x130 { 208 } else { 200 }),
    };
    let mut last_runs: Vec<DateTime<Local>> = (0..n_times).filter_map(|i| u64_at(&d, times_at + i * 8).and_then(filetime)).collect();
    last_runs.sort_by(|a, b| b.cmp(a));
    let run_count = u32_at(&d, count_at).unwrap_or(0);

    let mut files = Vec::new();
    if let Some(block) = d.get(names_off..names_off.saturating_add(names_size)) {
        let units: Vec<u16> = block.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        for s in units.split(|u| *u == 0).filter(|s| !s.is_empty()).take(MAX_FILES) {
            files.push(String::from_utf16_lossy(s));
        }
    }
    let entry = match version {
        17 => 40,
        30 | 31 => 96,
        _ => 104,
    };
    let mut volumes = Vec::new();
    for i in 0..vol_count.min(32) {
        let base = vol_off + i * entry;
        let (Some(path_off), Some(chars)) = (u32_at(&d, base), u32_at(&d, base + 4)) else { break };
        let start = vol_off + path_off as usize;
        let device = d.get(start..start + chars as usize * 2).map(utf16z).unwrap_or_default();
        volumes.push(Volume { device, serial: u32_at(&d, base + 16).unwrap_or(0), created: u64_at(&d, base + 8).and_then(filetime) });
    }
    Ok(Prefetch { version, exe, hash, run_count, last_runs, files, volumes })
}

impl Prefetch {
    /// Full path of the executable, from the referenced-file list.
    pub fn exe_path(&self) -> String {
        let want = format!("\\{}", self.exe.to_uppercase());
        self.files.iter().find(|f| f.to_uppercase().ends_with(&want)).cloned().unwrap_or_else(|| self.exe.clone())
    }

    /// One artifact per recorded run time (or one without a time).
    pub fn artifacts(&self, source: &str) -> Vec<Artifact> {
        let path = self.exe_path();
        let detail = format!(
            "run {} time{} · {} files referenced · volume {} · format {} · hash {:08X}",
            self.run_count,
            if self.run_count == 1 { "" } else { "s" },
            self.files.len(),
            self.volumes
                .first()
                .map(|v| format!("{} serial {:08X}{}", v.device, v.serial, v.created.map(|t| format!(" created {}", t.format("%Y-%m-%d"))).unwrap_or_default()))
                .unwrap_or_default(),
            self.version,
            self.hash
        );
        let mk = |time| Artifact { kind: "prefetch", time, subject: path.clone(), detail: detail.clone(), source: source.into(), user: None };
        if self.last_runs.is_empty() {
            vec![mk(None)]
        } else {
            self.last_runs.iter().map(|t| mk(Some(*t))).collect()
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A synthetic version-30 prefetch file.
    pub fn sample() -> Vec<u8> {
        let mut d = vec![0u8; 0x400];
        d[0..4].copy_from_slice(&30u32.to_le_bytes());
        d[4..8].copy_from_slice(b"SCCA");
        let name: Vec<u8> = "EVIL.EXE".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        d[16..16 + name.len()].copy_from_slice(&name);
        d[76..80].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        d[84..88].copy_from_slice(&0x130u32.to_le_bytes());
        // Two run times: 2020-01-01 and 2020-01-02.
        d[128..136].copy_from_slice(&132_223_104_000_000_000u64.to_le_bytes());
        d[136..144].copy_from_slice(&132_223_968_000_000_000u64.to_le_bytes());
        d[208..212].copy_from_slice(&5u32.to_le_bytes());
        let names: Vec<u8> = "\\VOLUME{1}\\WINDOWS\\SYSTEM32\\NTDLL.DLL\0\\VOLUME{1}\\USERS\\A\\APPDATA\\EVIL.EXE\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        d[100..104].copy_from_slice(&0x200u32.to_le_bytes());
        d[104..108].copy_from_slice(&(names.len() as u32).to_le_bytes());
        d[0x200..0x200 + names.len()].copy_from_slice(&names);
        // One volume at 0x300 with its device path right after the entry.
        d[108..112].copy_from_slice(&0x300u32.to_le_bytes());
        d[112..116].copy_from_slice(&1u32.to_le_bytes());
        let dev: Vec<u8> = "\\VOLUME{1}".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        d[0x300..0x304].copy_from_slice(&96u32.to_le_bytes());
        d[0x304..0x308].copy_from_slice(&10u32.to_le_bytes());
        d[0x310..0x314].copy_from_slice(&0x1234ABCDu32.to_le_bytes());
        d[0x300 + 96..0x300 + 96 + dev.len()].copy_from_slice(&dev);
        d
    }

    #[test]
    fn parses_uncompressed_v30() {
        let p = parse(&sample()).unwrap();
        assert_eq!(p.exe, "EVIL.EXE");
        assert_eq!(p.run_count, 5);
        assert_eq!(p.last_runs.len(), 2);
        assert!(p.last_runs[0] > p.last_runs[1], "newest first");
        assert_eq!(p.exe_path(), "\\VOLUME{1}\\USERS\\A\\APPDATA\\EVIL.EXE");
        assert_eq!(p.volumes[0].serial, 0x1234ABCD);
        assert_eq!(p.volumes[0].device, "\\VOLUME{1}");
        assert_eq!(p.artifacts("x.pf").len(), 2);
    }

    #[test]
    fn parses_mam_compressed() {
        use crate::artifacts::xpress::tests::{encode, Op};
        let raw = sample();
        let enc = encode(&raw.iter().map(|b| Op::Lit(*b)).collect::<Vec<_>>());
        let mut mam = b"MAM\x04".to_vec();
        mam.extend((raw.len() as u32).to_le_bytes());
        mam.extend(enc);
        let p = parse(&mam).unwrap();
        assert_eq!(p.exe, "EVIL.EXE");
        assert_eq!(p.run_count, 5);
        assert!(parse(b"MAM\x04\x10\x00\x00\x00garbage").is_err());
        assert!(parse(b"not a prefetch").is_err());
    }
}
