//! Artifacts read from registry hive files: Amcache.hve
//! (InventoryApplicationFile) and an offline SYSTEM hive (ShimCache, BAM).

use super::regf::Hive;
use super::{filetime, shimcache, u64_at, Artifact};

/// Amcache: one entry per program file the Program Inventory saw.
pub fn amcache(h: &Hive, source: &str) -> Result<Vec<Artifact>, String> {
    let Some(inv) = h.key("Root\\InventoryApplicationFile") else {
        return Err("no Root\\InventoryApplicationFile key (pre-2017 Amcache layout is not supported)".into());
    };
    let mut out = Vec::new();
    for k in inv.subkeys() {
        let path = k.text("LowerCaseLongPath").unwrap_or_default();
        if path.is_empty() {
            continue;
        }
        // FileId is the SHA-1 of the first 31 MB, prefixed with 0000.
        let sha1 = k.text("FileId").map(|f| f.trim_start_matches("0000").to_lowercase()).unwrap_or_default();
        let mut detail = Vec::new();
        for (label, name) in [("publisher", "Publisher"), ("product", "ProductName"), ("version", "Version"), ("linked", "LinkDate"), ("size", "Size")] {
            if let Some(v) = k.text(name).filter(|v| !v.is_empty()) {
                detail.push(format!("{label} {v}"));
            }
        }
        if !sha1.is_empty() {
            detail.push(format!("sha1 {sha1}"));
        }
        out.push(Artifact { kind: "amcache", time: k.last_write(), subject: path, detail: detail.join(" · "), source: source.into(), user: None });
    }
    Ok(out)
}

/// The control set the system booted with (Select\Current), e.g. "ControlSet001".
fn control_set(h: &Hive) -> String {
    let n = h.key("Select").and_then(|k| k.value("Current")).and_then(|v| v.data.first().copied()).unwrap_or(1);
    format!("ControlSet{n:03}")
}

/// ShimCache and BAM from a SYSTEM hive.
pub fn system(h: &Hive, source: &str) -> (Vec<Artifact>, Vec<String>) {
    let cs = control_set(h);
    let mut out = Vec::new();
    let mut notes = Vec::new();
    match h.key(&format!("{cs}\\Control\\Session Manager\\AppCompatCache")).and_then(|k| k.value("AppCompatCache")) {
        Some(v) => match shimcache::parse(&v.data) {
            Ok(entries) => out.extend(entries.into_iter().map(|e| e.artifact(&format!("{source} (AppCompatCache)")))),
            Err(e) => notes.push(format!("ShimCache: {e}")),
        },
        None => notes.push("ShimCache: no AppCompatCache value".into()),
    }
    let bam = h.key(&format!("{cs}\\Services\\bam\\State\\UserSettings")).or_else(|| h.key(&format!("{cs}\\Services\\bam\\UserSettings")));
    match bam {
        Some(users) => {
            for user in users.subkeys() {
                let sid = user.name();
                for v in user.values().into_iter().filter(|v| v.data.len() >= 8 && v.name.contains('\\')) {
                    out.push(Artifact {
                        kind: "bam",
                        time: u64_at(&v.data, 0).and_then(filetime),
                        subject: v.name.clone(),
                        detail: "last run (Background Activity Moderator)".into(),
                        source: format!("{source} (bam)"),
                        user: Some(sid.clone()),
                    });
                }
            }
        }
        None => notes.push("BAM: key not present (Windows 10 1709+ only)".into()),
    }
    (out, notes)
}

#[cfg(test)]
mod tests {
    use super::super::regf::tests::{wide, Builder};
    use super::super::regf::{REG_DWORD, REG_SZ};
    use super::*;

    #[test]
    fn amcache_entries() {
        let mut b = Builder::new();
        let p = b.value("LowerCaseLongPath", REG_SZ, &wide("c:\\users\\a\\evil.exe"));
        let f = b.value("FileId", REG_SZ, &wide("0000ABCDEF"));
        let pubr = b.value("Publisher", REG_SZ, &wide("Evil Corp"));
        let e = b.key("0006abc", 132_223_104_000_000_000, &[], &[p, f, pubr]);
        let inv = b.key("InventoryApplicationFile", 0, &[e], &[]);
        let rk = b.key("Root", 0, &[inv], &[]);
        let top = b.key("{root}", 0, &[rk], &[]);
        let h = Hive::parse(b.finish(top)).unwrap();
        let a = amcache(&h, "Amcache.hve").unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].subject, "c:\\users\\a\\evil.exe");
        assert!(a[0].detail.contains("sha1 abcdef") && a[0].detail.contains("Evil Corp"));
        assert_eq!(a[0].time.unwrap().timestamp(), 1_577_836_800);
    }

    #[test]
    fn system_hive_bam_and_shimcache() {
        let mut b = Builder::new();
        let cur = b.value("Current", REG_DWORD, &2u32.to_le_bytes());
        let select = b.key("Select", 0, &[], &[cur]);
        let ft = 132_223_104_000_000_000u64.to_le_bytes();
        let mut bamv = ft.to_vec();
        bamv.extend([0u8; 16]);
        let bv = b.value("\\Device\\HarddiskVolume3\\Users\\a\\x.exe", 3, &bamv);
        let ver = b.value("Version", REG_DWORD, &1u32.to_le_bytes());
        let sid = b.key("S-1-5-21-1", 0, &[], &[bv, ver]);
        let us = b.key("UserSettings", 0, &[sid], &[]);
        let st = b.key("State", 0, &[us], &[]);
        let bam = b.key("bam", 0, &[st], &[]);
        let svc = b.key("Services", 0, &[bam], &[]);
        let cs = b.key("ControlSet002", 0, &[svc], &[]);
        let root = b.key("ROOT", 0, &[select, cs], &[]);
        let h = Hive::parse(b.finish(root)).unwrap();
        let (a, notes) = system(&h, "SYSTEM");
        assert_eq!(a.len(), 1, "{notes:?}");
        assert_eq!(a[0].kind, "bam");
        assert_eq!(a[0].user.as_deref(), Some("S-1-5-21-1"));
        assert_eq!(a[0].time.unwrap().timestamp(), 1_577_836_800);
        assert!(notes.iter().any(|n| n.contains("ShimCache")));
    }
}

#[cfg(test)]
mod dump {
    /// Writes a sample hive for cross-checking with another parser when
    /// PW_HIVE_DUMP is set (no-op otherwise).
    #[test]
    fn dump_sample_hive() {
        use super::super::regf::tests::{wide, Builder};
        use super::super::regf::REG_SZ;
        let Ok(path) = std::env::var("PW_HIVE_DUMP") else { return };
        let mut b = Builder::new();
        let slot = b.reserve(0x4c + 4);
        let p = b.value("LowerCaseLongPath", REG_SZ, &wide("c:\\users\\a\\evil.exe"));
        let big = b.value("Blob", 3, &[7u8; 40]);
        let e = b.key("0006abc", 132_223_104_000_000_000, &[], &[p, big]);
        let inv = b.key("InventoryApplicationFile", 0, &[e], &[]);
        let rk = b.key("Root", 0, &[inv], &[]);
        let top = b.key_into(slot, "ROOT", 0, &[rk], &[]);
        let bytes = b.finish(top);
        assert!(super::Hive::parse(bytes.clone()).unwrap().key("Root\\InventoryApplicationFile\\0006abc").is_some());
        std::fs::write(path, bytes).unwrap();
    }
}
