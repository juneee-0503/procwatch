//! Where procwatch keeps things, how it writes them, and path facts that
//! don't belong to any one feature.

use std::fs;
use std::path::PathBuf;

/// The settings file; other files live beside it.
pub fn config_path() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    base.map(|b| b.join("procwatch").join("config"))
}

/// Write-then-rename so a crash never leaves a truncated file.
pub fn write_atomic(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    // Unique, so a second instance or thread can't rename a half-written
    // file into place; synced, so a crash can't leave an empty one there.
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!("tmp{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    let result = fs::File::create(&tmp).and_then(|mut f| {
        f.write_all(text.as_bytes())?;
        f.sync_all()
    });
    let result = result.and_then(|()| fs::rename(&tmp, path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}


/// Folders where legitimate auto-start programs rarely live.
pub fn risky_location(path: &str) -> bool {
    let p = path.to_lowercase().replace('\\', "/");
    ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/folders/", "/dev/shm/", "/downloads/", "/users/shared/", "/appdata/local/temp/", "/users/public/", "/windows/temp/"]
        .iter()
        .any(|d| p.contains(d))
}

/// `\REGISTRY\MACHINE\...` as people write it.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub fn registry_path(raw: &str) -> String {
    let trimmed = raw.trim_start_matches('\\');
    let upper = trimmed.to_ascii_uppercase();
    for (native, short) in [("REGISTRY\\MACHINE", "HKLM"), ("REGISTRY\\USER", "HKU"), ("REGISTRY\\A", "HKA")] {
        if upper.starts_with(native) {
            // ASCII prefix, so the same byte length in both.
            return format!("{short}{}", &trimmed[native.len()..]);
        }
    }
    raw.to_string()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_paths() {
        assert_eq!(registry_path(r"\REGISTRY\MACHINE\SOFTWARE\X"), r"HKLM\SOFTWARE\X");
        assert_eq!(registry_path(r"\Registry\User\S-1-5\Software"), r"HKU\S-1-5\Software");
        assert_eq!(registry_path("relative\\key"), "relative\\key");
        assert_eq!(registry_path("\\REGISTRY\\MACHINE\\キー"), "HKLM\\キー");
    }
}
