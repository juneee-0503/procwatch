//! Where procwatch keeps things, how it writes them, and path facts that
//! don't belong to any one feature.

use std::fs;
use std::path::{Path, PathBuf};

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


/// Create a folder only this user can read. Command lines in histories and
/// evidence can hold passwords. Fails if the name exists, so a planted
/// symlink can't redirect what goes in.
pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(path)
}

/// Like `create_dir_all`, with the last folder private; an existing one is
/// tightened rather than trusted.
pub fn ensure_private_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    match create_private_dir(path) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// A new throwaway folder. The name is unpredictable and creation is
/// exclusive, because `/tmp` is shared and procwatch may be root there.
pub fn private_temp_dir(tag: &str) -> std::io::Result<PathBuf> {
    let base = std::env::temp_dir();
    for n in 0..64u32 {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
        let p = base.join(format!("procwatch-{tag}-{}-{nanos:x}-{n}", std::process::id()));
        match create_private_dir(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("no free temporary name"))
}

/// Options for files only this user can read, refusing to follow a link
/// planted at the name.
pub fn private_file() -> fs::OpenOptions {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut o = fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    o
}

/// Write a file that must not exist yet: exports land in the working
/// directory under predictable names.
pub fn write_new(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    private_file().write(true).create_new(true).open(path)?.write_all(text.as_bytes())
}

/// Where the event history lives; other data files sit beside it.
pub fn data_dir() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
        return Some(PathBuf::from(x).join("procwatch").join("events"));
    }
    #[cfg(target_os = "macos")]
    return std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support/procwatch/events"));
    #[cfg(windows)]
    return std::env::var_os("LOCALAPPDATA").map(|h| PathBuf::from(h).join("procwatch").join("events"));
    #[cfg(not(any(target_os = "macos", windows)))]
    return std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share/procwatch/events"));
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
    fn private_paths_are_exclusive_and_closed() {
        let d = private_temp_dir("paths-test").unwrap();
        assert!(create_private_dir(&d).is_err(), "an existing name is refused");
        let f = d.join("x");
        write_new(&f, "one").unwrap();
        assert!(write_new(&f, "two").is_err(), "exports never overwrite");
        assert_eq!(fs::read_to_string(&f).unwrap(), "one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
            let link = d.join("link");
            std::os::unix::fs::symlink(&f, &link).unwrap();
            assert!(private_file().append(true).create(true).open(&link).is_err(), "links aren't followed");
            let open = d.join("open");
            fs::create_dir(&open).unwrap();
            fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
            ensure_private_dir(&open).unwrap();
            assert_eq!(fs::metadata(&open).unwrap().permissions().mode() & 0o777, 0o700, "tightened");
        }
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn registry_paths() {
        assert_eq!(registry_path(r"\REGISTRY\MACHINE\SOFTWARE\X"), r"HKLM\SOFTWARE\X");
        assert_eq!(registry_path(r"\Registry\User\S-1-5\Software"), r"HKU\S-1-5\Software");
        assert_eq!(registry_path("relative\\key"), "relative\\key");
        assert_eq!(registry_path("\\REGISTRY\\MACHINE\\キー"), "HKLM\\キー");
    }
}
