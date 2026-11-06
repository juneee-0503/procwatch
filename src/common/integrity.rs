//! Is this still the program and configuration that were approved?
//!
//! Hashes are recorded on first sight and by deliberate acceptance. This
//! can't stop someone able to rewrite the record as well: its real value
//! comes from the heartbeat, which carries these hashes off the machine.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Default, Serialize, Deserialize)]
struct Manifest {
    #[serde(default)]
    v: u32,
    #[serde(default)]
    program: Option<String>,
    #[serde(default)]
    configs: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Check {
    /// Seen for the first time, and now recorded.
    Recorded,
    Same,
    Changed { was: String, now: String },
    Unreadable(String),
}

static WARNINGS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// What config loading found wrong since this was last asked.
pub fn take_warnings() -> Vec<String> {
    WARNINGS.lock().map(|mut w| std::mem::take(&mut *w)).unwrap_or_default()
}

fn warn(text: String) {
    crate::common::audit::record("configuration refused", &text);
    if let Ok(mut w) = WARNINGS.lock() {
        w.push(text);
    }
}

pub fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn manifest_path() -> Option<PathBuf> {
    crate::common::paths::data_dir().map(|d| d.join("integrity.json"))
}

fn load(path: &Path) -> Manifest {
    std::fs::read_to_string(path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn save(path: &Path, m: &Manifest) -> Result<(), String> {
    if let Some(d) = path.parent() {
        crate::common::paths::ensure_private_dir(d).map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(m).map_err(|e| e.to_string())?;
    crate::common::paths::write_atomic(path, &text).map_err(|e| e.to_string())
}

fn compare(known: Option<&String>, now: String) -> Check {
    match known {
        None => Check::Recorded,
        Some(k) if *k == now => Check::Same,
        Some(k) => Check::Changed { was: k.clone(), now },
    }
}

/// Hash of the running program.
pub fn program_hash() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    std::fs::read(&exe).map(|b| sha256(&b)).map_err(|e| format!("{}: {e}", exe.display()))
}

pub fn check_program() -> Check {
    let Some(path) = manifest_path() else { return Check::Unreadable("no data folder".into()) };
    let now = match program_hash() {
        Ok(h) => h,
        Err(e) => return Check::Unreadable(e),
    };
    let mut m = load(&path);
    let result = compare(m.program.as_ref(), now.clone());
    if result == Check::Recorded {
        m.v = 1;
        m.program = Some(now);
        if let Err(e) = save(&path, &m) {
            return Check::Unreadable(e);
        }
    }
    result
}

/// Approve the running program, after an upgrade.
pub fn accept_program() -> Result<String, String> {
    let path = manifest_path().ok_or("no data folder")?;
    let hash = program_hash()?;
    let mut m = load(&path);
    let before = m.program.replace(hash.clone());
    save(&path, &m)?;
    crate::common::audit::record("program accepted", &format!("was {}, now {hash}", before.unwrap_or_default()));
    Ok(hash)
}

/// Kept with the record, not beside the file: the configuration folder is
/// read-only to the service.
fn good_copy(path: &Path, manifest: &Path) -> PathBuf {
    let name: String = path.display().to_string().chars().map(|c| if c.is_alphanumeric() || c == '.' { c } else { '_' }).collect();
    manifest.with_file_name(format!("{name}.good"))
}

/// A configuration file's text, if it's what was approved. If it changed
/// behind procwatch's back the last good copy is used instead, the change
/// is recorded, and the file is left for someone to look at.
pub fn read_config(path: &Path) -> Result<String, String> {
    read_config_at(path, manifest_path().as_deref())
}

fn read_config_at(path: &Path, manifest: Option<&Path>) -> Result<String, String> {
    crate::common::paths::trusted(path)?;
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let Some(manifest) = manifest else { return Ok(text) };
    let mut m = load(manifest);
    let key = path.display().to_string();
    match compare(m.configs.get(&key), sha256(text.as_bytes())) {
        Check::Recorded => {
            m.v = 1;
            m.configs.insert(key, sha256(text.as_bytes()));
            let _ = crate::common::paths::write_atomic(&good_copy(path, manifest), &text);
            let _ = save(manifest, &m);
            Ok(text)
        }
        Check::Changed { was, now } => {
            warn(format!("{} changed outside procwatch (was {was}, now {now}): using the last approved copy; run --config-accept to approve it", path.display()));
            std::fs::read_to_string(good_copy(path, manifest)).map_err(|e| format!("{} changed and no approved copy remains: {e}", path.display()))
        }
        _ => Ok(text),
    }
}

/// Approve a configuration file as it stands now. Every approved change
/// keeps the previous version for rollback.
pub fn seal_config(path: &Path) -> Result<(), String> {
    seal_config_at(path, &manifest_path().ok_or("no data folder")?)
}

fn seal_config_at(path: &Path, manifest: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut m = load(manifest);
    let hash = sha256(text.as_bytes());
    let before = m.configs.insert(path.display().to_string(), hash.clone());
    m.v = 1;
    crate::common::paths::write_atomic(&good_copy(path, manifest), &text).map_err(|e| e.to_string())?;
    save(manifest, &m)?;
    crate::common::audit::record("configuration changed", &format!("{}: was {}, now {hash}", path.display(), before.unwrap_or_default()));
    Ok(())
}

/// Hash of everything approved, for the heartbeat.
pub fn config_digest() -> String {
    let m = manifest_path().map(|p| load(&p)).unwrap_or_default();
    sha256(m.configs.values().cloned().collect::<Vec<_>>().join("\n").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tampering_falls_back_to_the_approved_copy() {
        let dir = crate::common::paths::private_temp_dir("integrity").unwrap();
        let (file, manifest) = (dir.join("defense.yml"), dir.join("integrity.json"));
        std::fs::write(&file, "good").unwrap();
        assert_eq!(read_config_at(&file, Some(&manifest)).unwrap(), "good", "first sight");
        std::fs::write(&file, "evil").unwrap();
        assert_eq!(read_config_at(&file, Some(&manifest)).unwrap(), "good", "refused");
        assert!(take_warnings().iter().any(|w| w.contains("changed outside")));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "evil", "left as evidence");
        std::fs::write(&file, "new").unwrap();
        seal_config_at(&file, &manifest).unwrap();
        assert_eq!(read_config_at(&file, Some(&manifest)).unwrap(), "new", "approved");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn comparing_hashes() {
        assert_eq!(compare(None, "a".into()), Check::Recorded);
        assert_eq!(compare(Some(&"a".to_string()), "a".into()), Check::Same);
        assert!(matches!(compare(Some(&"a".to_string()), "b".into()), Check::Changed { .. }));
    }
}
