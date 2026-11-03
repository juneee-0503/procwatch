//! Response actions beyond ending processes:
//!
//! - **File quarantine**: move a file into the case's `quarantine/`
//!   folder, strip its permissions, and keep a record so it can be
//!   restored exactly.
//! - **Network isolation plan**: write a reviewed-before-use pair of
//!   scripts (isolate / restore) for the platform firewall. procwatch never
//!   runs them itself — a wrong firewall rule can cut off the very host
//!   you're investigating, so a person runs them deliberately, as root.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::case::{now, safe, Case};
use crate::fileinfo::sha256_file;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quarantined {
    pub original_path: String,
    pub stored_as: String,
    pub sha256: String,
    pub size: u64,
    pub time: String,
    pub mode: Option<u32>,
    pub restored: bool,
}

fn record_path(case: &Case, sha: &str) -> PathBuf {
    case.dir.join("quarantine").join(format!("{}.json", &sha[..16]))
}

/// Move `path` into quarantine. Running processes keep their open copy;
/// end them first if the file is an executable that is running.
pub fn quarantine(case: &Case, path: &Path) -> anyhow::Result<Quarantined> {
    let meta = fs::metadata(path)?;
    if !meta.is_file() {
        anyhow::bail!("only regular files can be quarantined");
    }
    let sha = sha256_file(path)?;
    let dir = case.dir.join("quarantine");
    fs::create_dir_all(&dir)?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let dest = dir.join(format!("{}_{}.quarantined", &sha[..16], safe(&name)));
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        Some(meta.permissions().mode())
    };
    #[cfg(not(unix))]
    let mode = None;

    // rename is atomic on one filesystem; otherwise copy, verify, delete.
    if fs::rename(path, &dest).is_err() {
        fs::copy(path, &dest)?;
        if sha256_file(&dest)? != sha {
            let _ = fs::remove_file(&dest);
            anyhow::bail!("copy verification failed");
        }
        fs::remove_file(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o000))?;
    }
    #[cfg(not(unix))]
    {
        let mut p = fs::metadata(&dest)?.permissions();
        p.set_readonly(true);
        fs::set_permissions(&dest, p)?;
    }
    let rec = Quarantined {
        original_path: path.display().to_string(),
        stored_as: case.rel(&dest),
        sha256: sha.clone(),
        size: meta.len(),
        time: now(),
        mode,
        restored: false,
    };
    fs::write(record_path(case, &sha), serde_json::to_string_pretty(&rec)?)?;
    let id = case.register_quarantine(&dest, &rec.original_path).map(|i| i.id).unwrap_or_else(|e| format!("(not registered: {e})"));
    case.log("quarantined file", &format!("{id} {} → {} sha256={sha}", rec.original_path, rec.stored_as))?;
    Ok(rec)
}

pub fn list(case: &Case) -> Vec<Quarantined> {
    let mut v: Vec<Quarantined> = fs::read_dir(case.dir.join("quarantine"))
        .map(|r| {
            r.flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
                .filter_map(|e| fs::read_to_string(e.path()).ok())
                .filter_map(|t| serde_json::from_str(&t).ok())
                .collect()
        })
        .unwrap_or_default();
    v.sort_by(|a, b| b.time.cmp(&a.time));
    v
}

/// Put a quarantined file back where it was, with its original mode.
pub fn restore(case: &Case, q: &Quarantined) -> anyhow::Result<()> {
    let original = Path::new(&q.original_path);
    if original.exists() {
        anyhow::bail!("{} already exists — move it away first", q.original_path);
    }
    let stored = case.dir.join(&q.stored_as);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&stored, fs::Permissions::from_mode(0o600))?;
    }
    if let Some(dir) = original.parent() {
        fs::create_dir_all(dir)?;
    }
    if fs::rename(&stored, original).is_err() {
        fs::copy(&stored, original)?;
        fs::remove_file(&stored)?;
    }
    #[cfg(unix)]
    if let Some(mode) = q.mode {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(original, fs::Permissions::from_mode(mode & 0o7777))?;
    }
    let mut rec = q.clone();
    rec.restored = true;
    fs::write(record_path(case, &q.sha256), serde_json::to_string_pretty(&rec)?)?;
    case.log("restored file", &format!("{} sha256={}", q.original_path, q.sha256))?;
    Ok(())
}

/// Write `isolate` and `restore` scripts for this platform's firewall into
/// the case folder. `allow` is an optional management address that stays
/// reachable. Returns the two paths. Nothing is executed.
pub fn write_isolation_plan(case: &Case, allow: Option<&str>) -> anyhow::Result<(PathBuf, PathBuf)> {
    let dir = case.dir.join("response");
    fs::create_dir_all(&dir)?;
    let (iso_name, res_name, iso, res) = scripts(allow);
    let iso_path = dir.join(iso_name);
    let res_path = dir.join(res_name);
    fs::write(&iso_path, iso)?;
    fs::write(&res_path, res)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [&iso_path, &res_path] {
            fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
        }
    }
    case.log(
        "isolation plan written (not applied)",
        &format!("{} / {}{}", case.rel(&iso_path), case.rel(&res_path), allow.map(|a| format!(", management address {a}")).unwrap_or_default()),
    )?;
    Ok((iso_path, res_path))
}

fn header(comment: &str) -> String {
    format!(
        "{comment} Generated by procwatch {}. REVIEW BEFORE RUNNING. Requires administrator/root.\n\
         {comment} Blocks all network traffic except loopback (and the management address, if given).\n\
         {comment} DNS, updates and remote access will stop working until the restore script is run.\n",
        now()
    )
}

#[cfg(target_os = "macos")]
fn scripts(allow: Option<&str>) -> (&'static str, &'static str, String, String) {
    let mgmt = allow
        .map(|a| format!("pass in quick from {a} keep state\npass out quick to {a} keep state\n"))
        .unwrap_or_default();
    let iso = format!(
        "#!/bin/sh\n{}set -e\nRULES=\"$(dirname \"$0\")/procwatch-isolate.pf\"\ncat > \"$RULES\" <<'EOF'\nset skip on lo0\n{mgmt}block drop all\nEOF\n\
         # Load the isolation ruleset in place of the main one and enable pf.\n\
         pfctl -f \"$RULES\"\npfctl -E 2>&1 | tee \"$(dirname \"$0\")/pf-token.txt\"\necho \"Host isolated. Run restore-network.sh to undo.\"\n",
        header("#")
    );
    let res = format!(
        "#!/bin/sh\n{}set -e\n# Reload the normal ruleset and release our pf enable token.\npfctl -f /etc/pf.conf\n\
         TOKEN=$(grep -o 'Token : [0-9]*' \"$(dirname \"$0\")/pf-token.txt\" | awk '{{print $3}}')\n[ -n \"$TOKEN\" ] && pfctl -X \"$TOKEN\" || true\necho \"Network restored.\"\n",
        header("#")
    );
    ("isolate-network.sh", "restore-network.sh", iso, res)
}

#[cfg(target_os = "linux")]
fn scripts(allow: Option<&str>) -> (&'static str, &'static str, String, String) {
    let mgmt = allow
        .map(|a| format!("nft add rule inet procwatch_isolate input ip saddr {a} accept\nnft add rule inet procwatch_isolate output ip daddr {a} accept\n"))
        .unwrap_or_default();
    let iso = format!(
        "#!/bin/sh\n{}set -e\nnft add table inet procwatch_isolate\n\
         nft add chain inet procwatch_isolate input '{{ type filter hook input priority -200; policy drop; }}'\n\
         nft add chain inet procwatch_isolate output '{{ type filter hook output priority -200; policy drop; }}'\n\
         nft add rule inet procwatch_isolate input iif lo accept\nnft add rule inet procwatch_isolate output oif lo accept\n{mgmt}\
         echo \"Host isolated. Run restore-network.sh to undo.\"\n",
        header("#")
    );
    let res = format!("#!/bin/sh\n{}nft delete table inet procwatch_isolate && echo \"Network restored.\"\n", header("#"));
    ("isolate-network.sh", "restore-network.sh", iso, res)
}

#[cfg(target_os = "windows")]
fn scripts(allow: Option<&str>) -> (&'static str, &'static str, String, String) {
    let mgmt = allow
        .map(|a| {
            format!(
                "netsh advfirewall firewall add rule name=\"procwatch-mgmt-in\" dir=in action=allow remoteip={a}\r\n\
                 netsh advfirewall firewall add rule name=\"procwatch-mgmt-out\" dir=out action=allow remoteip={a}\r\n"
            )
        })
        .unwrap_or_default();
    let iso = format!(
        "@echo off\r\n{}\
         netsh advfirewall export \"%~dp0firewall-backup.wfw\" || exit /b 1\r\n\
         netsh advfirewall set allprofiles state on\r\n\
         netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound\r\n{mgmt}\
         echo Host isolated. Run restore-network.cmd to undo.\r\n",
        header("REM").replace('\n', "\r\n")
    );
    let res = format!(
        "@echo off\r\n{}netsh advfirewall import \"%~dp0firewall-backup.wfw\" && echo Network restored.\r\n",
        header("REM").replace('\n', "\r\n")
    );
    ("isolate-network.cmd", "restore-network.cmd", iso, res)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn scripts(_allow: Option<&str>) -> (&'static str, &'static str, String, String) {
    ("isolate-network.txt", "restore-network.txt", "Not supported on this platform.\n".into(), String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_and_restore_round_trip() {
        let parent = std::env::temp_dir().join(format!("pw-q-{}", std::process::id()));
        let case = Case::create(&parent).unwrap();
        let f = parent.join("suspicious.bin");
        fs::write(&f, b"payload").unwrap();
        let rec = quarantine(&case, &f).unwrap();
        assert!(!f.exists());
        assert_eq!(list(&case).len(), 1);
        restore(&case, &rec).unwrap();
        assert_eq!(fs::read(&f).unwrap(), b"payload");
        assert!(list(&case)[0].restored);
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn isolation_plan_is_written_not_run() {
        let parent = std::env::temp_dir().join(format!("pw-iso-{}", std::process::id()));
        let case = Case::create(&parent).unwrap();
        let (iso, res) = write_isolation_plan(&case, Some("10.0.0.5")).unwrap();
        let text = fs::read_to_string(iso).unwrap();
        assert!(text.contains("REVIEW BEFORE RUNNING") && text.contains("10.0.0.5"));
        assert!(res.exists());
        let _ = fs::remove_dir_all(parent);
    }
}
