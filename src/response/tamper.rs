//! Making the agent harder to interfere with, and noticing when someone
//! tries.
//!
//! Against an ordinary user this stops the common ways in. Against an
//! administrator it mostly raises the noise: they can undo all of it, and
//! real protection on Windows needs a Protected Process Light certificate,
//! which only Microsoft grants. See `docs/edr.md`.

use std::path::{Path, PathBuf};

/// Applies what this platform offers; says what took effect.
pub fn harden() -> Vec<String> {
    let mut done = Vec::new();
    #[cfg(target_os = "linux")]
    {
        // No core files and no ptrace from other users' or equal processes.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0 {
            done.push("not dumpable: no ptrace or core dumps".to_string());
        }
    }
    #[cfg(target_os = "macos")]
    {
        const PT_DENY_ATTACH: libc::c_int = 31;
        if unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } == 0 {
            done.push("debuggers can't attach".to_string());
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{LocalFree, TRUE};
        use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
        use windows_sys::Win32::Security::{SetKernelObjectSecurity, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        // SYSTEM keeps full access; administrators can only look. Nobody
        // else can even open the process.
        let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;0x101000;;;BA)".encode_utf16().chain(Some(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        unsafe {
            let parsed = ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut());
            if parsed == TRUE && SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, sd) == TRUE {
                done.push("process access limited to SYSTEM; administrators can only query it".to_string());
            }
            LocalFree(sd);
        }
    }
    done
}

/// A file whose content shouldn't change while the agent runs.
pub struct Watched {
    pub what: &'static str,
    path: PathBuf,
    sha256: String,
    reported: bool,
}

impl Watched {
    pub fn new(what: &'static str, path: &Path) -> Result<Watched, String> {
        let sha256 = crate::files::info::sha256_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Watched { what, path: path.to_path_buf(), sha256, reported: false })
    }

    /// A description of the change, the first time it's seen.
    pub fn changed(&mut self) -> Option<String> {
        let now = crate::files::info::sha256_file(&self.path).map_err(|e| e.to_string());
        if now.as_deref() == Ok(self.sha256.as_str()) || self.reported {
            return None;
        }
        self.reported = true;
        Some(match now {
            Ok(h) => format!("{} {} changed: was {}, now {h}", self.what, self.path.display(), self.sha256),
            Err(e) => format!("{} {} unreadable: {e}", self.what, self.path.display()),
        })
    }
}

/// Restarts `run` when it fails, ever more slowly. Returns when it succeeds
/// or `give_up` says so, for a process that fails the same way each time.
pub fn guard(mut run: impl FnMut() -> Option<i32>, mut note: impl FnMut(String), mut sleep: impl FnMut(std::time::Duration)) -> i32 {
    const MAX_WAIT_SECS: u64 = 30;
    const MAX_FAST_FAILURES: u32 = 8;
    let (mut wait, mut fast) = (1, 0);
    loop {
        let began = std::time::Instant::now();
        match run() {
            Some(0) => return 0,
            status => {
                let lived = began.elapsed().as_secs();
                fast = if lived >= 60 { 0 } else { fast + 1 };
                wait = if lived >= 60 { 1 } else { (wait * 2).min(MAX_WAIT_SECS) };
                if fast >= MAX_FAST_FAILURES {
                    note(format!("agent failed {fast} times in a row; giving up"));
                    return status.unwrap_or(1);
                }
                note(format!("agent ended unexpectedly ({status:?}); restarting in {wait} s"));
                sleep(std::time::Duration::from_secs(wait));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notices_a_changed_file_once() {
        let dir = crate::common::paths::private_temp_dir("tamper").unwrap();
        let path = dir.join("policy.yml");
        std::fs::write(&path, "a").unwrap();
        let mut w = Watched::new("policy", &path).unwrap();
        assert_eq!(w.changed(), None);
        std::fs::write(&path, "b").unwrap();
        assert!(w.changed().unwrap().contains("changed"));
        assert_eq!(w.changed(), None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_guard_restarts_then_gives_up() {
        let (mut calls, mut waits) = (0, Vec::new());
        let code = guard(
            || {
                calls += 1;
                Some(if calls < 3 { 1 } else { 0 })
            },
            |_| {},
            |d| waits.push(d.as_secs()),
        );
        assert_eq!((code, calls, waits), (0, 3, vec![2, 4]));
        let mut notes = 0;
        assert_eq!(guard(|| Some(5), |_| notes += 1, |_| {}), 5);
        assert_eq!(notes, 8);
    }
}
