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
}
