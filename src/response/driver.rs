//! Talking to `procwatch.sys`, the optional Windows driver. The format is
//! `driver/windows/protocol.h`; see the README there for its status.

#![cfg_attr(not(windows), allow(dead_code))]

const PROTOCOL_VERSION: u32 = 2;
const MAX_PATTERN: usize = 260;
const MAX_RULES: usize = 128;
pub const ON_FILE: u32 = 1;
pub const ON_REGISTRY: u32 = 2;

/// The message that replaces the driver's rules. Patterns are NT paths.
pub fn encode(enforce: bool, rules: &[(u32, &str)]) -> Result<Vec<u8>, String> {
    if rules.len() > MAX_RULES {
        return Err(format!("the driver takes at most {MAX_RULES} rules"));
    }
    let mut m = Vec::with_capacity(12 + rules.len() * (4 + MAX_PATTERN * 2));
    for v in [PROTOCOL_VERSION, u32::from(enforce), rules.len() as u32] {
        m.extend_from_slice(&v.to_le_bytes());
    }
    for (on, pattern) in rules {
        let wide: Vec<u16> = pattern.encode_utf16().collect();
        if wide.is_empty() || wide.len() >= MAX_PATTERN {
            return Err(format!("{pattern}: a driver pattern must be 1 to {} characters", MAX_PATTERN - 1));
        }
        m.extend_from_slice(&on.to_le_bytes());
        for i in 0..MAX_PATTERN {
            m.extend_from_slice(&wide.get(i).copied().unwrap_or(0).to_le_bytes());
        }
    }
    Ok(m)
}

/// Windows paths as the driver sees them. It only knows a trailing `*`, so
/// anything else is refused rather than loaded as a different rule.
pub fn nt_patterns(registry: bool, patterns: &[String]) -> Result<Vec<String>, String> {
    patterns
        .iter()
        .map(|p| {
            if p[..p.len().saturating_sub(1)].contains(['*', '?']) || p.ends_with('?') {
                return Err(format!("{p}: the driver only supports a * at the end"));
            }
            if registry { registry_nt(p) } else { file_nt(p) }.ok_or_else(|| format!("{p}: can't be turned into a kernel path"))
        })
        .collect()
}

fn registry_nt(p: &str) -> Option<String> {
    let (root, rest) = p.split_once('\\')?;
    let nt = match root.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => "\\REGISTRY\\MACHINE",
        "HKU" | "HKEY_USERS" => "\\REGISTRY\\USER",
        _ => return None,
    };
    Some(format!("{nt}\\{rest}"))
}

#[cfg(windows)]
fn file_nt(p: &str) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    let (drive, rest) = p.split_once(":\\")?;
    let name: Vec<u16> = format!("{drive}:").encode_utf16().chain(Some(0)).collect();
    let mut out = [0u16; 1024];
    let n = unsafe { QueryDosDeviceW(name.as_ptr(), out.as_mut_ptr(), out.len() as u32) };
    if n == 0 {
        return None;
    }
    let end = out.iter().position(|c| *c == 0)?;
    Some(format!("{}\\{rest}", String::from_utf16_lossy(&out[..end])))
}

#[cfg(not(windows))]
fn file_nt(_: &str) -> Option<String> {
    None
}

/// A connection to the driver; closing it clears the driver's rules.
#[cfg(windows)]
pub struct Client(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Client {
    pub fn connect() -> Result<Client, String> {
        use windows_sys::Win32::Storage::InstallableFileSystems::FilterConnectCommunicationPort;
        let port: Vec<u16> = "\\ProcwatchPort".encode_utf16().chain(Some(0)).collect();
        let mut h = std::ptr::null_mut();
        let r = unsafe { FilterConnectCommunicationPort(port.as_ptr(), 0, std::ptr::null(), 0, std::ptr::null(), &mut h) };
        if r < 0 {
            return Err(format!("the procwatch driver isn't loaded ({r:#x}); see driver/windows/README.md"));
        }
        Ok(Client(h))
    }

    pub fn send(&self, message: &[u8]) -> Result<(), String> {
        use windows_sys::Win32::Storage::InstallableFileSystems::FilterSendMessage;
        let mut returned = 0;
        let r = unsafe { FilterSendMessage(self.0, message.as_ptr().cast(), message.len() as u32, std::ptr::null_mut(), 0, &mut returned) };
        if r < 0 {
            return Err(format!("the driver refused the rules ({r:#x})"));
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for Client {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_drivers_layout() {
        let m = encode(true, &[(ON_REGISTRY, "\\REGISTRY\\MACHINE\\X*")]).unwrap();
        assert_eq!(m.len(), 12 + 4 + 520, "sizeof(PW_SET_RULES) header plus one PW_RULE");
        assert_eq!(&m[..4], &2u32.to_le_bytes());
        assert_eq!(&m[4..8], &1u32.to_le_bytes(), "enforce");
        assert_eq!(&m[8..12], &1u32.to_le_bytes());
        assert_eq!(&m[12..16], &2u32.to_le_bytes());
        assert_eq!(&m[16..18], &(b'\\' as u16).to_le_bytes());
        assert!(encode(false, &[(ON_FILE, "")]).is_err());
        assert!(encode(false, &[(ON_FILE, &"x".repeat(MAX_PATTERN))]).is_err());
        assert!(encode(false, &vec![(ON_FILE, "x"); MAX_RULES + 1]).is_err());
        assert_eq!(nt_patterns(true, &["HKLM\\SOFTWARE\\X*".to_string()]).unwrap(), ["\\REGISTRY\\MACHINE\\SOFTWARE\\X*"]);
        assert!(nt_patterns(true, &["HKCU\\X".to_string()]).is_err(), "per-user roots differ by user");
        assert!(nt_patterns(true, &["HKLM\\*\\Run".to_string()]).is_err());
    }
}
