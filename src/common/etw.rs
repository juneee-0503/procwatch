//! ETW session plumbing shared by every Windows source. These are the
//! public providers Windows' own tools consume; they need administrator
//! rights but no driver.

use std::sync::OnceLock;

use ferrisetw::parser::{Parser, Pointer};
use ferrisetw::provider::Provider;
use ferrisetw::trace::UserTrace;

/// Volume device names and their drive letters.
fn drives() -> &'static [(String, char)] {
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    static DRIVES: OnceLock<Vec<(String, char)>> = OnceLock::new();
    DRIVES.get_or_init(|| {
        (b'A'..=b'Z')
            .filter_map(|letter| {
                let drive: Vec<u16> = format!("{}:", letter as char).encode_utf16().chain(std::iter::once(0)).collect();
                let mut buf = [0u16; 512];
                let n = unsafe { QueryDosDeviceW(drive.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
                (n > 0).then(|| (String::from_utf16_lossy(&buf[..buf.iter().position(|c| *c == 0).unwrap_or(0)]), letter as char))
            })
            .filter(|(dev, _)| !dev.is_empty())
            .collect()
    })
}

/// ETW file names are NT device paths; show the drive letter.
pub fn dos_path(nt: &str) -> String {
    if nt.starts_with("\\Device\\") {
        for (dev, letter) in drives() {
            if let Some(rest) = nt.strip_prefix(dev.as_str()) {
                return format!("{letter}:{rest}");
            }
        }
    }
    nt.to_string()
}

/// First of `names` that holds non-empty text: field names vary by build.
pub fn text(p: &Parser, names: &[&str]) -> String {
    names.iter().find_map(|n| p.try_parse::<String>(n).ok().filter(|s| !s.is_empty())).unwrap_or_default()
}

pub fn pointer(p: &Parser, name: &str) -> Option<u64> {
    p.try_parse::<Pointer>(name).ok().map(|v| *v as u64)
}

pub fn start(name: &str, providers: Vec<Provider>) -> Result<UserTrace, String> {
    // A stale session from a crashed run would block the name.
    let _ = ferrisetw::trace::stop_trace_by_name(name);
    let mut b = UserTrace::new().named(name.to_string());
    for p in providers {
        b = b.enable(p);
    }
    b.start_and_process().map_err(|e| format!("ETW needs administrator rights ({e:?})"))
}

