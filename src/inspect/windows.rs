//! Windows deep-inspection backend. Implemented by shelling out to
//! PowerShell for the same reason the disk-cleanup tool did: it avoids a
//! pile of unsafe FFI/windows-rs boilerplate for operations the shell
//! already exposes as single cmdlets, and keeps this file readable to
//! someone still learning Rust.
//!
//! Starting PowerShell costs 300ms–1s, so everything is gathered in a
//! **single** invocation that prints tagged `KEY=value` lines, instead of
//! one spawn per field.

use super::{run_command, DeepInfo, SignatureStatus};
use std::process::Command;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(15);

pub fn inspect(pid: u32, exe_path: Option<&str>, modules: bool) -> DeepInfo {
    let mut info = DeepInfo {
        open_files: crate::handles::for_process(pid),
        modules_loaded: modules,
        ..DeepInfo::default()
    };
    let modules_part = if modules {
        r#"try {
    $p.Modules | ForEach-Object { Write-Output ("MOD=" + $_.FileName) }
} catch { Write-Output ("NOTE=modules: " + $_.Exception.Message) }"#
    } else {
        ""
    };

    let sig_part = match exe_path {
        Some(path) => format!(
            r#"
try {{
    $s = Get-AuthenticodeSignature -LiteralPath '{}' -ErrorAction Stop
    Write-Output ("SIG=" + $s.Status + "|" + $s.SignerCertificate.Subject)
    if ($s.SignerCertificate) {{
        Write-Output ("SIGD=Issuer|" + $s.SignerCertificate.Issuer)
        Write-Output ("SIGD=Thumbprint|" + $s.SignerCertificate.Thumbprint)
        Write-Output ("SIGD=Valid until|" + $s.SignerCertificate.NotAfter)
        Write-Output ("SIGD=Signature type|" + $s.SignatureType)
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = 'Online'
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(5)
        $ok = $chain.Build($s.SignerCertificate)
        Write-Output ("SIGD=Chain and revocation|" + $(if ($ok) {{ 'valid' }} else {{ ($chain.ChainStatus | ForEach-Object {{ $_.StatusInformation.Trim() }}) -join '; ' }}))
    }}
    if ($s.TimeStamperCertificate) {{ Write-Output ("SIGD=Timestamped by|" + $s.TimeStamperCertificate.Subject) }}
}} catch {{ Write-Output ("NOTE=signature: " + $_.Exception.Message) }}"#,
            super::ps_quote(path)
        ),
        None => "Write-Output 'NOTE=signature: executable path unavailable'".to_string(),
    };

    // `-IncludeUserName` requires elevation, so the owner falls back to
    // WMI's GetOwner(), which works unelevated for the caller's own
    // processes.
    let script = format!(
        r#"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue
if (-not $p) {{ Write-Output 'NOTE=process not found or access denied'; exit }}
Write-Output ("HANDLES=" + $p.HandleCount)
try {{
    $o = Get-CimInstance Win32_Process -Filter "ProcessId={pid}" -ErrorAction Stop |
        Invoke-CimMethod -MethodName GetOwner -ErrorAction Stop
    if ($o.User) {{ Write-Output ("OWNER=" + $o.Domain + "\" + $o.User) }}
}} catch {{ Write-Output ("NOTE=owner: " + $_.Exception.Message) }}
Get-CimInstance Win32_Service -Filter "ProcessId={pid}" -ErrorAction SilentlyContinue | ForEach-Object {{ Write-Output ("SVC=" + $_.Name + "|" + $_.DisplayName) }}
{modules_part}
{sig_part}
"#
    );

    let output = run_command(
        Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]),
        TIMEOUT,
    );
    let text = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(e) => {
            info.notes.push(format!("powershell: {e}"));
            return info;
        }
    };

    for line in text.lines().map(str::trim) {
        let Some((key, value)) = line.split_once('=') else { continue };
        let value = value.trim();
        match key {
            "HANDLES" => info.handle_count = value.parse().ok(),
            "OWNER" => info.integrity_or_privilege = Some(value.to_string()),
            "MOD" if !value.is_empty() => info.loaded_modules.push(value.to_string()),
            "SIG" => info.signature_status = parse_signature(value),
            "SIGD" => {
                if let Some((k, v)) = value.split_once('|') {
                    info.signature_details.push((k.to_string(), v.to_string()));
                }
            }
            "SVC" => {
                let (name, shown) = value.split_once('|').unwrap_or((value, ""));
                info.security.push(("Service".into(), if shown.is_empty() { name.to_string() } else { format!("{name} ({shown})") }));
            }
            "NOTE" => info.notes.push(value.to_string()),
            _ => {}
        }
    }
    info.security.extend(token_facts(pid));
    info.loaded_modules.sort_by_key(|m| m.to_lowercase());
    info.loaded_modules.dedup();

    info
}

/// Names of the token's enabled privileges. SeDebugPrivilege and friends are
/// what let a process reach into others.
unsafe fn enabled_privileges(token: windows_sys::Win32::Foundation::HANDLE) -> Vec<String> {
    use windows_sys::Win32::Security::{GetTokenInformation, LookupPrivilegeNameW, TokenPrivileges, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED};
    let mut buf = vec![0u64; 512];
    let mut len = 0;
    if GetTokenInformation(token, TokenPrivileges, buf.as_mut_ptr() as *mut _, (buf.len() * 8) as u32, &mut len) == 0 {
        return Vec::new();
    }
    // TOKEN_PRIVILEGES: a count, then that many entries, 4-byte aligned.
    let count = (buf[0] & 0xffff_ffff) as usize;
    let first = (buf.as_ptr() as *const u8).add(4) as *const LUID_AND_ATTRIBUTES;
    let room = (buf.len() * 8 - 4) / size_of::<LUID_AND_ATTRIBUTES>();
    let mut out = Vec::new();
    for i in 0..count.min(room) {
        let e = std::ptr::read_unaligned(first.add(i));
        if e.Attributes & SE_PRIVILEGE_ENABLED == 0 {
            continue;
        }
        let mut name = [0u16; 128];
        let mut n = name.len() as u32;
        if LookupPrivilegeNameW(std::ptr::null(), &e.Luid, name.as_mut_ptr(), &mut n) != 0 {
            out.push(String::from_utf16_lossy(&name[..n as usize]));
        }
    }
    out
}

/// Integrity level and elevation, read from the process token. A query
/// handle is all this needs; nothing of the process itself is touched.
fn token_facts(pid: u32) -> Vec<(String, String)> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenElevation, TokenIntegrityLevel, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};
    let mut out = Vec::new();
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return out;
        }
        let mut token: HANDLE = std::ptr::null_mut();
        let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token) != 0;
        CloseHandle(process);
        if !opened {
            return out;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut len = 0;
        let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        if GetTokenInformation(token, TokenElevation, &mut elevation as *mut _ as *mut _, size, &mut len) != 0 {
            out.push(("Elevated".to_string(), if elevation.TokenIsElevated != 0 { "yes" } else { "no" }.to_string()));
        }
        let enabled = enabled_privileges(token);
        if !enabled.is_empty() {
            out.push(("Enabled privileges".to_string(), enabled.join(", ")));
        }
        // u64s: the buffer must be aligned for the structure it holds.
        let mut buf = [0u64; 16];
        if GetTokenInformation(token, TokenIntegrityLevel, buf.as_mut_ptr() as *mut _, std::mem::size_of_val(&buf) as u32, &mut len) != 0 {
            let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            let sid = label.Label.Sid;
            let count = *GetSidSubAuthorityCount(sid);
            if count > 0 {
                let rid = *GetSidSubAuthority(sid, count as u32 - 1);
                let level = match rid {
                    0..=0x0fff => "untrusted",
                    0x1000..=0x1fff => "low",
                    0x2000..=0x2fff => "medium",
                    0x3000..=0x3fff => "high",
                    _ => "system",
                };
                out.push(("Integrity".to_string(), level.to_string()));
            }
        }
        CloseHandle(token);
    }
    out
}

fn parse_signature(value: &str) -> SignatureStatus {
    let (status, signer) = value.split_once('|').unwrap_or((value, ""));
    match status.trim() {
        "Valid" => SignatureStatus::Valid { signer: signer.trim().to_string() },
        "NotSigned" => SignatureStatus::Unsigned,
        "" => SignatureStatus::Unknown,
        other => SignatureStatus::Invalid { reason: other.to_string() },
    }
}

/// Authenticode status and certificate details for a single file.
pub fn file_signature(path: &str) -> anyhow::Result<(SignatureStatus, Vec<(String, String)>)> {
    let script = format!(
        r#"
$s = Get-AuthenticodeSignature -LiteralPath '{}' -ErrorAction Stop
Write-Output ("SIG=" + $s.Status + "|" + $s.SignerCertificate.Subject)
if ($s.SignerCertificate) {{
    Write-Output ("SIGD=Issuer|" + $s.SignerCertificate.Issuer)
    Write-Output ("SIGD=Thumbprint|" + $s.SignerCertificate.Thumbprint)
    Write-Output ("SIGD=Valid until|" + $s.SignerCertificate.NotAfter)
    Write-Output ("SIGD=Signature type|" + $s.SignatureType)
}}"#,
        super::ps_quote(path)
    );
    let out = run_command(Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]), TIMEOUT)?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut status = SignatureStatus::Unknown;
    let mut details = Vec::new();
    for line in text.lines().map(str::trim) {
        if let Some(v) = line.strip_prefix("SIG=") {
            status = parse_signature(v);
        } else if let Some((k, v)) = line.strip_prefix("SIGD=").and_then(|v| v.split_once('|')) {
            details.push((k.to_string(), v.to_string()));
        }
    }
    Ok((status, details))
}
