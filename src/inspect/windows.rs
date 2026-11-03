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
        open_files: Err("per-handle enumeration needs Sysinternals handle.exe; the handle count is shown instead".into()),
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
            path.replace('\'', "''")
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
            "NOTE" => info.notes.push(value.to_string()),
            _ => {}
        }
    }
    info.loaded_modules.sort_by_key(|m| m.to_lowercase());
    info.loaded_modules.dedup();

    info
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
        path.replace('\'', "''")
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
