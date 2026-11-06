//! macOS deep-inspection backend. Uses the same system CLIs Activity
//! Monitor and command-line tooling rely on: `lsof` for open file/socket
//! handles, `codesign` for signature verification, `vmmap` for the list
//! of mapped dylibs (best-effort — `vmmap` on another user's process
//! requires elevated privileges, which is an OS restriction, not a
//! limitation of this tool).

use super::{DeepInfo, OpenFile, SignatureStatus};
use crate::common::command::run_command;
use std::thread;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(8);

pub fn inspect(pid: u32, exe_path: Option<&str>, modules: bool) -> DeepInfo {
    // The four probes are independent and each costs a process spawn
    // (vmmap alone can take a second or more), so run them concurrently.
    let exe = exe_path.map(str::to_string);
    let dylibs = thread::spawn(move || if modules { Some(loaded_dylibs(pid)) } else { None });
    let files = thread::spawn(move || open_files(pid));
    let sig = thread::spawn(move || exe.map(|p| signature_status(&p)));
    let owner = process_owner(pid);

    let mut info = DeepInfo::default();

    match dylibs.join() {
        Ok(Some(Ok(mods))) => info.loaded_modules = mods,
        Ok(Some(Err(e))) => info.notes.push(format!("modules (vmmap): {e}")),
        Ok(None) => {}
        Err(_) => info.notes.push("modules (vmmap): worker panicked".into()),
    }
    info.modules_loaded = modules;

    info.open_files = match files.join() {
        Ok(Ok(f)) => {
            info.handle_count = Some(f.len() as u64);
            Ok(f)
        }
        Ok(Err(e)) => Err(format!("lsof: {e}")),
        Err(_) => Err("lsof: worker panicked".into()),
    };

    match sig.join() {
        Ok(Some(Ok((s, details)))) => {
            info.signature_status = s;
            info.signature_details = details;
        }
        Ok(Some(Err(e))) => info.notes.push(format!("signature (codesign): {e}")),
        Ok(None) => info.notes.push("signature: executable path unavailable".into()),
        Err(_) => info.notes.push("signature (codesign): worker panicked".into()),
    }

    match owner {
        Ok(o) if !o.is_empty() => info.integrity_or_privilege = Some(o),
        Ok(_) => {}
        Err(e) => info.notes.push(format!("owner (ps): {e}")),
    }

    info
}

pub fn loaded_dylibs(pid: u32) -> anyhow::Result<Vec<String>> {
    // `vmmap` lists an app's live memory mappings; filter to dylibs.
    // Requires the process to be owned by the current user, or `sudo`.
    let output = run_command(crate::common::command::tool("vmmap").args(["-w", &pid.to_string()]), TIMEOUT)?;
    if !output.status.success() {
        anyhow::bail!("insufficient privileges for pid {pid}");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // The path is the last column and may itself contain spaces, so take
    // everything from the first " /" rather than splitting on whitespace.
    let mut libs: Vec<String> = text
        .lines()
        .filter(|l| l.contains(".dylib"))
        .filter_map(|l| l.find(" /").map(|i| l[i + 1..].trim().to_string()))
        .collect();
    libs.sort();
    libs.dedup();
    Ok(libs)
}

pub fn open_files(pid: u32) -> anyhow::Result<Vec<OpenFile>> {
    // -F gives machine-readable records: one field per line, prefixed by
    // its type letter (f = fd, t = type, n = name). -n/-P skip DNS and
    // port-name lookups, which otherwise take seconds.
    let output = run_command(
        crate::common::command::tool("lsof").args(["-n", "-P", "-F", "ftn", "-p", &pid.to_string()]),
        TIMEOUT,
    )?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut files: Vec<OpenFile> = Vec::new();
    for line in text.lines() {
        let (tag, value) = line.split_at(line.len().min(1));
        match tag {
            "f" => files.push(OpenFile { fd: value.to_string(), kind: String::new(), name: String::new() }),
            "t" => {
                if let Some(f) = files.last_mut() {
                    f.kind = value.to_string();
                }
            }
            "n" => {
                if let Some(f) = files.last_mut() {
                    f.name = value.to_string();
                }
            }
            _ => {}
        }
    }
    // lsof exits non-zero on partial errors too; trust any output we got.
    if files.is_empty() && !output.status.success() {
        anyhow::bail!("insufficient privileges for pid {pid}");
    }
    Ok(files)
}

/// Signature status plus details (identifier, team, certificate chain).
/// `codesign -dv` describes the signature; `codesign -v --strict`
/// actually verifies it against the file on disk.
pub fn signature_status(path: &str) -> anyhow::Result<(SignatureStatus, Vec<(String, String)>)> {
    signature_status_with(path, false)
}

/// Code-signature validity via the Security framework. With
/// `resources == false` only the executable's own code is checked (fast);
/// `true` also re-hashes every resource in the bundle like
/// `codesign --verify --strict` (seconds for big apps).
fn check_validity(path: &str, resources: bool) -> Result<(), i32> {
    use std::ffi::c_void;
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFURLCreateFromFileSystemRepresentation(alloc: *const c_void, buf: *const u8, len: isize, is_dir: u8) -> *const c_void;
        fn CFRelease(cf: *const c_void);
    }
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SecStaticCodeCreateWithPath(path: *const c_void, flags: u32, code: *mut *const c_void) -> i32;
        fn SecStaticCodeCheckValidity(code: *const c_void, flags: u32, requirement: *const c_void) -> i32;
    }
    const DO_NOT_VALIDATE_RESOURCES: u32 = 1 << 2;
    const STRICT: u32 = 1 << 4;
    let bytes = path.as_bytes();
    unsafe {
        let url = CFURLCreateFromFileSystemRepresentation(std::ptr::null(), bytes.as_ptr(), bytes.len() as isize, 0);
        if url.is_null() {
            return Err(-1);
        }
        let mut code: *const c_void = std::ptr::null();
        let rc = SecStaticCodeCreateWithPath(url, 0, &mut code);
        CFRelease(url);
        if rc != 0 || code.is_null() {
            return Err(rc);
        }
        let flags = if resources { STRICT } else { DO_NOT_VALIDATE_RESOURCES };
        let rc = SecStaticCodeCheckValidity(code, flags, std::ptr::null());
        CFRelease(code);
        if rc == 0 { Ok(()) } else { Err(rc) }
    }
}

/// `thorough` also validates bundle resources (slow on big apps).
pub fn signature_status_with(path: &str, thorough: bool) -> anyhow::Result<(SignatureStatus, Vec<(String, String)>)> {
    let output = run_command(crate::common::command::tool("codesign").args(["-dvvv", path]), TIMEOUT)?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("not signed") {
        return Ok((SignatureStatus::Unsigned, Vec::new()));
    }

    let mut details: Vec<(String, String)> = Vec::new();
    let mut chain: Vec<String> = Vec::new();
    for line in stderr.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        match k {
            "Identifier" => details.push(("Identifier".into(), v.into())),
            "TeamIdentifier" if v != "not set" => details.push(("Team ID".into(), v.into())),
            "Authority" => chain.push(v.into()),
            "Timestamp" | "Signed Time" => details.push(("Signed".into(), v.into())),
            "Signature" if v == "adhoc" => details.push(("Type".into(), "ad-hoc (no certificate)".into())),
            "Runtime Version" => details.push(("Runtime".into(), v.into())),
            _ => {}
        }
    }
    if stderr.contains("Platform identifier=") {
        details.push(("Type".into(), "Apple platform binary".into()));
    }
    for (i, a) in chain.iter().enumerate() {
        details.push((if i == 0 { "Chain".into() } else { String::new() }, format!("{}{a}", "  ".repeat(i))));
    }

    if let Err(rc) = check_validity(path, thorough) {
        // errSecCSUnsigned
        if rc == -67062 {
            return Ok((SignatureStatus::Unsigned, details));
        }
        let reason = match rc {
            -67061 => "signature does not match the code (file was modified)".to_string(),
            -67054 => "a sealed resource is missing or modified".to_string(),
            -67030 => "invalid signature (code or resources changed)".to_string(),
            -67050 => "code failed its internal requirement".to_string(),
            other => format!("signature check failed (OSStatus {other})"),
        };
        return Ok((SignatureStatus::Invalid { reason }, details));
    }
    let signer = chain
        .first()
        .cloned()
        .or_else(|| details.iter().find(|(k, _)| k == "Type").map(|(_, v)| v.clone()))
        .unwrap_or_else(|| "signed".to_string());
    Ok((SignatureStatus::Valid { signer }, details))
}

fn process_owner(pid: u32) -> anyhow::Result<String> {
    let output = run_command(
        crate::common::command::tool("ps").args(["-o", "user=", "-p", &pid.to_string()]),
        TIMEOUT,
    )?;
    if !output.status.success() {
        anyhow::bail!("process {pid} not found");
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn call_stacks(pid: u32) -> Result<Vec<String>, String> {
    // `sample` also writes a copy of its report to a file; keep that in a
    // temp path we delete, rather than leaving files in /tmp.
    let tmp = std::env::temp_dir().join(format!("procwatch-sample-{pid}-{}.txt", std::process::id()));
    let out = run_command(
        crate::common::command::tool("sample").args([&pid.to_string(), "1", "-mayDie", "-file"]).arg(&tmp),
        Duration::from_secs(20),
    );
    // With -file the report goes to the file rather than stdout.
    let report = std::fs::read_to_string(&tmp).ok();
    let _ = std::fs::remove_file(&tmp);
    let out = out.map_err(|e| e.to_string())?;
    let text = report.unwrap_or_else(|| String::from_utf8_lossy(&out.stdout).into_owned());
    if !out.status.success() || !text.contains("Call graph:") {
        let err = String::from_utf8_lossy(&out.stderr);
        let msg = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("sampling failed").trim().to_string();
        return Err(if msg.contains("ermission") || msg.contains("not permitted") || msg.contains("task_for_pid") {
            format!("{msg} (other users' processes need root)")
        } else {
            msg
        });
    }
    // Keep the call graph and the "top of stack" summary; drop addresses.
    let strip = |l: &str| match l.rfind("  [0x") {
        Some(i) => l[..i].to_string(),
        None => l.to_string(),
    };
    let mut lines = Vec::new();
    let mut section = 0;
    for l in text.lines() {
        if l.starts_with("Call graph:") {
            section = 1;
            lines.push("Call graph (samples per frame, 1 ms each):".to_string());
            continue;
        }
        if l.starts_with("Total number in stack") {
            section = 0;
            continue;
        }
        if l.starts_with("Sort by top of stack") {
            section = 2;
            lines.push(String::new());
            lines.push("Hottest functions (top of stack):".to_string());
            continue;
        }
        if l.starts_with("Binary Images") {
            break;
        }
        if section > 0 && !l.trim().is_empty() {
            lines.push(strip(l));
        }
    }
    Ok(lines)
}
