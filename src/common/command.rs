//! Running external tools safely: always a timeout, always an output limit,
//! and quoting for what gets pasted into a shell language.

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Run an external command with stdin closed, stdout/stderr captured, and a
/// hard timeout. Tools like `vmmap` or PowerShell can occasionally hang on
/// a wedged target process; without a timeout the worker would never
/// return and the panel would show "loading" forever.
///
/// stdout/stderr are drained on separate threads so a chatty child (vmmap
/// easily prints >64 KiB) can't deadlock on a full pipe while we wait.
#[allow(dead_code)] // unused on platforms without a shell-based backend
pub fn run_command(cmd: &mut Command, timeout: Duration) -> anyhow::Result<Output> {
    run_command_capped(cmd, timeout, MAX_OUTPUT)
}

/// A system tool, from where the system keeps it.
///
/// procwatch usually runs with more rights than whoever controls `PATH`, so
/// looking a tool up by name would run a planted program with those rights.
/// Only a tool that isn't in a system location falls back to `PATH`, which
/// on Unix covers package-manager installs such as `lsof`.
pub fn tool(name: &str) -> Command {
    Command::new(resolve(name))
}

#[cfg(unix)]
fn resolve(name: &str) -> std::path::PathBuf {
    ["/usr/bin", "/bin", "/usr/sbin", "/sbin"].iter().map(|d| std::path::Path::new(d).join(name)).find(|p| p.is_file()).unwrap_or_else(|| name.into())
}

#[cfg(windows)]
fn resolve(name: &str) -> std::path::PathBuf {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    // Asked of the OS: an environment variable could point anywhere.
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return name.into();
    }
    let system = std::path::PathBuf::from(String::from_utf16_lossy(&buf[..n]));
    let file = format!("{name}.exe");
    let candidates = [
        system.join(&file),
        system.join("WindowsPowerShell").join("v1.0").join(&file),
        system.parent().map(|w| w.join(&file)).unwrap_or_else(|| file.clone().into()),
    ];
    candidates.into_iter().find(|p| p.is_file()).unwrap_or_else(|| name.into())
}

#[cfg(not(any(unix, windows)))]
fn resolve(name: &str) -> std::path::PathBuf {
    name.into()
}

/// Output kept from one tool; more means something is wrong with it.
const MAX_OUTPUT: usize = 256 << 20;
/// How long pipes may stay open after the tool itself has exited.
const PIPE_SETTLE: Duration = Duration::from_secs(2);

/// Escape text for a PowerShell single-quoted string. PowerShell also ends
/// such a string at the typographic quotes, and paths are attacker-chosen:
/// doubling only `'` would let a file name run commands with our rights.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn ps_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
            out.push(c);
        }
        out.push(c);
    }
    out
}

/// Like [`run_command`], but stops reading (and kills the child) once
/// stdout exceeds `max_bytes` — for tools like `log show` whose output can
/// run to gigabytes. The output then holds the first `max_bytes`.
#[allow(dead_code)]
pub fn run_command_capped(cmd: &mut Command, timeout: Duration, max_bytes: usize) -> anyhow::Result<Output> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;

    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    type Shared = Arc<Mutex<Vec<u8>>>;
    let capped = Arc::new(AtomicBool::new(false));
    fn drain<R: Read + Send + 'static>(pipe: Option<R>, max: usize, capped: Arc<AtomicBool>) -> (Shared, thread::JoinHandle<()>) {
        let shared: Shared = Arc::default();
        let out = shared.clone();
        let reader = thread::spawn(move || {
            let Some(mut p) = pipe else { return };
            let mut chunk = [0u8; 64 * 1024];
            loop {
                match p.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let Ok(mut buf) = out.lock() else { break };
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.len() >= max {
                            buf.truncate(max);
                            capped.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            }
        });
        (shared, reader)
    }
    let (out_buf, out_reader) = drain(child.stdout.take(), max_bytes, capped.clone());
    let (err_buf, err_reader) = drain(child.stderr.take(), 1 << 20, Arc::new(AtomicBool::new(false)));

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if capped.load(Ordering::Relaxed) {
            // Enough output; stop the tool instead of waiting for it.
            let _ = child.kill();
            break child.wait()?;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("timed out after {}s", timeout.as_secs());
        }
        thread::sleep(Duration::from_millis(20));
    };

    // A background grandchild can hold the pipes open long after the child
    // exits; joining the readers would then wait forever, defeating the
    // timeout. Give them a moment and take what they have.
    let settle = Instant::now() + PIPE_SETTLE;
    while !(out_reader.is_finished() && err_reader.is_finished()) && Instant::now() < settle {
        thread::sleep(Duration::from_millis(5));
    }
    let take = |b: &Shared| b.lock().map(|mut v| std::mem::take(&mut *v)).unwrap_or_default();
    Ok(Output { status, stdout: take(&out_buf), stderr: take(&err_buf) })
}

#[cfg(test)]
mod tests {
    #[test]
    fn system_tools_ignore_path() {
        // A planted `sh` first on PATH must not win.
        #[cfg(unix)]
        assert!(std::path::Path::new(super::tool("sh").get_program()).is_absolute());
        #[cfg(windows)]
        assert!(std::path::Path::new(super::tool("cmd").get_program()).is_absolute());
        assert_eq!(super::tool("no-such-tool-here").get_program(), "no-such-tool-here");
    }

    #[test]
    fn powershell_quoting_covers_every_quote_character() {
        assert_eq!(super::ps_quote("C:\\a b\\x.exe"), "C:\\a b\\x.exe");
        assert_eq!(super::ps_quote("it's"), "it''s");
        for q in ['\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}'] {
            assert_eq!(super::ps_quote(&format!("a{q};calc;{q}b")), format!("a{q}{q};calc;{q}{q}b"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_background_grandchild_cannot_hold_the_call_open() {
        let t = std::time::Instant::now();
        let out = super::run_command(std::process::Command::new("/bin/sh").args(["-c", "echo done; sleep 30 &"]), std::time::Duration::from_secs(20)).unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("done"));
        assert!(t.elapsed() < std::time::Duration::from_secs(10), "{:?}", t.elapsed());
    }
}
