//! Launch-and-trace: start a program held at its first instruction, attach
//! deep trace, then let it run — so everything it does, including children
//! that live a millisecond, is recorded from the start.
//!
//! Only for analysis environments (an isolated VM you can reset): this
//! runs the program for real.
//!
//! - Unix: fork; the child redirects stdio, stops itself with SIGSTOP and
//!   only then calls exec. The parent waits for the stop, the caller
//!   attaches the watcher, then `resume` sends SIGCONT.
//! - Windows: CreateProcessW with CREATE_SUSPENDED in its own console;
//!   `resume` resumes the main thread.

use std::path::{Path, PathBuf};


pub struct Launched {
    pub pid: u32,
    pub program: String,
    #[cfg(windows)]
    thread: isize,
}

/// Quote one argument the way `CommandLineToArgvW` reads it: backslashes
/// are literal unless they precede a quote, where they must be doubled.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_arg(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '\n', '"']) {
        return a.to_string();
    }
    let mut out = String::from("\"");
    let mut slashes = 0;
    for c in a.chars() {
        match c {
            '\\' => slashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(slashes * 2 + 1));
                out.push('"');
                slashes = 0;
            }
            c => {
                out.push_str(&"\\".repeat(slashes));
                out.push(c);
                slashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

/// Resolve a program name through PATH (absolute/relative paths as given).
pub fn resolve(program: &str) -> Option<PathBuf> {
    let p = Path::new(program);
    if program.contains('/') || program.contains('\\') {
        return p.exists().then(|| p.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let c = dir.join(program);
        if c.is_file() {
            return Some(c);
        }
        #[cfg(windows)]
        {
            let c = dir.join(format!("{program}.exe"));
            if c.is_file() {
                return Some(c);
            }
        }
    }
    None
}

#[cfg(unix)]
pub fn start(argv: &[String], log: Option<&Path>) -> Result<Launched, String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let program = argv.first().ok_or("nothing to run")?;
    let path = resolve(program).ok_or_else(|| format!("{program}: not found"))?;
    // Everything the child needs is prepared before fork: after fork in a
    // threaded program only async-signal-safe calls are allowed.
    let cpath = CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let cargs: Vec<CString> = argv.iter().map(|a| CString::new(a.as_bytes()).map_err(|e| e.to_string())).collect::<Result<_, _>>()?;
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let devnull = CString::new("/dev/null").unwrap();
    let log_fd = match log {
        Some(l) => {
            let c = CString::new(l.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND | libc::O_CLOEXEC, 0o600) };
            if fd < 0 {
                return Err(format!("{}: {}", l.display(), std::io::Error::last_os_error()));
            }
            fd
        }
        None => -1,
    };
    let null_fd = unsafe { libc::open(devnull.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if pid == 0 {
        unsafe {
            if null_fd >= 0 {
                libc::dup2(null_fd, 0);
            }
            let out = if log_fd >= 0 { log_fd } else { null_fd };
            if out >= 0 {
                libc::dup2(out, 1);
                libc::dup2(out, 2);
            }
            // Own process group: terminal signals for procwatch don't hit it.
            libc::setpgid(0, 0);
            libc::raise(libc::SIGSTOP);
            libc::execv(cpath.as_ptr(), ptrs.as_ptr());
            libc::_exit(127);
        }
    }
    unsafe {
        if log_fd >= 0 {
            libc::close(log_fd);
        }
        if null_fd >= 0 {
            libc::close(null_fd);
        }
    }
    // Wait until it has stopped itself.
    let mut status = 0;
    let r = loop {
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
        if r >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break r;
        }
    };
    if r != pid || !libc::WIFSTOPPED(status) {
        // Don't leave it stopped forever, or as a zombie.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &mut status, 0);
        }
        return Err("the program didn't reach its start point".into());
    }
    Ok(Launched { pid: pid as u32, program: path.display().to_string() })
}

#[cfg(unix)]
pub fn resume(l: &Launched) -> Result<(), String> {
    if unsafe { libc::kill(l.pid as libc::pid_t, libc::SIGCONT) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

/// Reap the launched program when it exits so it doesn't linger as a
/// zombie (it's our child). Returns the exit status if it has exited.
#[cfg(unix)]
pub fn reap(pid: u32) -> Option<i32> {
    let mut status = 0;
    let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
    (r == pid as libc::pid_t).then(|| if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -libc::WTERMSIG(status) })
}

#[cfg(windows)]
pub fn start(argv: &[String], _log: Option<&Path>) -> Result<Launched, String> {
    use windows_sys::Win32::System::Threading::{CreateProcessW, CREATE_NEW_CONSOLE, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW};
    let program = argv.first().ok_or("nothing to run")?;
    let path = resolve(program).ok_or_else(|| format!("{program}: not found"))?;
    let mut cmdline: Vec<u16> = std::iter::once(windows_arg(&path.display().to_string()))
        .chain(argv[1..].iter().map(|a| windows_arg(a)))
        .collect::<Vec<_>>()
        .join(" ")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(std::ptr::null(), cmdline.as_mut_ptr(), std::ptr::null(), std::ptr::null(), 0, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, std::ptr::null(), std::ptr::null(), &si, &mut pi)
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    unsafe { windows_sys::Win32::Foundation::CloseHandle(pi.hProcess) };
    Ok(Launched { pid: pi.dwProcessId, program: path.display().to_string(), thread: pi.hThread as isize })
}

#[cfg(windows)]
pub fn resume(l: &Launched) -> Result<(), String> {
    use windows_sys::Win32::System::Threading::ResumeThread;
    let h = l.thread as windows_sys::Win32::Foundation::HANDLE;
    let r = unsafe { ResumeThread(h) };
    unsafe { windows_sys::Win32::Foundation::CloseHandle(h) };
    if r == u32::MAX {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(windows)]
pub fn reap(_pid: u32) -> Option<i32> {
    None
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn starts_stopped_then_runs_and_logs() {
        let log = std::env::temp_dir().join(format!("pw-launch-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&log);
        let l = start(&["/bin/sh".into(), "-c".into(), "echo launched-ok".into()], Some(&log)).unwrap();
        // Still stopped: nothing written yet.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(std::fs::read_to_string(&log).unwrap_or_default(), "");
        resume(&l).unwrap();
        let mut code = None;
        for _ in 0..50 {
            code = reap(l.pid);
            if code.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(code, Some(0));
        assert_eq!(std::fs::read_to_string(&log).unwrap().trim(), "launched-ok");
        assert!(start(&["definitely-not-a-program-xyz".into()], None).is_err());
        let _ = std::fs::remove_file(log);
    }
}

#[cfg(test)]
mod quoting {
    #[test]
    fn windows_arguments_round_trip_through_the_argv_rules() {
        use super::windows_arg as q;
        assert_eq!(q("plain"), "plain");
        assert_eq!(q(""), "\"\"");
        assert_eq!(q("a b"), "\"a b\"");
        assert_eq!(q(r"C:\dir with space\"), r#""C:\dir with space\\""#);
        assert_eq!(q(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(q(r#"a\"b"#), r#""a\\\"b""#);
        assert_eq!(q(r"C:\no\spaces\"), r"C:\no\spaces\");
    }
}
