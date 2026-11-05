//! Standard process-management actions: signals, suspend/resume, priority.
//!
//! These are the same operations Task Manager / Activity Monitor / Process
//! Explorer expose — nothing here reads or writes another process's memory,
//! injects code, or does anything beyond what the OS's own process-control
//! primitives provide.

use anyhow::{anyhow, Result};

/// A signal-like action. On Windows the four that map onto OS primitives
/// are offered; the rest are Unix-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
pub enum Sig {
    Term,
    Kill,
    Hup,
    Int,
    Quit,
    Stop,
    Cont,
    Usr1,
    Usr2,
}

impl Sig {
    /// Signals offered in the menu on this platform, most common first.
    pub fn available() -> &'static [Sig] {
        #[cfg(unix)]
        {
            &[Sig::Term, Sig::Kill, Sig::Hup, Sig::Int, Sig::Quit, Sig::Stop, Sig::Cont, Sig::Usr1, Sig::Usr2]
        }
        #[cfg(not(unix))]
        {
            &[Sig::Term, Sig::Kill, Sig::Stop, Sig::Cont]
        }
    }

    #[cfg(unix)]
    fn raw(self) -> libc::c_int {
        match self {
            Sig::Term => libc::SIGTERM,
            Sig::Kill => libc::SIGKILL,
            Sig::Hup => libc::SIGHUP,
            Sig::Int => libc::SIGINT,
            Sig::Quit => libc::SIGQUIT,
            Sig::Stop => libc::SIGSTOP,
            Sig::Cont => libc::SIGCONT,
            Sig::Usr1 => libc::SIGUSR1,
            Sig::Usr2 => libc::SIGUSR2,
        }
    }

    /// Menu label, e.g. `15 SIGTERM` on Unix, `End task` on Windows.
    pub fn label(self) -> String {
        #[cfg(unix)]
        {
            let name = match self {
                Sig::Term => "SIGTERM",
                Sig::Kill => "SIGKILL",
                Sig::Hup => "SIGHUP",
                Sig::Int => "SIGINT",
                Sig::Quit => "SIGQUIT",
                Sig::Stop => "SIGSTOP",
                Sig::Cont => "SIGCONT",
                Sig::Usr1 => "SIGUSR1",
                Sig::Usr2 => "SIGUSR2",
            };
            format!("{:>2} {name}", self.raw())
        }
        #[cfg(not(unix))]
        {
            match self {
                Sig::Term => "End task",
                Sig::Kill => "Terminate",
                Sig::Stop => "Suspend",
                Sig::Cont => "Resume",
                _ => "Unsupported",
            }
            .to_string()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Signal(Sig),
    /// Set absolute nice value.
    SetNice(i32),
}

/// What happened to one target of an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Done,
    /// It was already gone when the action ran.
    AlreadyExited,
    /// The PID now belongs to a different process: nothing was done.
    PidReused { now_started: u64 },
    Failed(String),
}

/// Apply `action` only if `pid` is still the process that started at
/// `expected_start` (0 = unknown, skip the check). Start times are compared
/// with a small tolerance because platforms round them differently.
pub fn apply_checked(pid: u32, expected_start: u64, action: Action) -> Outcome {
    if expected_start > 0 {
        match super::native::start_time(pid) {
            None if !process_exists(pid) => return Outcome::AlreadyExited,
            // Can't tell who holds this PID now, so don't touch it.
            None => return Outcome::Failed("can't confirm this is still the same process".into()),
            Some(now) if now.abs_diff(expected_start) > 2 => return Outcome::PidReused { now_started: now },
            Some(_) => {}
        }
    }
    match apply(pid, action) {
        Ok(()) => Outcome::Done,
        Err(e) if !process_exists(pid) => {
            let _ = e;
            Outcome::AlreadyExited
        }
        Err(e) => Outcome::Failed(e.to_string()),
    }
}

pub fn process_exists(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // Signal 0 checks existence; EPERM still means it exists.
        let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
        r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(windows)]
    {
        super::native::exists(pid)
    }
    #[cfg(not(any(unix, windows)))]
    {
        super::native::start_time(pid).is_some()
    }
}

/// The process the OS can't run without: init, or the Windows kernel.
fn is_system_root(pid: u32) -> bool {
    if cfg!(windows) { pid == 4 } else { pid == 1 }
}

/// Apply `action` to `pid`. Returns Err with a human-readable reason on
/// failure (most commonly: insufficient privileges, or the process already
/// exited).
pub fn apply(pid: u32, action: Action) -> Result<()> {
    if pid == 0 {
        return Err(anyhow!("refusing to act on pid 0"));
    }
    if pid == std::process::id() && matches!(action, Action::Signal(_)) {
        return Err(anyhow!("refusing to signal procwatch itself"));
    }
    if is_system_root(pid) && matches!(action, Action::Signal(_)) {
        return Err(anyhow!("refusing to signal the system's root process"));
    }
    match action {
        Action::SetNice(n) => super::native::set_nice(pid, n),
        Action::Signal(sig) => send(pid, sig),
    }
}

#[cfg(unix)]
fn send(pid: u32, sig: Sig) -> Result<()> {
    // SIGTERM/SIGKILL/SIGSTOP/... are ordinary POSIX signals — the same
    // mechanism `kill(1)` and Activity Monitor use.
    let pid = libc::pid_t::try_from(pid).map_err(|_| anyhow!("pid out of range"))?;
    if unsafe { libc::kill(pid, sig.raw()) } != 0 {
        return Err(anyhow!("{}", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(windows)]
fn send(pid: u32, sig: Sig) -> Result<()> {
    use crate::common::command::run_command;
    use std::process::Command;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    fn first_line(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("").to_string()
    }

    match sig {
        Sig::Term => {
            // Without /F taskkill posts WM_CLOSE, like Task Manager's
            // "End task": the app may save state or ask the user.
            let out = run_command(Command::new("taskkill").args(["/PID", &pid.to_string()]), Duration::from_secs(10))?;
            if !out.status.success() {
                let msg = first_line(&out.stderr);
                return Err(anyhow!(if msg.is_empty() { format!("taskkill exited with {}", out.status) } else { msg }));
            }
            Ok(())
        }
        Sig::Kill => unsafe {
            let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if h.is_null() {
                return Err(anyhow!("{}", std::io::Error::last_os_error()));
            }
            let ok = TerminateProcess(h, 1) != 0;
            let err = std::io::Error::last_os_error();
            CloseHandle(h);
            if ok { Ok(()) } else { Err(anyhow!("{err}")) }
        },
        Sig::Stop | Sig::Cont => {
            // NtSuspendProcess/NtResumeProcess are semi-documented NT
            // native APIs — the same mechanism Sysinternals' `pssuspend`
            // (a Microsoft-signed tool) uses. Called via PowerShell
            // P/Invoke rather than hand-rolled unsafe FFI.
            let verb = if sig == Sig::Stop { "NtSuspendProcess" } else { "NtResumeProcess" };
            let script = format!(
                r#"
$sig = @'
[DllImport("ntdll.dll")] public static extern int {verb}(IntPtr processHandle);
'@
$type = Add-Type -MemberDefinition $sig -Name NtControl -Namespace Win32 -PassThru
$proc = Get-Process -Id {pid} -ErrorAction Stop
$rc = $type::{verb}($proc.Handle)
if ($rc -ne 0) {{ [Console]::Error.WriteLine("NTSTATUS 0x{{0:X8}}" -f $rc); exit 1 }}
"#
            );
            let out = run_command(
                Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]),
                Duration::from_secs(15),
            )?;
            if !out.status.success() {
                let msg = first_line(&out.stderr);
                return Err(anyhow!("{verb} failed: {}", if msg.is_empty() { "likely needs admin" } else { &msg }));
            }
            Ok(())
        }
        _ => Err(anyhow!("signal not supported on Windows")),
    }
}

#[cfg(not(any(unix, windows)))]
fn send(_pid: u32, _sig: Sig) -> Result<()> {
    Err(anyhow!("process actions are not implemented on this platform"))
}
