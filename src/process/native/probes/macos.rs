pub fn start_time(pid: u32) -> Option<u64> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let n = unsafe { libc::proc_pidinfo(pid as libc::c_int, libc::PROC_PIDTBSDINFO, 0, &mut info as *mut _ as *mut libc::c_void, size) };
    (n == size).then_some(info.pbi_start_tvsec)
}

use super::super::{Native, ThreadInfo};
use std::collections::HashMap;
use std::mem::{size_of, MaybeUninit};
use std::sync::OnceLock;

// Not exported by the libc crate.
const PROC_PIDLISTTHREADS: libc::c_int = 6;

/// `pti_total_*` are Mach absolute-time units, which are *not*
/// nanoseconds on Apple Silicon; convert with the timebase.
fn ticks_to_secs(ticks: u64) -> f64 {
    static TB: OnceLock<(u32, u32)> = OnceLock::new();
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }
    extern "C" {
        fn mach_timebase_info(info: *mut Timebase) -> libc::c_int;
    }
    let (numer, denom) = *TB.get_or_init(|| {
        let mut info = Timebase { numer: 0, denom: 0 };
        let ok = unsafe { mach_timebase_info(&mut info) } == 0;
        if ok && info.denom != 0 { (info.numer, info.denom) } else { (1, 1) }
    });
    ticks as f64 * numer as f64 / denom as f64 / 1e9
}

fn task_info(pid: u32) -> Option<libc::proc_taskinfo> {
    let mut info = MaybeUninit::<libc::proc_taskinfo>::zeroed();
    let size = size_of::<libc::proc_taskinfo>() as libc::c_int;
    let n = unsafe {
        libc::proc_pidinfo(pid as libc::c_int, libc::PROC_PIDTASKINFO, 0, info.as_mut_ptr().cast(), size)
    };
    (n == size).then(|| unsafe { info.assume_init() })
}

fn footprint(pid: u32) -> Option<u64> {
    let mut info = MaybeUninit::<libc::rusage_info_v2>::zeroed();
    let rc = unsafe { libc::proc_pid_rusage(pid as libc::c_int, libc::RUSAGE_INFO_V2, info.as_mut_ptr().cast()) };
    (rc == 0).then(|| unsafe { info.assume_init() }.ri_phys_footprint).filter(|v| *v > 0)
}

fn nice(pid: u32) -> Option<i32> {
    unsafe {
        *libc::__error() = 0;
        let v = libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t);
        (v != -1 || *libc::__error() == 0).then_some(v)
    }
}

pub fn collect(pids: &[u32]) -> HashMap<u32, Native> {
    pids.iter()
        .map(|&pid| {
            let ti = task_info(pid);
            let native = Native {
                threads: ti.map(|t| t.pti_threadnum.max(0) as u32),
                nice: nice(pid),
                priority: ti.map(|t| t.pti_priority),
                cpu_time: ti.map(|t| ticks_to_secs(t.pti_total_user + t.pti_total_system)),
                footprint: footprint(pid),
            };
            (pid, native)
        })
        .collect()
}

pub fn threads(pid: u32) -> anyhow::Result<Vec<ThreadInfo>> {
    let count = task_info(pid).map(|t| t.pti_threadnum.max(1) as usize).unwrap_or(64);
    let mut ids = vec![0u64; count + 16];
    let bytes = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            PROC_PIDLISTTHREADS,
            0,
            ids.as_mut_ptr().cast(),
            (ids.len() * size_of::<u64>()) as libc::c_int,
        )
    };
    if bytes <= 0 {
        anyhow::bail!("{} (other users' processes need root)", std::io::Error::last_os_error());
    }
    ids.truncate(bytes as usize / size_of::<u64>());

    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let mut info = MaybeUninit::<libc::proc_threadinfo>::zeroed();
        let size = size_of::<libc::proc_threadinfo>() as libc::c_int;
        let n = unsafe {
            libc::proc_pidinfo(pid as libc::c_int, libc::PROC_PIDTHREADINFO, id, info.as_mut_ptr().cast(), size)
        };
        if n != size {
            continue; // thread exited between list and query
        }
        let info = unsafe { info.assume_init() };
        let name = unsafe { std::ffi::CStr::from_ptr(info.pth_name.as_ptr()) }.to_string_lossy().into_owned();
        let state = match info.pth_run_state {
            1 => "running",
            2 => "stopped",
            3 => "waiting",
            4 => "uninterruptible",
            5 => "halted",
            _ => "?",
        };
        out.push(ThreadInfo {
            id,
            name,
            state: state.to_string(),
            // TH_USAGE_SCALE = 1000 → tenths of a percent.
            cpu_pct: Some(info.pth_cpu_usage as f32 / 10.0),
            priority: Some(info.pth_curpri),
            user_time: Some(info.pth_user_time as f64 / 1e9),
            system_time: Some(info.pth_system_time as f64 / 1e9),
        });
    }
    Ok(out)
}

pub fn set_nice(pid: u32, nice: i32) -> anyhow::Result<()> {
    if unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, nice) } != 0 {
        anyhow::bail!("{}", std::io::Error::last_os_error());
    }
    Ok(())
}
