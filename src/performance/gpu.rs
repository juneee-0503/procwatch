//! GPU usage — **best-effort, system-wide only**, not per-process.
//!
//! Neither Windows nor macOS exposes a stable, public, per-process GPU
//! utilization API to third-party applications the way they do for CPU
//! and memory:
//!   - Windows: "GPU Engine" performance counters exist and are
//!     per-process, but only reliably for engines the GPU scheduler
//!     tags; coverage varies by driver/vendor.
//!   - macOS: there is no public per-process GPU API at all. Activity
//!     Monitor's GPU column uses a private framework. The closest public
//!     signal is `powermetrics`, which is system-wide and requires sudo.
//!
//! So this module reports **overall GPU utilization for the system**,
//! clearly labeled as such, rather than pretending to a per-process
//! number it cannot actually measure.

#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // `available` is informational; the UI keys off `utilization_pct`
pub struct GpuSnapshot {
    pub available: bool,
    pub utilization_pct: Option<f32>,
    pub note: String,
}

pub fn system_gpu_usage() -> GpuSnapshot {
    #[cfg(target_os = "windows")]
    return windows_impl::sample();
    #[cfg(target_os = "macos")]
    return macos_impl::sample();
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        GpuSnapshot {
            available: false,
            utilization_pct: None,
            note: "GPU sampling not implemented on this platform".to_string(),
        }
    }
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::GpuSnapshot;
    use crate::common::command::run_command;
    use std::time::Duration;

    pub fn sample() -> GpuSnapshot {
        // "GPU Engine" counters report per-engine utilization; summing the
        // "Utilization Percentage" instances gives a reasonable overall
        // number. Requires no special privileges.
        let script = r#"
try {
    $c = (Get-Counter '\GPU Engine(*)\Utilization Percentage' -ErrorAction Stop).CounterSamples
    $sum = ($c | Measure-Object -Property CookedValue -Sum).Sum
    Write-Output $sum
} catch {
    Write-Output "ERR"
}
"#;
        let output = run_command(
            crate::common::command::tool("powershell").args(["-NoProfile", "-NonInteractive", "-Command", script]),
            Duration::from_secs(10),
        );

        match output {
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stdout).trim().to_string();
                match text.parse::<f32>() {
                    Ok(v) => GpuSnapshot {
                        available: true,
                        utilization_pct: Some(v.clamp(0.0, 100.0)),
                        note: "system-wide GPU Engine utilization (summed across engines)"
                            .to_string(),
                    },
                    Err(_) => GpuSnapshot {
                        available: false,
                        utilization_pct: None,
                        note: "GPU Engine counters unavailable on this system/driver".to_string(),
                    },
                }
            }
            Err(e) => GpuSnapshot {
                available: false,
                utilization_pct: None,
                note: format!("failed to query GPU counters: {e}"),
            },
        }
    }
}

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::GpuSnapshot;

    pub fn sample() -> GpuSnapshot {
        // Deliberately not shelling out to `sudo powermetrics` — requiring
        // this TUI to prompt for sudo just to paint a GPU bar is a bad
        // trade-off. We report the honest limitation instead.
        GpuSnapshot {
            available: false,
            utilization_pct: None,
            note: "macOS exposes no public per-process or unprivileged system GPU API; \
                   run `sudo powermetrics --samplers gpu_power -n 1` yourself if you need this"
                .to_string(),
        }
    }
}
