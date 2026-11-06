//! Alarm tones. The three patterns follow IEC 60601-1-8, the alarm standard
//! patient monitors are built to: ten pulses for high priority, three for
//! medium, two for low. These are synthesised here; no maker's recording is
//! used. Each priority's rhythm is what tells it apart, as on a monitor.

use std::path::PathBuf;
use std::time::Duration;

const RATE: u32 = 22_050;
const PITCH: f64 = 523.25;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    High,
    Medium,
    Low,
}

impl Tone {
    fn name(self) -> &'static str {
        match self {
            Tone::High => "high",
            Tone::Medium => "medium",
            Tone::Low => "low",
        }
    }

    /// (pulse, gap after it) in milliseconds, one burst.
    pub fn pattern(self) -> Vec<(u32, u32)> {
        match self {
            // Two groups of five, the standard's 3+2 rhythm.
            Tone::High => {
                let group = [(150, 100), (150, 100), (150, 200), (150, 100), (150, 400)];
                group.iter().chain(group.iter()).copied().collect()
            }
            Tone::Medium => vec![(200, 200), (200, 200), (200, 0)],
            Tone::Low => vec![(250, 250), (250, 0)],
        }
    }

    /// How long until the burst repeats; None plays it once.
    pub fn repeat(self) -> Option<Duration> {
        match self {
            Tone::High => Some(Duration::from_secs(10)),
            Tone::Medium => Some(Duration::from_secs(25)),
            Tone::Low => None,
        }
    }
}

fn pulse(out: &mut Vec<i16>, ms: u32, volume: f64) {
    let n = (RATE * ms / 1000) as usize;
    // The standard asks for harmonics: a pure sine is hard to place in a room.
    for i in 0..n {
        let t = i as f64 / f64::from(RATE);
        let ramp = (i.min(n - 1 - i) as f64 / (f64::from(RATE) * 0.015)).min(1.0);
        let wave: f64 = [1.0, 0.5, 0.33, 0.25].iter().enumerate().map(|(h, a)| a * (t * PITCH * (h as f64 + 1.0) * std::f64::consts::TAU).sin()).sum();
        out.push((wave / 2.08 * ramp * volume * f64::from(i16::MAX)) as i16);
    }
}

/// One burst as a WAV file.
pub fn wav(tone: Tone, volume: f64) -> Vec<u8> {
    let mut samples = Vec::new();
    for (on, off) in tone.pattern() {
        pulse(&mut samples, on, volume.clamp(0.0, 1.0));
        samples.resize(samples.len() + (RATE * off / 1000) as usize, 0);
    }
    let data = (samples.len() * 2) as u32;
    let mut out = Vec::with_capacity(44 + data as usize);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36 + data).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&RATE.to_le_bytes());
    out.extend_from_slice(&(RATE * 2).to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data.to_le_bytes());
    samples.iter().for_each(|s| out.extend_from_slice(&s.to_le_bytes()));
    out
}

fn tone_file(tone: Tone, volume: f64) -> Option<PathBuf> {
    let dir = crate::common::paths::data_dir()?;
    crate::common::paths::ensure_private_dir(&dir).ok()?;
    let path = dir.join(format!("alarm-{}-{}.wav", tone.name(), (volume * 100.0) as u32));
    if !path.exists() {
        std::fs::write(&path, wav(tone, volume)).ok()?;
    }
    Some(path)
}

/// The system's player for a file, if there is one.
fn player() -> Option<(String, Vec<String>)> {
    let on_path = |name: &str| std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(name).exists()));
    if cfg!(target_os = "macos") {
        return Some(("afplay".to_string(), Vec::new()));
    }
    if cfg!(windows) {
        return Some(("powershell".to_string(), vec!["-NoProfile".to_string(), "-Command".to_string()]));
    }
    ["paplay", "pw-play", "aplay"].iter().find(|n| on_path(n)).map(|n| ((*n).to_string(), if *n == "aplay" { vec!["-q".to_string()] } else { Vec::new() }))
}

/// Plays without waiting, so nothing that calls this can stall. Falls back
/// to the terminal bell on a machine with no player.
pub fn play(tone: Tone, volume: f64) {
    let _ = std::thread::Builder::new().name("alarm-sound".into()).spawn(move || {
        use std::process::{Command, Stdio};
        let played = tone_file(tone, volume).zip(player()).is_some_and(|(file, (program, mut args))| {
            let file = file.display().to_string();
            args.push(if cfg!(windows) { format!("(New-Object Media.SoundPlayer '{}').PlaySync()", file.replace('\'', "''")) } else { file });
            Command::new(program).args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
        });
        if !played {
            use std::io::Write;
            let mut out = std::io::stdout();
            let _ = out.write_all(b"\x07");
            let _ = out.flush();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_priorities_have_the_standard_pulse_counts() {
        assert_eq!(Tone::High.pattern().len(), 10);
        assert_eq!(Tone::Medium.pattern().len(), 3);
        assert_eq!(Tone::Low.pattern().len(), 2);
    }

    #[test]
    fn writes_a_valid_wav() {
        let w = wav(Tone::Medium, 0.5);
        assert_eq!((&w[..4], &w[8..12], &w[36..40]), (&b"RIFF"[..], &b"WAVE"[..], &b"data"[..]));
        assert_eq!(u32::from_le_bytes(w[4..8].try_into().unwrap()) as usize, w.len() - 8);
        let peak = w[44..].as_chunks::<2>().0.iter().map(|b| i16::from_le_bytes(*b).unsigned_abs()).max().unwrap();
        assert!((10_000..=17_000).contains(&peak), "{peak}");
        assert!(wav(Tone::High, 1.0).len() > w.len());
    }
}
