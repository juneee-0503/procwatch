//! Alarm tones: the ISO pattern of Mindray patient monitors, which is their
//! factory default. Figures come from Mindray's operator's manuals (ePM 10M,
//! ePM 12M, T1): 600 Hz, triple+double+triple+double beeps for high priority,
//! triple for medium and a single beep for low, repeating every 10, 20 and
//! 20 seconds. Where the manuals give no figure, timing follows IEC 60601-1-8,
//! which they say these tones comply with. Synthesised: no recording of a
//! real monitor is used, so the sound of its speaker is not reproduced.

use std::path::PathBuf;
use std::time::Duration;

const RATE: u32 = 22_050;
/// "ISO mode with frequency of 600 Hz".
const PITCH: f64 = 600.0;
/// IEC 60601-1-8: pulses of 75 to 200 ms for high priority, and 125 to 250 ms
/// for the others; rise time 10% of the pulse; x from 50 to 125 ms, y from
/// 125 to 250 ms, and 0.35 to 1.3 s between the two groups of a high alarm.
const HIGH_PULSE: u32 = 150;
const X: u32 = 100;
const GROUP_GAP: u32 = 400;
const MEDIUM_PULSE: u32 = 200;
const Y: u32 = 200;
const LOW_PULSE: u32 = 250;
/// Bump when the sound changes: tones are cached on disk by this name.
const VERSION: u32 = 2;

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
            // The gap between the three and the two is the standard's 2x + t.
            Tone::High => {
                let triple_double = |end| [(HIGH_PULSE, X), (HIGH_PULSE, X), (HIGH_PULSE, 2 * X + HIGH_PULSE), (HIGH_PULSE, X), (HIGH_PULSE, end)];
                triple_double(GROUP_GAP).into_iter().chain(triple_double(0)).collect()
            }
            Tone::Medium => vec![(MEDIUM_PULSE, Y), (MEDIUM_PULSE, Y), (MEDIUM_PULSE, 0)],
            // The standard allows one or two; Mindray's ISO mode has one.
            Tone::Low => vec![(LOW_PULSE, 0)],
        }
    }

    /// The silence between bursts: Mindray's ISO defaults.
    pub fn interval(self) -> Duration {
        Duration::from_secs(match self {
            Tone::High => 10,
            Tone::Medium | Tone::Low => 20,
        })
    }

    /// From the start of one burst to the start of the next.
    pub fn period(self) -> Duration {
        let burst: u32 = self.pattern().iter().map(|(on, off)| on + off).sum();
        self.interval() + Duration::from_millis(u64::from(burst))
    }
}

fn pulse(out: &mut Vec<i16>, ms: u32, volume: f64) {
    let n = (RATE * ms / 1000) as usize;
    // The standard asks for harmonics: a pure sine is hard to place in a room.
    let edge = f64::from(RATE) * f64::from(ms) / 1000.0 * 0.1;
    for i in 0..n {
        let t = i as f64 / f64::from(RATE);
        let ramp = (i.min(n - 1 - i) as f64 / edge).min(1.0);
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
    let path = dir.join(format!("alarm-v{VERSION}-{}-{}.wav", tone.name(), (volume * 100.0) as u32));
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

    /// (milliseconds on, milliseconds off) measured from the samples, the way
    /// the standard defines them: at half of full amplitude.
    fn measure(w: &[u8]) -> Vec<(u32, u32)> {
        let samples: Vec<i32> = w[44..].as_chunks::<2>().0.iter().map(|b| i32::from(i16::from_le_bytes(*b))).collect();
        let window = (RATE / 200) as usize;
        let level: Vec<i32> = samples.chunks(window).map(|c| c.iter().map(|s| s.abs()).max().unwrap_or(0)).collect();
        let half = level.iter().max().unwrap() / 2;
        let (mut out, mut on, mut off) = (Vec::new(), 0, 0);
        for l in level {
            if l >= half {
                if off > 0 && on > 0 {
                    out.push((on, off));
                    on = 0;
                }
                off = 0;
                on += 5;
            } else if on > 0 {
                off += 5;
            }
        }
        out.push((on, off));
        out
    }

    /// Strength of one frequency in one pulse.
    fn strength(w: &[u8], hz: f64) -> f64 {
        let s: Vec<f64> = w[44..].as_chunks::<2>().0.iter().take(RATE as usize / 8).map(|b| f64::from(i16::from_le_bytes(*b))).collect();
        let (mut re, mut im) = (0.0, 0.0);
        for (i, v) in s.iter().enumerate() {
            let a = std::f64::consts::TAU * hz * i as f64 / f64::from(RATE);
            re += v * a.cos();
            im += v * a.sin();
        }
        (re * re + im * im).sqrt()
    }

    fn close(a: u32, b: u32) -> bool {
        a.abs_diff(b) <= 30
    }

    #[test]
    fn the_rhythm_measured_from_the_sound_is_mindrays() {
        let high = measure(&wav(Tone::High, 0.5));
        assert_eq!(high.len(), 10, "triple+double+triple+double: {high:?}");
        for (i, (on, _)) in high.iter().enumerate() {
            assert!((75..=200).contains(on), "pulse {i}: {on} ms");
        }
        let gaps: Vec<u32> = high.iter().map(|p| p.1).collect();
        for (i, want) in [X, X, 2 * X + HIGH_PULSE, X, GROUP_GAP, X, X, 2 * X + HIGH_PULSE, X].iter().enumerate() {
            assert!(close(gaps[i], *want), "gap {i}: {} ms, wanted {want}: {gaps:?}", gaps[i]);
        }
        assert!(gaps[2] > gaps[1] * 2, "the three and the two sound apart");
        assert!((350..=1300).contains(&gaps[4]));
        let medium = measure(&wav(Tone::Medium, 0.5));
        assert_eq!(medium.len(), 3, "triple beep: {medium:?}");
        assert!(medium.iter().all(|(on, _)| (125..=250).contains(on)));
        assert!(medium[..2].iter().all(|(_, off)| (125..=250).contains(off)));
        let low = measure(&wav(Tone::Low, 0.5));
        assert_eq!(low.len(), 1, "single beep: {low:?}");
        assert!((125..=250).contains(&low[0].0));
    }

    #[test]
    fn the_pitch_measured_from_the_sound_is_600_hz() {
        let w = wav(Tone::Low, 0.5);
        let at = |hz| strength(&w, hz);
        assert!(at(600.0) > at(523.25) * 3.0 && at(600.0) > at(700.0) * 3.0, "the fundamental is 600 Hz");
        let harmonics = [at(600.0), at(1200.0), at(1800.0), at(2400.0)];
        let loudest = harmonics.iter().copied().fold(0.0, f64::max);
        for h in harmonics {
            assert!(20.0 * (h / loudest).log10() > -15.0, "four components within 15 dB: {harmonics:?}");
        }
    }

    #[test]
    fn intervals_are_the_factory_defaults() {
        assert_eq!([Tone::High, Tone::Medium, Tone::Low].map(|t| t.interval().as_secs()), [10, 20, 20]);
        assert!(Tone::High.interval() <= Tone::Medium.interval(), "IEC: high must not repeat more slowly");
        assert!(Tone::Medium.interval() <= Tone::Low.interval());
        assert_eq!(Tone::Low.period(), Duration::from_millis(20_250), "measured from the end of a burst");
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
