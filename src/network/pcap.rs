//! Packet capture to a file, for opening in Wireshark.
//!
//! Linux reads an `AF_PACKET` socket, macOS a BPF device, and both write
//! classic pcap. Windows drives the built-in `pktmon`, which writes pcapng.
//! Packets hold whatever crossed the wire, so the file is private to its
//! owner, is never overwritten, and has a size limit.

#![cfg_attr(windows, allow(dead_code))]

use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Options {
    pub interface: Option<String>,
    pub seconds: u64,
    pub max_bytes: u64,
    pub snaplen: u32,
}

impl Default for Options {
    fn default() -> Options {
        Options { interface: None, seconds: 60, max_bytes: 100 << 20, snaplen: 65_535 }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub packets: u64,
    pub bytes: u64,
    /// Packets the kernel couldn't hand over, if it says.
    pub dropped: Option<u64>,
    pub hit_size_limit: bool,
}

const PCAP_MAGIC: u32 = 0xa1b2_c3d4;
const HEADER_LEN: u64 = 24;
const RECORD_LEN: u64 = 16;

/// pcap link types (the numbers Wireshark reads).
#[allow(dead_code)]
pub mod link {
    pub const NULL: u32 = 0;
    pub const ETHERNET: u32 = 1;
}

/// Writes the classic pcap format, stopping at the size limit.
pub struct Writer<W: Write> {
    out: W,
    written: u64,
    max_bytes: u64,
    snaplen: u32,
    pub stats: Stats,
}

impl<W: Write> Writer<W> {
    pub fn new(mut out: W, linktype: u32, snaplen: u32, max_bytes: u64) -> std::io::Result<Writer<W>> {
        out.write_all(&PCAP_MAGIC.to_le_bytes())?;
        out.write_all(&2u16.to_le_bytes())?;
        out.write_all(&4u16.to_le_bytes())?;
        out.write_all(&[0; 8])?; // zone and accuracy, unused by the format
        out.write_all(&snaplen.to_le_bytes())?;
        out.write_all(&linktype.to_le_bytes())?;
        Ok(Writer { out, written: HEADER_LEN, max_bytes, snaplen, stats: Stats::default() })
    }

    /// False once the file is full.
    pub fn packet(&mut self, secs: u32, micros: u32, wire_len: u32, data: &[u8]) -> std::io::Result<bool> {
        let data = &data[..data.len().min(self.snaplen as usize)];
        let size = RECORD_LEN + data.len() as u64;
        if self.written + size > self.max_bytes {
            self.stats.hit_size_limit = true;
            return Ok(false);
        }
        self.out.write_all(&secs.to_le_bytes())?;
        self.out.write_all(&micros.to_le_bytes())?;
        self.out.write_all(&(data.len() as u32).to_le_bytes())?;
        self.out.write_all(&wire_len.to_le_bytes())?;
        self.out.write_all(data)?;
        self.written += size;
        self.stats.packets += 1;
        self.stats.bytes += u64::from(wire_len);
        Ok(true)
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}

/// One record of a BPF read buffer, and where the next begins. Lengths come
/// from the kernel but are checked: a bad one must end the buffer, not read
/// past it.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub fn bpf_record(buf: &[u8], at: usize) -> Option<(u32, u32, u32, &[u8], usize)> {
    let u32_at = |o: usize| Some(u32::from_ne_bytes(buf.get(at.checked_add(o)?..at.checked_add(o + 4)?)?.try_into().ok()?));
    let (secs, micros, caplen, datalen) = (u32_at(0)?, u32_at(4)?, u32_at(8)? as usize, u32_at(12)?);
    let hdrlen = u16::from_ne_bytes(buf.get(at + 16..at + 18)?.try_into().ok()?) as usize;
    if hdrlen < 18 {
        return None;
    }
    let start = at.checked_add(hdrlen)?;
    let end = start.checked_add(caplen)?;
    let data = buf.get(start..end)?;
    Some((secs, micros, datalen, data, end.checked_add(3)? & !3))
}

fn create(path: &Path) -> Result<std::io::BufWriter<std::fs::File>, String> {
    let file = crate::common::paths::private_file().write(true).create_new(true).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(std::io::BufWriter::with_capacity(1 << 20, file))
}

#[cfg(target_os = "linux")]
fn capture(path: &Path, o: &Options, deadline: Instant) -> Result<Stats, String> {
    use std::ffi::CString;
    const ETH_P_ALL: u16 = 0x0003;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, i32::from(ETH_P_ALL.to_be())) };
    if fd < 0 {
        return Err(format!("packet socket: {} (needs root or CAP_NET_RAW)", std::io::Error::last_os_error()));
    }
    let close = Closer(fd);
    if let Some(name) = &o.interface {
        let c = CString::new(name.as_str()).map_err(|_| "bad interface name".to_string())?;
        let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
        if index == 0 {
            return Err(format!("no interface called {name}"));
        }
        let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sa.sll_family = libc::AF_PACKET as u16;
        sa.sll_protocol = ETH_P_ALL.to_be();
        sa.sll_ifindex = index as i32;
        if unsafe { libc::bind(fd, (&raw const sa).cast(), std::mem::size_of_val(&sa) as u32) } != 0 {
            return Err(format!("binding to {name}: {}", std::io::Error::last_os_error()));
        }
    }
    let tv = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
    unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&raw const tv).cast(), std::mem::size_of_val(&tv) as u32) };
    let mut w = Writer::new(create(path)?, link::ETHERNET, o.snaplen, o.max_bytes).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 65_536];
    let mut flushed = Instant::now();
    while Instant::now() < deadline {
        // MSG_TRUNC reports the real length of what didn't fit.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_TRUNC) };
        if n > 0 {
            let wire = n as usize;
            let now = chrono::Utc::now();
            let got = wire.min(buf.len());
            if !w.packet(now.timestamp() as u32, now.timestamp_subsec_micros(), wire as u32, &buf[..got]).map_err(|e| e.to_string())? {
                break;
            }
        }
        if flushed.elapsed() >= Duration::from_secs(1) {
            flushed = Instant::now();
            w.flush().map_err(|e| e.to_string())?;
        }
    }
    w.flush().map_err(|e| e.to_string())?;
    // From <linux/if_packet.h>.
    const PACKET_STATISTICS: libc::c_int = 6;
    let mut st = [0u32; 2]; // packets, drops
    let mut len = std::mem::size_of_val(&st) as u32;
    if unsafe { libc::getsockopt(fd, libc::SOL_PACKET, PACKET_STATISTICS, st.as_mut_ptr().cast(), &mut len) } == 0 {
        w.stats.dropped = Some(u64::from(st[1]));
    }
    drop(close);
    Ok(w.stats)
}

#[cfg(target_os = "macos")]
fn capture(path: &Path, o: &Options, deadline: Instant) -> Result<Stats, String> {
    use std::os::fd::AsRawFd;
    // From <net/bpf.h>; libc doesn't carry all of them.
    const BIOCGBLEN: libc::c_ulong = 0x4004_4266;
    const BIOCSETIF: libc::c_ulong = 0x8020_426c;
    const BIOCIMMEDIATE: libc::c_ulong = 0x8004_4270;
    const BIOCGDLT: libc::c_ulong = 0x4004_426a;
    const BIOCSRTIMEOUT: libc::c_ulong = 0x8010_426d;
    const BIOCGSTATS: libc::c_ulong = 0x4008_426f;
    let device = (0..256)
        .find_map(|i| std::fs::File::open(format!("/dev/bpf{i}")).ok())
        .ok_or("no usable /dev/bpf device: needs root, or read access to /dev/bpf*")?;
    let fd = device.as_raw_fd();
    let name = match &o.interface {
        Some(n) => n.clone(),
        None => default_interface().ok_or("no default route: name an interface with --interface")?,
    };
    let mut ifr = [0u8; 32];
    if name.len() >= 16 {
        return Err("interface name too long".into());
    }
    ifr[..name.len()].copy_from_slice(name.as_bytes());
    let on: u32 = 1;
    let mut blen: u32 = 0;
    let mut dlt: u32 = 0;
    let tv = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
    unsafe {
        libc::ioctl(fd, BIOCIMMEDIATE, &on);
        if libc::ioctl(fd, BIOCSETIF, ifr.as_ptr()) != 0 {
            return Err(format!("{name}: {}", std::io::Error::last_os_error()));
        }
        libc::ioctl(fd, BIOCSRTIMEOUT, &tv);
        libc::ioctl(fd, BIOCGBLEN, &mut blen);
        libc::ioctl(fd, BIOCGDLT, &mut dlt);
    }
    let mut w = Writer::new(create(path)?, dlt, o.snaplen, o.max_bytes).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; blen.max(4096) as usize];
    let mut full = false;
    while !full && Instant::now() < deadline {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            continue;
        }
        let filled = &buf[..n as usize];
        let mut at = 0;
        while let Some((secs, micros, wire, data, next)) = bpf_record(filled, at) {
            if !w.packet(secs, micros, wire, data).map_err(|e| e.to_string())? {
                full = true;
                break;
            }
            at = next;
        }
        w.flush().map_err(|e| e.to_string())?;
    }
    let mut stats = [0u32; 2];
    if unsafe { libc::ioctl(fd, BIOCGSTATS, stats.as_mut_ptr()) } == 0 {
        w.stats.dropped = Some(u64::from(stats[1]));
    }
    Ok(w.stats)
}

#[cfg(target_os = "macos")]
fn default_interface() -> Option<String> {
    let out = crate::common::command::tool("route").args(["-n", "get", "default"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.lines().find_map(|l| l.trim().strip_prefix("interface: ").map(str::to_string))
}

#[cfg(windows)]
fn capture(path: &Path, o: &Options, deadline: Instant) -> Result<Stats, String> {
    use crate::common::command::tool;
    if path.exists() {
        return Err(format!("{} already exists", path.display()));
    }
    let run = |args: &[&str]| -> Result<String, String> {
        let out = tool("pktmon").args(args).output().map_err(|e| format!("pktmon: {e} (needs Windows 10 2004 or later)"))?;
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if out.status.success() {
            Ok(text)
        } else {
            Err(format!("pktmon {}: {text} (needs administrator)", args[0]))
        }
    };
    if o.interface.is_some() {
        return Err("--interface isn't supported on Windows: pktmon captures every interface".into());
    }
    let dir = crate::common::paths::private_temp_dir("pcap").map_err(|e| e.to_string())?;
    let etl = dir.join("capture.etl");
    let etl_text = etl.to_string_lossy().into_owned();
    let mb = (o.max_bytes >> 20).max(1).to_string();
    let snap = o.snaplen.to_string();
    run(&["start", "--capture", "--file-name", &etl_text, "--file-size", &mb, "--pkt-size", &snap])?;
    // pktmon runs on its own in the kernel: it has to be stopped even if the
    // wait is cut short by an error below.
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    let stopped = run(&["stop"]);
    let converted = stopped.and_then(|_| run(&["etl2pcap", &etl_text, "--out", &path.to_string_lossy()]));
    let _ = std::fs::remove_dir_all(&dir);
    let summary = converted?;
    let packets = summary.lines().find_map(|l| l.split_whitespace().find_map(|w| w.parse::<u64>().ok())).unwrap_or(0);
    Ok(Stats { packets, bytes: std::fs::metadata(path).map_or(0, |m| m.len()), ..Stats::default() })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn capture(_: &Path, _: &Options, _: Instant) -> Result<Stats, String> {
    Err("packet capture isn't available on this platform".into())
}

#[cfg(target_os = "linux")]
struct Closer(i32);
#[cfg(target_os = "linux")]
impl Drop for Closer {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

pub fn run_capture(path: &Path, o: &Options) -> Result<Stats, String> {
    capture(path, o, Instant::now() + Duration::from_secs(o.seconds))
}

/// `--capture-packets`.
pub fn run(path: &Path, o: &Options) -> i32 {
    eprintln!("Capturing for up to {} s, at most {} MB, to {}. Packets can hold passwords and private data.", o.seconds, o.max_bytes >> 20, path.display());
    match run_capture(path, o) {
        Err(e) => {
            eprintln!("procwatch: {e}");
            2
        }
        Ok(s) => {
            let dropped = s.dropped.map_or("not reported".to_string(), |d| d.to_string());
            println!("{} packets, {} bytes, dropped by the kernel: {dropped}{}", s.packets, s.bytes, if s.hit_size_limit { " (stopped at the size limit)" } else { "" });
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_the_pcap_format() {
        let mut w = Writer::new(Vec::new(), link::ETHERNET, 4, 1024).unwrap();
        assert!(w.packet(7, 8, 6, &[1, 2, 3, 4, 5, 6]).unwrap());
        let (b, stats) = (w.out, w.stats);
        assert_eq!(b.len(), 24 + 16 + 4, "cut at the snap length");
        assert_eq!(&b[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(u32::from_le_bytes(b[20..24].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(b[32..36].try_into().unwrap()), 4, "captured");
        assert_eq!(u32::from_le_bytes(b[36..40].try_into().unwrap()), 6, "on the wire");
        assert_eq!(&b[40..], &[1, 2, 3, 4]);
        assert_eq!((stats.packets, stats.bytes), (1, 6));
    }

    #[test]
    fn stops_at_the_size_limit() {
        let mut w = Writer::new(Vec::new(), link::NULL, 100, 24 + 16 + 3).unwrap();
        assert!(w.packet(0, 0, 3, &[0; 3]).unwrap());
        assert!(!w.packet(0, 0, 1, &[0]).unwrap());
        assert!(w.stats.hit_size_limit);
        assert_eq!(w.out.len(), 43);
    }

    fn record(buf: &mut Vec<u8>, caplen: u32, data: &[u8]) {
        for v in [1u32, 2, caplen, 9] {
            buf.extend_from_slice(&v.to_ne_bytes());
        }
        buf.extend_from_slice(&18u16.to_ne_bytes());
        buf.extend_from_slice(data);
        buf.resize((buf.len() + 3) & !3, 0);
    }

    #[test]
    fn walks_bpf_buffers_and_survives_bad_lengths() {
        let mut b = Vec::new();
        record(&mut b, 3, b"abc");
        record(&mut b, 2, b"de");
        let (_, _, wire, data, next) = bpf_record(&b, 0).unwrap();
        assert_eq!((wire, data), (9, &b"abc"[..]));
        let (_, _, _, data, next) = bpf_record(&b, next).unwrap();
        assert_eq!(data, b"de");
        assert!(bpf_record(&b, next).is_none());
        let mut bad = Vec::new();
        record(&mut bad, u32::MAX, b"x");
        assert!(bpf_record(&bad, 0).is_none());
        assert!(bpf_record(&[], usize::MAX - 2).is_none());
    }
}
