//! Mutation fuzzing for every parser that reads untrusted bytes: binary
//! headers and structure, Prefetch / Xpress, ShimCache, registry hives,
//! EVTX, YARA and Sigma rule text, IOC lists, shell histories, base64.
//!
//! Deterministic (fixed seed) so failures reproduce. Each input must parse
//! without panicking and within `SLOW`. A short run is part of the normal
//! tests; `cargo test --release fuzz_ -- --ignored` runs the long one
//! (`PW_FUZZ_ITERATIONS`, default 50 000 per target).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

const SLOW: Duration = Duration::from_secs(2);

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

const INTERESTING: [u8; 8] = [0x00, 0xff, 0x7f, 0x80, 0x01, 0xfe, 0x20, 0x41];

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut d = seed.to_vec();
    for _ in 0..=rng.below(8) {
        if d.is_empty() {
            d.push(rng.next() as u8);
            continue;
        }
        let i = rng.below(d.len());
        match rng.below(9) {
            0 => d[i] ^= 1 << rng.below(8),
            1 => d[i] = INTERESTING[rng.below(INTERESTING.len())],
            2 => d.truncate(i),
            3 => {
                let n = rng.below(16) + 1;
                for _ in 0..n {
                    d.insert(i, rng.next() as u8);
                }
            }
            4 => {
                // Overwrite a 32-bit field with a boundary value.
                let v: u32 = [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, d.len() as u32, 0x1000][rng.below(7)];
                if i + 4 <= d.len() {
                    d[i..i + 4].copy_from_slice(&v.to_le_bytes());
                }
            }
            5 => {
                let j = rng.below(d.len());
                let n = rng.below(64).min(d.len() - i.max(j));
                let chunk = d[j..j + n].to_vec();
                d.splice(i..i, chunk);
            }
            6 => {
                let n = rng.below(32).min(d.len() - i);
                d.drain(i..i + n);
            }
            7 => d[i] = d[i].wrapping_add(1 + rng.below(3) as u8),
            _ => {
                let j = rng.below(d.len());
                d.swap(i, j);
            }
        }
    }
    d.truncate(4 << 20);
    d
}

/// Run `f` over mutations of `seeds`; panics name the target and input.
fn run(target: &str, seeds: &[Vec<u8>], iterations: usize, f: impl Fn(&[u8])) {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ target.len() as u64);
    for n in 0..iterations {
        let seed = &seeds[n % seeds.len()];
        let input = if n < seeds.len() { seed.clone() } else { mutate(&mut rng, seed) };
        let t = Instant::now();
        let r = catch_unwind(AssertUnwindSafe(|| f(&input)));
        let took = t.elapsed();
        if r.is_err() || took > SLOW {
            let path = std::env::temp_dir().join(format!("procwatch-fuzz-{target}-{n}.bin"));
            let _ = std::fs::write(&path, &input);
            panic!("{target}: {} on iteration {n} ({} bytes, saved to {})", if r.is_err() { "panic" } else { "too slow" }, input.len(), path.display());
        }
    }
}

fn iterations(default: usize) -> usize {
    std::env::var("PW_FUZZ_ITERATIONS").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn walk(k: crate::host::artifacts::regf::Key, depth: usize, budget: &mut usize) {
    if depth > 8 || *budget == 0 {
        return;
    }
    let _ = k.name();
    let _ = k.last_write();
    for v in k.values().iter().take(64) {
        let _ = v.text();
    }
    for c in k.subkeys().into_iter().take(64) {
        *budget = budget.saturating_sub(1);
        walk(c, depth + 1, budget);
    }
}

pub(crate) fn binaries(data: &[u8]) {
    let _ = crate::files::binfmt::header(data);
    let _ = crate::files::binfmt::structure(data);
    let _ = crate::files::binfmt::indicators(data);
}

pub(crate) fn hive(data: &[u8]) {
    if let Ok(h) = crate::host::artifacts::regf::Hive::parse(data.to_vec()) {
        let mut budget = 2000;
        walk(h.root(), 0, &mut budget);
        let _ = crate::host::artifacts::hives::amcache(&h, "fuzz");
        let _ = crate::host::artifacts::hives::system(&h, "fuzz");
    }
}

fn seeds_binaries() -> Vec<Vec<u8>> {
    let mut v = vec![crate::files::binfmt::tests::synthetic_pe()];
    for p in ["/bin/ls", "/usr/bin/true", "/bin/sh"] {
        if let Ok(b) = std::fs::read(p) {
            v.push(b.into_iter().take(64 << 10).collect());
        }
    }
    let mut elf = vec![0x7f, b'E', b'L', b'F', 2, 1, 1];
    elf.resize(256, 0);
    v.push(elf);
    // Universal header whose slice points at itself.
    let mut fat = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1];
    fat.extend([0u8; 8]);
    fat.extend(0u32.to_be_bytes());
    fat.extend(64u32.to_be_bytes());
    fat.resize(64, 0);
    v.push(fat);
    v
}

fn seeds_hive() -> Vec<Vec<u8>> {
    use crate::host::artifacts::regf::tests::{wide, Builder};
    let mut b = Builder::new();
    let v1 = b.value("LowerCaseLongPath", 1, &wide("c:\\x.exe"));
    let v2 = b.value("Big", 3, &[9u8; 300]);
    let k = b.key("0006", 1, &[], &[v1, v2]);
    let inv = b.key("InventoryApplicationFile", 0, &[k], &[]);
    let r = b.key("Root", 0, &[inv], &[]);
    let top = b.key("ROOT", 0, &[r], &[]);
    vec![b.finish(top)]
}

fn small() -> usize {
    iterations(400).min(400)
}

#[test]
fn quick_binaries() {
    run("binaries", &seeds_binaries(), small(), binaries);
}

#[test]
fn quick_artifacts() {
    run("prefetch", &[crate::host::artifacts::prefetch::tests::sample()], small(), |d| {
        let _ = crate::host::artifacts::prefetch::parse(d);
    });
    run("hive", &seeds_hive(), small(), hive);
}

#[test]
#[ignore]
fn fuzz_binaries() {
    run("binaries", &seeds_binaries(), iterations(10_000), binaries);
}

#[test]
#[ignore]
fn fuzz_prefetch_and_xpress() {
    use crate::host::artifacts::xpress::tests::{encode, Op};
    let raw = crate::host::artifacts::prefetch::tests::sample();
    let mut mam = b"MAM\x04".to_vec();
    mam.extend((raw.len() as u32).to_le_bytes());
    mam.extend(encode(&raw.iter().map(|b| Op::Lit(*b)).collect::<Vec<_>>()));
    run("prefetch", &[raw, mam.clone()], iterations(50_000), |d| {
        let _ = crate::host::artifacts::prefetch::parse(d);
    });
    run("xpress", &[mam[8..].to_vec()], iterations(50_000), |d| {
        let _ = crate::host::artifacts::xpress::decompress(d, 65536);
    });
}

#[test]
#[ignore]
fn fuzz_shimcache_and_hive() {
    let mut shim = vec![0u8; 0x34];
    shim[0..4].copy_from_slice(&0x34u32.to_le_bytes());
    let path: Vec<u8> = "C:\\x.exe".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let mut body = (path.len() as u16).to_le_bytes().to_vec();
    body.extend(&path);
    body.extend(1u64.to_le_bytes());
    body.extend(0u32.to_le_bytes());
    shim.extend(b"10ts");
    shim.extend(0u32.to_le_bytes());
    shim.extend((body.len() as u32).to_le_bytes());
    shim.extend(body);
    run("shimcache", &[shim], iterations(50_000), |d| {
        let _ = crate::host::artifacts::shimcache::parse(d);
    });
    run("hive", &seeds_hive(), iterations(20_000), hive);
}

#[test]
#[ignore]
fn fuzz_evtx() {
    // No real EVTX sample ships with the tests; fuzz the file-header path
    // with a minimal header-shaped seed.
    let mut seed = b"ElfFile\0".to_vec();
    seed.resize(4096 + 65536, 0);
    seed[4096..4104].copy_from_slice(b"ElfChnk\0");
    run("evtx", &[seed], iterations(5_000), |d| {
        if let Ok(mut p) = evtx::EvtxParser::from_buffer(d.to_vec()) {
            for rec in p.records_json_value().take(50).flatten() {
                let _ = crate::host::artifacts::evtx::from_json(&rec.data, None, 0);
            }
        }
    });
}

#[test]
#[ignore]
fn fuzz_rule_and_text_parsers() {
    let yara = include_str!("../rules/yara/procwatch-builtin.yar").as_bytes().to_vec();
    let rules = crate::files::yara::builtin();
    run("yara", &[yara], iterations(20_000), |d| {
        let (r, _) = crate::files::yara::parse(&String::from_utf8_lossy(d), "fuzz");
        let _ = crate::files::yara::scan_bytes(&r, d);
        let _ = crate::files::yara::scan_bytes(&rules, d);
    });
    let sigma = include_str!("../rules/sigma/procwatch-builtin.yml").as_bytes().to_vec();
    run("sigma", &[sigma], iterations(10_000), |d| {
        let _ = crate::detection::sigma::parse(&String::from_utf8_lossy(d), "fuzz");
    });
    let ioc = b"44d88612fea8a8f36de82e1278abb02f\n203.0.113.7\nhxxp://bad[.]example/x\n/tmp/.x\n\"Invoke\"\n".to_vec();
    run("ioc", &[ioc], iterations(20_000), |d| {
        let _ = crate::detection::ioc::parse(&String::from_utf8_lossy(d));
    });
    let hist = b": 1700000000:0;curl x | sh\n#1700000000\nwhoami\n- cmd: ls\n  when: 1700000000\n".to_vec();
    run("history", &[hist], iterations(20_000), |d| {
        let _ = crate::host::artifacts::parse_history(std::path::Path::new("/h/.zsh_history"), d, None);
        let _ = crate::host::artifacts::parse_history(std::path::Path::new("/h/fish_history"), d, None);
        let _ = crate::host::artifacts::base64_decode(&String::from_utf8_lossy(d));
        let _ = crate::common::filter::Filter::parse(&String::from_utf8_lossy(d));
    });
}
