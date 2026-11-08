//! The programs loaded into the kernel. Each runs when a system call enters
//! and writes one fixed-size record to a ring buffer. They only observe: no
//! program can change, block or signal anything, and they read nothing but
//! the arguments of the call being made (a path, an argument list, an
//! address). They are all built from `Probe`, which keeps the shape the
//! verifier needs in one place.

use super::asm::{Asm, Cond, Size, R0, R1, R2, R3, R6, R7, R8, R10};

/// Record layout, in bytes. See `event::decode`.
pub const KIND: i16 = 0;
pub const ARGC: i16 = 4;
pub const TASK: i16 = 8;
pub const UID: i16 = 16;
pub const TIME: i16 = 24;
pub const COMM: i16 = 32;
pub const ARG0: i16 = 48;
pub const ARG1: i16 = 56;
pub const PATH: i16 = 64;
pub const PATH_LEN: usize = 256;
pub const ARGS: i16 = 320;
pub const ARG_LEN: usize = 160;
pub const MAX_ARGS: usize = 7;
pub const RECORD: usize = 1440;

// Kernel helper functions, by their stable numbers.
const MAP_LOOKUP: i32 = 1;
const KTIME: i32 = 5;
const PID_TGID: i32 = 14;
const UID_GID: i32 = 15;
const COMM_NAME: i32 = 16;
const READ_USER: i32 = 112;
const READ_USER_STR: i32 = 114;
const RING_RESERVE: i32 = 131;
const RING_SUBMIT: i32 = 132;
const RING_DISCARD: i32 = 133;

// Where a syscall tracepoint keeps its arguments, in eight-byte slots.
const fn slot(n: i16) -> i16 {
    16 + n * 8
}

const O_WRONLY: i32 = 0x1;
const O_RDWR: i32 = 0x2;
const O_CREAT: i32 = 0x40;
const O_TRUNC: i32 = 0x200;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Kind {
    Exec = 1,
    Connect = 2,
    Open = 3,
    Memfd = 4,
    Ptrace = 5,
    Module = 6,
    Dup = 7,
}

impl Kind {
    pub fn from_u32(v: u32) -> Option<Kind> {
        [Kind::Exec, Kind::Connect, Kind::Open, Kind::Memfd, Kind::Ptrace, Kind::Module, Kind::Dup].into_iter().find(|k| *k as u32 == v)
    }
}

/// The maps every program shares.
#[derive(Debug, Clone, Copy)]
pub struct Maps {
    pub ring: i32,
    pub lost: i32,
}

/// Assembles the common start and end around a program's own work.
struct Probe {
    a: Asm,
    lost: i32,
}

impl Probe {
    /// `filter` runs first, with the context in R7, and can leave for `done`.
    fn new(maps: Maps, kind: Kind, filter: impl FnOnce(&mut Asm)) -> Probe {
        let mut a = Asm::default();
        a.mov(R7, R1);
        filter(&mut a);
        a.load_map(R1, maps.ring);
        a.mov_imm(R2, RECORD as i32);
        a.mov_imm(R3, 0);
        a.call(RING_RESERVE);
        a.jump_if(Cond::Eq, R0, 0, "lost");
        a.mov(R6, R0);
        a.store_imm(Size::W, R6, KIND, kind as i32);
        a.store_imm(Size::W, R6, ARGC, 0);
        a.call(PID_TGID);
        a.store(Size::Dw, R6, TASK, R0);
        a.call(UID_GID);
        a.store(Size::Dw, R6, UID, R0);
        a.call(KTIME);
        a.store(Size::Dw, R6, TIME, R0);
        a.mov(R1, R6);
        a.add_imm(R1, i32::from(COMM));
        a.mov_imm(R2, 16);
        a.call(COMM_NAME);
        // Records are reused: nothing old may show through as a path.
        a.store_imm(Size::Dw, R6, ARG0, 0);
        a.store_imm(Size::Dw, R6, ARG1, 0);
        a.store_imm(Size::B, R6, PATH, 0);
        Probe { a, lost: maps.lost }
    }

    fn arg(&mut self, from: i16, into: i16) {
        self.a.load(Size::Dw, R1, R7, slot(from));
        self.a.store(Size::Dw, R6, into, R1);
    }

    /// A user string at a tracepoint argument, into the record.
    fn string(&mut self, from: i16, into: i16, len: usize) {
        self.a.mov(R1, R6);
        self.a.add_imm(R1, i32::from(into));
        self.a.mov_imm(R2, len as i32);
        self.a.load(Size::Dw, R3, R7, slot(from));
        self.a.call(READ_USER_STR);
    }

    fn finish(mut self) -> Result<Vec<u8>, String> {
        let a = &mut self.a;
        a.mov(R1, R6);
        a.mov_imm(R2, 0);
        a.call(RING_SUBMIT);
        a.label("done");
        a.mov_imm(R0, 0);
        a.exit();
        // The verifier refuses code that nothing can reach.
        if a.jumps_to("discard") {
            a.label("discard");
            a.mov(R1, R6);
            a.mov_imm(R2, 0);
            a.call(RING_DISCARD);
            a.mov_imm(R0, 0);
            a.exit();
        }
        // The buffer was full: count it, so the loss can be reported.
        a.label("lost");
        a.store_imm(Size::W, R10, -4, 0);
        a.load_map(R1, self.lost);
        a.mov(R2, R10);
        a.add_imm(R2, -4);
        a.call(MAP_LOOKUP);
        a.jump_if(Cond::Eq, R0, 0, "out");
        a.mov_imm(R1, 1);
        a.atomic_add(R0, 0, R1);
        a.label("out");
        a.mov_imm(R0, 0);
        a.exit();
        self.a.finish()
    }
}

/// `execve(path, argv, envp)` and `execveat(fd, path, argv, ...)`.
fn exec(maps: Maps, path: i16, argv: i16) -> Result<Vec<u8>, String> {
    let mut p = Probe::new(maps, Kind::Exec, |_| {});
    p.string(path, PATH, PATH_LEN);
    let a = &mut p.a;
    a.mov_imm(R8, 0);
    const NEXT: [&str; MAX_ARGS] = ["a0", "a1", "a2", "a3", "a4", "a5", "a6"];
    for (i, skip) in NEXT.iter().enumerate() {
        a.label(skip);
        // The pointer to this argument is itself in user memory.
        a.mov(R1, R10);
        a.add_imm(R1, -16);
        a.mov_imm(R2, 8);
        a.load(Size::Dw, R3, R7, slot(argv));
        a.add_imm(R3, (i * 8) as i32);
        a.call(READ_USER);
        a.jump_if(Cond::Ne, R0, 0, "args_end");
        a.load(Size::Dw, R3, R10, -16);
        a.jump_if(Cond::Eq, R3, 0, "args_end");
        a.mov(R1, R6);
        a.add_imm(R1, i32::from(ARGS) + (i * ARG_LEN) as i32);
        a.mov_imm(R2, ARG_LEN as i32);
        a.call(READ_USER_STR);
        a.add_imm(R8, 1);
    }
    a.label("args_end");
    a.store(Size::W, R6, ARGC, R8);
    p.finish()
}

/// `connect(fd, address, length)`, for internet addresses that aren't local.
fn connect(maps: Maps) -> Result<Vec<u8>, String> {
    let mut p = Probe::new(maps, Kind::Connect, |_| {});
    p.arg(0, ARG0);
    let a = &mut p.a;
    a.mov(R1, R6);
    a.add_imm(R1, i32::from(PATH));
    a.mov_imm(R2, 16);
    a.load(Size::Dw, R3, R7, slot(1));
    a.call(READ_USER);
    a.jump_if(Cond::Ne, R0, 0, "discard");
    a.load(Size::H, R1, R6, PATH);
    a.jump_if(Cond::Eq, R1, AF_INET6, "v6");
    a.jump_if(Cond::Ne, R1, AF_INET, "discard");
    a.load(Size::B, R1, R6, PATH + 4);
    a.jump_if(Cond::Eq, R1, 127, "discard");
    a.jump("connect_end");
    a.label("v6");
    a.mov(R1, R6);
    a.add_imm(R1, i32::from(PATH));
    a.mov_imm(R2, 28);
    a.load(Size::Dw, R3, R7, slot(1));
    a.call(READ_USER);
    a.jump_if(Cond::Ne, R0, 0, "discard");
    a.label("connect_end");
    p.finish()
}

/// Bytes of an ASCII path prefix as the little-endian word they load as.
const fn word(prefix: &[u8]) -> u64 {
    let mut v = 0;
    let mut i = 0;
    while i < prefix.len() {
        v |= (prefix[i] as u64) << (i * 8);
        i += 1;
    }
    v
}

const fn mask(bytes: u32) -> u64 {
    if bytes >= 8 { u64::MAX } else { (1 << (bytes * 8)) - 1 }
}

/// Opening for writing under the paths attackers persist in. `open` keeps
/// its path and flags one slot earlier than `openat`.
fn open(maps: Maps, path: i16, flags: i16) -> Result<Vec<u8>, String> {
    let mut p = Probe::new(maps, Kind::Open, |a| {
        a.load(Size::Dw, R1, R7, slot(flags));
        a.and_imm(R1, O_WRONLY | O_RDWR | O_CREAT | O_TRUNC);
        a.jump_if(Cond::Eq, R1, 0, "done");
    });
    p.arg(flags, ARG0);
    p.string(path, PATH, PATH_LEN);
    let a = &mut p.a;
    a.load(Size::Dw, R8, R6, PATH);
    let wanted: [(&[u8], &'static str); 4] = [(b"/etc/", "p1"), (b"/root/", "p2"), (b"/home/", "p3"), (b"/var/spo", "p4")];
    for (prefix, next) in wanted {
        a.mov(R1, R8);
        a.load_u64(R2, mask(prefix.len() as u32));
        a.raw_and(R1, R2);
        a.load_u64(R2, word(prefix));
        a.jump_if_regs_eq(R1, R2, "submit");
        a.label(next);
    }
    // Logs are always being written; only emptying one is news.
    a.load_u64(R2, word(b"/var/log"));
    a.jump_if_regs_ne(R8, R2, "discard");
    a.load(Size::Dw, R1, R7, slot(flags));
    a.jump_if(Cond::Set, R1, O_TRUNC, "submit");
    a.jump("discard");
    a.label("submit");
    p.finish()
}

fn memfd(maps: Maps) -> Result<Vec<u8>, String> {
    let mut p = Probe::new(maps, Kind::Memfd, |_| {});
    p.string(0, PATH, PATH_LEN);
    p.finish()
}

fn ptrace(maps: Maps) -> Result<Vec<u8>, String> {
    let mut p = Probe::new(maps, Kind::Ptrace, |_| {});
    p.arg(0, ARG0);
    p.arg(1, ARG1);
    p.finish()
}

fn module(maps: Maps) -> Result<Vec<u8>, String> {
    Probe::new(maps, Kind::Module, |_| {}).finish()
}

/// Duplicating a descriptor onto standard input, output or error.
fn dup(maps: Maps) -> Result<Vec<u8>, String> {
    let mut p = Probe::new(maps, Kind::Dup, |a| {
        a.load(Size::Dw, R1, R7, slot(1));
        a.jump_if(Cond::Gt, R1, 2, "done");
        a.load(Size::Dw, R1, R7, slot(0));
        a.jump_if(Cond::Eq, R1, 0, "done");
        a.jump_if(Cond::Eq, R1, 1, "done");
        a.jump_if(Cond::Eq, R1, 2, "done");
    });
    p.arg(0, ARG0);
    p.arg(1, ARG1);
    p.finish()
}

/// Which tracepoint runs which program. Some don't exist on every
/// architecture, such as `open` and `dup2` on arm64.
pub fn all(maps: Maps) -> Result<Vec<(&'static str, Vec<u8>)>, String> {
    Ok(vec![
        ("sys_enter_execve", exec(maps, 0, 1)?),
        ("sys_enter_execveat", exec(maps, 1, 2)?),
        ("sys_enter_connect", connect(maps)?),
        ("sys_enter_openat", open(maps, 1, 2)?),
        ("sys_enter_open", open(maps, 0, 1)?),
        ("sys_enter_memfd_create", memfd(maps)?),
        ("sys_enter_ptrace", ptrace(maps)?),
        ("sys_enter_init_module", module(maps)?),
        ("sys_enter_finit_module", module(maps)?),
        ("sys_enter_dup2", dup(maps)?),
        ("sys_enter_dup3", dup(maps)?),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS: Maps = Maps { ring: 3, lost: 4 };

    /// The rules the verifier enforces that can be checked without one.
    fn sound(name: &str, code: &[u8]) {
        assert_eq!(code.len() % 8, 0);
        let n = code.len() / 8;
        assert!(n < 4096, "{name} too long");
        let mut wide = false;
        let mut exits = 0;
        let mut reached = vec![false; n + 2];
        reached[0] = true;
        for i in 0..n {
            let ins = &code[i * 8..(i + 1) * 8];
            if wide {
                wide = false;
                continue;
            }
            match ins[0] {
                0x18 => wide = true,
                0x95 => exits += 1,
                c if c & 0x07 == 0x05 && c != 0x85 => {
                    let off = i16::from_le_bytes([ins[2], ins[3]]) as i64;
                    let target = i as i64 + 1 + off;
                    assert!(target >= 0 && target < n as i64, "{name}: jump at {i}");
                    assert!(off >= 0, "{name}: backward jump at {i}");
                    reached[target as usize] = true;
                    if c != 0x05 {
                        reached[i + 1] = true;
                    }
                    continue;
                }
                _ => {}
            }
            if ins[0] != 0x95 {
                reached[i + if ins[0] == 0x18 { 2 } else { 1 }] = true;
            }
        }
        for (i, r) in reached.iter().enumerate().take(n) {
            let second_half = i > 0 && code[(i - 1) * 8] == 0x18;
            assert!(*r || second_half, "{name}: nothing reaches instruction {i}");
        }
        assert!(exits >= 1, "{name}");
        assert_eq!(code[(n - 1) * 8] & 0x07, 0x05, "{name} must end in a jump or exit");
    }

    #[test]
    fn every_program_is_well_formed() {
        for (name, code) in all(MAPS).unwrap() {
            sound(name, &code);
        }
    }

    #[test]
    fn the_record_holds_every_argument() {
        assert_eq!(ARGS as usize, PATH as usize + PATH_LEN);
        assert_eq!(ARGS as usize + MAX_ARGS * ARG_LEN, RECORD);
        assert_eq!(RECORD % 8, 0);
    }

    #[test]
    fn prefixes_load_as_the_kernel_will_see_them() {
        assert_eq!(word(b"/etc/passwd\0"[..5].as_ref()), u64::from_le_bytes(*b"/etc/\0\0\0"));
        assert_eq!(u64::from_le_bytes(*b"/etc/pas") & mask(5), word(b"/etc/"));
        assert_eq!(mask(8), u64::MAX);
    }
}
