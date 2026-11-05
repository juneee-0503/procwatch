//! A small BPF assembler. The programs are built here rather than compiled
//! from C, so procwatch stays one file: no clang, no kernel headers and no
//! object files to ship, and the kernel's verifier checks them at load.

use std::collections::HashMap;

pub const R0: u8 = 0;
pub const R1: u8 = 1;
pub const R2: u8 = 2;
pub const R3: u8 = 3;
pub const R6: u8 = 6;
pub const R7: u8 = 7;
pub const R8: u8 = 8;
pub const R10: u8 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Size {
    W = 0x00,
    H = 0x08,
    B = 0x10,
    Dw = 0x18,
}

const LDX: u8 = 0x61;
const STX: u8 = 0x63;
const ST: u8 = 0x62;
const JMP: u8 = 0x05;

/// Conditional jumps, comparing with a constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cond {
    Eq = 0x15,
    Ne = 0x55,
    Gt = 0x25,
    /// Any bit in common.
    Set = 0x45,
}

#[derive(Default)]
pub struct Asm {
    insns: Vec<[u8; 8]>,
    labels: HashMap<&'static str, usize>,
    jumps: Vec<(usize, &'static str)>,
}

impl Asm {
    fn raw(&mut self, code: u8, dst: u8, src: u8, off: i16, imm: i32) {
        let o = off.to_le_bytes();
        let i = imm.to_le_bytes();
        self.insns.push([code, dst | (src << 4), o[0], o[1], i[0], i[1], i[2], i[3]]);
    }

    pub fn label(&mut self, name: &'static str) {
        let at = self.insns.len();
        assert!(self.labels.insert(name, at).is_none(), "label {name} used twice");
    }

    pub fn mov_imm(&mut self, dst: u8, imm: i32) {
        self.raw(0xb7, dst, 0, 0, imm);
    }

    pub fn mov(&mut self, dst: u8, src: u8) {
        self.raw(0xbf, dst, src, 0, 0);
    }

    pub fn add_imm(&mut self, dst: u8, imm: i32) {
        self.raw(0x07, dst, 0, 0, imm);
    }

    pub fn and_imm(&mut self, dst: u8, imm: i32) {
        self.raw(0x57, dst, 0, 0, imm);
    }

    /// `dst &= src`.
    pub fn raw_and(&mut self, dst: u8, src: u8) {
        self.raw(0x5f, dst, src, 0, 0);
    }

    /// A 64-bit constant, in two instruction slots.
    pub fn load_u64(&mut self, dst: u8, value: u64) {
        self.raw(0x18, dst, 0, 0, value as u32 as i32);
        self.raw(0, 0, 0, 0, (value >> 32) as u32 as i32);
    }

    /// A map's file descriptor, which the verifier turns into its address.
    pub fn load_map(&mut self, dst: u8, fd: i32) {
        const PSEUDO_MAP_FD: u8 = 1;
        self.raw(0x18, dst, PSEUDO_MAP_FD, 0, fd);
        self.raw(0, 0, 0, 0, 0);
    }

    pub fn load(&mut self, size: Size, dst: u8, src: u8, off: i16) {
        self.raw(LDX | size as u8, dst, src, off, 0);
    }

    pub fn store(&mut self, size: Size, dst: u8, off: i16, src: u8) {
        self.raw(STX | size as u8, dst, src, off, 0);
    }

    pub fn store_imm(&mut self, size: Size, dst: u8, off: i16, imm: i32) {
        self.raw(ST | size as u8, dst, 0, off, imm);
    }

    /// `*(u64 *)(dst + off) += src`, atomically.
    pub fn atomic_add(&mut self, dst: u8, off: i16, src: u8) {
        self.raw(0xdb, dst, src, off, 0);
    }

    pub fn call(&mut self, helper: i32) {
        self.raw(0x85, 0, 0, 0, helper);
    }

    pub fn exit(&mut self) {
        self.raw(0x95, 0, 0, 0, 0);
    }

    pub fn jump(&mut self, target: &'static str) {
        self.jumps.push((self.insns.len(), target));
        self.raw(JMP, 0, 0, 0, 0);
    }

    pub fn jump_if(&mut self, cond: Cond, reg: u8, imm: i32, target: &'static str) {
        self.jumps.push((self.insns.len(), target));
        self.raw(cond as u8, reg, 0, 0, imm);
    }

    pub fn jumps_to(&self, target: &str) -> bool {
        self.jumps.iter().any(|(_, t)| *t == target)
    }

    pub fn jump_if_regs_eq(&mut self, a: u8, b: u8, target: &'static str) {
        self.jumps.push((self.insns.len(), target));
        self.raw(0x1d, a, b, 0, 0);
    }

    pub fn jump_if_regs_ne(&mut self, a: u8, b: u8, target: &'static str) {
        self.jumps.push((self.insns.len(), target));
        self.raw(0x5d, a, b, 0, 0);
    }

    /// The finished program as little-endian instructions.
    pub fn finish(mut self) -> Result<Vec<u8>, String> {
        for (at, name) in std::mem::take(&mut self.jumps) {
            let target = *self.labels.get(name).ok_or_else(|| format!("no label {name}"))?;
            let off = target as i64 - at as i64 - 1;
            let off = i16::try_from(off).map_err(|_| format!("jump to {name} too far"))?;
            self.insns[at][2..4].copy_from_slice(&off.to_le_bytes());
        }
        Ok(self.insns.concat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected bytes are from the kernel's instruction reference.
    #[test]
    fn encodes_instructions() {
        let mut a = Asm::default();
        a.mov_imm(R0, 0);
        a.exit();
        a.call(14);
        a.load(Size::Dw, R1, R2, 8);
        a.store(Size::W, R6, 4, R8);
        a.store_imm(Size::W, R6, 0, 7);
        a.mov(R6, R1);
        a.add_imm(R1, 64);
        let b = a.finish().unwrap();
        let line = |i: usize| b[i * 8..(i + 1) * 8].to_vec();
        assert_eq!(line(0), [0xb7, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(line(1), [0x95, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(line(2), [0x85, 0, 0, 0, 14, 0, 0, 0]);
        assert_eq!(line(3), [0x79, 0x21, 8, 0, 0, 0, 0, 0]);
        assert_eq!(line(4), [0x63, 0x86, 4, 0, 0, 0, 0, 0]);
        assert_eq!(line(5), [0x62, 0x06, 0, 0, 7, 0, 0, 0]);
        assert_eq!(line(6), [0xbf, 0x16, 0, 0, 0, 0, 0, 0]);
        assert_eq!(line(7), [0x07, 0x01, 0, 0, 64, 0, 0, 0]);
    }

    #[test]
    fn wide_loads_take_two_slots() {
        let mut a = Asm::default();
        a.load_u64(R1, 0x1122_3344_5566_7788);
        a.load_map(R1, 9);
        let b = a.finish().unwrap();
        assert_eq!(b.len(), 32);
        assert_eq!(b[..8], [0x18, 1, 0, 0, 0x88, 0x77, 0x66, 0x55]);
        assert_eq!(b[8..16], [0, 0, 0, 0, 0x44, 0x33, 0x22, 0x11]);
        assert_eq!(b[16..24], [0x18, 0x11, 0, 0, 9, 0, 0, 0]);
    }

    #[test]
    fn jumps_resolve_forwards_and_backwards() {
        let mut a = Asm::default();
        a.label("start");
        a.jump_if(Cond::Eq, R0, 0, "end");
        a.jump("start");
        a.label("end");
        a.exit();
        let b = a.finish().unwrap();
        assert_eq!(b[..4], [0x15, 0, 1, 0]);
        assert_eq!(i16::from_le_bytes([b[10], b[11]]), -2);
    }

    #[test]
    fn mistakes_are_reported() {
        let mut a = Asm::default();
        a.jump("nowhere");
        assert!(a.finish().is_err());
    }
}
