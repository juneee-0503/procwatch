//! LZ77 + Huffman ("Xpress Huffman") decompression as specified in
//! [MS-XCA] §2.2.4. Windows 10 and later store Prefetch files in this
//! format (the "MAM" container).

const TABLE_BITS: u32 = 15;

/// (symbol, code length) for every 15-bit prefix.
fn build_table(lens: &[u8; 512]) -> Result<Vec<(u16, u8)>, String> {
    let mut table = vec![(0u16, 0u8); 1 << TABLE_BITS];
    let mut syms: Vec<(u8, u16)> = lens.iter().enumerate().filter(|(_, l)| **l > 0).map(|(s, l)| (*l, s as u16)).collect();
    // Canonical order: by code length, then symbol value.
    syms.sort_unstable();
    let mut code: u32 = 0;
    let mut prev_len = 0u8;
    for (len, sym) in syms {
        code <<= len - prev_len;
        prev_len = len;
        let span = 1u32 << (TABLE_BITS - len as u32);
        let first = code << (TABLE_BITS - len as u32);
        if first + span > (1 << TABLE_BITS) {
            return Err("invalid Huffman table".into());
        }
        for e in &mut table[first as usize..(first + span) as usize] {
            *e = (sym, len);
        }
        code += 1;
    }
    Ok(table)
}

/// Decompress `input` into exactly `out_size` bytes.
pub fn decompress(input: &[u8], out_size: usize) -> Result<Vec<u8>, String> {
    if out_size > 512 << 20 {
        return Err("declared size is implausibly large".into());
    }
    let byte = |p: usize| input.get(p).copied().unwrap_or(0) as u32;
    let read16 = |p: usize| byte(p) | (byte(p + 1) << 8);
    let mut out: Vec<u8> = Vec::with_capacity(out_size);
    let mut pos = 0usize;
    while out.len() < out_size {
        if pos + 256 > input.len() {
            return Err("compressed data is truncated".into());
        }
        let mut lens = [0u8; 512];
        for i in 0..256 {
            lens[2 * i] = input[pos + i] & 0x0f;
            lens[2 * i + 1] = input[pos + i] >> 4;
        }
        let table = build_table(&lens)?;
        pos += 256;
        let mut bits: u32 = (read16(pos) << 16) | read16(pos + 2);
        pos += 4;
        let mut extra: i32 = 16;
        let block_end = (out.len() + 65536).min(out_size);
        macro_rules! consume {
            ($n:expr) => {{
                let n = $n as u32;
                if n > 0 {
                    bits = if n >= 32 { 0 } else { bits << n };
                    extra -= n as i32;
                    if extra < 0 {
                        bits |= read16(pos) << (-extra) as u32;
                        extra += 16;
                        pos += 2;
                    }
                }
            }};
        }
        while out.len() < block_end {
            if pos > input.len() + 4 {
                return Err("ran past the end of the compressed data".into());
            }
            let (sym, len) = table[(bits >> (32 - TABLE_BITS)) as usize];
            if len == 0 {
                return Err("invalid Huffman code".into());
            }
            consume!(len);
            if sym < 256 {
                out.push(sym as u8);
                continue;
            }
            let s = sym - 256;
            let mut mlen = (s & 0x0f) as usize;
            let obits = (s >> 4) as u32;
            if mlen == 15 {
                mlen = byte(pos) as usize;
                pos += 1;
                if mlen == 255 {
                    mlen = read16(pos) as usize;
                    pos += 2;
                    if mlen == 0 {
                        mlen = (read16(pos) | (read16(pos + 2) << 16)) as usize;
                        pos += 4;
                    }
                    if mlen < 15 {
                        return Err("invalid match length".into());
                    }
                    mlen -= 15;
                }
                mlen += 15;
            }
            mlen += 3;
            let mut offset = if obits == 0 { 0 } else { (bits >> (32 - obits)) as usize };
            offset += 1usize << obits;
            consume!(obits);
            if offset > out.len() {
                return Err("match refers before the start of the output".into());
            }
            let start = out.len() - offset;
            let mlen = mlen.min(out_size - out.len());
            for k in 0..mlen {
                let b = out[start + k];
                out.push(b);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Minimal encoder for tests: every symbol has a 9-bit code (so the
    /// canonical code of symbol s is s), literals plus short matches.
    pub fn encode(ops: &[Op]) -> Vec<u8> {
        struct Bits {
            words: Vec<u16>,
            acc: u32,
            n: u32,
        }
        impl Bits {
            fn put(&mut self, v: u32, bits: u32) {
                for i in (0..bits).rev() {
                    self.acc = (self.acc << 1) | ((v >> i) & 1);
                    self.n += 1;
                    if self.n == 16 {
                        self.words.push(self.acc as u16);
                        self.acc = 0;
                        self.n = 0;
                    }
                }
            }
        }
        let mut out = vec![0x99u8; 256];
        let mut b = Bits { words: Vec::new(), acc: 0, n: 0 };
        for op in ops {
            match *op {
                Op::Lit(c) => b.put(c as u32, 9),
                Op::Match { len, offset } => {
                    assert!((3..18).contains(&len) && offset >= 1);
                    let obits = usize::BITS - 1 - offset.leading_zeros();
                    b.put(256 + ((obits << 4) | (len as u32 - 3)), 9);
                    b.put((offset - (1 << obits)) as u32, obits);
                }
            }
        }
        if b.n > 0 {
            b.put(0, 16 - b.n);
        }
        b.words.extend([0, 0]);
        for w in b.words {
            out.extend(w.to_le_bytes());
        }
        out
    }

    pub enum Op {
        Lit(u8),
        Match { len: usize, offset: usize },
    }

    #[test]
    fn round_trip() {
        use Op::*;
        let mut ops: Vec<Op> = b"abcabcabc-xyz".iter().map(|b| Lit(*b)).collect();
        ops.push(Match { len: 9, offset: 13 });
        ops.push(Match { len: 4, offset: 1 });
        let enc = encode(&ops);
        let dec = decompress(&enc, 13 + 9 + 4).unwrap();
        assert_eq!(&dec, b"abcabcabc-xyzabcabcabccccc");
    }

    #[test]
    fn rejects_garbage() {
        assert!(decompress(&[0u8; 10], 100).is_err());
        let mut bad = vec![0u8; 300];
        bad[0] = 1; // a single 1-bit code: incomplete but decodable
        assert!(decompress(&bad, 1usize << 30).is_err());
    }
}

#[cfg(test)]
mod dump {
    /// Writes a sample stream for cross-checking against another decoder
    /// when PW_XPRESS_DUMP is set (no-op otherwise).
    #[test]
    fn dump_sample() {
        use super::tests::{encode, Op};
        let Ok(path) = std::env::var("PW_XPRESS_DUMP") else { return };
        let mut ops: Vec<Op> = (0..60_000u32).map(|i| Op::Lit((i % 251) as u8)).collect();
        ops.push(Op::Match { len: 17, offset: 251 });
        ops.push(Op::Match { len: 3, offset: 1 });
        std::fs::write(path, encode(&ops)).unwrap();
    }
}
