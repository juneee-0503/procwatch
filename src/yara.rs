//! Content rules in a subset of the YARA language, matched against files
//! on disk (never process memory).
//!
//! Supported:
//! - `rule name : tags { meta: … strings: … condition: … }`, `private`
//!   and `global` prefixes are accepted and ignored
//! - text strings with `ascii`, `wide`, `nocase`, `fullword`; escapes
//!   `\n \t \r \\ \" \xHH`
//! - hex strings with `??`, nibble wildcards (`4?`), jumps `[n]` `[n-m]`
//! - conditions: `and or not ( )`, `$a`, `#a` (count), `$a at N`,
//!   `$a in (N..M)`, `any|all|N of them`, `any|all|N of ($a*, $b)`,
//!   `filesize`, `uint8/16/32(N)` (+ `be` variants), comparisons, numbers
//!   with `KB`/`MB`, hex numbers
//!
//! Rules using regular expressions, modules (`pe.`, `math.`), `for …`
//! loops or `xor`/`base64` modifiers are rejected with a reason.

use std::path::Path;

use serde::Serialize;

/// First line of the built-in rule file; marks procwatch's own files.
const SELF_MARKER: &str = "// procwatch built-in content rules";

/// Files are read up to this size.
pub const MAX_SCAN: u64 = 64 << 20;

#[derive(Debug, Clone)]
enum Tok {
    Byte(u8, u8), // value, mask
    Jump(usize, usize),
}

#[derive(Debug, Clone)]
enum Pat {
    Text { bytes: Vec<Vec<u8>>, nocase: bool, fullword: bool },
    Hex(Vec<Tok>),
}

#[derive(Debug, Clone)]
struct Str {
    id: String,
    pat: Pat,
}

#[derive(Debug, Clone)]
enum Expr {
    Bool(bool),
    Num(i64),
    Found(String),
    Count(String),
    At(String, Box<Expr>),
    In(String, Box<Expr>, Box<Expr>),
    Of(Quant, Vec<String>),
    FileSize,
    Int { size: u8, be: bool, at: Box<Expr> },
    Not(Box<Expr>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Cmp(Box<Expr>, String, Box<Expr>),
}

#[derive(Debug, Clone, Copy)]
enum Quant {
    Any,
    All,
    N(usize),
}

#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub name: String,
    pub tags: Vec<String>,
    pub meta: Vec<(String, String)>,
    pub file: String,
    #[serde(skip)]
    strings: Vec<Str>,
    #[serde(skip)]
    condition: Expr,
}

impl Rule {
    pub fn meta(&self, k: &str) -> Option<&str> {
        self.meta.iter().find(|(m, _)| m.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Match {
    pub rule: String,
    pub tags: Vec<String>,
    pub description: String,
    /// From the rule's `severity` meta (default medium).
    pub severity: crate::model::Severity,
    /// From the rule's `confidence` meta (default medium).
    pub confidence: crate::model::Confidence,
    /// (string id, first offset, count)
    pub strings: Vec<(String, usize, usize)>,
}

// ── lexer ──────────────────────────────────────────────────────────────

fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let b: Vec<char> = src.chars().collect();
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c);
            if c == '\\' && i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            i += 1;
        } else if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
        } else if c == '/' && b.get(i + 1) == Some(&'/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && b.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == '*' && b[i + 1] == '/') {
                i += 1;
            }
            i += 2;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn unescape(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            match b[i + 1] {
                b'n' => out.push(b'\n'),
                b't' => out.push(b'\t'),
                b'r' => out.push(b'\r'),
                b'\\' => out.push(b'\\'),
                b'"' => out.push(b'"'),
                b'x' if i + 3 < b.len() => {
                    // Work on bytes: the two digits may be followed by (or
                    // be) multi-byte UTF-8, which a str slice would split.
                    let hex = |c: u8| (c as char).to_digit(16);
                    match (hex(b[i + 2]), hex(b[i + 3])) {
                        (Some(h), Some(l)) => out.push((h * 16 + l) as u8),
                        _ => return Err(format!("bad escape in \"{s}\"")),
                    }
                    i += 2;
                }
                c => return Err(format!("unknown escape \\{} in \"{s}\"", c as char)),
            }
            i += 2;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn parse_hex(body: &str) -> Result<Vec<Tok>, String> {
    let mut toks = Vec::new();
    let s: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'[' => {
                let end = s[i..].find(']').ok_or("unclosed jump in hex string")? + i;
                let inner = &s[i + 1..end];
                let (lo, hi) = match inner.split_once('-') {
                    Some((a, b)) => (a.parse().unwrap_or(0), if b.is_empty() { 4096 } else { b.parse().map_err(|_| "bad jump")? }),
                    None => {
                        let n = inner.parse().map_err(|_| "bad jump")?;
                        (n, n)
                    }
                };
                toks.push(Tok::Jump(lo, hi.min(65536)));
                i = end + 1;
            }
            b'(' | b'|' => return Err("alternatives in hex strings are not supported".into()),
            _ => {
                let pair = s.get(i..i + 2).ok_or("odd number of hex digits")?;
                let nib = |c: char| -> Result<(u8, u8), String> {
                    if c == '?' {
                        Ok((0, 0))
                    } else {
                        c.to_digit(16).map(|d| (d as u8, 0xf)).ok_or_else(|| format!("bad hex digit '{c}'"))
                    }
                };
                let mut cs = pair.chars();
                let (hv, hm) = nib(cs.next().unwrap())?;
                let (lv, lm) = nib(cs.next().unwrap())?;
                toks.push(Tok::Byte((hv << 4) | lv, (hm << 4) | lm));
                i += 2;
            }
        }
    }
    if !matches!(toks.first(), Some(Tok::Byte(..))) || !matches!(toks.last(), Some(Tok::Byte(..))) {
        return Err("hex strings must start and end with a byte".into());
    }
    Ok(toks)
}

fn parse_string(line: &str) -> Result<Str, String> {
    let (id, rest) = line.split_once('=').ok_or_else(|| format!("expected '$name = …' in: {line}"))?;
    let id = id.trim().to_string();
    let rest = rest.trim();
    if rest.starts_with('/') {
        return Err(format!("{id}: regular-expression strings are not supported"));
    }
    if let Some(body) = rest.strip_prefix('{') {
        let end = body.rfind('}').ok_or("unclosed hex string")?;
        return Ok(Str { id, pat: Pat::Hex(parse_hex(&body[..end])?) });
    }
    let body = rest.strip_prefix('"').ok_or_else(|| format!("{id}: expected a string"))?;
    let mut end = None;
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            end = Some(i);
            break;
        }
        i += 1;
    }
    let end = end.ok_or_else(|| format!("{id}: unterminated string"))?;
    let text = unescape(&body[..end])?;
    let mods: Vec<&str> = body[end + 1..].split_whitespace().collect();
    for m in &mods {
        if !["ascii", "wide", "nocase", "fullword", "private"].contains(m) {
            return Err(format!("{id}: modifier '{m}' is not supported"));
        }
    }
    let wide = mods.contains(&"wide");
    let ascii = mods.contains(&"ascii") || !wide;
    let mut forms = Vec::new();
    if ascii {
        forms.push(text.clone());
    }
    if wide {
        forms.push(text.iter().flat_map(|b| [*b, 0]).collect());
    }
    Ok(Str { id, pat: Pat::Text { bytes: forms, nocase: mods.contains(&"nocase"), fullword: mods.contains(&"fullword") } })
}

// ── condition parser ───────────────────────────────────────────────────

fn ctokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let c: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if "(),".contains(ch) {
            out.push(ch.to_string());
            i += 1;
        } else if "<>=!".contains(ch) {
            let two: String = c[i..(i + 2).min(c.len())].iter().collect();
            if ["<=", ">=", "==", "!="].contains(&two.as_str()) {
                out.push(two);
                i += 2;
            } else {
                out.push(ch.to_string());
                i += 1;
            }
        } else if ch == '.' && c.get(i + 1) == Some(&'.') {
            out.push("..".into());
            i += 2;
        } else {
            let start = i;
            while i < c.len() && !c[i].is_whitespace() && !"(),<>=!".contains(c[i]) && !(c[i] == '.' && c.get(i + 1) == Some(&'.')) {
                i += 1;
            }
            out.push(c[start..i].iter().collect());
        }
    }
    out
}

/// Conditions come from rule files; a stack overflow can't be caught, and
/// long `a and b and …` chains nest as deeply as parentheses do.
const MAX_NESTING: usize = 64;
const MAX_CONDITION_TOKENS: usize = 4096;

struct P<'a> {
    depth: usize,
    t: Vec<String>,
    i: usize,
    ids: &'a [String],
}

impl P<'_> {
    fn peek(&self) -> Option<&str> {
        self.t.get(self.i).map(String::as_str)
    }
    fn next(&mut self) -> Result<String, String> {
        let t = self.t.get(self.i).cloned().ok_or("condition ends too early")?;
        self.i += 1;
        Ok(t)
    }
    fn expect(&mut self, s: &str) -> Result<(), String> {
        let t = self.next()?;
        if t != s {
            return Err(format!("expected '{s}', found '{t}'"));
        }
        Ok(())
    }
    fn or(&mut self) -> Result<Expr, String> {
        let mut v = vec![self.and()?];
        while self.peek() == Some("or") {
            self.i += 1;
            v.push(self.and()?);
        }
        Ok(if v.len() == 1 { v.remove(0) } else { Expr::Or(v) })
    }
    fn and(&mut self) -> Result<Expr, String> {
        let mut v = vec![self.cmp()?];
        while self.peek() == Some("and") {
            self.i += 1;
            v.push(self.cmp()?);
        }
        Ok(if v.len() == 1 { v.remove(0) } else { Expr::And(v) })
    }
    fn cmp(&mut self) -> Result<Expr, String> {
        let l = self.unary()?;
        if let Some(op) = self.peek().filter(|t| ["<", ">", "<=", ">=", "==", "!="].contains(t)).map(str::to_string) {
            self.i += 1;
            let r = self.unary()?;
            return Ok(Expr::Cmp(Box::new(l), op, Box::new(r)));
        }
        Ok(l)
    }
    fn set(&mut self) -> Result<Vec<String>, String> {
        if self.peek() == Some("them") {
            self.i += 1;
            return Ok(self.ids.to_vec());
        }
        self.expect("(")?;
        let mut out = Vec::new();
        loop {
            let t = self.next()?;
            let pat = t.trim_end_matches('*');
            let wild = t.ends_with('*');
            let hits: Vec<String> = self.ids.iter().filter(|id| if wild { id.starts_with(pat) } else { *id == &t }).cloned().collect();
            if hits.is_empty() {
                return Err(format!("{t} matches no string"));
            }
            out.extend(hits);
            match self.next()?.as_str() {
                "," => continue,
                ")" => break,
                o => return Err(format!("unexpected '{o}' in string set")),
            }
        }
        Ok(out)
    }
    fn unary(&mut self) -> Result<Expr, String> {
        self.depth += 1;
        if self.depth > MAX_NESTING {
            return Err("condition nested too deeply".into());
        }
        let e = self.unary_inner();
        self.depth -= 1;
        e
    }
    fn unary_inner(&mut self) -> Result<Expr, String> {
        let t = self.next()?;
        let num = |s: &str| -> Option<i64> {
            let (n, mult) = if let Some(n) = s.strip_suffix("KB") { (n, 1024) } else if let Some(n) = s.strip_suffix("MB") { (n, 1 << 20) } else { (s, 1) };
            let v = if let Some(h) = n.strip_prefix("0x") { i64::from_str_radix(h, 16).ok()? } else { n.parse::<i64>().ok()? };
            Some(v * mult)
        };
        match t.as_str() {
            "not" => Ok(Expr::Not(Box::new(self.unary()?))),
            "(" => {
                let e = self.or()?;
                self.expect(")")?;
                Ok(e)
            }
            "true" => Ok(Expr::Bool(true)),
            "false" => Ok(Expr::Bool(false)),
            "filesize" => Ok(Expr::FileSize),
            "any" | "all" => {
                self.expect("of")?;
                Ok(Expr::Of(if t == "any" { Quant::Any } else { Quant::All }, self.set()?))
            }
            "for" => Err("'for' loops are not supported".into()),
            f if f.starts_with("uint") || f.starts_with("int") => {
                let be = f.ends_with("be");
                let size = f.trim_start_matches('u').trim_start_matches("int").trim_end_matches("be").parse::<u8>().map_err(|_| format!("unknown function {f}"))?;
                if ![8, 16, 32].contains(&size) {
                    return Err(format!("unknown function {f}"));
                }
                self.expect("(")?;
                let at = self.or()?;
                self.expect(")")?;
                Ok(Expr::Int { size, be, at: Box::new(at) })
            }
            s if s.starts_with('$') => {
                let id = s.to_string();
                if !self.ids.contains(&id) {
                    return Err(format!("{id} is not defined"));
                }
                match self.peek() {
                    Some("at") => {
                        self.i += 1;
                        Ok(Expr::At(id, Box::new(self.unary()?)))
                    }
                    Some("in") => {
                        self.i += 1;
                        self.expect("(")?;
                        let a = self.or()?;
                        self.expect("..")?;
                        let b = self.or()?;
                        self.expect(")")?;
                        Ok(Expr::In(id, Box::new(a), Box::new(b)))
                    }
                    _ => Ok(Expr::Found(id)),
                }
            }
            s if s.starts_with('#') => {
                let id = format!("${}", &s[1..]);
                if !self.ids.contains(&id) {
                    return Err(format!("{s} refers to an undefined string"));
                }
                Ok(Expr::Count(id))
            }
            s if num(s).is_some() => {
                if self.peek() == Some("of") {
                    self.i += 1;
                    return Ok(Expr::Of(Quant::N(num(s).unwrap_or(0) as usize), self.set()?));
                }
                Ok(Expr::Num(num(s).unwrap_or(0)))
            }
            s if s.contains('.') => Err(format!("modules ('{s}') are not supported")),
            s => Err(format!("unexpected '{s}' in condition")),
        }
    }
}

// ── rule file parser ───────────────────────────────────────────────────

/// Parse a rules file. Returns usable rules and per-rule problems.
pub fn parse(src: &str, file: &str) -> (Vec<Rule>, Vec<String>) {
    let src = strip_comments(src);
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    let mut rest = src.as_str();
    while let Some(pos) = find_rule(rest) {
        rest = &rest[pos..];
        let Some(open) = rest.find('{') else { break };
        let header = rest[..open].trim();
        // Find the matching close brace, skipping strings and hex bodies.
        let mut depth = 0;
        let mut end = None;
        let mut in_str = false;
        let bytes = rest.as_bytes();
        let mut i = open;
        while i < bytes.len() {
            let c = bytes[i];
            if in_str {
                if c == b'\\' {
                    i += 1;
                } else if c == b'"' {
                    in_str = false;
                }
            } else if c == b'"' {
                in_str = true;
            } else if c == b'{' {
                depth += 1;
            } else if c == b'}' {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            i += 1;
        }
        let Some(end) = end else {
            errors.push(format!("{file}: unclosed rule"));
            break;
        };
        let body = &rest[open + 1..end];
        rest = &rest[end + 1..];
        let head: Vec<&str> = header.split_whitespace().filter(|w| !["private", "global"].contains(w)).collect();
        let name = head.get(1).map(|s| s.trim_end_matches(':').to_string()).unwrap_or_default();
        let tags: Vec<String> = header.split_once(':').map(|(_, t)| t.split_whitespace().map(str::to_string).collect()).unwrap_or_default();
        match parse_body(body) {
            Ok((meta, strings, condition)) => rules.push(Rule { name, tags, meta, file: file.to_string(), strings, condition }),
            Err(e) => errors.push(format!("{file}: rule {name}: {e}")),
        }
    }
    (rules, errors)
}

fn find_rule(s: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(p) = s[from..].find("rule") {
        let at = from + p;
        let before_ok = at == 0 || s[..at].ends_with(char::is_whitespace);
        let after_ok = s[at + 4..].starts_with(char::is_whitespace);
        if before_ok && after_ok {
            // Include "private"/"global" prefixes on the same line.
            let line_start = s[..at].rfind('\n').map_or(0, |n| n + 1);
            return Some(line_start);
        }
        from = at + 4;
    }
    None
}

/// Split a strings section into `$id = …` definitions, which may share a
/// line; a `$` inside a quoted or hex body doesn't start a new one.
fn split_defs(src: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let (mut in_str, mut in_hex, mut esc) = (false, false, false);
    let mut prev = ' ';
    for ch in src.chars() {
        if in_str {
            cur.push(ch);
            if esc {
                esc = false;
            } else if ch == '\\' {
                esc = true;
            } else if ch == '"' {
                in_str = false;
            }
        } else if in_hex {
            cur.push(ch);
            if ch == '}' {
                in_hex = false;
            }
        } else {
            match ch {
                '$' if prev.is_whitespace() || cur.trim().is_empty() => {
                    if !cur.trim().is_empty() {
                        out.push(cur.trim().to_string());
                    }
                    cur = String::from('$');
                }
                '"' => {
                    in_str = true;
                    cur.push(ch);
                }
                '{' => {
                    in_hex = true;
                    cur.push(ch);
                }
                _ => cur.push(ch),
            }
        }
        prev = ch;
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

type Body = (Vec<(String, String)>, Vec<Str>, Expr);

fn parse_body(body: &str) -> Result<Body, String> {
    let sect = |name: &str| -> Option<usize> {
        let mut from = 0;
        while let Some(p) = body[from..].find(name) {
            let at = from + p;
            let ok = (at == 0 || body[..at].ends_with(char::is_whitespace)) && body[at + name.len()..].trim_start().starts_with(':');
            if ok {
                return Some(at);
            }
            from = at + name.len();
        }
        None
    };
    let (m, s, c) = (sect("meta"), sect("strings"), sect("condition").ok_or("no condition section")?);
    let after_colon = |at: usize| body[at..].find(':').map(|p| at + p + 1).unwrap_or(at);
    let span = |start: Option<usize>, ends: &[Option<usize>]| -> &str {
        let Some(st) = start else { return "" };
        let from = after_colon(st);
        let to = ends.iter().flatten().filter(|e| **e > st).min().copied().unwrap_or(body.len());
        &body[from..to]
    };
    let mut meta = Vec::new();
    for line in span(m, &[s, Some(c)]).lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some((k, v)) = line.split_once('=') {
            meta.push((k.trim().to_string(), v.trim().trim_matches('"').to_string()));
        }
    }
    let mut strings = Vec::new();
    for def in split_defs(span(s, &[Some(c)])) {
        strings.push(parse_string(&def)?);
    }
    let ids: Vec<String> = strings.iter().map(|s| s.id.clone()).collect();
    let cond_src = span(Some(c), &[]);
    let tokens = ctokens(cond_src);
    if tokens.len() > MAX_CONDITION_TOKENS {
        return Err(format!("condition too long ({} tokens)", tokens.len()));
    }
    let mut p = P { depth: 0, t: tokens, i: 0, ids: &ids };
    let condition = p.or()?;
    if p.i < p.t.len() {
        return Err(format!("unexpected '{}' in condition", p.t[p.i]));
    }
    Ok((meta, strings, condition))
}

/// Load `.yar` / `.yara` files under `dir` (recursively).
pub fn load_dir(dir: &Path) -> (Vec<Rule>, Vec<String>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            errors.push(format!("can't read {}", d.display()));
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "yar" || x == "yara") {
                match std::fs::read_to_string(&p) {
                    Ok(t) => {
                        let (r, e) = parse(&t, &p.file_name().unwrap_or_default().to_string_lossy());
                        rules.extend(r);
                        errors.extend(e);
                    }
                    Err(e) => errors.push(format!("{}: {e}", p.display())),
                }
            }
        }
    }
    (rules, errors)
}

pub fn builtin() -> Vec<Rule> {
    parse(include_str!("../rules/yara/procwatch-builtin.yar"), "built-in").0
}

pub fn default_dir() -> Option<std::path::PathBuf> {
    crate::common::paths::config_path().map(|p| p.with_file_name("yara"))
}

/// Built-in rules plus the user's folder.
pub fn load(dir: Option<&Path>) -> (Vec<Rule>, Vec<String>) {
    let mut rules = builtin();
    let mut errors = Vec::new();
    if let Some(d) = dir.map(Path::to_path_buf).or_else(default_dir).filter(|d| d.exists()) {
        let (u, e) = load_dir(&d);
        rules.retain(|b| !u.iter().any(|x| x.name == b.name));
        rules.extend(u);
        errors = e;
    }
    (rules, errors)
}

// ── matching ───────────────────────────────────────────────────────────

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `hay` is the data, already ASCII-lowercased when `nocase` (and the
/// needle lowercased too); fullword checks look at the original `data`.
fn text_offsets(data: &[u8], hay: &[u8], needle: &[u8], fullword: bool, limit: usize, out: &mut Vec<usize>) {
    if needle.is_empty() || needle.len() > hay.len() {
        return;
    }
    for i in memchr::memmem::find_iter(hay, needle) {
        let ok = !fullword || ((i == 0 || !is_word(data[i - 1])) && data.get(i + needle.len()).is_none_or(|b| !is_word(*b)));
        if ok {
            out.push(i);
            if out.len() >= limit {
                break;
            }
        }
    }
}

/// Backtracking over jumps is exponential in the worst case; a rule mustn't
/// be able to stall a scan, so each start position gets a budget.
const HEX_STEPS: u32 = 200_000;

fn hex_at(data: &[u8], at: usize, toks: &[Tok]) -> bool {
    fn step(data: &[u8], mut at: usize, mut toks: &[Tok], budget: &mut u32) -> bool {
        // Bytes loop rather than recurse: patterns can be long.
        while let Some(Tok::Byte(v, m)) = toks.first() {
            if !data.get(at).is_some_and(|b| b & m == *v & m) {
                return false;
            }
            at += 1;
            toks = &toks[1..];
        }
        match toks.first() {
            Some(Tok::Jump(lo, hi)) => (*lo..=*hi).any(|j| {
                if *budget == 0 {
                    return false;
                }
                *budget -= 1;
                at + j <= data.len() && step(data, at + j, &toks[1..], budget)
            }),
            _ => true,
        }
    }
    step(data, at, toks, &mut { HEX_STEPS })
}

fn offsets(s: &Str, data: &[u8], lower: &[u8]) -> Vec<usize> {
    const LIMIT: usize = 10_000;
    let mut out = Vec::new();
    match &s.pat {
        Pat::Text { bytes, nocase, fullword } => {
            for b in bytes {
                if *nocase {
                    text_offsets(data, lower, &b.to_ascii_lowercase(), *fullword, LIMIT, &mut out);
                } else {
                    text_offsets(data, data, b, *fullword, LIMIT, &mut out);
                }
            }
            out.sort_unstable();
            out.dedup();
        }
        Pat::Hex(toks) => {
            // Anchor on the leading run of fully specified bytes, if any.
            let prefix: Vec<u8> = toks.iter().map_while(|t| match t {
                Tok::Byte(v, 0xff) => Some(*v),
                _ => None,
            }).collect();
            if prefix.len() >= 2 {
                for i in memchr::memmem::find_iter(data, &prefix) {
                    if hex_at(data, i, toks) {
                        out.push(i);
                        if out.len() >= LIMIT {
                            break;
                        }
                    }
                }
            } else {
                let Tok::Byte(v0, m0) = toks[0] else { return out };
                for i in 0..data.len() {
                    if data[i] & m0 == v0 & m0 && hex_at(data, i, toks) {
                        out.push(i);
                        if out.len() >= LIMIT {
                            break;
                        }
                    }
                }
            }
        }
    }
    out
}

struct Ctx<'a> {
    data: &'a [u8],
    size: u64,
    hits: &'a std::collections::HashMap<String, Vec<usize>>,
}

fn num(e: &Expr, c: &Ctx) -> Option<i64> {
    Some(match e {
        Expr::Num(n) => *n,
        Expr::FileSize => c.size as i64,
        Expr::Count(id) => c.hits.get(id).map_or(0, Vec::len) as i64,
        Expr::Int { size, be, at } => {
            let at = num(at, c)? as usize;
            let n = (*size / 8) as usize;
            let b = c.data.get(at..at + n)?;
            let mut v: u64 = 0;
            for (i, byte) in b.iter().enumerate() {
                if *be {
                    v = (v << 8) | *byte as u64;
                } else {
                    v |= (*byte as u64) << (8 * i);
                }
            }
            v as i64
        }
        other => truth(other, c) as i64,
    })
}

fn truth(e: &Expr, c: &Ctx) -> bool {
    let found = |id: &String| c.hits.get(id).is_some_and(|v| !v.is_empty());
    match e {
        Expr::Bool(b) => *b,
        Expr::Found(id) => found(id),
        Expr::At(id, at) => num(at, c).is_some_and(|n| c.hits.get(id).is_some_and(|v| v.contains(&(n as usize)))),
        Expr::In(id, a, b) => match (num(a, c), num(b, c)) {
            (Some(a), Some(b)) => c.hits.get(id).is_some_and(|v| v.iter().any(|o| (*o as i64) >= a && (*o as i64) <= b)),
            _ => false,
        },
        Expr::Of(q, ids) => {
            let n = ids.iter().filter(|i| found(i)).count();
            match q {
                Quant::Any => n > 0,
                Quant::All => n == ids.len(),
                Quant::N(k) => n >= *k,
            }
        }
        Expr::Not(x) => !truth(x, c),
        Expr::And(v) => v.iter().all(|x| truth(x, c)),
        Expr::Or(v) => v.iter().any(|x| truth(x, c)),
        Expr::Cmp(a, op, b) => match (num(a, c), num(b, c)) {
            (Some(x), Some(y)) => match op.as_str() {
                "<" => x < y,
                ">" => x > y,
                "<=" => x <= y,
                ">=" => x >= y,
                "==" => x == y,
                _ => x != y,
            },
            _ => false,
        },
        other => num(other, c).is_some_and(|n| n != 0),
    }
}

/// Match rules against a buffer (`size` = real file size, which may be
/// larger than the buffer if the file was truncated for scanning).
pub fn scan_bytes(rules: &[Rule], data: &[u8], size: u64) -> Vec<Match> {
    let any_nocase = rules.iter().flat_map(|r| &r.strings).any(|s| matches!(s.pat, Pat::Text { nocase: true, .. }));
    let lower = if any_nocase { data.to_ascii_lowercase() } else { Vec::new() };
    let mut out = Vec::new();
    for r in rules {
        let hits: std::collections::HashMap<String, Vec<usize>> = r.strings.iter().map(|s| (s.id.clone(), offsets(s, data, &lower))).collect();
        if truth(&r.condition, &Ctx { data, size, hits: &hits }) {
            let mut strings: Vec<(String, usize, usize)> = hits.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| (k.clone(), v[0], v.len())).collect();
            strings.sort();
            out.push(Match {
                rule: r.name.clone(),
                tags: r.tags.clone(),
                description: r.meta("description").unwrap_or_default().to_string(),
                severity: r.meta("severity").map(crate::model::Severity::parse).unwrap_or(crate::model::Severity::Medium),
                confidence: match r.meta("confidence").map(str::to_lowercase).as_deref() {
                    Some("high") => crate::model::Confidence::High,
                    Some("low") => crate::model::Confidence::Low,
                    _ => crate::model::Confidence::Medium,
                },
                strings,
            });
        }
    }
    out
}

/// Scan many files on a few threads. Returns (path, matches) for files
/// that matched, and (path, error) for files that couldn't be read.
pub fn scan_files(rules: &[Rule], paths: &[String]) -> (Vec<(String, Vec<Match>)>, Vec<String>) {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()).clamp(2, 8);
    let chunk = paths.len().div_ceil(threads).max(1);
    std::thread::scope(|s| {
        let handles: Vec<_> = paths
            .chunks(chunk)
            .map(|part| {
                s.spawn(move || {
                    let mut hits = Vec::new();
                    let mut failed = Vec::new();
                    for p in part {
                        match scan_file(rules, Path::new(p)) {
                            Ok((m, _)) if !m.is_empty() => hits.push((p.clone(), m)),
                            Ok(_) => {}
                            Err(e) => failed.push(format!("{p}: {e}")),
                        }
                    }
                    (hits, failed)
                })
            })
            .collect();
        let mut hits = Vec::new();
        let mut failed = Vec::new();
        for h in handles {
            match h.join() {
                Ok((a, b)) => {
                    hits.extend(a);
                    failed.extend(b);
                }
                Err(_) => failed.push("a scan thread crashed".into()),
            }
        }
        (hits, failed)
    })
}

/// Scan one file (first `MAX_SCAN` bytes).
pub fn scan_file(rules: &[Rule], path: &Path) -> Result<(Vec<Match>, bool), String> {
    use std::io::Read;
    crate::fileinfo::require_regular(path).map_err(|e| e.to_string())?;
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut data = Vec::with_capacity(size.min(MAX_SCAN) as usize);
    f.take(MAX_SCAN).read_to_end(&mut data).map_err(|e| e.to_string())?;
    // Any procwatch build (and its own rule file) carries the built-in
    // rules as text and would match them.
    if memchr::memmem::find(&data, SELF_MARKER.as_bytes()).is_some() {
        return Ok((Vec::new(), false));
    }
    Ok((scan_bytes(rules, &data, size), size > MAX_SCAN))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_rules_are_rejected_or_bounded() {
        let deep = format!("rule a {{ strings: $a = \"x\" condition: {}$a{} }}", "(".repeat(100_000), ")".repeat(100_000));
        assert!(parse(&deep, "t").0.is_empty());
        let nots = format!("rule a {{ strings: $a = \"x\" condition: {}$a }}", "not ".repeat(100_000));
        assert!(parse(&nots, "t").0.is_empty());
        let long = format!("rule a {{ strings: $a = \"x\" condition: $a{} }}", " and $a".repeat(100_000));
        assert!(parse(&long, "t").0.is_empty());
        // Many wide jumps over data that nearly matches.
        let toks: Vec<Tok> = std::iter::repeat_n([Tok::Byte(b'a', 0xff), Tok::Jump(0, 64)], 12).flatten().chain([Tok::Byte(b'z', 0xff)]).collect();
        let t = std::time::Instant::now();
        assert!(!hex_at(&vec![b'a'; 4096], 0, &toks));
        assert!(t.elapsed() < std::time::Duration::from_secs(1), "{:?}", t.elapsed());
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_instead_of_blocking() {
        let p = std::env::temp_dir().join(format!("procwatch-fifo-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let c = std::ffi::CString::new(p.display().to_string()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(scan_file(&[], &p).is_err());
        assert!(crate::fileinfo::hash_file(&p).is_err());
        assert!(crate::binfmt::analyze(&p).is_err());
        assert_eq!(crate::fileinfo::file_type(&p), "not a regular file");
        let _ = std::fs::remove_file(&p);
    }

    const SRC: &str = r#"
// comment
rule MZ_with_marker : test pe {
  meta:
    description = "PE with marker"
  strings:
    $mz = { 4D 5A }
    $m = "Evil" nocase wide ascii
    $h = { 45 ?? 4? [1-3] 21 }
    $w = "kiwi" fullword
  condition:
    $mz at 0 and uint16(0) == 0x5A4D and ($m or #w > 1) and filesize < 1MB
}
private rule Re { strings: $r = /ab+c/ condition: $r }
rule Pe { condition: pe.is_pe }
rule Any { strings: $a = "zzz" $b = "yyy" condition: any of ($a*, $b) and not $a in (0..1) }
"#;

    #[test]
    fn parses_and_rejects() {
        let (rules, errors) = parse(SRC, "t.yar");
        assert_eq!(rules.len(), 2, "{errors:?}");
        assert!(unescape("\\x4é").is_err() && unescape("\\x41").unwrap() == b"A", "no panic on split UTF-8");
        assert_eq!(split_defs("$a = \"x $y\" $b = { 41 } $c=\"q\""), vec!["$a = \"x $y\"", "$b = { 41 }", "$c=\"q\""]);
        assert_eq!(errors.len(), 2);
        assert!(errors[0].contains("regular-expression"));
        assert!(errors[1].contains("modules"));
        assert_eq!(rules[0].tags, vec!["test", "pe"]);
        assert_eq!(rules[0].meta("description"), Some("PE with marker"));
    }

    #[test]
    fn matches() {
        let (rules, _) = parse(SRC, "t.yar");
        let mut data = b"MZ\x90\x00 eViL kiwi, kiwi! E1Ax!".to_vec();
        let m = scan_bytes(&rules, &data, data.len() as u64);
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(m[0].rule, "MZ_with_marker");
        assert!(m[0].strings.iter().any(|(id, _, n)| id == "$w" && *n == 2));
        // fullword: "kiwis" doesn't count; wide form matches.
        data = b"MZ..E\x00v\x00i\x00l\x00 kiwis".to_vec();
        let m = scan_bytes(&rules, &data, data.len() as u64);
        assert_eq!(m.len(), 1);
        assert!(!m[0].strings.iter().any(|(id, _, _)| id == "$w"));
        // Not at offset 0.
        assert!(scan_bytes(&rules, b" MZ Evil", 8).is_empty());
        // in (0..1) excludes an early match.
        assert!(scan_bytes(&rules, b"zzz", 3).is_empty());
        assert_eq!(scan_bytes(&rules, b"..zzz", 5).len(), 1);
    }

    #[test]
    fn hex_jumps_and_nibbles() {
        let toks = parse_hex("41 [2-3] 4? 43").unwrap();
        assert!(hex_at(b"Axx4FC", 0, &toks) || hex_at(b"AxxOC", 0, &toks) || hex_at(b"Axx\x4fC", 0, &toks));
        assert!(hex_at(b"Axx\x4fC", 0, &toks));
        assert!(!hex_at(b"Ax\x4fC", 0, &toks));
        assert!(parse_hex("[2] 41").is_err());
        assert!(parse_hex("?? 41").is_ok());
    }

    #[test]
    fn skips_procwatch_itself() {
        let dir = std::env::temp_dir().join(format!("pw-yara-self-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("copy.bin");
        std::fs::write(&f, format!("{SELF_MARKER} … sekurlsa::logonpasswords privilege::debug")).unwrap();
        let (m, _) = scan_file(&builtin(), &f).unwrap();
        assert!(m.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn builtin_rules_parse() {
        let (r, e) = parse(include_str!("../rules/yara/procwatch-builtin.yar"), "b");
        assert!(e.is_empty(), "{e:?}");
        assert!(r.len() >= 4);
    }
}
