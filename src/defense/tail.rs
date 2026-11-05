//! Following a log file through growth and rotation.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Most read in one poll, so a burst can't stall the module.
const MAX_READ: u64 = 4 << 20;
/// A longer line is cut: logs are read as attackers wrote them.
const MAX_LINE: usize = 64 * 1024;

pub struct Tail {
    path: PathBuf,
    offset: u64,
    id: u64,
    partial: Vec<u8>,
    pub opened: bool,
}

#[cfg(unix)]
fn file_id(m: &std::fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::ino(m)
}

#[cfg(not(unix))]
fn file_id(_: &std::fs::Metadata) -> u64 {
    0
}

impl Tail {
    /// Starts at the end: what happened before isn't news.
    pub fn new(path: &Path) -> Tail {
        let m = std::fs::metadata(path).ok();
        Tail { path: path.to_path_buf(), offset: m.as_ref().map_or(0, std::fs::Metadata::len), id: m.as_ref().map_or(0, file_id), partial: Vec::new(), opened: m.is_some() }
    }

    pub fn poll(&mut self) -> Vec<String> {
        let Ok(m) = std::fs::metadata(&self.path) else {
            self.opened = false;
            return Vec::new();
        };
        // A new file, or one cut short, is read from its start.
        if file_id(&m) != self.id || m.len() < self.offset || !self.opened {
            if self.opened {
                self.offset = 0;
                self.partial.clear();
            }
            self.id = file_id(&m);
            self.opened = true;
        }
        if m.len() == self.offset {
            return Vec::new();
        }
        let Ok(mut f) = std::fs::File::open(&self.path) else { return Vec::new() };
        if f.seek(SeekFrom::Start(self.offset)).is_err() {
            return Vec::new();
        }
        let mut chunk = Vec::new();
        let Ok(n) = f.by_ref().take(MAX_READ).read_to_end(&mut chunk) else { return Vec::new() };
        self.offset += n as u64;
        self.partial.extend_from_slice(&chunk);
        let mut lines = Vec::new();
        let mut start = 0;
        while let Some(end) = memchr::memchr(b'\n', &self.partial[start..]) {
            let line = &self.partial[start..start + end];
            lines.push(String::from_utf8_lossy(&line[..line.len().min(MAX_LINE)]).trim_end_matches('\r').to_string());
            start += end + 1;
        }
        self.partial.drain(..start);
        self.partial.truncate(MAX_LINE);
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn follows_growth_partial_lines_and_rotation() {
        let dir = crate::common::paths::private_temp_dir("tail").unwrap();
        let path = dir.join("auth.log");
        std::fs::write(&path, "old\n").unwrap();
        let mut t = Tail::new(&path);
        assert!(t.poll().is_empty(), "history isn't news");
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"one\ntw").unwrap();
        assert_eq!(t.poll(), ["one"]);
        f.write_all(b"o\n").unwrap();
        assert_eq!(t.poll(), ["two"]);
        drop(f);
        std::fs::rename(&path, dir.join("auth.log.1")).unwrap();
        std::fs::write(&path, "new\n").unwrap();
        assert_eq!(t.poll(), ["new"]);
        std::fs::write(&path, "").unwrap();
        assert!(t.poll().is_empty());
        std::fs::write(&path, "x\n").unwrap();
        assert_eq!(t.poll(), ["x"]);
        std::fs::remove_file(&path).unwrap();
        assert!(t.poll().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
