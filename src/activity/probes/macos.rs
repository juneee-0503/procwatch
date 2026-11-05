use super::super::*;
use std::io::BufRead;

pub fn start(b: SharedBatcher) -> Result<std::process::Child, String> {
    let mut child = std::process::Command::new("/usr/bin/fs_usage")
        .args(["-w", "-f", "filesys"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("fs_usage: {e}"))?;
    let out = child.stdout.take().ok_or("fs_usage: no output")?;
    let _ = std::thread::Builder::new().name("activity-fs_usage".into()).spawn(move || {
        for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
            if let Some((op, path, pid)) = crate::files::attribution::parse_fs_usage(&line) {
                if let Ok(mut b) = b.lock() {
                    b.push(Activity::new(pid, Class::File, op, path));
                }
            }
        }
    });
    Ok(child)
}
