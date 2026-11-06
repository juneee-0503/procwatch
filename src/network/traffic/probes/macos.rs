use super::super::*;

/// One sample per run: nettop buffers its output when writing to a pipe,
/// so a long-running one delivers data many seconds late.
pub fn sample() -> Option<Totals> {
    let mut cmd = std::process::Command::new("/usr/bin/nettop");
    cmd.args(["-P", "-x", "-L", "1", "-J", "bytes_in,bytes_out"]);
    let out = crate::common::command::run_command(&mut cmd, Duration::from_secs(8)).ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let totals: Totals = text.lines().filter_map(parse_nettop).map(|(pid, rx, tx)| (pid, (rx, tx))).collect();
    (!totals.is_empty()).then_some(totals)
}
