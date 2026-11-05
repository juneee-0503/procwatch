//! Snapshot export of the current process list to CSV.

use crate::common::text::csv_field;
use std::fs;
use std::path::PathBuf;

use chrono::Local;

use crate::app::{App, RowKey};
use crate::process::ProcessInfo;

fn opt<T: ToString>(v: Option<T>) -> String {
    v.map(|v| v.to_string()).unwrap_or_default()
}

fn row(i: &ProcessInfo, mem_total: u64) -> Vec<String> {
    let mem_pct = if mem_total == 0 { 0.0 } else { i.mem() as f64 * 100.0 / mem_total as f64 };
    vec![
        i.pid.to_string(),
        opt(i.ppid),
        i.user.clone().unwrap_or_default(),
        opt(i.priority),
        opt(i.nice),
        opt(i.threads),
        i.state_char().to_string(),
        format!("{:.1}", i.cpu_usage_pct),
        format!("{mem_pct:.2}"),
        i.mem().to_string(),
        i.virtual_memory_bytes.to_string(),
        i.cpu_time_secs.map(|t| format!("{t:.2}")).unwrap_or_default(),
        format!("{:.0}", i.disk_read_rate),
        format!("{:.0}", i.disk_write_rate),
        i.start_time_secs.to_string(),
        i.name.clone(),
        i.exe_path.clone().unwrap_or_default(),
        i.cmd.join(" "),
    ]
}

/// Write the rows currently shown (respecting filters and sort) to
/// `procwatch-YYYYmmdd-HHMMSS.csv` in the working directory.
pub fn export_csv(app: &App) -> anyhow::Result<(PathBuf, usize)> {
    let path = PathBuf::from(format!("procwatch-{}.csv", Local::now().format("%Y%m%d-%H%M%S")));
    let mut out = String::from(
        "pid,ppid,user,priority,nice,threads,state,cpu_pct,mem_pct,memory_bytes,virt_bytes,cpu_time_s,\
         disk_read_bps,disk_write_bps,start_unix,name,exe,command\n",
    );
    let mut n = 0;
    let pids: Vec<u32> = app
        .rows
        .iter()
        .flat_map(|r| match &r.key {
            RowKey::Proc(p) => vec![*p],
            RowKey::Group(g) => app.groups.get(g).map(|g| g.members.clone()).unwrap_or_default(),
        })
        .collect();
    let mut seen = std::collections::HashSet::new();
    for pid in pids.into_iter().filter(|p| seen.insert(*p)) {
        if let Some(node) = app.tree.get(pid) {
            let fields: Vec<String> = row(&node.info, app.stats.mem_total).iter().map(|f| csv_field(f)).collect();
            out.push_str(&fields.join(","));
            out.push('\n');
            n += 1;
        }
    }
    crate::common::paths::write_new(&path, &out)?;
    Ok((fs::canonicalize(&path).unwrap_or(path), n))
}

#[cfg(test)]
mod tests {
    #[test]
    fn escapes_csv() {
        assert_eq!(super::csv_field("plain"), "plain");
        assert_eq!(super::csv_field("a,b"), "\"a,b\"");
        assert_eq!(super::csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }
}
