//! Keeping metrics: one line a minute per day file, holding the low, average
//! and high of every metric. A month of a busy server is a few megabytes, and
//! the format can be read with nothing but `jq`.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Local, NaiveDate};
use serde::{Deserialize, Serialize};

use crate::kernel::model::{Sample, SAMPLES};
use crate::kernel::{Capability, Context, Event, Module};

const KEEP_DAYS: i64 = 30;
const MAX_SERIES: usize = 2000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Point {
    pub min: f64,
    pub avg: f64,
    pub max: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Row {
    pub t: DateTime<Local>,
    pub m: BTreeMap<String, Point>,
}

/// `net.rx{interface=eth0}`.
pub fn series(s: &Sample) -> String {
    if s.labels.is_empty() {
        return s.metric.to_string();
    }
    let labels: Vec<String> = s.labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
    format!("{}{{{}}}", s.metric, labels.join(","))
}

#[derive(Default)]
struct Minute {
    values: BTreeMap<String, (f64, f64, f64, u32)>,
}

impl Minute {
    fn add(&mut self, key: String, v: f64) {
        if self.values.len() >= MAX_SERIES && !self.values.contains_key(&key) {
            return;
        }
        let e = self.values.entry(key).or_insert((v, 0.0, v, 0));
        e.0 = e.0.min(v);
        e.1 += v;
        e.2 = e.2.max(v);
        e.3 += 1;
    }

    fn take(&mut self) -> BTreeMap<String, Point> {
        std::mem::take(&mut self.values).into_iter().map(|(k, (min, sum, max, n))| (k, Point { min, avg: sum / f64::from(n.max(1)), max })).collect()
    }
}

fn day_file(dir: &Path, day: NaiveDate) -> PathBuf {
    dir.join(format!("{day}.jsonl"))
}

pub fn default_dir() -> Option<PathBuf> {
    crate::common::paths::data_dir().map(|d| d.join("metrics"))
}

/// Remove days past keeping.
fn prune(dir: &Path, today: NaiveDate) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let day = name.strip_suffix(".jsonl").and_then(|d| d.parse::<NaiveDate>().ok());
        if day.is_some_and(|d| (today - d).num_days() > KEEP_DAYS) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Rows within `hours`, oldest first.
pub fn read(dir: &Path, hours: u64, now: DateTime<Local>) -> Vec<Row> {
    let from = now - chrono::Duration::hours(hours.min(24 * 366) as i64);
    let mut rows = Vec::new();
    let mut day = from.date_naive();
    while day <= now.date_naive() {
        if let Ok(f) = std::fs::File::open(day_file(dir, day)) {
            rows.extend(std::io::BufReader::new(f).lines().map_while(Result::ok).filter_map(|l| serde_json::from_str::<Row>(&l).ok()).filter(|r| r.t >= from && r.t <= now));
        }
        let Some(next) = day.succ_opt() else { break };
        day = next;
    }
    rows
}

pub struct HistoryModule {
    dir: Option<PathBuf>,
    minute: Minute,
    started: Option<DateTime<Local>>,
}

impl HistoryModule {
    pub fn new(dir: Option<PathBuf>) -> HistoryModule {
        HistoryModule { dir, minute: Minute::default(), started: None }
    }

    fn flush(&mut self, now: DateTime<Local>) {
        let m = self.minute.take();
        let Some(dir) = &self.dir else { return };
        if m.is_empty() {
            return;
        }
        let Ok(line) = serde_json::to_string(&Row { t: now, m }) else { return };
        if crate::common::paths::private_file().create(true).append(true).open(day_file(dir, now.date_naive())).and_then(|mut f| writeln!(f, "{line}")).is_ok() {
            prune(dir, now.date_naive());
        }
    }
}

impl Module for HistoryModule {
    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::yes("metric history")]
    }

    fn subscribes(&self) -> Vec<&'static str> {
        vec![SAMPLES]
    }

    fn interval(&self) -> Option<Duration> {
        Some(Duration::from_secs(60))
    }

    fn start(&mut self, _: &Context) -> Result<(), String> {
        let dir = self.dir.as_ref().ok_or("no data folder")?;
        crate::common::paths::ensure_private_dir(dir).map_err(|e| e.to_string())?;
        self.started = Some(Local::now());
        Ok(())
    }

    fn on_event(&mut self, e: &Event, _: &Context) {
        if let Some(batch) = e.get::<Vec<Sample>>() {
            for s in batch {
                self.minute.add(series(s), s.value);
            }
        }
    }

    fn tick(&mut self, _: &Context) {
        self.flush(Local::now());
    }

    fn stop(&mut self) {
        self.flush(Local::now());
    }
}

/// `--history`.
pub fn run(metric: Option<&str>, hours: u64, json: bool) -> i32 {
    let Some(dir) = default_dir() else {
        eprintln!("no data folder");
        return 2;
    };
    let rows = read(&dir, hours, Local::now());
    if rows.is_empty() {
        eprintln!("no history in the last {hours} hours");
        return 1;
    }
    let Some(metric) = metric else {
        let names: std::collections::BTreeSet<&String> = rows.iter().flat_map(|r| r.m.keys()).collect();
        names.iter().for_each(|n| crate::safe_println!("{n}"));
        return 0;
    };
    for r in &rows {
        for (name, p) in r.m.iter().filter(|(n, _)| n.as_str() == metric || n.starts_with(&format!("{metric}{{"))) {
            if json {
                crate::safe_println!("{}", serde_json::json!({ "time": r.t.to_rfc3339(), "metric": name, "min": p.min, "avg": p.avg, "max": p.max }));
            } else {
                crate::safe_println!("{} {name} min {:.1} avg {:.1} max {:.1}", r.t.format("%Y-%m-%d %H:%M"), p.min, p.avg, p.max);
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::Unit;

    #[test]
    fn minutes_summarise_and_read_back() {
        let dir = crate::common::paths::private_temp_dir("history").unwrap();
        let mut h = HistoryModule::new(Some(dir.clone()));
        for v in [1.0, 2.0, 6.0] {
            h.minute.add(series(&Sample::new("net.rx", v, Unit::BytesPerSecond).label("interface", "eth0")), v);
        }
        let now = Local::now();
        h.flush(now);
        h.flush(now);
        let rows = read(&dir, 1, now);
        assert_eq!(rows.len(), 1, "an empty minute writes nothing");
        assert_eq!(rows[0].m["net.rx{interface=eth0}"], Point { min: 1.0, avg: 3.0, max: 6.0 });
        assert!(read(&dir, 1, now + chrono::Duration::hours(5)).is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn old_days_go_and_series_are_limited() {
        let dir = crate::common::paths::private_temp_dir("history").unwrap();
        let today = Local::now().date_naive();
        let old = day_file(&dir, today - chrono::Duration::days(KEEP_DAYS + 1));
        let kept = day_file(&dir, today - chrono::Duration::days(2));
        std::fs::write(&old, "").unwrap();
        std::fs::write(&kept, "").unwrap();
        std::fs::write(dir.join("notes.txt"), "").unwrap();
        prune(&dir, today);
        assert!(!old.exists() && kept.exists() && dir.join("notes.txt").exists());
        let mut m = Minute::default();
        for i in 0..MAX_SERIES + 10 {
            m.add(i.to_string(), 1.0);
        }
        assert_eq!(m.values.len(), MAX_SERIES);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
