//! The unified data model. Whatever a platform calls something and whatever
//! unit it reports, by the time a value is on the bus it has one name, one
//! unit and one kind of timestamp, so alerting doesn't care about platforms.

use std::time::SystemTime;

use serde::Serialize;

/// Bus topic carrying `Vec<Sample>`.
pub const SAMPLES: &str = "kernel.samples";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Bytes,
    BytesPerSecond,
    PerSecond,
    Percent,
    Count,
    Milliseconds,
    Celsius,
    Watts,
}

/// One measurement. Names are dotted and platform-neutral: `cpu.run_queue`,
/// `disk.queue_depth`. What a thing belongs to goes in labels: `device=sda`.
#[derive(Debug, Clone, Serialize)]
pub struct Sample {
    pub metric: &'static str,
    pub value: f64,
    pub unit: Unit,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<(&'static str, String)>,
    #[serde(serialize_with = "ser_time")]
    pub at: SystemTime,
}

fn ser_time<S: serde::Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_f64(t.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0))
}

impl Sample {
    pub fn new(metric: &'static str, value: f64, unit: Unit) -> Sample {
        Sample { metric, value, unit, labels: Vec::new(), at: SystemTime::now() }
    }

    pub fn label(mut self, key: &'static str, value: impl Into<String>) -> Sample {
        self.labels.push((key, value.into()));
        self
    }
}
