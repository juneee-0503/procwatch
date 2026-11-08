pub fn start_time(_pid: u32) -> Option<u64> {
    None
}
use super::super::{Native, ThreadInfo};
use std::collections::HashMap;

pub fn collect(_pids: &[u32]) -> HashMap<u32, Native> {
    HashMap::new()
}
pub fn threads(_pid: u32) -> anyhow::Result<Vec<ThreadInfo>> {
    anyhow::bail!("not supported on this platform")
}
pub fn set_nice(_pid: u32, _nice: i32) -> anyhow::Result<()> {
    anyhow::bail!("not supported on this platform")
}
