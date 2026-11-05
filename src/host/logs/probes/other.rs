use super::super::*;
pub fn fetch(_minutes: u32, _scope: Scope) -> Result<Vec<Entry>, String> {
    Err("event logs are not supported on this platform".into())
}
