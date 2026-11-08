//! Reading files that carry a format version. A mistake in today's format
//! must be reported, because a misspelt setting would silently do nothing. A
//! file from a newer version may hold settings this one doesn't know, and
//! those are skipped, so downgrading doesn't stop anything from starting.

use serde::de::DeserializeOwned;

pub fn parse<T: DeserializeOwned>(text: &str, current: u32) -> Result<T, String> {
    let value: serde_yaml::Value = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
    let version = value.get("version").and_then(serde_yaml::Value::as_u64).unwrap_or(u64::from(current));
    let mut unknown = Vec::new();
    let parsed: T = serde_ignored::deserialize(value, |path| unknown.push(path.to_string())).map_err(|e| e.to_string())?;
    if version <= u64::from(current) && !unknown.is_empty() {
        return Err(format!("unknown setting: {}", unknown.join(", ")));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize, Default, PartialEq, Debug)]
    #[serde(default)]
    struct S {
        version: u32,
        a: u32,
    }

    #[test]
    fn strict_today_tolerant_of_tomorrow() {
        assert_eq!(parse::<S>("a: 1", 1).unwrap().a, 1);
        assert!(parse::<S>("b: 1", 1).unwrap_err().contains('b'));
        assert_eq!(parse::<S>("version: 2\na: 1\nb: 1", 1).unwrap().a, 1);
        assert!(parse::<S>("a: x", 1).is_err());
    }
}
