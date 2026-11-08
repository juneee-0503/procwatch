//! Refusing traffic from an attacker, with nftables on Linux. Only an agent
//! policy in enforce mode does this. Every ban has an expiry, nothing is
//! saved across a restart, and procwatch removes its table when it stops, so
//! a mistake here can't permanently lock anyone out.

use std::io::Write;
use std::net::IpAddr;

use super::filter::Cidr;

/// Bans in an hour. Log lines can be forged by anyone able to write to the
/// log, so a flood of them must not become a flood of firewall rules.
pub const MAX_PER_HOUR: usize = 256;

fn v4(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(_))
}

/// The nft script for one ban. Safe to repeat.
pub fn script(ip: IpAddr, seconds: u64) -> String {
    let set = if v4(ip) { "banned4" } else { "banned6" };
    format!(
        "add table inet procwatch\n\
         add set inet procwatch banned4 {{ type ipv4_addr; flags timeout; }}\n\
         add set inet procwatch banned6 {{ type ipv6_addr; flags timeout; }}\n\
         add chain inet procwatch input {{ type filter hook input priority -10; policy accept; }}\n\
         flush chain inet procwatch input\n\
         add rule inet procwatch input ip saddr @banned4 drop\n\
         add rule inet procwatch input ip6 saddr @banned6 drop\n\
         add element inet procwatch {set} {{ {ip} timeout {seconds}s }}\n"
    )
}

/// Why this address must not be banned, if so.
pub fn refused(ip: IpAddr, allow: &[Cidr], sessions: &[IpAddr], gateway: Option<IpAddr>) -> Option<&'static str> {
    let linklocal = match ip {
        IpAddr::V4(a) => a.is_link_local() || a.is_broadcast() || a.is_multicast(),
        IpAddr::V6(a) => (a.segments()[0] & 0xffc0) == 0xfe80 || a.is_multicast(),
    };
    if ip.is_loopback() || ip.is_unspecified() || linklocal {
        return Some("this machine or its local link");
    }
    if allow.iter().any(|c| c.contains(ip)) {
        return Some("on the allow list");
    }
    if sessions.contains(&ip) {
        return Some("someone is logged in from there");
    }
    if gateway == Some(ip) {
        return Some("the network gateway");
    }
    None
}

/// Addresses in `who` output.
pub fn parse_who(text: &str) -> Vec<IpAddr> {
    text.lines().filter_map(|l| l.rsplit_once('(')?.1.split(')').next()?.parse().ok()).collect()
}

/// The gateway in `ip route show default`.
pub fn parse_route(text: &str) -> Option<IpAddr> {
    text.split_whitespace().skip_while(|w| *w != "via").nth(1)?.parse().ok()
}

fn output(name: &str, args: &[&str]) -> String {
    crate::common::command::tool(name).args(args).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
}

/// Who is logged in now and the route out, read just before each ban.
pub fn guarded() -> (Vec<IpAddr>, Option<IpAddr>) {
    (parse_who(&output("who", &[])), parse_route(&output("ip", &["route", "show", "default"])))
}

fn nft(script: &str) -> Result<(), String> {
    use std::process::Stdio;
    let mut child = crate::common::command::tool("nft").args(["-f", "-"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().map_err(|e| format!("nft: {e}"))?;
    if let Some(mut input) = child.stdin.take() {
        input.write_all(script.as_bytes()).map_err(|e| e.to_string())?;
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("nft: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

pub fn ban(ip: IpAddr, seconds: u64) -> Result<(), String> {
    if cfg!(target_os = "linux") {
        nft(&script(ip, seconds))
    } else {
        Err("banning is only available on Linux".into())
    }
}

/// Lift every ban.
pub fn clear() -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Ok(());
    }
    let listed = crate::common::command::tool("nft").args(["list", "table", "inet", "procwatch"]).output().is_ok_and(|o| o.status.success());
    if listed {
        nft("delete table inet procwatch\n")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn scripts_expire_and_pick_the_family() {
        let s = script(ip("203.0.113.9"), 3600);
        assert!(s.contains("add element inet procwatch banned4 { 203.0.113.9 timeout 3600s }"), "{s}");
        assert!(script(ip("2001:db8::1"), 60).contains("banned6 { 2001:db8::1 timeout 60s }"));
    }

    #[test]
    fn people_and_infrastructure_are_never_banned() {
        let allow = [Cidr::parse("192.0.2.0/24").unwrap()];
        let (me, gw) = ([ip("198.51.100.1")], Some(ip("198.51.100.254")));
        for spared in ["127.0.0.1", "::1", "0.0.0.0", "169.254.1.1", "fe80::1", "192.0.2.5", "198.51.100.1", "198.51.100.254", "224.0.0.1"] {
            assert!(refused(ip(spared), &allow, &me, gw).is_some(), "{spared}");
        }
        assert_eq!(refused(ip("203.0.113.9"), &allow, &me, gw), None);
    }

    #[test]
    fn reads_who_and_routes() {
        let who = "alice pts/0 2026-11-05 10:00 (198.51.100.1)\nbob tty1 2026-11-05 09:00\ncarol pts/1 2026-11-05 10:01 (laptop.lan)\n";
        assert_eq!(parse_who(who), [ip("198.51.100.1")]);
        assert_eq!(parse_route("default via 10.0.0.1 dev eth0 proto dhcp"), Some(ip("10.0.0.1")));
        assert_eq!(parse_route("default dev tun0"), None);
    }
}
