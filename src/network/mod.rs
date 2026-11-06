//! Per-process network connections, cross-platform via `netstat2`.
//! Equivalent to what `netstat -b` (Windows) or `lsof -i` (macOS) show.

pub mod dns;
pub mod module;
pub mod pcap;
pub mod traffic;

use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo, TcpState,
};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Connection {
    pub protocol: &'static str,
    pub local: String,
    pub remote: String,
    pub state: ConnState,
}

/// Coarse connection state, ordered by how interesting it usually is
/// (listeners and live connections first, teardown states last).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConnState {
    Listen,
    Established,
    Opening,
    Closing,
    Stateless,
    Other,
}

impl ConnState {
    pub fn label(self) -> &'static str {
        match self {
            ConnState::Listen => "LISTEN",
            ConnState::Established => "ESTABLISHED",
            ConnState::Opening => "SYN",
            ConnState::Closing => "CLOSING",
            ConnState::Stateless => "-",
            ConnState::Other => "OTHER",
        }
    }
}

fn tcp_state(state: &TcpState) -> ConnState {
    match state {
        TcpState::Listen => ConnState::Listen,
        TcpState::Established => ConnState::Established,
        TcpState::SynSent | TcpState::SynReceived => ConnState::Opening,
        TcpState::FinWait1
        | TcpState::FinWait2
        | TcpState::CloseWait
        | TcpState::Closing
        | TcpState::LastAck
        | TcpState::TimeWait
        | TcpState::Closed
        | TcpState::DeleteTcb => ConnState::Closing,
        _ => ConnState::Other,
    }
}

/// `1.2.3.4:80`, `[::1]:80`, or `*:*` for an unbound endpoint.
fn endpoint(addr: IpAddr, port: u16) -> String {
    // Dual-stack sockets report IPv4 peers as IPv4-mapped (::ffff:a.b.c.d)
    // or, on macOS, IPv4-compatible (::a.b.c.d) addresses; show them as v4.
    let addr = match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None if v6.segments()[..6] == [0; 6] && !v6.is_loopback() && !v6.is_unspecified() => {
                v6.to_ipv4().map(IpAddr::V4).unwrap_or(addr)
            }
            None => addr,
        },
        v4 => v4,
    };
    let host = if addr.is_unspecified() {
        "*".to_string()
    } else if addr.is_ipv6() {
        format!("[{addr}]")
    } else {
        addr.to_string()
    };
    let port = if port == 0 { "*".to_string() } else { port.to_string() };
    format!("{host}:{port}")
}

/// Build a map of PID -> list of its active network connections, sorted.
/// Best-effort: on some platforms/privilege levels, sockets owned by other
/// users' processes may be invisible; that's a normal OS restriction, not
/// a bug in this tool.
pub fn connections_by_pid() -> HashMap<u32, Vec<Connection>> {
    try_connections().unwrap_or_default()
}

/// None when the socket table couldn't be read, which is different from
/// there being no connections: treating it as empty would report every
/// socket closed, then every socket as new on the next sample.
pub fn try_connections() -> Option<HashMap<u32, Vec<Connection>>> {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let mut map: HashMap<u32, Vec<Connection>> = HashMap::new();

    let sockets = get_sockets_info(af_flags, proto_flags).ok()?;

    for SocketInfo { protocol_socket_info, associated_pids, .. } in sockets {
        let conn = match &protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => Connection {
                protocol: "TCP",
                local: endpoint(tcp.local_addr, tcp.local_port),
                remote: endpoint(tcp.remote_addr, tcp.remote_port),
                state: tcp_state(&tcp.state),
            },
            ProtocolSocketInfo::Udp(udp) => Connection {
                protocol: "UDP",
                local: endpoint(udp.local_addr, udp.local_port),
                remote: "*:*".to_string(),
                state: ConnState::Stateless,
            },
        };
        for pid in associated_pids {
            map.entry(pid).or_default().push(conn.clone());
        }
    }

    for conns in map.values_mut() {
        conns.sort_by(|a, b| a.state.cmp(&b.state).then_with(|| a.cmp(b)));
        conns.dedup();
    }

    Some(map)
}

#[cfg(test)]
mod tests {
    use super::endpoint;
    use std::net::IpAddr;

    #[test]
    fn formats_endpoints() {
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(endpoint(p("::7f00:1"), 80), "127.0.0.1:80");
        assert_eq!(endpoint(p("::ffff:10.0.0.1"), 443), "10.0.0.1:443");
        assert_eq!(endpoint(p("::1"), 22), "[::1]:22");
        assert_eq!(endpoint(p("0.0.0.0"), 0), "*:*");
        assert_eq!(endpoint(p("fe80::1"), 5353), "[fe80::1]:5353");
    }
}
