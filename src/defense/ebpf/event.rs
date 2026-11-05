//! Reading the records the kernel programs write.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::program::{Kind, ARG0, ARG1, ARGC, ARGS, ARG_LEN, COMM, KIND, MAX_ARGS, PATH, PATH_LEN, RECORD, TASK, UID};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub kind: Kind,
    /// The process, not the thread.
    pub pid: u32,
    pub uid: u32,
    /// The caller's name. For an exec, what started the new program.
    pub comm: String,
    pub path: String,
    pub args: Vec<String>,
    pub addr: Option<SocketAddr>,
    pub arg0: u64,
    pub arg1: u64,
    /// Remote end of the socket on this process's standard input or output.
    pub peer: Option<IpAddr>,
}

fn text(b: &[u8]) -> String {
    let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn u32_at(b: &[u8], at: i16) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at as usize..at as usize + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: i16) -> Option<u64> {
    Some(u64::from_ne_bytes(b.get(at as usize..at as usize + 8)?.try_into().ok()?))
}

fn address(b: &[u8]) -> Option<SocketAddr> {
    let family = u16::from_ne_bytes(b.get(..2)?.try_into().ok()?);
    let port = u16::from_be_bytes(b.get(2..4)?.try_into().ok()?);
    let ip = match family {
        2 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(b.get(4..8)?).ok()?)),
        10 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b.get(8..24)?).ok()?)),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

pub fn decode(b: &[u8]) -> Option<Event> {
    if b.len() != RECORD {
        return None;
    }
    let kind = Kind::from_u32(u32_at(b, KIND)?)?;
    let task = u64_at(b, TASK)?;
    let mut e = Event {
        kind,
        pid: (task >> 32) as u32,
        uid: u64_at(b, UID)? as u32,
        comm: text(b.get(COMM as usize..COMM as usize + 16)?),
        path: String::new(),
        args: Vec::new(),
        addr: None,
        arg0: u64_at(b, ARG0)?,
        arg1: u64_at(b, ARG1)?,
        peer: None,
    };
    let body = b.get(PATH as usize..PATH as usize + PATH_LEN)?;
    match kind {
        Kind::Connect => e.addr = address(body),
        _ => e.path = text(body),
    }
    if kind == Kind::Exec {
        let argc = (u32_at(b, ARGC)? as usize).min(MAX_ARGS);
        for i in 0..argc {
            let at = ARGS as usize + i * ARG_LEN;
            e.args.push(text(b.get(at..at + ARG_LEN)?));
        }
    }
    Some(e)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn record(kind: Kind, pid: u32, comm: &str) -> Vec<u8> {
        let mut r = vec![0u8; RECORD];
        r[KIND as usize..][..4].copy_from_slice(&(kind as u32).to_ne_bytes());
        r[TASK as usize + 4..][..4].copy_from_slice(&pid.to_ne_bytes());
        r[UID as usize..][..4].copy_from_slice(&1000u32.to_ne_bytes());
        r[COMM as usize..][..comm.len()].copy_from_slice(comm.as_bytes());
        r
    }

    #[test]
    fn reads_an_exec() {
        let mut r = record(Kind::Exec, 42, "nginx");
        r[PATH as usize..][..7].copy_from_slice(b"/bin/sh");
        r[ARGC as usize..][..4].copy_from_slice(&2u32.to_ne_bytes());
        r[ARGS as usize..][..2].copy_from_slice(b"sh");
        r[ARGS as usize + ARG_LEN..][..2].copy_from_slice(b"-c");
        r[ARGS as usize + 2 * ARG_LEN..][..3].copy_from_slice(b"old");
        let e = decode(&r).unwrap();
        assert_eq!((e.pid, e.uid, e.comm.as_str(), e.path.as_str()), (42, 1000, "nginx", "/bin/sh"));
        assert_eq!(e.args, ["sh", "-c"], "stale bytes past the count are ignored");
    }

    #[test]
    fn reads_addresses() {
        let mut r = record(Kind::Connect, 1, "x");
        r[PATH as usize..][..2].copy_from_slice(&2u16.to_ne_bytes());
        r[PATH as usize + 2..][..2].copy_from_slice(&3333u16.to_be_bytes());
        r[PATH as usize + 4..][..4].copy_from_slice(&[203, 0, 113, 1]);
        assert_eq!(decode(&r).unwrap().addr, "203.0.113.1:3333".parse().ok());
        r[PATH as usize..][..2].copy_from_slice(&10u16.to_ne_bytes());
        r[PATH as usize + 8..][..16].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(decode(&r).unwrap().addr, "[2001:db8::1]:3333".parse().ok());
    }

    #[test]
    fn refuses_what_it_does_not_recognise() {
        assert!(decode(&[0; 10]).is_none());
        assert!(decode(&vec![0; RECORD]).is_none(), "kind 0");
        assert!(decode(&vec![0xff; RECORD]).is_none());
        let mut r = record(Kind::Exec, 1, "x");
        r[ARGC as usize..][..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert_eq!(decode(&r).unwrap().args.len(), MAX_ARGS);
    }
}
