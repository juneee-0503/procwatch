use super::super::*;
use std::net::IpAddr;
use std::sync::Mutex;

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;

use crate::common::etw::start;

const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
/// Kernel-Network keywords: IPv4 and IPv6.
const NET_KEYWORDS: u64 = 0x10 | 0x20;
const MAX_TRAFFIC_PIDS: usize = 16_384;

/// Who wants connection events, while an activity capture runs.
static SINK: Mutex<Option<Emit<ConnOp>>> = Mutex::new(None);

pub fn set_connection_sink(sink: Option<Emit<ConnOp>>) {
    if let Ok(mut s) = SINK.lock() {
        *s = sink;
    }
}

pub fn start_traffic(out: Emit<Totals>, stop: Arc<AtomicBool>) -> Result<UserTrace, String> {
    let totals: Arc<Mutex<Totals>> = Arc::default();
    let shared = totals.clone();
    let provider = Provider::by_guid(KERNEL_NETWORK)
        .any(NET_KEYWORDS)
        .add_callback(move |r: &EventRecord, sl: &SchemaLocator| {
            // The event says which process; the header is often System.
            let id = r.event_id();
            let (received, sent, op) = match id {
                11 | 27 | 43 | 59 => (true, false, ""),
                10 | 26 | 42 | 58 => (false, true, ""),
                12 | 28 => (false, false, "connect"),
                15 | 31 => (false, false, "accept"),
                13 | 29 => (false, false, "disconnect"),
                _ => return,
            };
            let Ok(schema) = sl.event_schema(r) else { return };
            let p = Parser::create(r, &schema);
            let Ok(pid) = p.try_parse::<u32>("PID") else { return };
            if received || sent {
                let size = u64::from(p.try_parse::<u32>("size").unwrap_or(0));
                if let Ok(mut t) = shared.lock() {
                    let e = t.entry(pid).or_default();
                    if received {
                        e.0 += size;
                    } else {
                        e.1 += size;
                    }
                }
                return;
            }
            if let Ok(s) = SINK.lock() {
                if let Some(sink) = s.as_ref() {
                    let ip = p.try_parse::<IpAddr>("daddr").map(|a| a.to_string()).unwrap_or_default();
                    // Network byte order, whatever the schema says.
                    let port = p.try_parse::<u16>("dport").map(u16::swap_bytes).unwrap_or(0);
                    sink.send(ConnOp { pid, op, remote: format!("{ip}:{port}") });
                }
            }
        })
        .build();
    let trace = start("procwatch-traffic", vec![provider])?;
    let _ = std::thread::Builder::new().name("traffic".into()).spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let now = totals
                .lock()
                .map(|mut t| {
                    // Exited processes' entries; rates only need the live ones.
                    if t.len() > MAX_TRAFFIC_PIDS {
                        t.clear();
                    }
                    t.clone()
                })
                .unwrap_or_default();
            if !now.is_empty() && !out.send(now) {
                return;
            }
        }
    });
    Ok(trace)
}

