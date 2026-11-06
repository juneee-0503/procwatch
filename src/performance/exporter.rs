//! A Prometheus endpoint. Off unless a listen address is configured. Metrics
//! describe a machine in detail, so anywhere but loopback it needs a token.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::kernel::dictionary::Kind;
use crate::kernel::model::{Sample, SeriesLimit, SAMPLES};
use crate::kernel::{Capability, Context, Event, Module};

const MAX_REQUEST: usize = 8192;
const MAX_SERIES: usize = 5000;

type Latest = Arc<Mutex<BTreeMap<String, f64>>>;

fn name(metric: &str) -> String {
    let body: String = metric.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    format!("procwatch_{body}")
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn line(s: &Sample) -> String {
    if s.labels.is_empty() {
        return name(s.metric);
    }
    let labels: Vec<String> = s.labels.iter().map(|(k, v)| format!("{k}=\"{}\"", escape(v))).collect();
    format!("{}{{{}}}", name(s.metric), labels.join(","))
}

fn render(latest: &BTreeMap<String, f64>) -> String {
    let mut out = String::new();
    let mut last = "";
    for (series, value) in latest {
        let family = series.split('{').next().unwrap_or(series);
        if family != last {
            let dotted = family.trim_start_matches("procwatch_");
            let counter = crate::kernel::dictionary::METRICS.iter().any(|m| m.kind == Kind::Counter && m.name.replace(['.', '-'], "_") == dotted);
            out.push_str(&format!("# TYPE {family} {}\n", if counter { "counter" } else { "gauge" }));
            last = family;
        }
        out.push_str(&format!("{series} {value}\n"));
    }
    out
}

/// Takes the same time wherever the first difference is.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn answer(request: &str, token: &str, latest: &BTreeMap<String, f64>) -> (&'static str, String) {
    let first = request.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if method != "GET" {
        return ("405 Method Not Allowed", String::new());
    }
    if !token.is_empty() {
        let given = request.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("authorization")).map(|(_, v)| v.trim()));
        if !given.and_then(|g| g.strip_prefix("Bearer ")).is_some_and(|g| same(g.as_bytes(), token.as_bytes())) {
            return ("401 Unauthorized", String::new());
        }
    }
    match path {
        "/metrics" => ("200 OK", render(latest)),
        "/health" => ("200 OK", "ok\n".to_string()),
        _ => ("404 Not Found", String::new()),
    }
}

fn serve(mut s: TcpStream, token: &str, latest: &Latest) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    while request.len() < MAX_REQUEST && !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut chunk) {
            Ok(n) if n > 0 => request.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&request);
    let (status, body) = match latest.lock() {
        Ok(l) => answer(&text, token, &l),
        Err(_) => ("500 Internal Server Error", String::new()),
    };
    let head = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(body.as_bytes());
}

pub struct ExporterModule {
    listen: String,
    token: String,
    latest: Latest,
    stop: Arc<AtomicBool>,
    limit: SeriesLimit,
}

impl ExporterModule {
    pub fn new(listen: String, token: String) -> ExporterModule {
        ExporterModule { listen, token, latest: Latest::default(), stop: Arc::new(AtomicBool::new(false)), limit: SeriesLimit::default() }
    }
}

impl Module for ExporterModule {
    fn capabilities(&self) -> Vec<Capability> {
        vec![if self.listen.is_empty() {
            Capability::no("Prometheus endpoint", "turned off in Settings")
        } else {
            Capability::yes("Prometheus endpoint")
        }]
    }

    fn subscribes(&self) -> Vec<&'static str> {
        vec![SAMPLES]
    }

    fn importance(&self) -> crate::kernel::module::Importance {
        crate::kernel::module::Importance::Optional
    }

    fn self_test(&mut self) -> Result<String, String> {
        if self.listen.is_empty() {
            return Err("turned off: set an address in Settings".into());
        }
        self.listen.parse::<SocketAddr>().map(|a| format!("will listen on {a}")).map_err(|_| format!("{}: not an address and port", self.listen))
    }

    fn start(&mut self, _: &Context) -> Result<(), String> {
        let addr: SocketAddr = self.listen.parse().map_err(|_| format!("{}: not an address and port", self.listen))?;
        if !addr.ip().is_loopback() && self.token.is_empty() {
            return Err(format!("{addr} isn't loopback: set exporter.token"));
        }
        // On a reload the old instance may still hold the port for a moment.
        let mut bound = TcpListener::bind(addr);
        for _ in 0..10 {
            if bound.is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
            bound = TcpListener::bind(addr);
        }
        let listener = bound.map_err(|e| format!("{addr}: {e}"))?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        self.stop.store(false, Ordering::Relaxed);
        let (token, latest, stop) = (self.token.clone(), self.latest.clone(), self.stop.clone());
        std::thread::Builder::new()
            .name("exporter".into())
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((s, _)) => {
                            let _ = s.set_nonblocking(false);
                            serve(s, &token, &latest);
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(100)),
                    }
                }
            })
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn on_event(&mut self, e: &Event, _: &Context) {
        let (Some(batch), Ok(mut latest)) = (e.get::<Vec<Sample>>(), self.latest.lock()) else { return };
        for s in batch {
            let key = line(s);
            if let Some(gone) = self.limit.admit(s.metric, &key, Instant::now()) {
                latest.remove(&gone);
            }
            if latest.len() < MAX_SERIES || latest.contains_key(&key) {
                latest.insert(key, s.value);
            }
        }
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::Unit;

    fn latest() -> BTreeMap<String, f64> {
        let s = Sample::new("disk.queue_depth", 3.5, Unit::Count).label("device", "s\"da");
        BTreeMap::from([(line(&s), s.value), (line(&Sample::new("cpu.run_queue", 2.0, Unit::Count)), 2.0)])
    }

    #[test]
    fn writes_the_exposition_format() {
        let text = render(&latest());
        assert!(text.contains("# TYPE procwatch_cpu_run_queue gauge\nprocwatch_cpu_run_queue 2\n"), "{text}");
        assert!(text.contains("procwatch_disk_queue_depth{device=\"s\\\"da\"} 3.5"), "{text}");
    }

    #[test]
    fn answers_and_refuses() {
        let l = latest();
        assert_eq!(answer("GET /metrics HTTP/1.1\r\n\r\n", "", &l).0, "200 OK");
        assert_eq!(answer("GET /other HTTP/1.1\r\n\r\n", "", &l).0, "404 Not Found");
        assert_eq!(answer("POST /metrics HTTP/1.1\r\n\r\n", "", &l).0, "405 Method Not Allowed");
        assert_eq!(answer("GET /metrics HTTP/1.1\r\n\r\n", "s3", &l).0, "401 Unauthorized");
        assert_eq!(answer("GET /metrics HTTP/1.1\r\nAuthorization: Bearer no\r\n\r\n", "s3", &l).0, "401 Unauthorized");
        assert_eq!(answer("GET /metrics HTTP/1.1\r\nauthorization: Bearer s3\r\n\r\n", "s3", &l).0, "200 OK");
    }
}
