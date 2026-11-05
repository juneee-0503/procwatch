//! The event bus: the only way modules reach each other.
//!
//! Publishing never blocks. Each subscriber has a bounded queue, and a slow
//! subscriber loses events (counted) rather than stalling everyone else.

use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

pub type Payload = Arc<dyn Any + Send + Sync>;

#[derive(Clone)]
pub struct Event {
    pub topic: &'static str,
    pub source: &'static str,
    pub at: SystemTime,
    pub payload: Payload,
}

impl Event {
    /// The payload, if it is a `T`.
    pub fn get<T: 'static>(&self) -> Option<&T> {
        self.payload.downcast_ref()
    }
}

/// A payload one subscriber takes ownership of, for data too large to copy.
pub struct Exclusive<T>(Mutex<Option<T>>);

impl<T> Exclusive<T> {
    pub fn new(v: T) -> Self {
        Exclusive(Mutex::new(Some(v)))
    }
    pub fn take(&self) -> Option<T> {
        self.0.lock().ok()?.take()
    }
}

struct Subscriber {
    /// Empty means every topic.
    topics: Vec<&'static str>,
    tx: SyncSender<Event>,
}

#[derive(Default)]
struct Inner {
    subscribers: RwLock<Vec<Subscriber>>,
    dropped: AtomicU64,
    published: AtomicU64,
}

#[derive(Clone, Default)]
pub struct Bus(Arc<Inner>);

impl Bus {
    pub fn subscribe(&self, topics: &[&'static str], capacity: usize) -> Receiver<Event> {
        let (tx, rx) = sync_channel(capacity.max(1));
        if let Ok(mut s) = self.0.subscribers.write() {
            s.push(Subscriber { topics: topics.to_vec(), tx });
        }
        rx
    }

    pub fn publish(&self, topic: &'static str, source: &'static str, payload: Payload) {
        let event = Event { topic, source, at: SystemTime::now(), payload };
        self.0.published.fetch_add(1, Ordering::Relaxed);
        let mut gone = false;
        if let Ok(subs) = self.0.subscribers.read() {
            for s in subs.iter().filter(|s| s.topics.is_empty() || s.topics.contains(&topic)) {
                match s.tx.try_send(event.clone()) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        self.0.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(TrySendError::Disconnected(_)) => gone = true,
                }
            }
        }
        if gone {
            if let Ok(mut subs) = self.0.subscribers.write() {
                subs.retain(|s| {
                    // A zero-size probe: only a closed queue reports this.
                    !matches!(s.tx.try_send(Event { topic: "", source: "", at: SystemTime::now(), payload: Arc::new(()) }), Err(TrySendError::Disconnected(_)))
                });
            }
        }
    }

    /// Events lost to full queues.
    pub fn dropped(&self) -> u64 {
        self.0.dropped.load(Ordering::Relaxed)
    }

    pub fn published(&self) -> u64 {
        self.0.published.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_by_topic_and_types_payloads() {
        let bus = Bus::default();
        let a = bus.subscribe(&["a"], 4);
        let all = bus.subscribe(&[], 4);
        bus.publish("a", "t", Arc::new(5u32));
        bus.publish("b", "t", Arc::new("x"));
        assert_eq!(a.try_recv().unwrap().get::<u32>(), Some(&5));
        assert!(a.try_recv().is_err(), "other topics don't arrive");
        assert_eq!(all.try_iter().count(), 2);
        assert_eq!(bus.published(), 2);
    }

    #[test]
    fn a_stuck_subscriber_loses_events_but_blocks_nobody() {
        let bus = Bus::default();
        let _slow = bus.subscribe(&["a"], 2);
        let fine = bus.subscribe(&["a"], 100);
        for i in 0..50u32 {
            bus.publish("a", "t", Arc::new(i));
        }
        assert_eq!(bus.dropped(), 48);
        assert_eq!(fine.try_iter().count(), 50);
    }

    #[test]
    fn departed_subscribers_are_forgotten() {
        let bus = Bus::default();
        drop(bus.subscribe(&["a"], 1));
        bus.publish("a", "t", Arc::new(1u8));
        assert_eq!(bus.0.subscribers.read().unwrap().len(), 0);
    }

    #[test]
    fn exclusive_payloads_are_taken_once() {
        let e = Exclusive::new(String::from("big"));
        assert_eq!(e.take().as_deref(), Some("big"));
        assert_eq!(e.take(), None);
    }
}
