//! How data sources hand over what they find.
//!
//! A source takes an `Emit<T>` for its own event type and knows nothing about
//! who listens. That keeps every collection module free of the application:
//! adding a new source means defining its event type, not editing a shared
//! message enum from the bottom of the dependency graph.

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;

/// Where a source sends events. Cheap to clone and safe to share.
pub struct Emit<T>(Arc<dyn Fn(T) -> bool + Send + Sync>);

impl<T> Clone for Emit<T> {
    fn clone(&self) -> Self {
        Emit(self.0.clone())
    }
}

impl<T: 'static> Emit<T> {
    pub fn new(f: impl Fn(T) -> bool + Send + Sync + 'static) -> Self {
        Emit(Arc::new(f))
    }

    /// Wrap events into a channel's message type.
    pub fn to<M: Send + 'static>(tx: Sender<M>, wrap: impl Fn(T) -> M + Send + Sync + 'static) -> Self {
        Emit::new(move |v| tx.send(wrap(v)).is_ok())
    }

    /// False once nobody is listening: the source should stop.
    pub fn send(&self, v: T) -> bool {
        (self.0)(v)
    }
}

impl<T: Send + 'static> Emit<T> {
    /// A plain channel, for callers that consume events themselves.
    pub fn channel() -> (Emit<T>, Receiver<T>) {
        let (tx, rx) = mpsc::channel();
        (Emit::to(tx, |v| v), rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivers_and_reports_a_gone_listener() {
        let (e, rx) = Emit::channel();
        assert!(e.clone().send(5));
        assert_eq!(rx.recv().unwrap(), 5);
        drop(rx);
        assert!(!e.send(6));
        let (tx, rx) = mpsc::channel();
        assert!(Emit::to(tx, |v: u8| format!("{v}")).send(7));
        assert_eq!(rx.recv().unwrap(), "7");
    }
}
