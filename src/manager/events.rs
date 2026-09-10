//! Fans a single `Event` out to every currently-registered IPC client.

use crate::ipc::messages::Event;
use std::collections::HashMap;
use std::sync::mpsc::Sender;

#[derive(Default)]
pub struct EventBus {
    clients: HashMap<u64, Sender<Event>>,
    next_id: u64,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self) -> (u64, std::sync::mpsc::Receiver<Event>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let id = self.next_id;
        self.next_id += 1;
        self.clients.insert(id, tx);
        (id, rx)
    }

    pub fn unregister(&mut self, id: u64) {
        self.clients.remove(&id);
    }

    /// Broadcasts to everyone, quietly dropping any client whose
    /// receiver has gone away (their connection closed) rather than
    /// erroring -- a disconnected client isn't this daemon's problem.
    pub fn broadcast(&mut self, event: Event) {
        self.clients.retain(|_, tx| tx.send(event.clone()).is_ok());
    }
}
