//! Packet reception and in-order delivery.

use std::collections::BTreeMap;

use crate::{intent::Intent, packet::PacketHeader, replay::ReplayWindow};

/// Packet receiver with replay detection and optional reordering.
///
/// Validates sequence numbers, detects replays, and buffers out-of-order
/// reliable packets for in-order delivery.
pub struct Receiver {
    /// Next expected sequence number for in-order delivery
    expected_seq: u32,
    /// Out-of-order packets awaiting reordering
    buffer: BTreeMap<u32, Vec<u8>>,
    /// Memory used by buffer
    buffer_size_bytes: usize,
    /// Replay detection window
    replay: ReplayWindow,
}

impl Receiver {
    /// Create a new receiver with replay detection.
    pub fn new() -> Self {
        Self {
            expected_seq: 1,
            buffer: BTreeMap::new(),
            buffer_size_bytes: 0,
            replay: ReplayWindow::new(1024),
        }
    }
}

impl Default for Receiver {
    fn default() -> Self {
        Self::new()
    }
}

impl Receiver {
    /// Check if sequence number passes replay detection.
    pub fn accept(&mut self, seq: u32) -> bool {
        self.replay.check(seq)
    }

    /// Deliver a received packet, handling reordering if needed.
    pub fn deliver(
        &mut self,
        header: PacketHeader,
        payload: Vec<u8>,
        mut on_deliver: impl FnMut(Vec<u8>),
    ) {
        match header.intent {
            Intent::Realtime => {
                on_deliver(payload);
            }
            Intent::Reliable => {
                if header.seq == self.expected_seq {
                    on_deliver(payload);
                    self.expected_seq = self.expected_seq.wrapping_add(1);

                    // Deliver any buffered packets that are now contiguous
                    while let Some(buffered) = self.buffer.remove(&self.expected_seq) {
                        let sz = buffered.len();
                        self.buffer_size_bytes = self.buffer_size_bytes.saturating_sub(sz);
                        on_deliver(buffered);
                        self.expected_seq = self.expected_seq.wrapping_add(1);
                    }
                } else {
                    self.buffer_size_bytes += payload.len();
                    self.buffer.insert(header.seq, payload);
                }
            }
        }
    }

    /// Number of buffered out-of-order reliable packets.
    pub fn pending_reliable(&self) -> usize {
        self.buffer.len()
    }

    /// Total memory used by reorder buffer in bytes.
    pub fn buffer_size(&self) -> usize {
        self.buffer_size_bytes
    }
}
