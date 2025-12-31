//! Connection state tracking for peer connections.

use crate::error::CloseReason;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Maximum number of unacknowledged reliable packets per connection.
pub const MAX_RELIABLE_IN_FLIGHT: usize = 256;
/// Maximum memory for out-of-order packet reordering buffer per connection.
pub const MAX_REORDER_BUFFER: usize = 512;
/// Maximum handshake messages before aborting handshake.
pub const MAX_HANDSHAKE_MESSAGES: u8 = 5;
/// Maximum packet size accepted by transport.
pub const MAX_PACKET_SIZE: usize = 2048;
/// Maximum concurrent connections per transport instance.
pub const MAX_CONNECTIONS: usize = 10000;

/// Connection state in the protocol state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnState {
    /// Handshake in progress
    Init,
    /// Handshake complete, ready for data
    Active,
    /// Connection closed
    Closed,
}

/// Reliable packet stored in retransmission buffer.
pub struct ReliablePacket {
    /// Packet payload bytes
    pub bytes: Vec<u8>,
    /// Time packet was sent
    pub sent_at: Instant,
    /// Number of retransmissions
    pub retries: u8,
}

/// Per-peer connection state tracking.
///
/// Manages sequence numbering, ACKs, retransmission, timeouts, and protocol violations.
pub struct Connection {
    /// Unique connection identifier
    pub conn_id: u32,
    /// Current connection state
    pub state: ConnState,
    /// Next sequence number to send
    pub next_seq: u32,
    /// Last acknowledged sequence number
    pub last_acked: u32,
    /// Round-trip time estimate
    pub rtt: Duration,
    /// Unacknowledged reliable packets pending retransmission
    pub reliable: BTreeMap<u32, ReliablePacket>,
    /// Connection closed flag
    pub closed: bool,
    /// Reason connection was closed
    pub close_reason: Option<CloseReason>,
    /// Memory used by reorder buffer
    pub reorder_buffer_size: usize,
    /// Handshake messages received
    pub handshake_msg_count: u8,
    /// Protocol violation strikes
    pub violation_strikes: u8,
    /// Last packet activity time
    pub last_activity: Instant,
    /// ACK sequence counter for nonce generation
    pub ack_seq_counter: u32,
    /// Flag indicating wraparound warning has been issued
    pub wraparound_warned: bool,
}

impl Connection {
    /// Create a new connection with random ID.
    pub fn new(conn_id: u32) -> Self {
        Self {
            conn_id,
            state: ConnState::Init,
            next_seq: 1,
            last_acked: 0,
            rtt: Duration::from_millis(100),
            reliable: BTreeMap::new(),
            closed: false,
            close_reason: None,
            reorder_buffer_size: 0,
            handshake_msg_count: 0,
            violation_strikes: 0,
            last_activity: Instant::now(),
            ack_seq_counter: 0,
            wraparound_warned: false,
        }
    }

    /// Close the connection with a reason.
    pub fn close(&mut self, reason: CloseReason) {
        self.closed = true;
        self.close_reason = Some(reason);
        self.state = ConnState::Closed;
    }

    /// Check if nonce counters are approaching wraparound limit.
    ///
    /// Closes connection if wraparound threshold reached.
    pub fn check_counter_wraparound(&mut self) -> bool {
        const WRAPAROUND_THRESHOLD: u32 = u32::MAX - 1000;

        if self.next_seq >= WRAPAROUND_THRESHOLD {
            if !self.wraparound_warned {
                eprintln!("WARNING: next_seq approaching u32::MAX ({}), closing connection to prevent nonce reuse", self.next_seq);
                self.wraparound_warned = true;
            }
            self.close(CloseReason::ProtocolViolation);
            return true;
        }

        if self.ack_seq_counter >= WRAPAROUND_THRESHOLD {
            if !self.wraparound_warned {
                eprintln!("WARNING: ack_seq_counter approaching u32::MAX ({}), closing connection to prevent nonce reuse", self.ack_seq_counter);
                self.wraparound_warned = true;
            }
            self.close(CloseReason::ProtocolViolation);
            return true;
        }

        false
    }
}
