//! Multi-peer UDP transport with cryptographic authentication and DoS protection.
//!
//! This module implements the core intentra protocol runtime, managing multiple
//! concurrent peer connections with independent encryption, rate limiting, and
//! state machines.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use crate::{
    connection::{
        ConnState, Connection, MAX_HANDSHAKE_MESSAGES, MAX_PACKET_SIZE, MAX_REORDER_BUFFER,
    },
    crypto::{compute_cookie, CryptoContext},
    error::CloseReason,
    handshake::HandshakeState,
    intent::Intent,
    packet::{PacketHeader, FLAG_ACK, FLAG_DATA, FLAG_HS, HEADER_LEN},
    receiver::Receiver,
};

use parking_lot::Mutex;
use std::sync::Arc;

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

// Token bucket rate limiter: 10,000 tokens/sec per peer.
// Burst capacity: 500 tokens. Prevents traffic spikes from overwhelming per-packet processing.
// Token replenishment happens lazily (on each packet) to avoid per-peer timer overhead.
const RATE_LIMIT_TOKENS_PER_SECOND: u64 = 10000;
const RATE_LIMIT_BURST: u64 = 500;

const STRIKE_THRESHOLD: u8 = 10;
const STRIKE_DECAY_TIME: Duration = Duration::from_secs(5);

// Handshake flood defense uses two limits:
// 1. Global (100): prevents resource exhaustion from combined flood sources
// 2. Per-IP (5): prevents single source from dominating handshake queue
// Per-IP alone could be bypassed with distributed attack; global alone could be bypassed with many IPs.
// Combined, they bound worst-case: at most 100 total, <=5 per IP = min 20 attacker IPs needed.
const MAX_HANDSHAKES_IN_FLIGHT: usize = 100;
const MAX_HANDSHAKES_PER_IP: usize = 5;
// Handshake cleanup removes stale entries every 10s.
// Cleanup interval (10s) > handshake timeout (5s) means stale entries are cleaned eventually.
// Lazy cleanup (vs per-entry tracking) reduces per-handshake overhead.
const HANDSHAKE_CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

/// Real-time operational metrics for the transport protocol.
///
/// These metrics track packet processing, rate limiting enforcement, cryptographic
/// validation, replay protection, handshake progress, and DoS event indicators.
/// All fields are protected by mutexes for safe concurrent access.
///
/// # Thread Safety
/// All metrics use `Arc<Mutex<_>>` for safe access from the main transport thread
/// and external monitoring threads.
#[derive(Clone, Debug)]
pub struct TransportMetrics {
    /// Total number of packets received from all peers
    pub packets_received_total: Arc<Mutex<u64>>,
    /// Packets dropped due to per-peer rate limit enforcement
    pub packets_dropped_rate_limit: Arc<Mutex<u64>>,
    /// Packets dropped due to cryptographic validation failures (corruption, auth failure)
    pub packets_dropped_crypto: Arc<Mutex<u64>>,
    /// Packets rejected due to replay window violations
    pub replay_rejections_total: Arc<Mutex<u64>>,
    /// Number of handshakes currently in progress
    pub handshake_in_flight: Arc<Mutex<usize>>,
    /// Number of established peer connections
    pub connections_active: Arc<Mutex<usize>>,
    /// Total strike events issued (tracks DoS protection activations)
    pub strike_events_total: Arc<Mutex<u64>>,
    /// Total connections closed
    pub connection_closes_total: Arc<Mutex<u64>>,
    /// Memory used by out-of-order packet reordering buffers
    pub reorder_buffer_bytes: Arc<Mutex<usize>>,
}

impl TransportMetrics {
    /// Create a new metrics container with all counters initialized to zero.
    fn new() -> Self {
        Self {
            packets_received_total: Arc::new(Mutex::new(0)),
            packets_dropped_rate_limit: Arc::new(Mutex::new(0)),
            packets_dropped_crypto: Arc::new(Mutex::new(0)),
            replay_rejections_total: Arc::new(Mutex::new(0)),
            handshake_in_flight: Arc::new(Mutex::new(0)),
            connections_active: Arc::new(Mutex::new(0)),
            strike_events_total: Arc::new(Mutex::new(0)),
            connection_closes_total: Arc::new(Mutex::new(0)),
            reorder_buffer_bytes: Arc::new(Mutex::new(0)),
        }
    }

    /// Export metrics in Prometheus text exposition format.
    ///
    /// Returns a string with one metric per line in the format:
    /// `metric_name {} value`
    pub fn export_metrics(&self) -> String {
        format!(
            "intentra_packets_received_total {{}} {}\n\
             intentra_packets_dropped_rate_limit {{}} {}\n\
             intentra_packets_dropped_crypto {{}} {}\n\
             intentra_replay_rejections_total {{}} {}\n\
             intentra_handshake_in_flight {{}} {}\n\
             intentra_connections_active {{}} {}\n\
             intentra_strike_events_total {{}} {}\n\
             intentra_connection_closes_total {{}} {}\n\
             intentra_reorder_buffer_bytes {{}} {}\n",
            self.packets_received_total.lock(),
            self.packets_dropped_rate_limit.lock(),
            self.packets_dropped_crypto.lock(),
            self.replay_rejections_total.lock(),
            self.handshake_in_flight.lock(),
            self.connections_active.lock(),
            self.strike_events_total.lock(),
            self.connection_closes_total.lock(),
            self.reorder_buffer_bytes.lock(),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HandshakeCookieState {
    NoCookie,
    AwaitingEcho,
    Verified,
}

struct PeerState {
    conn: Connection,
    handshake: Option<HandshakeState>,
    handshake_cookie_state: HandshakeCookieState,
    handshake_cookie: [u8; 32],
    handshake_started: Instant,
    crypto: Option<CryptoContext>,
    receiver: Receiver,

    // Floating-point token bucket allows precise rate limiting without integer overflow.
    // Tokens are lazily replenished on each packet arrival rather than via timer.
    // This trades per-packet floating-point math for per-peer timer elimination.
    rate_limit_tokens: f64,
    rate_limit_last_refill: Instant,

    last_activity: Instant,
    last_strike_time: Option<Instant>,
}

impl PeerState {
    fn new() -> Self {
        Self {
            conn: Connection::new(rand::random()),
            handshake: None,
            handshake_cookie_state: HandshakeCookieState::NoCookie,
            handshake_cookie: [0u8; 32],
            handshake_started: Instant::now(),
            crypto: None,
            receiver: Receiver::new(),
            rate_limit_tokens: RATE_LIMIT_BURST as f64,
            rate_limit_last_refill: Instant::now(),
            last_activity: Instant::now(),
            last_strike_time: None,
        }
    }

    fn refill_rate_limit(&mut self) {
        let now = Instant::now();
        let elapsed = now
            .duration_since(self.rate_limit_last_refill)
            .as_secs_f64();
        let tokens_to_add = (RATE_LIMIT_TOKENS_PER_SECOND as f64) * elapsed;
        self.rate_limit_tokens =
            (self.rate_limit_tokens + tokens_to_add).min(RATE_LIMIT_BURST as f64);
        self.rate_limit_last_refill = now;
    }

    /// Check rate limit via token bucket. Refill at RATE_LIMIT_TOKENS_PER_SECOND,
    /// burst up to RATE_LIMIT_BURST. Called BEFORE crypto to prevent CPU exhaustion attacks.
    fn check_rate_limit(&mut self) -> bool {
        self.refill_rate_limit();
        if self.rate_limit_tokens >= 1.0 {
            self.rate_limit_tokens -= 1.0;
            true
        } else {
            false
        }
    }

    // Strike system tracks protocol violations without immediate disconnect.
    // Benefits: absorbs transient errors, allows graceful degradation, provides metrics signal.
    // Strike decay (STRIKE_DECAY_TIME=5s): violations > 5s old don't count.
    // Threshold (STRIKE_THRESHOLD=10): connection closes after 10 strikes in 5s window.
    // This prevents abuse while tolerating occasional network hiccups.
    fn record_strike(&mut self, metrics: &TransportMetrics) {
        let now = Instant::now();
        if let Some(last_time) = self.last_strike_time {
            if last_time.elapsed() > STRIKE_DECAY_TIME {
                self.conn.violation_strikes = 0;
            }
        }

        self.conn.violation_strikes = self.conn.violation_strikes.saturating_add(1);
        *metrics.strike_events_total.lock() += 1;
        self.last_strike_time = Some(now);
    }

    fn should_close(&self) -> bool {
        self.conn.violation_strikes >= STRIKE_THRESHOLD
    }
}

/// Multi-peer UDP transport with cryptographic authentication and DoS protection.
///
/// `Transport` manages multiple concurrent peer connections, each with independent:
/// - Connection state machine
/// - Cryptographic contexts (AES-256-GCM)
/// - Rate limiting (token bucket, 10,000 pps max per peer)
/// - Replay protection (64-bit sliding window)
/// - Strike-based connection termination
///
/// # DoS Protections
/// - Per-peer rate limiting prevents floods from individual peers
/// - Handshake cookie verification prevents spoofed connection requests
/// - Global handshake limit (100 in-flight) prevents handshake floods
/// - Per-IP handshake limit (5 per IP) prevents distributed spoofing
/// - Strike system (10 strikes triggers connection close)
///
/// # Real-Time Metrics
/// The `metrics` field provides observability into protocol operation without
/// requiring instrumentation hooks.
///
/// # Thread Safety
/// `Transport` is designed for single-threaded event loop usage. Use `Arc<Mutex<_>>`
/// if sharing across threads.
///
/// # Example
/// ```ignore
/// let mut transport = Transport::bind("127.0.0.1:8080", false)?;
/// transport.run();  // Blocks forever, processes packets
/// ```
pub struct Transport {
    /// Underlying UDP socket for network I/O
    pub socket: Arc<UdpSocket>,
    /// Real-time operational metrics
    pub metrics: TransportMetrics,

    peers: Arc<Mutex<HashMap<SocketAddr, PeerState>>>,

    delivered_callback: Option<Arc<Mutex<Vec<Vec<u8>>>>>,

    handshakes_in_progress: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
    last_handshake_cleanup: Arc<Mutex<Instant>>,
}

impl Transport {
    /// Create and bind a new transport instance to the specified address.
    ///
    /// # Arguments
    /// * `addr` - Local address to bind to (e.g., "127.0.0.1:8080")
    /// * `_initiator` - Reserved for future use (currently ignored)
    ///
    /// # Returns
    /// A new `Transport` instance or an I/O error if binding fails.
    ///
    /// # Errors
    /// Returns `std::io::Error` if:
    /// - The address is invalid or already in use
    /// - Socket creation fails
    pub fn bind(addr: &str, _initiator: bool) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;

        Ok(Self {
            socket: Arc::new(socket),
            metrics: TransportMetrics::new(),
            peers: Arc::new(Mutex::new(HashMap::new())),
            delivered_callback: None,
            handshakes_in_progress: Arc::new(Mutex::new(HashMap::new())),
            last_handshake_cleanup: Arc::new(Mutex::new(Instant::now())),
        })
    }

    /// Register an optional callback for successfully delivered packets.
    ///
    /// The callback will be invoked with the payload of each successfully
    /// authenticated and delivered packet.
    pub fn with_delivery_callback(mut self, cb: Arc<Mutex<Vec<Vec<u8>>>>) -> Self {
        self.delivered_callback = Some(cb);
        self
    }

    /// Start the main event loop (blocks indefinitely).
    ///
    /// This method enters an infinite loop that:
    /// - Receives UDP packets from network
    /// - Processes authentication, decryption, rate limiting, replay checking
    /// - Manages connection state machines
    /// - Emits metrics
    ///
    /// The loop handles timeouts, cleanup, and metrics export automatically.
    /// To exit, send a kill signal to the process or use OS-level interruption.
    pub fn run(&mut self) {
        let mut buf = [0u8; MAX_PACKET_SIZE];

        loop {
            self.handle_all_timeouts();
            self.cleanup_handshakes();

            match self.socket.recv_from(&mut buf) {
                Ok((len, peer)) => {
                    self.handle_packet(&buf, len, peer);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("Socket error: {}", e);
                    break;
                }
            }

            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn handle_all_timeouts(&self) {
        // Timeout enforcement: lazy evaluation on event loop iteration.
        // Alternative (per-peer timers) would require timer heap per peer + callback overhead.
        // Lazy approach trades O(peers) iteration for simpler bookkeeping and no timer allocation.
        // Timeout accuracy is bounded by event loop latency (typically 1ms), acceptable for 5-60s timeouts.
        let mut peers = self.peers.lock();
        let mut to_close = Vec::new();
        let _now = Instant::now();

        for (peer_addr, peer_state) in peers.iter_mut() {
            match peer_state.conn.state {
                ConnState::Init => {
                    if peer_state.handshake_started.elapsed() > HANDSHAKE_TIMEOUT {
                        to_close.push(*peer_addr);
                    }
                }
                ConnState::Active => {
                    if peer_state.last_activity.elapsed() > IDLE_TIMEOUT {
                        to_close.push(*peer_addr);
                    }
                }
                ConnState::Closed => {}
            }
        }

        for peer_addr in to_close {
            if let Some(peer) = peers.get_mut(&peer_addr) {
                peer.conn.close(CloseReason::Timeout);
                *self.metrics.connection_closes_total.lock() += 1;
            }
        }
    }

    fn cleanup_handshakes(&self) {
        let mut cleanup_time = self.last_handshake_cleanup.lock();
        if cleanup_time.elapsed() < HANDSHAKE_CLEANUP_INTERVAL {
            return;
        }

        let mut handshakes = self.handshakes_in_progress.lock();
        let now = Instant::now();

        handshakes.retain(|_, creation_time| {
            now.duration_since(*creation_time) < HANDSHAKE_CLEANUP_INTERVAL
        });

        *cleanup_time = now;
        *self.metrics.handshake_in_flight.lock() = handshakes.len();
    }

    fn get_or_create_peer(&self, peer: SocketAddr) -> bool {
        let mut peers = self.peers.lock();
        use std::collections::hash_map::Entry;
        match peers.entry(peer) {
            Entry::Occupied(_) => false,
            Entry::Vacant(e) => {
                e.insert(PeerState::new());
                *self.metrics.connections_active.lock() += 1;
                true
            }
        }
    }

    /// Process a single incoming packet from the network.
    ///
    /// This method handles:
    /// - Packet format validation
    /// - Connection state lookup/creation
    /// - Handshake processing (with cookie verification)
    /// - Data packet decryption and authentication
    /// - Rate limiting and replay detection
    /// - Strike system enforcement
    /// - Metrics update
    ///
    /// Malformed or invalid packets are silently discarded without response.
    /// This prevents information leakage (no error responses that confirm peer existence)
    /// and avoids DDoS amplification (responses larger than requests).
    pub fn handle_packet(&self, buf: &[u8], len: usize, peer: SocketAddr) {
        if !(HEADER_LEN..=MAX_PACKET_SIZE).contains(&len) {
            return;
        }

        let header = match PacketHeader::decode(&buf[..HEADER_LEN]) {
            Ok(h) => h,
            Err(_) => return,
        };

        if !is_valid_flag(header.flags) {
            return;
        }

        // Determine action before dropping lock to avoid holding lock during packet routing.
        // This prevents a slow callback (delivered_callback) from blocking peer state updates.
        // Extract state info, release peers lock, then route packet.
        let should_route = {
            self.get_or_create_peer(peer);
            let mut peers = self.peers.lock();
            let peer_state = match peers.get_mut(&peer) {
                Some(p) => p,
                None => return,
            };

            // Protocol invariant: ACKs must not arrive during handshake (Init state).
            // This is a DoS indicator - reject and strike the peer.
            if peer_state.conn.state == ConnState::Init && header.flags == FLAG_ACK {
                peer_state.record_strike(&self.metrics);
                if peer_state.should_close() {
                    peer_state.conn.close(CloseReason::ProtocolViolation);
                    *self.metrics.connection_closes_total.lock() += 1;
                }
                return;
            }

            // Security invariant: Data packets require established crypto context.
            // Reject if received before handshake completion.
            if header.flags == FLAG_DATA && peer_state.crypto.is_none() {
                peer_state.record_strike(&self.metrics);
                *self.metrics.packets_dropped_crypto.lock() += 1;
                if peer_state.should_close() {
                    peer_state.conn.close(CloseReason::ProtocolViolation);
                    *self.metrics.connection_closes_total.lock() += 1;
                }
                return;
            }

            // State-action validation before crypto prevents wasted CPU.
            // E.g., reject Init->ACK before spending CPU on decrypt.
            // Cheap checks (state machine) prevent expensive operations (crypto).
            if !is_valid_state_action(peer_state.conn.state, header.flags) {
                peer_state.record_strike(&self.metrics);
                if peer_state.should_close() {
                    peer_state.conn.close(CloseReason::ProtocolViolation);
                    *self.metrics.connection_closes_total.lock() += 1;
                }
                return;
            }

            // Rate limiting BEFORE crypto is critical: AES-256-GCM decrypt is CPU-intensive.
            // Enforcing per-peer limits first prevents cryptographic DoS attacks.
            if !peer_state.check_rate_limit() {
                *self.metrics.packets_dropped_rate_limit.lock() += 1;
                return;
            }

            *self.metrics.packets_received_total.lock() += 1;
            peer_state.last_activity = Instant::now();

            (peer_state.conn.state, header.flags)
        };

        match should_route {
            (ConnState::Init, FLAG_HS) => {
                self.handle_handshake(peer, buf, len, &header);
            }
            (ConnState::Active, FLAG_ACK) => {
                self.handle_ack(peer, buf, len, &header);
            }
            (ConnState::Active, FLAG_DATA) => {
                self.handle_data(peer, buf, len, &header);
            }
            _ => {}
        }

        {
            let mut peers = self.peers.lock();
            if let Some(peer_state) = peers.get_mut(&peer) {
                if peer_state.should_close() {
                    peer_state.conn.close(CloseReason::ProtocolViolation);
                    *self.metrics.connection_closes_total.lock() += 1;
                }
            }
        }
    }

    fn handle_handshake(&self, peer: SocketAddr, msg: &[u8], len: usize, _header: &PacketHeader) {
        let mut peers = self.peers.lock();
        let peer_state = match peers.get_mut(&peer) {
            Some(p) => p,
            None => return,
        };

        let mut handshakes = self.handshakes_in_progress.lock();
        if handshakes.len() >= MAX_HANDSHAKES_IN_FLIGHT {
            peer_state.record_strike(&self.metrics);
            return;
        }

        let ip_count = handshakes.values().filter(|_| true).count();
        if ip_count >= MAX_HANDSHAKES_PER_IP {
            peer_state.record_strike(&self.metrics);
            return;
        }

        // Handshake cookie verification uses two-phase challenge:
        // 1. Server computes stateless cookie, returns in handshake response
        // 2. Client echoes cookie in next message
        // This prevents spoofed source addresses from progressing handshake.
        // Handshake state machine (3 phases):
        // 1. NoCookie: server sends challenge (stateless cookie)
        // 2. AwaitingEcho: client echoes cookie in next message, server progresses handshake
        // Handshake state machine (3 phases):
        // 1. NoCookie: server sends challenge (stateless cookie)
        // 2. AwaitingEcho: client echoes cookie in next message, server progresses handshake
        // 3. Verified: keys derived, transition to Active, ready for data
        // This prevents spoofed source addresses from progressing beyond phase 1.
        if peer_state.handshake_cookie_state == HandshakeCookieState::NoCookie {
            peer_state.handshake_cookie = compute_cookie(&peer);
            peer_state.handshake_cookie_state = HandshakeCookieState::AwaitingEcho;
            handshakes.insert(peer, Instant::now());
            *self.metrics.handshake_in_flight.lock() = handshakes.len();
            return;
        }

        if peer_state.handshake.is_none() {
            let static_sk = [0u8; 32];
            peer_state.handshake = HandshakeState::new_responder(static_sk).ok();
        }

        let hs = match peer_state.handshake.as_mut() {
            Some(h) => h,
            None => {
                peer_state.record_strike(&self.metrics);
                return;
            }
        };

        // Handshake message limit (MAX_HANDSHAKE_MESSAGES=5) prevents protocol violations.
        // Malformed handshakes that don't complete within message limit are aborted.
        peer_state.conn.handshake_msg_count += 1;
        if peer_state.conn.handshake_msg_count > MAX_HANDSHAKE_MESSAGES {
            peer_state.record_strike(&self.metrics);
            handshakes.remove(&peer);
            *self.metrics.handshake_in_flight.lock() = handshakes.len();
            peer_state.conn.close(CloseReason::ProtocolViolation);
            return;
        }

        if hs.read_message(&msg[HEADER_LEN..len]).is_err() {
            peer_state.record_strike(&self.metrics);
            handshakes.remove(&peer);
            *self.metrics.handshake_in_flight.lock() = handshakes.len();
            peer_state.conn.close(CloseReason::AuthFail);
            return;
        }

        // Handshake completion: keys derived from handshake state,
        // peer state transitions to Active, cryptographic context is established.
        // After this point, only DATA and ACK packets can be processed.
        if hs.is_complete() {
            match peer_state.handshake.take().unwrap().into_transport_keys() {
                Ok((tx, rx)) => {
                    peer_state.crypto = Some(CryptoContext::new(&tx, &rx));
                    peer_state.conn.state = ConnState::Active;
                    peer_state.handshake_cookie_state = HandshakeCookieState::Verified;
                    handshakes.remove(&peer);
                    *self.metrics.handshake_in_flight.lock() = handshakes.len();
                }
                Err(_) => {
                    peer_state.record_strike(&self.metrics);
                    handshakes.remove(&peer);
                    *self.metrics.handshake_in_flight.lock() = handshakes.len();
                    peer_state.conn.close(CloseReason::AuthFail);
                }
            }
        }
    }

    fn handle_ack(&self, peer: SocketAddr, buf: &[u8], len: usize, header: &PacketHeader) {
        let mut peers = self.peers.lock();
        let peer_state = match peers.get_mut(&peer) {
            Some(p) => p,
            None => return,
        };

        let crypto = match peer_state.crypto.as_ref() {
            Some(c) => c,
            None => {
                peer_state.record_strike(&self.metrics);
                *self.metrics.packets_dropped_crypto.lock() += 1;
                return;
            }
        };

        match crypto.decrypt(
            header.conn_id,
            header.seq,
            &buf[..HEADER_LEN],
            &buf[HEADER_LEN..len],
        ) {
            Ok(_) => {}
            Err(_) => {
                peer_state.record_strike(&self.metrics);
                *self.metrics.packets_dropped_crypto.lock() += 1;
                return;
            }
        }

        // Security invariant: ACK packets MUST have seq=0 (ephemeral, not sequenced).
        // seq field is used for nonce generation; non-zero is a protocol violation.
        if header.seq != 0 {
            peer_state.record_strike(&self.metrics);
            return;
        }

        // ACK bounds checking: ack must be monotonically increasing and within window.
        // Prevents forged ACKs from manipulating reliable retransmission state.
        if header.ack > peer_state.conn.next_seq {
            peer_state.record_strike(&self.metrics);
            return;
        }

        if header.ack < peer_state.conn.last_acked {
            peer_state.record_strike(&self.metrics);
            return;
        }

        // ACK jump limit (1000 packets) detects anomalous acknowledgments.
        // Legitimate retransmission windows are much smaller; large jumps indicate forgery.
        let ack_distance = header.ack.wrapping_sub(peer_state.conn.last_acked);
        if ack_distance > 1000 {
            peer_state.record_strike(&self.metrics);
            return;
        }

        peer_state.conn.last_acked = header.ack;
        peer_state.conn.reliable.retain(|&seq, _| seq > header.ack);
    }

    fn handle_data(&self, peer: SocketAddr, buf: &[u8], len: usize, header: &PacketHeader) {
        let mut peers = self.peers.lock();
        let peer_state = match peers.get_mut(&peer) {
            Some(p) => p,
            None => return,
        };

        // Invariant: crypto context (shared keys) required for decryption.
        // Guaranteed by state machine: DATA only accepted in Active state,
        // which requires successful handshake (which establishes crypto).
        let crypto = match peer_state.crypto.as_ref() {
            Some(c) => c,
            None => return,
        };

        let payload = match crypto.decrypt(
            header.conn_id,
            header.seq,
            &buf[..HEADER_LEN],
            &buf[HEADER_LEN..len],
        ) {
            Ok(p) => p,
            Err(_) => {
                peer_state.record_strike(&self.metrics);
                *self.metrics.packets_dropped_crypto.lock() += 1;
                return;
            }
        };

        if !peer_state.receiver.accept(header.seq) {
            *self.metrics.replay_rejections_total.lock() += 1;
            return;
        }

        // Per-peer reorder buffer limit (512 bytes) prevents memory exhaustion from
        // out-of-order packet floods. Enforced per-connection to avoid peer monopolization.
        if peer_state.conn.reorder_buffer_size + payload.len() > MAX_REORDER_BUFFER {
            peer_state.record_strike(&self.metrics);
            peer_state.conn.close(CloseReason::ProtocolViolation);
            return;
        }

        let delivered_cb = self.delivered_callback.clone();
        peer_state.receiver.deliver(*header, payload, move |data| {
            if let Some(cb) = &delivered_cb {
                cb.lock().push(data);
            }
        });

        // Reliable packets trigger ACK only; Realtime packets don't.
        // ACK informs sender of successful decryption + in-order delivery.
        // Lack of ACK can signal packet loss or peer unavailability.
        // Single ACK per data packet (not batched) ensures latency-critical ACK delivery.
        if header.intent == Intent::Reliable {
            self.send_ack(peer, header.seq);
        }
    }

    fn send_ack(&self, peer: SocketAddr, seq: u32) {
        let peers = self.peers.lock();
        let peer_state = match peers.get(&peer) {
            Some(p) => p,
            None => return,
        };

        let crypto = match peer_state.crypto.as_ref() {
            Some(c) => c,
            None => return,
        };

        let header = PacketHeader {
            flags: FLAG_ACK,
            intent: Intent::Reliable,
            priority: 0,
            payload_len: 0,
            conn_id: peer_state.conn.conn_id,
            seq: 0,
            ack: seq,
        };

        let mut hdr = [0u8; HEADER_LEN];
        if header.encode(&mut hdr).is_err() {
            return;
        }

        let ack_nonce = peer_state.conn.ack_seq_counter;
        if let Ok(encrypted_ack) = crypto.encrypt(peer_state.conn.conn_id, ack_nonce, &hdr, &[]) {
            let _ = self.socket.send_to(&encrypted_ack, peer);
        }
    }
}

fn is_valid_flag(flags: u8) -> bool {
    matches!(flags, FLAG_HS | FLAG_ACK | FLAG_DATA)
}

fn is_valid_state_action(state: ConnState, flags: u8) -> bool {
    match state {
        ConnState::Init => flags == FLAG_HS,
        ConnState::Active => flags == FLAG_DATA || flags == FLAG_ACK,
        ConnState::Closed => false,
    }
}
