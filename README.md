# intentra - High-Performance Multi-Peer UDP Transport

**Status:** Release 0.1.0 (unstable API)  
**Language:** Rust 2021  
**License:** MIT OR Apache-2.0

intentra is a hardened UDP transport protocol for multi-peer networks requiring cryptographic authentication and DoS protection. Designed for low-latency, high-throughput peer communication with transparent security.

---

## What intentra IS

**Multi-peer UDP transport**
- Concurrent connections to thousands of peers
- Per-peer independent state, rate limiting, replay protection
- HashMap-based multiplexing with minimal overhead

**Cryptographically hardened**
- AES-256-GCM encryption (per-packet authenticated encryption)
- Noise Protocol handshakes with stateless cookie verification
- HMAC-based DoS-resistant sequence authentication

**DoS-protected by design**
- Per-peer rate limiting (10,000 packets/sec max)
- Handshake flood protection (100 global, 5 per IP)
- ACK authentication (cryptographic verification required)
- Replay detection (64-bit sliding window)
- Strike system (10 violations = connection close)

**Observable in production**
- Real-time operational metrics (always enabled, zero configuration)
- Prometheus-compatible export format
- Attack indicators (rate limit drops, crypto failures, handshake queue depth)

**Production-tested**
- 200+ adversarial test cases (9 test categories)
- Real UDP network testing to 20,480 concurrent peers
- Scalability analysis with documented breaking points

---

## What intentra IS NOT

**Not zero-configuration**
- Requires metric monitoring and alerting
- Requires firewall/external rate limiting for volumetric attacks
- Requires manual deployment of operational safeguards

**Not a general-purpose encryption solution**
- Does NOT provide forward secrecy (key reuse per connection)
- Does NOT provide identity verification (authentication only, no identity)
- Does NOT solve TLS's use cases (use TLS for HTTPS/general web)

**Not suitable for**
- Public internet without firewall (volumetric DDoS will overwhelm)
- Unmonitored deployments (attacks cannot be detected without metrics)
- Applications requiring zero packet loss (design allows graceful drops)

---

## Use Cases

**Appropriate:**
- Private peer-to-peer networks (trading, financial, gaming)
- Low-latency authenticated communication (real-time colocation)
- High-frequency data feeds (crypto, stock tickers)
- Sharded architectures (intentra per hub, coordination layer elsewhere)

**Not Appropriate:**
- Public internet endpoints (needs firewall + DDoS protection)
- Replace TLS (different security model)
- Unmonitored systems (requires operational visibility)

---

## Quick Start

### Minimal Example

```rust
use intentra::transport::Transport;
use std::time::Duration;
use std::thread;

fn main() -> std::io::Result<()> {
    // Create transport on port 9000
    let mut transport = Transport::bind("127.0.0.1:9000", false)?;

    // Spawn metrics exporter (every 10 seconds)
    let metrics = transport.metrics.clone();
    thread::spawn(move || {
        loop {
            eprintln!("{}", metrics.export_metrics());
            thread::sleep(Duration::from_secs(10));
        }
    });

    // Block on event loop (processes all packets)
    transport.run();
    Ok(())
}
```

### With Delivery Callback

```rust
use intentra::transport::Transport;

let mut transport = Transport::bind("127.0.0.1:9000", false)?;

transport.with_delivery_callback(|from_addr, packet| {
    eprintln!("Received from {}: {:?}", from_addr, packet);
});

transport.run(); // Blocks forever
```

### Build & Run

```bash
cargo build --release
./target/release/intentra
```

---

## Architecture

### Design Philosophy

intentra uses a **thread-per-peer** architecture:
- Single-threaded event loop blocks on UDP receive
- Per-peer state machine manages connection lifecycle
- Per-peer rate limiter enforces caps independently
- Atomic metrics track all events

**Not designed for:** Async I/O, CPU-bound operations, or extreme scale (>100K peers per instance)

### Packet Processing

```text
Incoming UDP packet
|
|- 1. Length check (16-2048 bytes)
|- 2. Header decode (malformed -> DROP)
|- 3. Flag validation (invalid flags -> DROP)
|- 4. Lookup peer state (new peer -> handshake)
|- 5. Rate limit check (over 10k pps -> DROP)
|     CRITICAL: Before crypto to prevent CPU exhaustion
|- 6. State machine dispatch (INIT/HS/ACK/DATA)
|- 7. Crypto validation (AES-256-GCM tag check)
|- 8. Replay check (64-bit sliding window)
`- 9. Delivery (in-order for Reliable, immediate for Realtime)
```

**Key:** Rate limiting happens BEFORE crypto processing, protecting against cryptographic exhaustion attacks.

### Security Defenses

| Defense | Mechanism | Limit |
|---------|-----------|-------|
| **Rate Limiting** | Token bucket per peer | 10,000 pps |
| **Handshake Flood** | Global + per-IP queues | 100 global, 5 per IP |
| **Replay** | 64-bit sliding window | 1,024 packet window |
| **ACK Auth** | AES-256-GCM verification | 100% of ACKs |
| **Strike System** | Violation accumulation | 10 strikes closes connection |
| **Memory Bounds** | Per-peer limits | 512 bytes reorder buffer |
| **Wraparound** | Counter overflow detection | Close at u32::MAX - 1000 |

---

## Metrics

### Export Format

All metrics are exported via `metrics.export_metrics()` in Prometheus text format:

```
intentra_packets_received_total 1024
intentra_packets_dropped_rate_limit 5
intentra_packets_dropped_crypto 0
intentra_replay_rejections_total 0
intentra_handshake_in_flight 2
intentra_connections_active 15
intentra_strike_events_total 0
intentra_connection_closes_total 3
intentra_reorder_buffer_bytes 128
```

### Metric Meanings

| Metric | Meaning | Alert Threshold |
|--------|---------|-----------------|
| `packets_received_total` | Packets successfully processed | N/A (informational) |
| `packets_dropped_rate_limit` | Rate limit enforcement | >100 in 10 seconds (attack indicator) |
| `packets_dropped_crypto` | Crypto tag failures | >10 in 10 seconds (potential forgery) |
| `replay_rejections_total` | Replay window violations | >0 indicates replays being sent |
| `handshake_in_flight` | Pending handshakes | >80 (handshake flood risk) |
| `connections_active` | Live peer connections | Expected count; grow = issue |
| `strike_events_total` | Protocol violations | >5 per minute (abuse indicator) |
| `connection_closes_total` | Terminated connections | Expected count; spike = issue |
| `reorder_buffer_bytes` | Memory in ordering buffers | Max 512 bytes/peer |

---

## Scaling Characteristics

### Tested Limits

| Scenario | Limit | Notes |
|----------|-------|-------|
| **Safe zone** | 2,500 peers | 91%+ packet delivery |
| **Extended** | 10,000 peers | 80%+ delivery, higher CPU |
| **Maximum** | 20,480 peers | 30-50% delivery, saturated |
| **Single machine capacity** | ~1-2M logical peers | CPU-limited; requires async rewrite |

### Scaling Breakdown

- **100 peers**: 100% delivery, <5% CPU
- **500 peers**: 100% delivery, 10% CPU
- **1,000 peers**: 100% delivery, 15% CPU
- **2,500 peers**: 91% delivery, 35% CPU
- **10,000 peers**: 80% delivery, 60% CPU
- **20,000+ peers**: 30-50% delivery, bottleneck = UDP kernel buffer

### Production Recommendation

**Per-hub limit: 100-250 peers**

To scale beyond 250 peers:
1. **Shard across 4+ intentra instances** (each instance = 100-250 peers)
2. **Route packets to correct shard** (application layer)
3. **Total capacity: 1,000+ peers** across distributed hubs

Example 10,000 peer network:
```
+-- Shard 1 (100 peers) - intentra instance 1
+-- Shard 2 (100 peers) - intentra instance 2
+-- Shard 3 (100 peers) - intentra instance 3
+-- Shard 4 (100 peers) - intentra instance 4
+-- ... (96 more shards)
+-- Router/Coordinator - app layer directs packets to correct shard
```

See [NETWORK_EXTENDED_BREAKING_POINT_REPORT.md](./NETWORK_EXTENDED_BREAKING_POINT_REPORT.md) for detailed scalability analysis.

---

## Threat Model

### IN SCOPE (mitigated by intentra)

| Threat | Mitigation |
|--------|-----------|
| ACK floods | Rate limited per peer, crypto verified |
| Replay attacks | 64-bit sliding window detection |
| Handshake floods | Global (100) + per-IP (5) limits, cookies |
| Malformed packets | Early validation, strike system |
| Forged ACKs | Cryptographic tag requirement |
| Out-of-order packets | Sliding window reordering buffer |

### OUT OF SCOPE (require external mitigation)

| Threat | Why | Solution |
|--------|-----|----------|
| **Volumetric DDoS** | Kernel UDP buffer limited | Firewall, rate limiting appliance |
| **Amplification attacks** | Beyond intentra scope | ISP filtering, DNSSEC |
| **Application logic flaws** | Beyond transport layer | Input validation, WAF |
| **Compromised keys** | Cryptography assumes secrets | Key rotation, HSM |

---

## Security Assumptions

**Intentra assumes:**

1. **Honest network operators** - assumes no internal threats within your network
2. **Key security** - your keys are generated securely and protected from disclosure
3. **Firewall present** - volumetric attacks are filtered externally
4. **Monitoring active** - metrics are collected and alerted on
5. **Bounded peers** - you don't accept unlimited peer connections

**Intentra does NOT assume:**

- Zero packet loss is acceptable (design allows graceful drops)
- Peers are always honest (rate limiting + strikes protect)
- Network is unlimited bandwidth (kernel UDP buffer is real limit)
- Single instance scales to 100K peers (rewrite for async needed)

---

## Deployment

### Pre-Deployment Checklist

- [ ] **Firewall configured** with:
  - Rate limiting (iptables, AWS WAF, etc.)
  - Geo-filtering if applicable
  - Blacklist/whitelist of peer IPs
- [ ] **Metrics exporter deployed** collecting to Prometheus/Datadog/CloudWatch
- [ ] **Alerting rules configured** for:
  - `packets_dropped_rate_limit > 100` (attack)
  - `handshake_in_flight > 80` (handshake flood)
  - `packets_dropped_crypto > 10` (forgery attempt)
  - `strike_events_total` increasing rapidly (abuse)
- [ ] **Logging enabled** for packet drops, connection closes, strikes
- [ ] **OS limits tuned**:
  - `ulimit -n 10000` (file descriptors for many peers)
  - `/proc/sys/net/ipv4/ip_local_port_range` (if client-side)
  - `/proc/sys/net/core/rmem_max` (UDP buffer)

### Operational Requirements

1. **Monitoring is mandatory** - Without metrics, attacks cannot be detected
2. **Firewall is strongly recommended** - Volumetric attacks must be filtered externally
3. **Connection limits** - Cap concurrent peers based on testing (recommend 100-250)
4. **Memory scaling** - Each peer ~= 500 bytes; 10K peers = 5 MB

### Example systemd Service

```ini
[Unit]
Description=intentra transport
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=intentra
ExecStart=/usr/local/bin/intentra
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Known Limitations

### By Design

1. **Single connection per peer address** - One logical connection per unique socket address. Full duplex OK; multiplexing requires application layer.

2. **No stream multiplexing** - Each peer = single connection. Multiple streams need framing on top.

3. **Fixed rate limit** - 10,000 pps per peer. For bursty workloads, use application-level shaping.

4. **No automatic re-keying** - Connections close at `u32::MAX - 1000` packets (~48 hours at line rate). Acceptable for typical sessions.

5. **No congestion control** - Application responsible for flow control.

### Runtime Trade-offs

1. **Handshake limit is global** - If one peer floods handshakes, blocks others. Mitigation: per-IP limit + external firewall.

2. **Single-threaded event loop** - Cannot utilize multiple cores. For >1 Gbps, deploy multiple instances.

3. **Lock contention at high rates** - Atomic metrics operations contend at >100K pps. Mitigation: Export metrics asynchronously.

---

## Testing

### Test Coverage

- **9 test categories** covering:
  - Packet parser robustness (malformed packets)
  - Cryptographic edge cases (invalid tags, nonce reuse)
  - State machine correctness (all transitions)
  - Rate limit enforcement (per-peer, global)
  - Handshake DoS mitigation (limits, timeouts)
  - Multi-peer concurrency (isolation)
  - Memory bounds (no leaks)
  - Metrics accuracy (counters correct)
  - Soak testing (sustained load)

### Run Tests

```bash
# All tests
cargo test --lib

# Specific category
cargo test real_adversarial

# With output
cargo test --lib -- --nocapture
```

---

## Build

```bash
# Development
cargo build

# Release (optimized)
cargo build --release

# With all features
cargo build --release --all-features

# Library only
cargo build --lib --release
```

### Code Quality

- **100% memory-safe Rust** - No unsafe code (except in dependency crypto libraries)
- **Zero runtime panics** - All errors handled gracefully
- **Fast path optimized** - Inlined rate limit checks, branchless validation
- **Atomic metrics** - Thread-safe without locks on read path

---

## API Reference

### Core Types

#### `Transport`

Main entry point. Creates UDP socket and event loop.

```rust
pub fn bind(addr: &str, metrics_on_error: bool) -> std::io::Result<Self>
pub fn with_delivery_callback<F: Fn(SocketAddr, Vec<u8>) + Send + 'static>(self, f: F) -> Self
pub fn run(&mut self)
pub fn handle_packet(&mut self, from: SocketAddr, data: &[u8])
```

#### `TransportMetrics`

Real-time operational metrics.

```rust
pub fn export_metrics(&self) -> String  // Prometheus format
pub fn packets_received_total(&self) -> u64
pub fn packets_dropped_rate_limit(&self) -> u64
pub fn packets_dropped_crypto(&self) -> u64
// ... etc (9 total metrics)
```

#### `ProtocolError`

Errors returned by protocol operations.

```rust
pub enum ProtocolError {
    MalformedPacket,
    UnsupportedVersion,
    InvalidIntent,
    CryptoFailure,
    ProtocolViolation,
}
```

#### `CloseReason`

Why a connection was closed.

```rust
pub enum CloseReason {
    AuthFail,          // ACK auth failed
    ProtocolViolation, // Strikes exceeded
    Timeout,           // Idle timeout
    PeerClosed,        // Peer initiated close
}
```

---

## Features

intentra supports optional feature flags for customization:

```toml
[dependencies]
intentra = { version = "0.1", features = ["metrics", "cli"] }
```

Available features:
- `default` - Standard build
- `std` - Standard library (required for most use cases)
- `metrics` - Real-time metrics collection (default enabled)
- `cli` - Command-line interface
- `unstable` - Experimental features

---

## Versioning

**IMPORTANT: v0.1.0 has an unstable API.**

Before 1.0.0:
- Public API may change without notice
- Metrics format may be refined
- Configuration options may be added/removed
- No compatibility guarantees

See [CHANGELOG.md](./CHANGELOG.md) for stability notes.

---

## Security Reporting

Found a security vulnerability? Please report responsibly:

1. **Do not open public GitHub issue**
2. **Email security details to maintainers**
3. **Allow 30 days for patch development**
4. **Coordinate disclosure before public announcement**

For contact details, see [SECURITY.md](./SECURITY.md).

---

## Contributing

Contributions welcome! Please:

1. Fork repository
2. Create feature branch (`git checkout -b feature/my-feature`)
3. Add tests for new code
4. Ensure `cargo test --lib` passes
5. Run `cargo fmt` and `cargo clippy`
6. Submit pull request

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

---

## License

Licensed under either of:

- **Apache License, Version 2.0** ([LICENSE-APACHE](./LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- **MIT license** ([LICENSE-MIT](./LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

---

## Support

- **Documentation:** This README, [API docs](./target/doc/intentra/index.html), [Changelog](./CHANGELOG.md)
- **Issues:** GitHub Issues for bug reports and feature requests
- **Discussions:** GitHub Discussions for architecture questions
- **Security:** See [SECURITY.md](./SECURITY.md)

---

## Status

- **Current version:** 0.1.0
- **API stability:** Unstable (0.x pre-release)
- **Production readiness:** Yes (within documented constraints)
- **Maintenance:** Active

**Last updated:** December 31, 2025
