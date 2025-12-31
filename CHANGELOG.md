# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2025-12-31

### Intentra v0.1.0: Initial Release

This is the first public release of the intentra protocol - a high-performance multi-peer UDP transport with cryptographic authentication and comprehensive DoS protection.

### What's Included

**Core Protocol:**
- Multi-peer UDP transport with support for thousands of concurrent connections
- Per-peer independent state management, rate limiting, and replay protection
- AES-256-GCM encryption with Noise Protocol handshakes
- 64-bit sliding window replay detection
- Token-bucket rate limiting (10,000 packets/sec per peer)

**Security Defenses:**
- Handshake cookie verification to prevent spoofed connections
- Per-peer strike system (10 strikes = connection close)
- Global handshake limit (100 in-flight) + per-IP limit (5 per IP)
- ACK authentication via cryptographic verification
- Implicit connection idle timeout (60 seconds)

**Observability:**
- Real-time operational metrics (always enabled, zero configuration)
- Prometheus-compatible metric export format
- Track packet counts, DoS events, crypto failures, and connection state

**Testing:**
- 200+ adversarial test cases covering:
  - Packet parser robustness
  - Cryptographic edge cases
  - State machine correctness
  - Rate limit enforcement
  - Handshake DoS mitigation
  - Multi-peer concurrency
  - Memory bounds
  - Soak/stress testing

### Stability & API

**IMPORTANT: v0.1.0 is UNSTABLE for API purposes.**

While the protocol itself is production-tested:
- Public API surface may change before 1.0.0
- Metrics structure and export format may be refined
- Configuration options may be added or modified
- No semver guarantees until 1.0.0

See [semver policy](#semver-policy) below.

### What's Not Included

This release explicitly does NOT include:

- **Zero-configuration operation**: Requires metric monitoring and alerting
- **Firewall bypass**: Volumetric DDoS must be handled by external infrastructure
- **Magical attack protection**: Only mitigates specific attack classes
- **Async runtime** (pure thread-based architecture)
- **High-level API** (raw packet-oriented interface)
- **Clustering/sharding** helpers (must be implemented by user)

### Known Limitations

**Scaling Characteristics:**
- Thread-per-peer architecture scales to ~2,500 concurrent peers per instance with 91%+ packet delivery
- Beyond 2,500 peers, packet loss increases logarithmically due to UDP kernel buffer saturation
- Maximum single-machine capacity: ~1-2 million logical peers (CPU-limited)
- **Recommended production limit: 100-250 peers per hub instance**
- To scale to 1M+ peers: Use sharding across 1,000+ instances or rewrite with async I/O

**Threading Model:**
- Single-threaded event loop (blocks on UDP recv)
- Per-peer internal threading not supported
- Not designed for CPU-bound workloads
- Async I/O rewrite recommended for >100K concurrent peers

See [NETWORK_EXTENDED_BREAKING_POINT_REPORT.md](./NETWORK_EXTENDED_BREAKING_POINT_REPORT.md) for detailed scalability analysis.

### Security Model

**Threat Protection:**
- Per-packet authentication (AES-256-GCM)
- Replay attack detection (64-bit sliding window)
- Handshake spoofing mitigation (cookie verification)
- Handshake flood protection (per-IP and global limits)
- Rate limit enforcement per peer
- Strike-based connection termination

**Threat Assumptions:**
- Does NOT protect against volumetric DDoS (requires firewall)
- Does NOT provide confidentiality if cipher implementation is broken
- Does NOT verify peer identity (authentication-only, no identity)
- Does NOT provide forward secrecy (key reuse across connections)

**Deployment Assumptions:**
- Trusted network operators (not immune to internal threats)
- Monitoring and alerting on metrics (requires external tooling)
- Proper key distribution (out of scope)
- Firewall-protected network (volumetric attacks must be filtered outside)

### Testing & Verification

All code has been tested with:
- 200+ adversarial test cases (9 categories)
- Logical peer simulation to 1,000,000 concurrent peers
- Real UDP network testing to 20,480 concurrent peers
- Scalability analysis with breaking point characterization
- Memory bounds verification
- DoS protection enforcement confirmation
- Metric accuracy validation

See repository for detailed test results and implementation details.

### Semantic Versioning Policy

This release uses the following versioning scheme:

- **0.x.y**: Unstable. Breaking changes allowed at any point.
  - Public API may change without notice
  - Metrics format may be refined
  - Configuration options may be added/removed
  - No compatibility promises

- **1.0.0+**: Stable. Semantic versioning begins.
  - Public API stability guaranteed
  - Breaking changes only on major version bump
  - Migration guides provided for major versions
  - Metrics format stability guaranteed

**Migration for 0.x->1.0.0:**
If you use intentra 0.x in production, expect API changes. Plan for migration before 1.0.0 release.

### Getting Started

```rust
use intentra::transport::Transport;

// Create transport
let mut transport = Transport::bind("127.0.0.1:8080", false)?;

// Start event loop (blocks forever)
transport.run();
```

See [README.md](./README.md) for detailed usage, architecture, and threat model.

### Support & Feedback

- Report security issues: [SECURITY.md](./SECURITY.md) (responsible disclosure)
- Report bugs: GitHub Issues
- Discuss design: GitHub Discussions
- Contributing: [CONTRIBUTING.md](./CONTRIBUTING.md)

### License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](./LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

---

**Release Date:** December 31, 2025  
**Status:** Ready for evaluation (0.x unstable API)  
**Breaking Changes:** Yes (unstable version)
