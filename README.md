# intentra

**Deterministic multi-peer UDP transport for real-time state distribution**

**Status:** v0.1.0 (unstable API)
**Language:** Rust 2021
**License:** MIT OR Apache-2.0

---

## What is intentra?

**intentra** is a hardened UDP transport designed for **low-latency, high-frequency state broadcast in private networks**.

It is optimized for workloads where:

* many peers exchange small state updates
* latency and determinism matter more than reliability
* packet drops are acceptable, stalls are not
* peers are known and networks are firewalled

---

## What it does well

* **Multi-peer UDP transport**
* Single-threaded event loop with per-peer state machines
* Deterministic packet processing (no head-of-line blocking)
* Graceful overload behavior (drops instead of stalls)

### Security & DoS resistance

* AES-256-GCM per-packet authenticated encryption
* Noise Protocol handshake (XX, X25519)
* Stateless cookie verification
* Per-peer rate limiting (10,000 pps)
* Replay protection (64-bit sliding window)
* Cryptographic ACK authentication

### Observability

* Always-on metrics (Prometheus format)
* Rate-limit drops, crypto failures, handshake pressure visible at runtime

---

## What it is NOT

* Not a replacement for TLS / QUIC / TCP
* Not suitable for unfiltered public internet exposure
* Not zero-configuration
* Not zero packet loss
* Not an RPC or stream-multiplexing framework

If you need HTTPS, request/response semantics, or public-internet robustness, use TLS or QUIC.

---

## Best-fit use cases

**Where intentra shines:**

* Robotics fleet telemetry
* Real-time simulation / digital twins
* Multiplayer game state replication
* Private market data feeds

**Not a good fit for:**

* Public-facing services
* Reliable file transfer
* RPC / microservices APIs

---

## Measured performance (real benchmarks)

All results below are **measured**.

**Test parameters**

* Packet size: 128 bytes
* Duration: 120s per test
* Senders: 2

### Capacity envelope

| Aggregate PPS | Delivery | Notes                 |
| ------------: | -------: | --------------------- |
|   ≤ 1,000,000 |    ≥ 99% | Stable, deterministic |
|    ~1,200,000 |     ~88% | Near limit            |
|   > 1,500,000 |    < 70% | Graceful degradation  |

Example:

* **2,000 peers @ 500 Hz** → ~1,000,000 PPS @ **99.99% delivery**
* **1,500 peers @ 800 Hz** → ~1.2M PPS @ **88% delivery**

Failure mode: **single-core CPU saturation**, not protocol collapse.

---

## Recommended operating range

* **Default state rate:** 200 Hz
* **High-performance tier:** 500 Hz
* **Avoid networked 1000 Hz unless local-only**

### Scaling guidance

* Recommended per instance: **100–250 active peers**
* Scale via **sharding across multiple intentra instances**
* Routing handled at application layer

---

## Quick start

```rust
use intentra::transport::Transport;

fn main() -> std::io::Result<()> {
    let mut transport = Transport::bind("127.0.0.1:9000", false)?;
    transport.run(); // blocks
    Ok(())
}
```

---

## Security model (summary)

**In scope (mitigated):**

* Replay attacks
* ACK floods
* Handshake floods
* Malformed packets
* Protocol abuse

**Out of scope (external mitigation required):**

* Volumetric DDoS
* Compromised keys
* Application-layer attacks

Firewall + monitoring are required for production use.

---

## Versioning

* API is **unstable** in v0.x
* Breaking changes may occur before 1.0
* See `CHANGELOG.md` for details

---

## License

Licensed under either of:

* Apache 2.0
* MIT

At your option.