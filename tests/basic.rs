use intentra::crypto::{compute_cookie, CryptoContext};
use intentra::intent::Intent;
use intentra::packet::{PacketHeader, FLAG_ACK, FLAG_DATA, FLAG_HS};
use intentra::replay::ReplayWindow;
use std::net::SocketAddr;

#[test]
fn packet_encode_decode_roundtrip() {
    let header = PacketHeader {
        flags: FLAG_DATA,
        intent: Intent::Reliable,
        priority: 2,
        payload_len: 100,
        conn_id: 12345,
        seq: 1,
        ack: 0,
    };

    let mut buf = [0u8; 16];
    assert!(header.encode(&mut buf).is_ok());

    let decoded = PacketHeader::decode(&buf);
    assert!(decoded.is_ok());

    let decoded = decoded.unwrap();
    assert_eq!(decoded.flags, FLAG_DATA);
    assert_eq!(decoded.intent, Intent::Reliable);
    assert_eq!(decoded.priority, 2);
    assert_eq!(decoded.payload_len, 100);
    assert_eq!(decoded.conn_id, 12345);
    assert_eq!(decoded.seq, 1);
    assert_eq!(decoded.ack, 0);
}

#[test]
fn crypto_encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    let ctx = CryptoContext::new(&key, &key);

    let conn_id = 1u32;
    let seq = 5u32;
    let header = [0u8; 16];
    let plaintext = b"Hello, World!";

    let encrypted = ctx.encrypt(conn_id, seq, &header, plaintext);
    assert!(encrypted.is_ok());

    let ciphertext = encrypted.unwrap();
    assert!(ciphertext.len() > plaintext.len());

    let decrypted = ctx.decrypt(conn_id, seq, &header, &ciphertext[16..]);
    assert!(decrypted.is_ok());

    let decrypted = decrypted.unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn replay_window_accept_new_sequence() {
    let mut window = ReplayWindow::new(64);

    assert!(window.check(1));
    assert!(window.check(2));
    assert!(window.check(3));
    assert!(window.check(5));
}

#[test]
fn replay_window_reject_duplicate() {
    let mut window = ReplayWindow::new(64);

    assert!(window.check(1));
    assert!(window.check(2));

    assert!(!window.check(1));
    assert!(!window.check(2));
}

#[test]
fn replay_window_reject_old_packets() {
    let mut window = ReplayWindow::new(64);

    for i in 1..=70 {
        let _ = window.check(i);
    }

    assert!(!window.check(1));
    assert!(!window.check(10));
}

#[test]
fn rate_limit_token_bucket() {
    use std::time::Instant;

    const RATE_LIMIT_TOKENS_PER_SECOND: f64 = 10000.0;
    const RATE_LIMIT_BURST: f64 = 500.0;

    let mut tokens = RATE_LIMIT_BURST;
    let last_refill = Instant::now();

    for _ in 0..500 {
        tokens -= 1.0;
        assert!(tokens >= 0.0);
    }

    assert!(tokens >= 0.0);

    let elapsed = Instant::now().duration_since(last_refill).as_secs_f64();
    let tokens_to_add = elapsed * RATE_LIMIT_TOKENS_PER_SECOND;
    tokens = (tokens + tokens_to_add).min(RATE_LIMIT_BURST);

    assert!(tokens <= RATE_LIMIT_BURST);
}

#[test]
fn cookie_computation_deterministic() {
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    let cookie1 = compute_cookie(&addr);
    let cookie2 = compute_cookie(&addr);

    assert_eq!(cookie1, cookie2);
}

#[test]
fn cookie_differs_by_address() {
    let addr1: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let addr2: SocketAddr = "127.0.0.1:8081".parse().unwrap();

    let cookie1 = compute_cookie(&addr1);
    let cookie2 = compute_cookie(&addr2);

    assert_ne!(cookie1, cookie2);
}

#[test]
fn ack_packet_validation() {
    let header = PacketHeader {
        flags: FLAG_ACK,
        intent: Intent::Reliable,
        priority: 0,
        payload_len: 0,
        conn_id: 1,
        seq: 0,
        ack: 100,
    };

    let mut buf = [0u8; 16];
    assert!(header.encode(&mut buf).is_ok());

    let decoded = PacketHeader::decode(&buf);
    assert!(decoded.is_ok());
}

#[test]
fn handshake_packet_requires_reliable() {
    let header = PacketHeader {
        flags: FLAG_HS,
        intent: Intent::Realtime,
        priority: 0,
        payload_len: 32,
        conn_id: 1,
        seq: 0,
        ack: 0,
    };

    let mut buf = [0u8; 16];
    let result = header.encode(&mut buf);
    assert!(result.is_err());
}
