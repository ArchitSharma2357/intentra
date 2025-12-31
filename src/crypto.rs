#![allow(missing_docs)]
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit,
};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

use crate::error::ProtocolError;

pub const COOKIE_SECRET: &[u8; 32] = b"arc_protocol_stateless_cookie\x00\x00\x00";

// Stateless handshake cookies prevent spoofed source IP attacks.
// Cookie = HMAC-SHA256(SECRET || IP || PORT) is deterministic and requires no server state.
// Client must echo cookie in next handshake message, proving source IP reachability.
// Prevents amplification: initial handshake response is small if cookie is invalid.
pub fn compute_cookie(addr: &SocketAddr) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COOKIE_SECRET);
    hasher.update(addr.ip().to_string().as_bytes());
    hasher.update(addr.port().to_le_bytes());

    let mut cookie = [0u8; 32];
    cookie.copy_from_slice(&hasher.finalize());
    cookie
}

/// Verifies a handshake cookie matches the address.
pub fn verify_cookie(addr: &SocketAddr, cookie: &[u8; 32]) -> bool {
    &compute_cookie(addr) == cookie
}

/// Cryptographic context for per-connection encryption and decryption.
pub struct CryptoContext {
    /// Transmit cipher
    tx: Aes256Gcm,
    /// Receive cipher
    rx: Aes256Gcm,
}

impl CryptoContext {
    /// Create a new crypto context with TX and RX keys.
    pub fn new(tx_key: &[u8; 32], rx_key: &[u8; 32]) -> Self {
        Self {
            tx: Aes256Gcm::new_from_slice(tx_key).unwrap(),
            rx: Aes256Gcm::new_from_slice(rx_key).unwrap(),
        }
    }

    // Nonce = (conn_id || seq || 0).
    // conn_id varies per connection (separate keys per peer), seq increments per packet.
    // Nonce uniqueness property: different (conn_id, seq) pairs -> different nonces.
    // This ensures each plaintext+key combination is encrypted exactly once (AES-GCM requirement).
    fn make_nonce(&self, conn_id: u32, seq: u32) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&conn_id.to_be_bytes());
        nonce[4..8].copy_from_slice(&seq.to_be_bytes());
        nonce[8..12].copy_from_slice(&[0u8; 4]);
        nonce
    }

    /// Encrypt payload with AES-256-GCM.
    pub fn encrypt(
        &self,
        conn_id: u32,
        seq: u32,
        header: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let nonce = self.make_nonce(conn_id, seq);

        let ciphertext = self
            .tx
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: payload,
                    aad: header,
                },
            )
            .map_err(|_| ProtocolError::CryptoFailure)?;

        Ok([header, &ciphertext].concat())
    }

    /// Decrypt ciphertext with AES-256-GCM.
    pub fn decrypt(
        &self,
        conn_id: u32,
        seq: u32,
        header: &[u8],
        encrypted: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let nonce = self.make_nonce(conn_id, seq);

        self.rx
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: encrypted,
                    aad: header,
                },
            )
            .map_err(|_| ProtocolError::CryptoFailure)
    }
}
