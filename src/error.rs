//! Error types for the intentra protocol.

use thiserror::Error;

/// Protocol-level errors that can occur during packet processing.
#[derive(Error, Debug)]
pub enum ProtocolError {
    /// Packet format is invalid or corrupted
    #[error("malformed packet")]
    MalformedPacket,
    /// Packet uses unsupported protocol version
    #[error("unsupported version")]
    UnsupportedVersion,
    /// Intent field contains invalid value
    #[error("invalid intent")]
    InvalidIntent,
    /// Cryptographic validation failed (authentication or decryption)
    #[error("crypto failure")]
    CryptoFailure,
    /// Protocol state machine violation
    #[error("protocol violation")]
    ProtocolViolation,
}

/// Reason for closing a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Authentication or cryptographic validation failed
    AuthFail,
    /// Peer violated protocol rules (e.g., too many strikes)
    ProtocolViolation,
    /// Connection idle timeout exceeded
    Timeout,
    /// Peer closed the connection gracefully
    PeerClosed,
}
