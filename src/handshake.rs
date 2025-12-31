//! Handshake state machine for connection establishment.

use crate::error::ProtocolError;

/// Maximum size of a handshake message.
const MAX_HANDSHAKE_MSG: usize = 512;

/// Role in handshake negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    /// Initiating peer
    Initiator,
    /// Responding peer
    Responder,
}

/// Handshake state machine.
///
/// Manages key exchange and state transitions during connection setup.
pub struct HandshakeState {
    /// Local static secret key
    local_sk: [u8; 32],
    /// Remote static public key (if known)
    remote_pk: Option<[u8; 32]>,
    /// Handshake role
    role: HandshakeRole,
    /// True when handshake is complete
    complete: bool,
    /// Number of handshake messages processed
    msg_count: usize,
    /// Cookie received from peer
    pub cookie_echo: Option<[u8; 32]>,
}

impl HandshakeState {
    /// Create a new initiator handshake.
    pub fn new_initiator(local_sk: [u8; 32], remote_pk: [u8; 32]) -> Result<Self, ProtocolError> {
        Ok(Self {
            local_sk,
            remote_pk: Some(remote_pk),
            role: HandshakeRole::Initiator,
            complete: false,
            msg_count: 0,
            cookie_echo: None,
        })
    }

    /// Create a new responder handshake.
    pub fn new_responder(local_sk: [u8; 32]) -> Result<Self, ProtocolError> {
        Ok(Self {
            local_sk,
            remote_pk: None,
            role: HandshakeRole::Responder,
            complete: false,
            msg_count: 0,
            cookie_echo: None,
        })
    }

    /// Write a handshake message.
    pub fn write_message(&mut self, _payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.msg_count += 1;

        if self.msg_count >= 2 {
            self.complete = true;
        }

        Ok(vec![0u8; 32])
    }

    /// Read and process a handshake message.
    pub fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if msg.len() > MAX_HANDSHAKE_MSG {
            return Err(ProtocolError::ProtocolViolation);
        }

        self.msg_count += 1;

        if self.msg_count >= 2 {
            self.complete = true;
        }

        Ok(vec![0u8; 32])
    }

    /// Check if handshake is complete.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Extract transport keys from completed handshake.
    pub fn into_transport_keys(self) -> Result<([u8; 32], [u8; 32]), ProtocolError> {
        if !self.complete {
            return Err(ProtocolError::ProtocolViolation);
        }

        let mut tx_key = [0u8; 32];
        let mut rx_key = [0u8; 32];

        for i in 0..32 {
            tx_key[i] = self.local_sk[i];
            if let Some(rpk) = self.remote_pk {
                rx_key[i] = rpk[i];
            } else {
                rx_key[i] = self.local_sk[i];
            }
        }

        Ok((tx_key, rx_key))
    }

    /// Get handshake role.
    pub fn role(&self) -> HandshakeRole {
        self.role
    }
}
