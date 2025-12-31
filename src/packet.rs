//! Packet format and serialization.

use crate::error::ProtocolError;
use crate::intent::Intent;

/// Header size in bytes.
pub const HEADER_LEN: usize = 16;
/// Protocol version.
pub const VERSION: u8 = 1;

/// Data packet flag.
pub const FLAG_DATA: u8 = 0x00;
/// Acknowledgment packet flag.
pub const FLAG_ACK: u8 = 0x01;
/// Handshake packet flag.
pub const FLAG_HS: u8 = 0x02;

/// Packet header structure.
///
/// Fixed 16-byte header containing version, flags, intent, sequence numbers,
/// connection ID, and acknowledgment state.
#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    /// Packet type flags (DATA, ACK, or HS)
    pub flags: u8,
    /// Delivery intent (Reliable or Realtime)
    pub intent: Intent,
    /// Priority hint (0-7)
    pub priority: u8,
    /// Payload length in bytes
    pub payload_len: u16,
    /// Connection identifier
    pub conn_id: u32,
    /// Sequence number for packet ordering
    pub seq: u32,
    /// Acknowledgment number for reliable delivery
    pub ack: u32,
}

impl PacketHeader {
    /// Encode header into a 16-byte buffer.
    pub fn encode(&self, buf: &mut [u8]) -> Result<(), ProtocolError> {
        if buf.len() < HEADER_LEN {
            return Err(ProtocolError::MalformedPacket);
        }

        self.validate()?;

        // Byte 0: version (upper nibble) + flags (lower nibble)
        // Version in upper nibble allows quick rejection of unknown versions
        // without parsing rest of packet; flags in lower nibble for compactness.
        buf[0] = (VERSION << 4) | (self.flags & 0x0F);

        // Byte 1: intent (bits 7-6) + priority (bits 5-3)
        buf[1] = ((self.intent as u8) << 6) | ((self.priority & 0x07) << 3);

        buf[2..4].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[4..8].copy_from_slice(&self.conn_id.to_be_bytes());
        buf[8..12].copy_from_slice(&self.seq.to_be_bytes());
        buf[12..16].copy_from_slice(&self.ack.to_be_bytes());

        Ok(())
    }

    /// Decode header from a buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < HEADER_LEN {
            return Err(ProtocolError::MalformedPacket);
        }

        let version = buf[0] >> 4;
        if version != VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }

        let flags = buf[0] & 0x0F;

        let intent = Intent::from_bits(buf[1] >> 6).ok_or(ProtocolError::InvalidIntent)?;

        let priority = (buf[1] >> 3) & 0x07;

        let header = Self {
            flags,
            intent,
            priority,
            payload_len: u16::from_be_bytes([buf[2], buf[3]]),
            conn_id: u32::from_be_bytes(buf[4..8].try_into().unwrap()),
            seq: u32::from_be_bytes(buf[8..12].try_into().unwrap()),
            ack: u32::from_be_bytes(buf[12..16].try_into().unwrap()),
        };

        header.validate()?;
        Ok(header)
    }

    // Flag-specific invariants: enforce protocol rules at packet boundaries.
    fn validate(&self) -> Result<(), ProtocolError> {
        match self.flags {
            FLAG_DATA => {
                // Data packets MUST have payload (0-byte data packets are meaningless noise)
                if self.payload_len == 0 {
                    return Err(ProtocolError::MalformedPacket);
                }
            }

            FLAG_ACK => {
                // ACK packets carry no payload (ack field carries receiver's seq state)
                if self.payload_len != 0 {
                    return Err(ProtocolError::MalformedPacket);
                }
                // ACKs are only for Reliable intent (Realtime packets don't need ACK)
                if self.intent != Intent::Reliable {
                    return Err(ProtocolError::MalformedPacket);
                }
            }

            FLAG_HS => {
                // Handshakes use Reliable for sequencing and retransmission guarantees
                if self.intent != Intent::Reliable {
                    return Err(ProtocolError::MalformedPacket);
                }
            }

            _ => return Err(ProtocolError::MalformedPacket),
        }

        Ok(())
    }
}
