#![doc = include_str!("../README.md")]
#![deny(unsafe_code, missing_docs)]

pub mod connection;
pub mod crypto;
pub mod error;
pub mod handshake;
pub mod intent;
pub mod packet;
pub mod receiver;
pub mod replay;
pub mod transport;

#[cfg(test)]
mod tests {
    use crate::crypto::CryptoContext;
    use crate::intent::Intent;
    use crate::packet::PacketHeader;
    use crate::receiver::Receiver;
    use crate::replay::ReplayWindow;

    #[test]
    fn test_packet_header_encode_decode() {
        let header = PacketHeader {
            flags: 0x00,
            intent: Intent::Reliable,
            priority: 3,
            payload_len: 100,
            conn_id: 12345,
            seq: 1,
            ack: 0,
        };

        let mut buf = [0u8; 16];
        header.encode(&mut buf).expect("failed to encode header");

        let decoded = PacketHeader::decode(&buf).expect("failed to decode header");
        assert_eq!(decoded.conn_id, 12345);
        assert_eq!(decoded.seq, 1);
    }

    #[test]
    fn test_crypto_context() {
        let tx_key = [0u8; 32];
        let rx_key = [1u8; 32];

        let _context = CryptoContext::new(&tx_key, &rx_key);
        // Context created successfully
    }

    #[test]
    fn test_replay_window() {
        let mut replay = ReplayWindow::new(32);

        assert!(replay.check(1));
        assert!(!replay.check(1)); // duplicate
        assert!(replay.check(2));
        assert!(replay.check(3));
    }

    #[test]
    fn test_receiver_buffering() {
        let mut receiver = Receiver::new();

        // Out-of-order packets should be accepted
        assert!(receiver.accept(2));
        assert!(receiver.accept(1));

        // Duplicate should be rejected
        assert!(!receiver.accept(1));
    }
}
