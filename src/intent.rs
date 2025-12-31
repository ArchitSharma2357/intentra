//! Intent field indicating delivery semantics.

/// Delivery semantics for a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intent {
    /// Realtime: immediate delivery, no ordering guarantee
    Realtime = 0,
    /// Reliable: in-order delivery with reordering buffer
    Reliable = 1,
}

impl Intent {
    /// Create Intent from numeric bits.
    pub fn from_bits(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Realtime),
            1 => Some(Self::Reliable),
            _ => None,
        }
    }
}
