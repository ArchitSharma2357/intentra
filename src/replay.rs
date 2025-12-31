//! Replay attack detection using sliding window.

/// 64-bit sliding window for replay detection.
///
/// Accepts each sequence number exactly once. Detects and rejects:
/// - Duplicate packets (same sequence number)
/// - Packets older than the window
///
/// Handles sequence number wraparound using the property that forward jumps
/// appear as large backward jumps in unsigned arithmetic.
pub struct ReplayWindow {
    /// Maximum sequence number seen so far
    max_seq: Option<u32>,
    /// Window size
    window: u32,
    /// Bit map of recent sequence numbers
    bitmap: u64,
}

impl ReplayWindow {
    /// Create a new replay window with specified size (max 64).
    pub fn new(window: u32) -> Self {
        Self {
            max_seq: None,
            window: std::cmp::min(window, 64),
            bitmap: 0,
        }
    }

    /// Check if sequence number is valid (not seen before, not too old).
    pub fn check(&mut self, seq: u32) -> bool {
        if self.max_seq.is_none() {
            self.max_seq = Some(seq);
            self.bitmap = 1;
            return true;
        }

        let max = self.max_seq.unwrap();

        let is_ahead = if seq > max {
            true
        } else if seq == max {
            false
        } else {
            (max as u64) - (seq as u64) > (1u64 << 31)
        };

        if is_ahead && seq != max {
            let forward_dist = if seq > max {
                seq.wrapping_sub(max)
            } else {
                seq.wrapping_add(1)
            };

            if forward_dist >= 64 {
                self.bitmap = 0;
            } else {
                self.bitmap <<= forward_dist;
            }
            self.max_seq = Some(seq);
            self.bitmap |= 1;
            return true;
        }

        if seq == max {
            return (self.bitmap & 1) == 0;
        }

        let backward_dist = max.wrapping_sub(seq);

        if backward_dist > self.window {
            return false;
        }

        if backward_dist >= 64 {
            return true;
        }

        let bit = 1u64 << backward_dist;
        if (self.bitmap & bit) != 0 {
            return false;
        }

        self.bitmap |= bit;
        true
    }
}
