// SPDX-License-Identifier: GPL-2.0-only
//! Ringbuf event parsing and intel aggregation.
//!
//! Events arrive from the BPF ringbuffer with three reason codes:
//! - `NEW_BLOCK` (100% rate): new IP inserted into `drop_ips` by tracepoint
//! - `BLACKLIST` / `DYNAMIC` (rate-limited): XDP drops for forensics aggregation

use std::collections::HashMap;

/// BPF ringbuf event — must match `struct event` in `tcp_syn_stop.bpf.c`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Event {
    pub src_ip: u32,
    pub dest_port: u16,
    pub reason: u8,
}

const _: () = assert!(std::mem::size_of::<Event>() == 7);

// Mirror the REASON_* constants from tcp_syn_stop.bpf.c.
// Only REASON_NEW_BLOCK is currently matched in the ringbuf consumer;
// the others are retained so the Rust enum stays in sync with the BPF header.
#[allow(dead_code)]
pub const REASON_BLACKLIST: u8 = 1;
#[allow(dead_code)]
pub const REASON_DYNAMIC: u8 = 2;
pub const REASON_NEW_BLOCK: u8 = 3;

/// Aggregated sampled-drop intel for periodic persistence.
///
/// Keyed by `(ip, port)`, capped at 2048 entries to bound memory.
/// Drained periodically for flush to SQLite.
pub struct IntelState {
    map: HashMap<(u32, u16), u32>,
}

const INTEL_CAP: usize = 2048;

impl IntelState {
    pub fn new() -> Self {
        Self {
            map: HashMap::with_capacity(256),
        }
    }

    /// Record a sampled drop event.  Silently drops if at capacity.
    pub fn add(&mut self, ip: u32, port: u16) {
        if self.map.len() >= INTEL_CAP && !self.map.contains_key(&(ip, port)) {
            return;
        }
        *self.map.entry((ip, port)).or_insert(0) += 1;
    }

    /// Drain all accumulated intel for flush.
    pub fn drain(&mut self) -> HashMap<(u32, u16), u32> {
        std::mem::take(&mut self.map)
    }

    /// Defined for API completeness; not currently called.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.map.len()
    }
}

/// Parse a raw ringbuf event from `data`.
pub fn parse_event(data: &[u8]) -> Option<Event> {
    if data.len() < std::mem::size_of::<Event>() {
        return None;
    }
    // SAFETY: Event is repr(C, packed) with no padding, size checked above.
    Some(unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<Event>()) })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_event_valid() {
        let mut buf = [0u8; 7];
        let ip: u32 = 0x0A000001u32.to_be();
        buf[0..4].copy_from_slice(&ip.to_ne_bytes());
        buf[4..6].copy_from_slice(&80u16.to_ne_bytes());
        buf[6] = REASON_NEW_BLOCK;

        let e = parse_event(&buf).unwrap();
        // Copy fields out of packed struct before comparing (E0793).
        let (src, port, reason) = (e.src_ip, e.dest_port, e.reason);
        assert_eq!(src, ip);
        assert_eq!(port, 80);
        assert_eq!(reason, REASON_NEW_BLOCK);
    }

    #[test]
    fn test_parse_event_too_short() {
        assert!(parse_event(&[0u8; 6]).is_none());
    }

    #[test]
    fn test_intel_add_and_drain() {
        let mut intel = IntelState::new();
        intel.add(1, 80);
        intel.add(1, 80);
        intel.add(2, 443);

        let drained = intel.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[&(1, 80)], 2);
        assert_eq!(drained[&(2, 443)], 1);
        assert_eq!(intel.len(), 0);
    }

    #[test]
    fn test_intel_cap() {
        let mut intel = IntelState::new();
        for i in 0..INTEL_CAP as u32 {
            intel.add(i, 80);
        }
        assert_eq!(intel.len(), INTEL_CAP);
        // New key rejected at cap
        intel.add(99999, 80);
        assert_eq!(intel.len(), INTEL_CAP);
        // Existing key still accepted
        intel.add(0, 80);
        assert_eq!(intel.len(), INTEL_CAP);
    }
}
