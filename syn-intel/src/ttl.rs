// SPDX-License-Identifier: GPL-2.0-only
//! TTL expiry engine — min-heap + scheduled-expiry hash table.
//!
//! Port of `src/ttl.c`.  Manages dynamic-block lifetimes: when the BPF
//! tracepoint fires a `NEW_BLOCK` event, the IP is scheduled for expiry
//! after `expire_ns`.  On each tick, expired entries are removed from the
//! BPF `drop_ips` map (unless still active).
//!
//! **Lazy-deletion invariant**: for each tracked IP, exactly one heap entry
//! has `expire_at == sched.get(ip)`.  All others are stale duplicates
//! silently skipped on pop.

use std::net::Ipv4Addr;

use log::{debug, info, warn};

use crate::bpf::BpfMaps;

/// Mirrors `MAX_ENTRIES_LRU` in the BPF program.
const MAX_ENTRIES_LRU: usize = 65536;

/// Heap capacity: 2× LRU size to accommodate lazy duplicates.
const HEAP_CAP: usize = MAX_ENTRIES_LRU * 2; // 131072

/// Sched hash table slots: power-of-2, load factor ≤ 0.5.
const SCHED_SLOTS: usize = MAX_ENTRIES_LRU * 2; // 131072

/// log2(SCHED_SLOTS) for Knuth multiplicative hash shift.
const SCHED_SHIFT: u32 = 17;

/// Tombstone marker in the sched table.
const SCHED_TOMBSTONE: u64 = u64::MAX;

// Compile-time check: SCHED_SLOTS must be a power of 2.
const _: () = assert!(SCHED_SLOTS.is_power_of_two());
const _: () = assert!(1 << SCHED_SHIFT == SCHED_SLOTS);

#[derive(Clone, Copy)]
struct HeapEntry {
    expire_at: u64,
    ip: u32,
}

#[derive(Clone, Copy)]
struct SchedEntry {
    expire_at: u64, // 0 = vacant, TOMBSTONE = deleted, else = occupied
    ip: u32,
}

/// Row returned from `expire()` for persistence.
pub struct ExpiredRow {
    pub ip: u32,
    pub count: u64,
    pub asn: String,
}

/// TTL state machine: min-heap + scheduled-expiry hash table.
pub struct TtlState {
    heap: Vec<HeapEntry>,
    sched: Vec<SchedEntry>,
    sched_tomb_count: usize,
    sched_live_count: usize,
    expire_ns: u64,
    active_blocks: u32,
    heap_drop_total: u64,
}

impl TtlState {
    /// Create a new TTL state with the given expiry duration in nanoseconds.
    pub fn new(expire_ns: u64) -> Self {
        Self {
            heap: Vec::with_capacity(HEAP_CAP),
            sched: vec![
                SchedEntry {
                    expire_at: 0,
                    ip: 0,
                };
                SCHED_SLOTS
            ],
            sched_tomb_count: 0,
            sched_live_count: 0,
            expire_ns,
            active_blocks: u32::default(),
            heap_drop_total: 0,
        }
    }

    pub fn expire_ns(&self) -> u64 {
        self.expire_ns
    }

    pub fn active_blocks(&self) -> u32 {
        self.active_blocks
    }

    pub fn heap_size(&self) -> usize {
        self.heap.len()
    }

    pub fn heap_drop_total(&self) -> u64 {
        self.heap_drop_total
    }

    /// Reconcile active-block counter with the actual map size.
    /// Called by autoban after iterating the full drop_ips map.
    pub fn set_active_blocks(&mut self, count: u32) {
        self.active_blocks = count;
    }

    /// Ensure an IP is tracked in the sched table and heap.
    /// Used by autoban to repair missed `NEW_BLOCK` events (ringbuf overflow).
    /// No-op if the IP is already scheduled.
    pub fn ensure_tracked(&mut self, ip_nbo: u32, expire_at: u64) {
        if self.sched_get(ip_nbo) != 0 {
            return; // Already tracked.
        }
        self.sched_upsert(ip_nbo, expire_at);
        self.heap_push(ip_nbo, expire_at);
    }

    /// Schedule an IP for expiry.  Called on `REASON_NEW_BLOCK` events.
    ///
    /// If the IP is not already tracked, increments `active_blocks`.
    /// Always upserts the sched table and pushes a (possibly duplicate)
    /// heap entry — stale duplicates are resolved lazily during `expire()`.
    pub fn schedule(&mut self, ip: u32, now_ns: u64) {
        let expire_at = now_ns + self.expire_ns;

        // Only count new IPs (not re-blocks after LRU eviction).
        if self.sched_get(ip) == 0 {
            self.active_blocks = self.active_blocks.saturating_add(1);
        }

        self.sched_upsert(ip, expire_at);
        self.heap_push(ip, expire_at);
    }

    /// Expire entries whose TTL has elapsed.
    ///
    /// Two-pass lazy deletion:
    /// 1. Pop heap entries where `expire_at <= now_ns`
    /// 2. Skip stale duplicates (sched mismatch)
    /// 3. Check BPF map `last_seen` — reschedule if still active
    /// 4. Delete from BPF map and collect for persistence
    pub fn expire(&mut self, maps: &BpfMaps, now_ns: u64) -> Vec<ExpiredRow> {
        if self.heap.is_empty() || self.heap[0].expire_at > now_ns {
            return Vec::new();
        }

        let mut rows = Vec::new();

        while !self.heap.is_empty() && self.heap[0].expire_at <= now_ns {
            let top = self.heap_pop();

            // Lazy-deletion guard: skip stale duplicate heap entries.
            if self.sched_get(top.ip) != top.expire_at {
                continue;
            }

            // Look up in BPF map to check recent activity.
            let info = match maps.lookup_drop_ip(top.ip) {
                Ok(Some(info)) => info,
                Ok(None) => {
                    // LRU evicted this IP — clean up bookkeeping.
                    self.sched_remove(top.ip);
                    self.active_blocks = self.active_blocks.saturating_sub(1);
                    continue;
                }
                Err(e) => {
                    debug!("lookup_drop_ip failed for {}: {e:#}", fmt_ip(top.ip));
                    continue;
                }
            };

            // Still active? Reschedule.
            if now_ns.saturating_sub(info.last_seen) <= self.expire_ns {
                let new_expire = info.last_seen + self.expire_ns;
                self.sched_upsert(top.ip, new_expire);
                self.heap_push(top.ip, new_expire);
                continue;
            }

            // Truly expired — remove from all structures.
            self.sched_remove(top.ip);
            self.active_blocks = self.active_blocks.saturating_sub(1);

            info!(
                "TTL Expired: Unblocking {} (Dropped {} packets)",
                fmt_ip(top.ip),
                info.count
            );

            if let Err(e) = maps.delete_drop_ip(top.ip) {
                warn!("delete_drop_ip failed for {}: {e:#}", fmt_ip(top.ip));
            }

            rows.push(ExpiredRow {
                ip: top.ip,
                count: info.count,
                asn: String::new(), // Caller resolves ASN from AsnTable.
            });
        }

        rows
    }

    // ── Heap operations ──────────────────────────────────────────────

    fn heap_push(&mut self, ip: u32, expire_at: u64) {
        if self.heap.len() >= HEAP_CAP {
            self.heap_drop_total += 1;
            return;
        }
        let idx = self.heap.len();
        self.heap.push(HeapEntry { expire_at, ip });
        self.sift_up(idx);
    }

    fn heap_pop(&mut self) -> HeapEntry {
        debug_assert!(!self.heap.is_empty());
        let top = self.heap[0];
        let last = self.heap.len() - 1;
        self.heap.swap(0, last);
        self.heap.pop();
        if !self.heap.is_empty() {
            self.sift_down(0);
        }
        top
    }

    fn sift_up(&mut self, mut i: usize) {
        while i > 0 {
            let p = (i - 1) / 2;
            if self.heap[p].expire_at <= self.heap[i].expire_at {
                break;
            }
            self.heap.swap(p, i);
            i = p;
        }
    }

    fn sift_down(&mut self, mut i: usize) {
        loop {
            let mut s = i;
            let l = 2 * i + 1;
            let r = 2 * i + 2;
            if l < self.heap.len() && self.heap[l].expire_at < self.heap[s].expire_at {
                s = l;
            }
            if r < self.heap.len() && self.heap[r].expire_at < self.heap[s].expire_at {
                s = r;
            }
            if s == i {
                break;
            }
            self.heap.swap(s, i);
            i = s;
        }
    }

    // ── Sched hash operations ────────────────────────────────────────

    /// Knuth multiplicative hash.
    fn sched_hash(ip: u32) -> usize {
        (ip.wrapping_mul(2_654_435_761) >> (32 - SCHED_SHIFT)) as usize
    }

    fn sched_upsert(&mut self, ip: u32, expire_at: u64) {
        let slot = Self::sched_hash(ip);
        let mut first_tomb: Option<usize> = None;

        for i in 0..SCHED_SLOTS {
            let idx = (slot + i) & (SCHED_SLOTS - 1);
            let ea = self.sched[idx].expire_at;

            if ea == 0 {
                // Vacant — insert here (or at earlier tombstone).
                let target = first_tomb.unwrap_or(idx);
                if first_tomb.is_some() {
                    self.sched_tomb_count -= 1;
                }
                self.sched[target] = SchedEntry { expire_at, ip };
                self.sched_live_count += 1;
                return;
            }
            if ea == SCHED_TOMBSTONE {
                if first_tomb.is_none() {
                    first_tomb = Some(idx);
                }
                continue;
            }
            if self.sched[idx].ip == ip {
                // Found existing — update timestamp.
                self.sched[idx].expire_at = expire_at;
                return;
            }
        }
        warn!("sched table full ({SCHED_SLOTS} slots)");
    }

    fn sched_get(&self, ip: u32) -> u64 {
        let slot = Self::sched_hash(ip);
        for i in 0..SCHED_SLOTS {
            let idx = (slot + i) & (SCHED_SLOTS - 1);
            let ea = self.sched[idx].expire_at;
            if ea == 0 {
                return 0; // Chain end.
            }
            if ea == SCHED_TOMBSTONE {
                continue;
            }
            if self.sched[idx].ip == ip {
                return ea;
            }
        }
        0
    }

    fn sched_remove(&mut self, ip: u32) {
        let slot = Self::sched_hash(ip);
        for i in 0..SCHED_SLOTS {
            let idx = (slot + i) & (SCHED_SLOTS - 1);
            let ea = self.sched[idx].expire_at;
            if ea == 0 {
                return; // Chain end.
            }
            if ea == SCHED_TOMBSTONE {
                continue;
            }
            if self.sched[idx].ip == ip {
                self.sched[idx].expire_at = SCHED_TOMBSTONE;
                self.sched_live_count -= 1;
                self.sched_tomb_count += 1;
                if self.sched_tomb_count > SCHED_SLOTS / 4 {
                    self.sched_compact();
                }
                return;
            }
        }
    }

    /// Rebuild the sched table, discarding tombstones.
    fn sched_compact(&mut self) {
        let old: Vec<SchedEntry> = self.sched.clone();
        for slot in &mut self.sched {
            *slot = SchedEntry {
                expire_at: 0,
                ip: 0,
            };
        }
        self.sched_tomb_count = 0;
        self.sched_live_count = 0;

        for entry in &old {
            if entry.expire_at != 0 && entry.expire_at != SCHED_TOMBSTONE {
                self.sched_upsert(entry.ip, entry.expire_at);
            }
        }
    }
}

fn fmt_ip(ip_nbo: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from_be(ip_nbo))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    fn make_ttl(expire_ns: u64) -> TtlState {
        TtlState::new(expire_ns)
    }

    // ── Heap tests ───────────────────────────────────────────────────

    #[test]
    fn test_heap_ordering() {
        let mut ttl = make_ttl(1000);
        ttl.heap_push(1, 300);
        ttl.heap_push(2, 100);
        ttl.heap_push(3, 200);

        assert_eq!(ttl.heap[0].expire_at, 100);
        let e = ttl.heap_pop();
        assert_eq!(e.ip, 2);
        assert_eq!(e.expire_at, 100);

        let e = ttl.heap_pop();
        assert_eq!(e.ip, 3);
        assert_eq!(e.expire_at, 200);

        let e = ttl.heap_pop();
        assert_eq!(e.ip, 1);
        assert_eq!(e.expire_at, 300);

        assert!(ttl.heap.is_empty());
    }

    #[test]
    fn test_heap_duplicate_timestamps() {
        let mut ttl = make_ttl(1000);
        ttl.heap_push(1, 100);
        ttl.heap_push(2, 100);
        ttl.heap_push(3, 100);

        assert_eq!(ttl.heap_size(), 3);
        // All should pop (order among ties is unspecified).
        ttl.heap_pop();
        ttl.heap_pop();
        ttl.heap_pop();
        assert!(ttl.heap.is_empty());
    }

    #[test]
    fn test_heap_overflow() {
        let mut ttl = make_ttl(1000);
        for i in 0..HEAP_CAP as u32 {
            ttl.heap_push(i, i as u64);
        }
        assert_eq!(ttl.heap_size(), HEAP_CAP);
        assert_eq!(ttl.heap_drop_total, 0);

        // One more should be dropped.
        ttl.heap_push(99999, 99999);
        assert_eq!(ttl.heap_size(), HEAP_CAP);
        assert_eq!(ttl.heap_drop_total, 1);
    }

    // ── Sched hash tests ────────────────────────────────────────────

    #[test]
    fn test_sched_basic_ops() {
        let mut ttl = make_ttl(1000);

        assert_eq!(ttl.sched_get(42), 0);

        ttl.sched_upsert(42, 500);
        assert_eq!(ttl.sched_get(42), 500);

        // Update existing.
        ttl.sched_upsert(42, 700);
        assert_eq!(ttl.sched_get(42), 700);

        ttl.sched_remove(42);
        assert_eq!(ttl.sched_get(42), 0);
    }

    #[test]
    fn test_sched_collision_chain() {
        let mut ttl = make_ttl(1000);
        // Insert IPs that might collide (same hash bucket).
        // Even if they don't collide, linear probing handles it.
        let ips: Vec<u32> = (1..=100).collect();
        for &ip in &ips {
            ttl.sched_upsert(ip, ip as u64 * 10);
        }
        for &ip in &ips {
            assert_eq!(ttl.sched_get(ip), ip as u64 * 10);
        }
        // Remove even IPs.
        for &ip in ips.iter().filter(|&&ip| ip % 2 == 0) {
            ttl.sched_remove(ip);
        }
        // Odd IPs still reachable.
        for &ip in ips.iter().filter(|&&ip| ip % 2 != 0) {
            assert_eq!(ttl.sched_get(ip), ip as u64 * 10);
        }
        // Even IPs gone.
        for &ip in ips.iter().filter(|&&ip| ip % 2 == 0) {
            assert_eq!(ttl.sched_get(ip), 0);
        }
    }

    #[test]
    fn test_sched_compaction() {
        let mut ttl = make_ttl(1000);
        // Insert many entries then remove them to trigger compaction.
        let count = SCHED_SLOTS / 4 + 10; // > 25% to trigger compact
        for i in 0..count as u32 {
            ttl.sched_upsert(i, (i + 1) as u64);
        }
        assert_eq!(ttl.sched_live_count, count);

        for i in 0..count as u32 {
            ttl.sched_remove(i);
        }
        // Compaction fires after SCHED_SLOTS/4+1 removals, re-inserting
        // the remaining 9 live entries.  Those 9 then get removed normally,
        // leaving 9 tombstones (below the 25% threshold).
        assert_eq!(ttl.sched_live_count, 0);
        assert_eq!(ttl.sched_tomb_count, 9);

        // All entries should be gone.
        for i in 0..count as u32 {
            assert_eq!(ttl.sched_get(i), 0);
        }
    }

    // ── Schedule (integrated) tests ─────────────────────────────────

    #[test]
    fn test_schedule_new_ip() {
        let mut ttl = make_ttl(1_000_000_000); // 1s in ns
        assert_eq!(ttl.active_blocks(), 0);

        ttl.schedule(0x0A000001u32.to_be(), 5_000_000_000);
        assert_eq!(ttl.active_blocks(), 1);
        assert_eq!(ttl.heap_size(), 1);

        // Same IP again — no double-count.
        ttl.schedule(0x0A000001u32.to_be(), 5_500_000_000);
        assert_eq!(ttl.active_blocks(), 1);
        assert_eq!(ttl.heap_size(), 2); // Lazy duplicate in heap.
    }

    #[test]
    fn test_schedule_multiple_ips() {
        let mut ttl = make_ttl(1_000_000_000);

        ttl.schedule(1u32.to_be(), 100);
        ttl.schedule(2u32.to_be(), 200);
        ttl.schedule(3u32.to_be(), 300);

        assert_eq!(ttl.active_blocks(), 3);
        assert_eq!(ttl.heap_size(), 3);
    }

    // ── Lazy deletion test ──────────────────────────────────────────

    #[test]
    fn test_lazy_deletion_skips_stale() {
        let mut ttl = make_ttl(1000);

        // Push two entries for same IP — second is authoritative.
        ttl.heap_push(42, 100);
        ttl.sched_upsert(42, 100);

        // Re-schedule with later expiry (simulates reschedule).
        ttl.heap_push(42, 200);
        ttl.sched_upsert(42, 200);

        // Pop first entry (expire_at=100) — should be stale.
        let first = ttl.heap_pop();
        assert_eq!(first.expire_at, 100);
        assert_ne!(ttl.sched_get(first.ip), first.expire_at);
        // ↑ This is the lazy-deletion guard: sched says 200, heap entry says 100.

        // Pop second entry (expire_at=200) — authoritative.
        let second = ttl.heap_pop();
        assert_eq!(second.expire_at, 200);
        assert_eq!(ttl.sched_get(second.ip), second.expire_at);
    }

    // ── Knuth hash distribution ─────────────────────────────────────

    #[test]
    fn test_sched_hash_range() {
        // All outputs should be within [0, SCHED_SLOTS).
        for ip in [0u32, 1, 0xFF_FF_FF_FF, 0x0A_00_00_01, 0xC0_A8_01_01] {
            let h = TtlState::sched_hash(ip);
            assert!(h < SCHED_SLOTS, "hash({ip}) = {h} out of range");
        }
    }

    // ── Heap edge cases ─────────────────────────────────────────────

    #[test]
    fn test_heap_pop_single() {
        let mut ttl = make_ttl(1000);
        ttl.heap_push(42, 500);
        assert_eq!(ttl.heap_size(), 1);

        let e = ttl.heap_pop();
        assert_eq!(e.ip, 42);
        assert_eq!(e.expire_at, 500);
        assert!(ttl.heap.is_empty());
    }

    #[test]
    fn test_heap_pop_all_in_order() {
        let mut ttl = make_ttl(1000);
        // Push 10 entries in reverse order.
        for i in (1..=10u32).rev() {
            ttl.heap_push(i, i as u64 * 100);
        }
        assert_eq!(ttl.heap_size(), 10);

        // Pop all — must come out in ascending expire_at order.
        let mut prev = 0u64;
        for _ in 0..10 {
            let e = ttl.heap_pop();
            assert!(e.expire_at > prev, "expected ascending order: got {} after {}", e.expire_at, prev);
            prev = e.expire_at;
        }
        assert!(ttl.heap.is_empty());
    }

    #[test]
    fn test_heap_sift_down_single_child() {
        let mut ttl = make_ttl(1000);
        // Push 2 entries: root has only a left child.
        ttl.heap_push(1, 200);
        ttl.heap_push(2, 100);
        assert_eq!(ttl.heap_size(), 2);

        // After sift-up, the smaller value should be at root.
        assert_eq!(ttl.heap[0].expire_at, 100);

        // Pop root — sift-down with only one child remaining.
        let e = ttl.heap_pop();
        assert_eq!(e.expire_at, 100);
        assert_eq!(ttl.heap_size(), 1);
        assert_eq!(ttl.heap[0].expire_at, 200);
    }

    // ── Sched edge cases ────────────────────────────────────────────

    #[test]
    fn test_sched_upsert_into_tombstone() {
        let mut ttl = make_ttl(1000);

        // Insert then remove — creates a tombstone.
        ttl.sched_upsert(42, 500);
        assert_eq!(ttl.sched_get(42), 500);
        ttl.sched_remove(42);
        assert_eq!(ttl.sched_get(42), 0);

        // New insert into the tombstone slot should succeed.
        ttl.sched_upsert(42, 700);
        assert_eq!(ttl.sched_get(42), 700);
    }

    #[test]
    fn test_sched_compact_preserves_all() {
        let mut ttl = make_ttl(1000);

        // Insert enough entries, then remove > 25% to trigger compaction.
        let total = SCHED_SLOTS / 4 + 100;
        for i in 0..total as u32 {
            ttl.sched_upsert(i + 1, (i + 1) as u64 * 10); // ip=0 is vacant sentinel
        }
        assert_eq!(ttl.sched_live_count, total);

        // Remove first SCHED_SLOTS/4 + 1 to trigger compaction.
        let remove_count = SCHED_SLOTS / 4 + 1;
        for i in 0..remove_count as u32 {
            ttl.sched_remove(i + 1);
        }

        // Verify remaining entries survived compaction.
        let surviving = total - remove_count;
        assert_eq!(ttl.sched_live_count, surviving);

        for i in remove_count..total {
            let ip = i as u32 + 1;
            assert_eq!(
                ttl.sched_get(ip),
                ip as u64 * 10,
                "entry ip={ip} lost after compaction"
            );
        }
    }

    // ── Integration edge cases ──────────────────────────────────────

    #[test]
    fn test_schedule_zero_expire_ns() {
        let mut ttl = make_ttl(0); // expire_ns = 0

        // With expire_ns=0, schedule should still work mechanically.
        // It inserts with expire_at = now_ns + 0 = now_ns.
        let now = 5_000_000_000u64;
        ttl.schedule(1u32.to_be(), now);

        // Entry is tracked (expire_at = now_ns + 0 = now_ns).
        assert_eq!(ttl.active_blocks(), 1);
        assert_eq!(ttl.heap_size(), 1);
    }

    #[test]
    fn test_set_active_blocks() {
        let mut ttl = make_ttl(1000);
        assert_eq!(ttl.active_blocks(), 0);

        // Manually schedule some IPs.
        ttl.schedule(1u32.to_be(), 100);
        ttl.schedule(2u32.to_be(), 200);
        assert_eq!(ttl.active_blocks(), 2);

        // Reconcile with actual map count (e.g., some were LRU-evicted).
        ttl.set_active_blocks(5);
        assert_eq!(ttl.active_blocks(), 5);

        // Set to 0 — all evicted.
        ttl.set_active_blocks(0);
        assert_eq!(ttl.active_blocks(), 0);
    }
}
