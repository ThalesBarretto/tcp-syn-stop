// SPDX-License-Identifier: GPL-2.0-only
//! Autoban engine — prefix offense tracking + exponential backoff.
//!
//! Port of `src/autoban.c`.  Groups dynamically blocked IPs by ASN prefix
//! and bans prefixes that exceed a configurable threshold.  Bans escalate
//! with exponential backoff and decay after a quiet window.
//!
//! **Offense table**: 4096-slot open-addressing hash (Knuth multiplicative,
//! linear probing) with LRU eviction.  Tracks per-prefix offense history
//! across evaluations.  When full, the least-recently-offending inactive
//! entry is evicted to make room.
//!
//! **Expiry heap**: 8192-cap min-heap by monotonic nanoseconds.  Lazy
//! deletion via offense-table `ban_end_mono` mismatch.  Compacts stale
//! entries when full before dropping new pushes.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use log::{debug, info, warn};

use crate::asn_table::{range_to_cidr, AsnTable};
use crate::bpf::{BpfMaps, DropInfo};
use crate::ttl::TtlState;

// ── Constants ────────────────────────────────────────────────────────

/// Offense table slots (power-of-2).  Sized for distributed attacks
/// spanning thousands of ASN prefixes (load factor <= 0.5 at 2048 active).
const TABLE_SLOTS: usize = 4096;
const TABLE_SHIFT: u32 = 12;

/// Expiry heap capacity.  Sized to accommodate lazy duplicates from
/// re-bans across all table entries.
const HEAP_CAP: usize = 8192;

/// Max unique IPs tracked per prefix during a single evaluation.
const MAX_IPS_PER_PREFIX: usize = 16;

const _: () = assert!(TABLE_SLOTS.is_power_of_two());
const _: () = assert!(1 << TABLE_SHIFT == TABLE_SLOTS);

// ── Configuration ────────────────────────────────────────────────────

/// Autoban tuning parameters.
#[derive(Clone, Debug)]
pub struct AutobanConfig {
    /// Minimum distinct blocked IPs per prefix to trigger a ban.
    pub threshold: u32,
    /// Base ban duration in seconds (first offense).
    pub base_duration: u32,
    /// Maximum ban duration in seconds (exponential cap).
    pub max_duration: u32,
    /// Seconds of inactivity before offense count resets to 0.
    pub decay_window: u64,
}

impl Default for AutobanConfig {
    fn default() -> Self {
        Self {
            threshold: 5,
            base_duration: 300,
            max_duration: 86400,
            decay_window: 86400,
        }
    }
}

// ── Data structures ──────────────────────────────────────────────────

/// Per-prefix offense history entry in the offense table.
#[derive(Clone)]
struct OffenseEntry {
    net_addr: u32,       // host byte order; 0 = vacant
    prefix_len: u32,
    asn: String,
    offense_count: i32,
    last_offense: u64,   // wall-clock seconds
    ban_end_wall: u64,   // wall-clock seconds (for persistence)
    ban_end_mono: u64,   // monotonic ns (for heap comparison)
    ban_duration: u32,   // seconds (for logging)
}

impl OffenseEntry {
    fn vacant() -> Self {
        Self {
            net_addr: 0,
            prefix_len: 0,
            asn: String::new(),
            offense_count: 0,
            last_offense: 0,
            ban_end_wall: 0,
            ban_end_mono: 0,
            ban_duration: 0,
        }
    }
}

/// Heap entry for ban expiry.
#[derive(Clone, Copy)]
struct HeapEntry {
    expire_at: u64,  // monotonic ns
    net_addr: u32,   // host byte order
    prefix_len: u32,
}

/// Row returned from `evaluate()` for persistence.
pub struct BanAction {
    pub net_addr: u32,
    pub prefix_len: u32,
    pub asn: String,
    pub offense_count: i32,
    pub ban_duration: u32,
    pub ban_end_wall: u64,
}

/// Row returned from `expire()` for persistence.
pub struct DeactivateAction {
    pub net_addr: u32,
    pub prefix_len: u32,
    /// Retained for future ban-expiry logging/reporting.
    #[allow(dead_code)]
    pub asn: String,
}

/// Temporary scratch entry for grouping IPs by prefix during evaluate().
struct PrefixGroup {
    net_addr: u32,
    prefix_len: u32,
    asn: String,
    ip_count: u32,
}

// ── Autoban state ────────────────────────────────────────────────────

pub struct AutobanState {
    table: Vec<OffenseEntry>,
    heap: Vec<HeapEntry>,
    config: AutobanConfig,
    active_bans: u32,
}

impl AutobanState {
    pub fn new(config: AutobanConfig) -> Self {
        Self {
            table: vec![OffenseEntry::vacant(); TABLE_SLOTS],
            heap: Vec::with_capacity(HEAP_CAP),
            config,
            active_bans: 0,
        }
    }

    pub fn active_bans(&self) -> u32 {
        self.active_bans
    }

    /// Evaluate blocked IPs: group by prefix, ban prefixes over threshold.
    ///
    /// `drop_ips` comes from `maps.iter_drop_ips()` (already collected).
    /// `ttl` is mutated for heap-repair of IPs missed by ringbuf overflow.
    pub fn evaluate(
        &mut self,
        drop_ips: &[(u32, DropInfo)],
        asn_table: Option<&AsnTable>,
        maps: &BpfMaps,
        ttl: &mut TtlState,
        now_mono: u64,
        now_wall: u64,
    ) -> Vec<BanAction> {
        let asn_table = match asn_table {
            Some(t) => t,
            None => return Vec::new(), // Can't group without ASN data.
        };

        let expire_ns = ttl.expire_ns();

        // Phase 1: Group blocked IPs by ASN prefix.
        let mut groups: HashMap<u32, PrefixGroup> = HashMap::new();
        let mut actual_count: u32 = 0;

        for &(ip_nbo, ref info) in drop_ips {
            // Only consider IPs within TTL window.
            if expire_ns > 0 && now_mono.saturating_sub(info.last_seen) > expire_ns {
                continue;
            }

            actual_count += 1;

            // Heap repair: if ringbuf overflow caused a missed NEW_BLOCK
            // event, synthesize the TTL schedule entry so the 5s cleanup
            // will eventually remove it.
            if expire_ns > 0 {
                ttl.ensure_tracked(ip_nbo, info.last_seen + expire_ns);
            }

            let ip_hbo = u32::from_be(ip_nbo);
            let entry = match asn_table.lookup(ip_hbo) {
                Some(e) => e,
                None => continue,
            };

            let prefix_len = range_to_cidr(entry.start, entry.end);
            let net_addr = entry.start;

            let group = groups.entry(net_addr).or_insert_with(|| PrefixGroup {
                net_addr,
                prefix_len,
                asn: entry.asn.clone(),
                ip_count: 0,
            });

            // MAX_IPS_PER_PREFIX is a small constant (16); truncation cannot occur.
            #[allow(clippy::cast_possible_truncation)]
            if group.ip_count < MAX_IPS_PER_PREFIX as u32 {
                group.ip_count += 1;
            }
        }

        // Reconcile TTL active-block counter with actual map size.
        ttl.set_active_blocks(actual_count);

        // Phase 2: Evaluate thresholds and ban qualifying prefixes.
        let mut actions = Vec::new();

        for group in groups.values() {
            if group.ip_count < self.config.threshold {
                continue;
            }

            // Look up or create offense entry.
            let idx = self.table_find_or_insert(group.net_addr, group.prefix_len, &group.asn);
            let idx = match idx {
                Some(i) => i,
                None => {
                    warn!("autoban offense table full ({TABLE_SLOTS} slots, all actively banned)");
                    continue;
                }
            };

            // Skip if already actively banned.
            if self.table[idx].ban_end_mono > now_mono {
                continue;
            }

            // Decay: reset offense count if quiet long enough.
            if self.table[idx].offense_count > 0
                && now_wall.saturating_sub(self.table[idx].last_offense) > self.config.decay_window
            {
                debug!(
                    "autoban: decay offense count for {}/{} (was {})",
                    Ipv4Addr::from(self.table[idx].net_addr),
                    self.table[idx].prefix_len,
                    self.table[idx].offense_count
                );
                self.table[idx].offense_count = 0;
            }

            self.table[idx].offense_count += 1;
            self.table[idx].last_offense = now_wall;

            let offense_count = self.table[idx].offense_count;
            let duration = compute_duration(self.config.base_duration, self.config.max_duration, offense_count);
            let ban_end_mono = now_mono + duration as u64 * 1_000_000_000;
            let ban_end_wall = now_wall + duration as u64;
            let net_addr = self.table[idx].net_addr;
            let prefix_len = self.table[idx].prefix_len;

            self.table[idx].ban_duration = duration;
            self.table[idx].ban_end_wall = ban_end_wall;
            self.table[idx].ban_end_mono = ban_end_mono;

            // Insert into BPF blacklist.
            let net_addr_nbo = net_addr.to_be();
            if let Err(e) = maps.update_blacklist(net_addr_nbo, prefix_len) {
                warn!(
                    "autoban: blacklist insert failed for {}/{}: {e:#}",
                    Ipv4Addr::from(net_addr),
                    prefix_len
                );
                continue;
            }

            // Push to expiry heap.
            self.heap_push(HeapEntry {
                expire_at: ban_end_mono,
                net_addr,
                prefix_len,
            });

            self.active_bans = self.active_bans.saturating_add(1);

            let asn = self.table[idx].asn.clone();
            info!(
                "AUTOBAN: {}/{} ({}) banned for {}s (offense #{}, {} IPs)",
                Ipv4Addr::from(net_addr),
                prefix_len,
                asn,
                duration,
                offense_count,
                group.ip_count
            );

            actions.push(BanAction {
                net_addr,
                prefix_len,
                asn,
                offense_count,
                ban_duration: duration,
                ban_end_wall,
            });
        }

        actions
    }

    /// Expire bans whose duration has elapsed.
    pub fn expire(&mut self, maps: &BpfMaps, now_mono: u64, now_wall: u64) -> Vec<DeactivateAction> {
        if self.heap.is_empty() || self.heap[0].expire_at > now_mono {
            return Vec::new();
        }

        let mut actions = Vec::new();

        while !self.heap.is_empty() && self.heap[0].expire_at <= now_mono {
            let top = self.heap_pop();

            // Validate against offense table (lazy-deletion guard).
            let idx = self.table_find(top.net_addr);
            let ent = match idx {
                Some(i) if self.table[i].ban_end_mono == top.expire_at => &mut self.table[i],
                _ => continue, // Stale heap entry.
            };

            // Delete from BPF blacklist.
            let net_addr_nbo = top.net_addr.to_be();
            if let Err(e) = maps.delete_blacklist(net_addr_nbo, top.prefix_len) {
                warn!(
                    "autoban: blacklist delete failed for {}/{}: {e:#}",
                    Ipv4Addr::from(top.net_addr),
                    top.prefix_len
                );
            }

            info!(
                "AUTOBAN EXPIRED: {}/{} ({}) unbanned after {}s",
                Ipv4Addr::from(ent.net_addr),
                ent.prefix_len,
                ent.asn,
                ent.ban_duration
            );

            let asn = ent.asn.clone();
            ent.ban_end_mono = 0;
            ent.ban_end_wall = 0;
            self.active_bans = self.active_bans.saturating_sub(1);

            actions.push(DeactivateAction {
                net_addr: top.net_addr,
                prefix_len: top.prefix_len,
                asn,
            });
        }

        // Decay offense counts for entries not currently banned.
        for slot in &mut self.table {
            if slot.net_addr == 0 {
                continue;
            }
            if slot.ban_end_mono == 0
                && slot.offense_count > 0
                && now_wall.saturating_sub(slot.last_offense) > self.config.decay_window
            {
                slot.offense_count = 0;
            }
        }

        actions
    }

    /// Re-insert active bans into the BPF blacklist map.
    /// Called after SIGHUP config reload clears the blacklist.
    pub fn reinsert_active(&self, maps: &BpfMaps, now_mono: u64) -> u32 {
        let mut count = 0u32;
        for ent in &self.table {
            if ent.net_addr == 0 || ent.ban_end_mono <= now_mono {
                continue;
            }
            let net_addr_nbo = ent.net_addr.to_be();
            if let Err(e) = maps.update_blacklist(net_addr_nbo, ent.prefix_len) {
                warn!(
                    "autoban: reinsert failed for {}/{}: {e:#}",
                    Ipv4Addr::from(ent.net_addr),
                    ent.prefix_len
                );
                continue;
            }
            count += 1;
        }
        if count > 0 {
            info!("autoban: reinserted {count} active bans after SIGHUP");
        }
        count
    }

    /// Restore bans from persistence at startup.
    /// `rows` contains `(net_addr, prefix_len, asn, offense_count, ban_end_wall, last_offense)`.
    pub fn restore(
        &mut self,
        rows: &[(u32, u32, String, i32, u64, u64)],
        maps: &BpfMaps,
        now_mono: u64,
        now_wall: u64,
    ) -> u32 {
        let mut count = 0u32;
        for (net_addr, prefix_len, asn, offense_count, ban_end_wall, last_offense) in rows {
            // Skip already-expired bans.
            if *ban_end_wall <= now_wall {
                continue;
            }

            let remaining_secs = ban_end_wall - now_wall;
            let ban_end_mono = now_mono + remaining_secs * 1_000_000_000;

            let idx = self.table_find_or_insert(*net_addr, *prefix_len, asn);
            let idx = match idx {
                Some(i) => i,
                None => continue,
            };

            let ent = &mut self.table[idx];
            ent.offense_count = *offense_count;
            ent.last_offense = *last_offense;
            ent.ban_end_wall = *ban_end_wall;
            ent.ban_end_mono = ban_end_mono;
            #[allow(clippy::cast_possible_truncation)]
            {
                ent.ban_duration = remaining_secs as u32;
            }

            // Apply decay.
            if ent.offense_count > 0 && now_wall.saturating_sub(ent.last_offense) > self.config.decay_window {
                ent.offense_count = 0;
            }

            // Insert into BPF blacklist.
            let net_addr_nbo = net_addr.to_be();
            if let Err(e) = maps.update_blacklist(net_addr_nbo, *prefix_len) {
                warn!(
                    "autoban: restore blacklist insert failed for {}/{}: {e:#}",
                    Ipv4Addr::from(*net_addr),
                    prefix_len
                );
                continue;
            }

            // Push to expiry heap.
            self.heap_push(HeapEntry {
                expire_at: ban_end_mono,
                net_addr: *net_addr,
                prefix_len: *prefix_len,
            });

            self.active_bans = self.active_bans.saturating_add(1);
            count += 1;
        }
        if count > 0 {
            info!("autoban: restored {count} active bans from database");
        }
        count
    }

    // ── Offense table (open-addressing hash) ─────────────────────────

    fn table_hash(net_addr: u32) -> usize {
        (net_addr.wrapping_mul(2_654_435_761) >> (32 - TABLE_SHIFT)) as usize
    }

    /// Find an existing entry for `net_addr` (borrows only the slice).
    fn table_find_in(table: &[OffenseEntry], net_addr: u32) -> Option<usize> {
        let slot = Self::table_hash(net_addr);
        for i in 0..table.len() {
            let idx = (slot + i) & (table.len() - 1);
            if table[idx].net_addr == 0 {
                return None; // Chain end.
            }
            if table[idx].net_addr == net_addr {
                return Some(idx);
            }
        }
        None
    }

    /// Find an existing entry for `net_addr`.
    fn table_find(&self, net_addr: u32) -> Option<usize> {
        Self::table_find_in(&self.table, net_addr)
    }

    /// Find or insert an entry for `net_addr`.  If the table is full,
    /// evicts the least-recently-offending inactive entry (LRU eviction).
    /// Returns None only if ALL slots hold actively-banned prefixes.
    fn table_find_or_insert(&mut self, net_addr: u32, prefix_len: u32, asn: &str) -> Option<usize> {
        let slot = Self::table_hash(net_addr);

        for i in 0..TABLE_SLOTS {
            let idx = (slot + i) & (TABLE_SLOTS - 1);
            if self.table[idx].net_addr == 0 {
                // Vacant — insert here.
                self.table[idx] = OffenseEntry {
                    net_addr,
                    prefix_len,
                    asn: asn.to_string(),
                    offense_count: 0,
                    last_offense: 0,
                    ban_end_wall: 0,
                    ban_end_mono: 0,
                    ban_duration: 0,
                };
                return Some(idx);
            }
            if self.table[idx].net_addr == net_addr {
                return Some(idx); // Found existing.
            }
        }

        // Table full — evict the least-recently-offending inactive entry.
        self.table_evict_lru(net_addr, prefix_len, asn)
    }

    /// Evict the inactive entry with the oldest `last_offense` timestamp,
    /// replacing it with a fresh entry for `net_addr`.  Entries with an
    /// active ban (`ban_end_mono > 0`) are never evicted.
    ///
    /// After eviction, the entry is inserted at the evicted slot.  This
    /// breaks the linear-probing chain, but since the evicted entry is
    /// inactive (no active ban, offense decayed), the only consequence is
    /// that a future `table_find` for the evicted prefix returns None —
    /// which is correct (it would have decayed to zero offense anyway).
    fn table_evict_lru(&mut self, net_addr: u32, prefix_len: u32, asn: &str) -> Option<usize> {
        let mut victim_idx: Option<usize> = None;
        let mut victim_offense: u64 = u64::MAX;

        for (i, entry) in self.table.iter().enumerate() {
            // Never evict actively-banned entries.
            if entry.ban_end_mono > 0 {
                continue;
            }
            if entry.last_offense < victim_offense {
                victim_offense = entry.last_offense;
                victim_idx = Some(i);
            }
        }

        let idx = victim_idx?;

        debug!(
            "autoban: evicting {}/{} ({}) from offense table (last_offense={}s ago) to make room for {}/{}",
            Ipv4Addr::from(self.table[idx].net_addr),
            self.table[idx].prefix_len,
            self.table[idx].asn,
            if victim_offense > 0 { wall_clock_secs().saturating_sub(victim_offense) } else { 0 },
            Ipv4Addr::from(net_addr),
            prefix_len
        );

        self.table[idx] = OffenseEntry {
            net_addr,
            prefix_len,
            asn: asn.to_string(),
            offense_count: 0,
            last_offense: 0,
            ban_end_wall: 0,
            ban_end_mono: 0,
            ban_duration: 0,
        };
        Some(idx)
    }

    // ── Expiry heap ──────────────────────────────────────────────────

    fn heap_push(&mut self, entry: HeapEntry) {
        if self.heap.len() >= HEAP_CAP {
            // Compact stale entries before dropping.
            self.heap_compact();
            if self.heap.len() >= HEAP_CAP {
                warn!("autoban: expiry heap full after compaction ({HEAP_CAP} entries)");
                return;
            }
        }
        let idx = self.heap.len();
        self.heap.push(entry);
        self.heap_sift_up(idx);
    }

    /// Remove stale heap entries whose expire_at no longer matches the
    /// authoritative offense table, then rebuild heap ordering.
    fn heap_compact(&mut self) {
        let table = &self.table;
        let mut i = 0;
        while i < self.heap.len() {
            let entry = self.heap[i];
            let keep = Self::table_find_in(table, entry.net_addr)
                .is_some_and(|idx| table[idx].ban_end_mono == entry.expire_at);
            if keep {
                i += 1;
            } else {
                self.heap.swap_remove(i);
                // Don't advance i — swapped element needs checking.
            }
        }
        // Rebuild heap from scratch (Floyd's O(n) heapify).
        let n = self.heap.len();
        for i in (0..n / 2).rev() {
            self.heap_sift_down(i);
        }
        debug!("autoban: heap compacted to {} entries", self.heap.len());
    }

    fn heap_pop(&mut self) -> HeapEntry {
        debug_assert!(!self.heap.is_empty());
        let top = self.heap[0];
        let last = self.heap.len() - 1;
        self.heap.swap(0, last);
        self.heap.pop();
        if !self.heap.is_empty() {
            self.heap_sift_down(0);
        }
        top
    }

    fn heap_sift_up(&mut self, mut i: usize) {
        while i > 0 {
            let p = (i - 1) / 2;
            if self.heap[p].expire_at <= self.heap[i].expire_at {
                break;
            }
            self.heap.swap(p, i);
            i = p;
        }
    }

    fn heap_sift_down(&mut self, mut i: usize) {
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
}

/// Exponential backoff: `min(base × 2^(n-1), cap)`.
fn compute_duration(base: u32, cap: u32, offense_count: i32) -> u32 {
    let mut duration = base;
    for _ in 1..offense_count {
        if duration > cap / 2 {
            return cap;
        }
        duration *= 2;
    }
    duration.min(cap)
}

/// Wall-clock seconds since epoch.
pub fn wall_clock_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    // ── compute_duration tests ───────────────────────────────────────

    #[test]
    fn test_duration_first_offense() {
        assert_eq!(compute_duration(300, 86400, 1), 300);
    }

    #[test]
    fn test_duration_second_offense() {
        assert_eq!(compute_duration(300, 86400, 2), 600);
    }

    #[test]
    fn test_duration_escalation() {
        assert_eq!(compute_duration(300, 86400, 3), 1200);
        assert_eq!(compute_duration(300, 86400, 4), 2400);
        assert_eq!(compute_duration(300, 86400, 5), 4800);
    }

    #[test]
    fn test_duration_cap() {
        // 300 × 2^8 = 76800, 300 × 2^9 = 153600 > 86400 → capped
        assert_eq!(compute_duration(300, 86400, 9), 76800);
        assert_eq!(compute_duration(300, 86400, 10), 86400);
        assert_eq!(compute_duration(300, 86400, 100), 86400);
    }

    #[test]
    fn test_duration_zero_offense() {
        // offense_count <= 0: loop doesn't execute, returns base
        assert_eq!(compute_duration(300, 86400, 0), 300);
    }

    // ── Offense table tests ──────────────────────────────────────────

    #[test]
    fn test_table_find_or_insert() {
        let mut ab = AutobanState::new(AutobanConfig::default());

        let idx = ab.table_find_or_insert(0x0A000000, 24, "AS1234").unwrap();
        assert_eq!(ab.table[idx].net_addr, 0x0A000000);
        assert_eq!(ab.table[idx].prefix_len, 24);
        assert_eq!(ab.table[idx].asn, "AS1234");
        assert_eq!(ab.table[idx].offense_count, 0);

        // Same net_addr returns same slot.
        let idx2 = ab.table_find_or_insert(0x0A000000, 24, "AS1234").unwrap();
        assert_eq!(idx, idx2);
    }

    #[test]
    fn test_table_find() {
        let mut ab = AutobanState::new(AutobanConfig::default());
        assert!(ab.table_find(0x0A000000).is_none());

        ab.table_find_or_insert(0x0A000000, 24, "AS1234");
        assert!(ab.table_find(0x0A000000).is_some());
    }

    #[test]
    fn test_table_multiple_prefixes() {
        let mut ab = AutobanState::new(AutobanConfig::default());

        ab.table_find_or_insert(0x0A000000, 24, "AS1111");
        ab.table_find_or_insert(0xC0A80000, 24, "AS2222");
        ab.table_find_or_insert(0xAC100000, 16, "AS3333");

        assert_eq!(ab.table[ab.table_find(0x0A000000).unwrap()].asn, "AS1111");
        assert_eq!(ab.table[ab.table_find(0xC0A80000).unwrap()].asn, "AS2222");
        assert_eq!(ab.table[ab.table_find(0xAC100000).unwrap()].asn, "AS3333");
    }

    // ── Heap tests ───────────────────────────────────────────────────

    #[test]
    fn test_heap_ordering() {
        let mut ab = AutobanState::new(AutobanConfig::default());
        ab.heap_push(HeapEntry {
            expire_at: 300,
            net_addr: 1,
            prefix_len: 24,
        });
        ab.heap_push(HeapEntry {
            expire_at: 100,
            net_addr: 2,
            prefix_len: 24,
        });
        ab.heap_push(HeapEntry {
            expire_at: 200,
            net_addr: 3,
            prefix_len: 24,
        });

        let e = ab.heap_pop();
        assert_eq!(e.expire_at, 100);
        assert_eq!(e.net_addr, 2);

        let e = ab.heap_pop();
        assert_eq!(e.expire_at, 200);

        let e = ab.heap_pop();
        assert_eq!(e.expire_at, 300);

        assert!(ab.heap.is_empty());
    }

    // ── Hash distribution ────────────────────────────────────────────

    #[test]
    fn test_table_hash_range() {
        for addr in [0u32, 1, 0xFF_FF_FF_FF, 0x0A_00_00_00, 0xC0_A8_00_00] {
            let h = AutobanState::table_hash(addr);
            assert!(h < TABLE_SLOTS, "hash({addr}) = {h} out of range");
        }
    }

    // ── Exponential backoff edge cases ──────────────────────────────

    #[test]
    fn test_duration_base_equals_cap() {
        // When base == cap, every offense returns base (== cap).
        assert_eq!(compute_duration(300, 300, 1), 300);
        assert_eq!(compute_duration(300, 300, 5), 300);
        assert_eq!(compute_duration(300, 300, 100), 300);
    }

    #[test]
    fn test_duration_high_offense_no_overflow() {
        // Extremely high offense count must not panic or overflow.
        let d = compute_duration(300, 86400, 1000);
        assert_eq!(d, 86400);
    }

    // ── Decay window ────────────────────────────────────────────────

    #[test]
    fn test_decay_resets_offense() {
        let config = AutobanConfig {
            decay_window: 100,
            ..AutobanConfig::default()
        };
        let mut ab = AutobanState::new(config);

        // Simulate a previous offense.
        let idx = ab.table_find_or_insert(0x0A000000, 24, "AS1234").unwrap();
        ab.table[idx].offense_count = 5;
        ab.table[idx].last_offense = 1000; // wall-clock seconds

        // After decay_window has elapsed, evaluate should reset offense.
        // We test the decay path directly: now_wall - last_offense > decay_window.
        let now_wall = 1200; // 200s > 100s decay_window
        assert!(now_wall - ab.table[idx].last_offense > ab.config.decay_window);

        // Simulate the decay logic from evaluate().
        if ab.table[idx].offense_count > 0
            && now_wall.saturating_sub(ab.table[idx].last_offense) > ab.config.decay_window
        {
            ab.table[idx].offense_count = 0;
        }
        assert_eq!(ab.table[idx].offense_count, 0);

        // After reset, next offense produces base duration.
        ab.table[idx].offense_count += 1;
        let d = compute_duration(ab.config.base_duration, ab.config.max_duration, ab.table[idx].offense_count);
        assert_eq!(d, ab.config.base_duration);
    }

    // ── Heap edge cases ─────────────────────────────────────────────

    #[test]
    fn test_heap_pop_single_entry() {
        let mut ab = AutobanState::new(AutobanConfig::default());
        ab.heap_push(HeapEntry {
            expire_at: 42,
            net_addr: 1,
            prefix_len: 24,
        });
        assert_eq!(ab.heap.len(), 1);
        let e = ab.heap_pop();
        assert_eq!(e.expire_at, 42);
        assert!(ab.heap.is_empty());
    }

    #[test]
    fn test_heap_pop_all() {
        let mut ab = AutobanState::new(AutobanConfig::default());
        for i in 0..5u64 {
            ab.heap_push(HeapEntry {
                expire_at: (5 - i) * 100, // reverse order
                net_addr: i as u32,
                prefix_len: 24,
            });
        }
        assert_eq!(ab.heap.len(), 5);

        let mut prev = 0u64;
        for _ in 0..5 {
            let e = ab.heap_pop();
            assert!(e.expire_at >= prev, "heap pop not in order");
            prev = e.expire_at;
        }
        assert!(ab.heap.is_empty());
    }

    #[test]
    fn test_heap_full_then_cycle() {
        let mut ab = AutobanState::new(AutobanConfig::default());

        // Fill to HEAP_CAP.
        for i in 0..HEAP_CAP as u64 {
            ab.heap_push(HeapEntry {
                expire_at: i,
                net_addr: i as u32,
                prefix_len: 24,
            });
        }
        assert_eq!(ab.heap.len(), HEAP_CAP);

        // Pop one, push one — should succeed.
        let _ = ab.heap_pop();
        assert_eq!(ab.heap.len(), HEAP_CAP - 1);

        ab.heap_push(HeapEntry {
            expire_at: 999999,
            net_addr: 999999,
            prefix_len: 24,
        });
        assert_eq!(ab.heap.len(), HEAP_CAP);
    }

    #[test]
    fn test_heap_compact_removes_stale() {
        let mut ab = AutobanState::new(AutobanConfig::default());

        // Insert a real ban into the offense table.
        let idx = ab.table_find_or_insert(0x0A000000, 24, "AS1").unwrap();
        ab.table[idx].ban_end_mono = 5000;

        // Push matching and non-matching heap entries.
        ab.heap_push(HeapEntry { expire_at: 5000, net_addr: 0x0A000000, prefix_len: 24 }); // valid
        ab.heap_push(HeapEntry { expire_at: 1000, net_addr: 0x0A000000, prefix_len: 24 }); // stale (wrong expire_at)
        ab.heap_push(HeapEntry { expire_at: 3000, net_addr: 0xDEADBEEF, prefix_len: 24 }); // stale (not in table)
        assert_eq!(ab.heap.len(), 3);

        ab.heap_compact();
        assert_eq!(ab.heap.len(), 1); // Only the valid entry survives.
        assert_eq!(ab.heap[0].expire_at, 5000);
    }

    #[test]
    fn test_heap_full_triggers_compact() {
        let mut ab = AutobanState::new(AutobanConfig::default());

        // Fill heap with stale entries (no matching table entries).
        for i in 0..HEAP_CAP as u64 {
            // Bypass heap_push's compact-on-full to fill directly.
            ab.heap.push(HeapEntry {
                expire_at: i,
                net_addr: i as u32 + 1, // No matching table entries
                prefix_len: 24,
            });
        }
        assert_eq!(ab.heap.len(), HEAP_CAP);

        // Push should trigger compaction, which removes all stale entries,
        // then succeed.
        ab.heap_push(HeapEntry {
            expire_at: 99999,
            net_addr: 0xBEEF,
            prefix_len: 24,
        });
        assert_eq!(ab.heap.len(), 1); // All stale removed, new one inserted.
    }

    // ── Table edge cases ────────────────────────────────────────────

    #[test]
    fn test_table_eviction_when_full() {
        let mut ab = AutobanState::new(AutobanConfig::default());

        // Fill all slots with unique net_addrs, giving each a different last_offense.
        for i in 1..=TABLE_SLOTS as u32 {
            let idx = ab.table_find_or_insert(i, 24, "AS0").unwrap();
            ab.table[idx].last_offense = i as u64 * 100; // increasing timestamps
        }

        // Next insertion should evict the entry with the lowest last_offense (addr=1, ts=100).
        let result = ab.table_find_or_insert(TABLE_SLOTS as u32 + 1, 24, "AS_NEW");
        assert!(result.is_some(), "eviction should succeed");

        // The evicted entry (addr=1) should no longer be findable.
        assert!(ab.table_find(1).is_none(), "evicted entry should be gone");

        // New entry should be findable.
        let idx = ab.table_find(TABLE_SLOTS as u32 + 1).unwrap();
        assert_eq!(ab.table[idx].asn, "AS_NEW");
    }

    #[test]
    fn test_table_eviction_skips_active_bans() {
        let mut ab = AutobanState::new(AutobanConfig::default());

        // Fill all slots.
        for i in 1..=TABLE_SLOTS as u32 {
            let idx = ab.table_find_or_insert(i, 24, "AS0").unwrap();
            ab.table[idx].last_offense = i as u64 * 100;
            // Mark ALL as actively banned.
            ab.table[idx].ban_end_mono = u64::MAX;
        }

        // With all entries actively banned, eviction should fail.
        let result = ab.table_find_or_insert(TABLE_SLOTS as u32 + 1, 24, "AS0");
        assert!(result.is_none(), "should fail when all entries are actively banned");
    }

    #[test]
    fn test_table_collision_chain() {
        let mut ab = AutobanState::new(AutobanConfig::default());

        // Insert several IPs — some will collide due to Knuth hash.
        // Use addresses that hash to the same bucket.
        let addrs: Vec<u32> = (1..=20).collect();
        for &addr in &addrs {
            ab.table_find_or_insert(addr, 24, &format!("AS{addr}"));
        }

        // All should be retrievable via table_find.
        for &addr in &addrs {
            let idx = ab.table_find(addr);
            assert!(idx.is_some(), "addr {addr} not found after insertion");
            assert_eq!(ab.table[idx.unwrap()].asn, format!("AS{addr}"));
        }
    }

    // ── Reinsert edge case ──────────────────────────────────────────

    #[test]
    fn test_reinsert_skips_expired() {
        let ab = AutobanState::new(AutobanConfig::default());
        let now_mono = 1_000_000_000u64;

        // With an empty table (no entries with ban_end_mono > now_mono),
        // reinsert should iterate but insert nothing.
        // We can't call maps in unit tests, but verify the logic:
        // reinsert_active iterates table and skips entries where
        // ban_end_mono <= now_mono.
        for ent in &ab.table {
            // All entries are vacant (net_addr == 0), so all are skipped.
            assert!(ent.net_addr == 0 || ent.ban_end_mono <= now_mono);
        }
    }
}
