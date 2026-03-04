// SPDX-License-Identifier: GPL-2.0-only
//! Per-IP PPS tracking, first-seen timestamps, and port accumulation.
//!
//! `IpTracker` watches BPF map snapshots every 5s tick to compute per-IP
//! peak PPS and record wall-clock first-seen time. Port observations
//! arrive from the ringbuf callback.  On the 60s persistence tick,
//! `build_snapshot_rows()` enriches BPF counts with this metadata.

use std::collections::{HashMap, HashSet};

use crate::asn_table::AsnTable;
use crate::bpf::DropInfo;
use crate::persist::SnapshotRow;

/// Maximum distinct ports tracked per IP (bounds memory).
const PORT_CAP: usize = 64;

struct IpEntry {
    prev_count: u64,
    peak_pps: u64,
    first_seen_wall: u64,
    ports: HashSet<u16>,
}

pub struct IpTracker {
    entries: HashMap<u32, IpEntry>,
    interval_secs: u64,
}

impl IpTracker {
    pub fn new(interval_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            interval_secs,
        }
    }

    /// Update tracker state from a BPF `drop_ips` map snapshot.
    ///
    /// For each IP in the snapshot: compute PPS from the count delta since
    /// the last tick, update peak PPS, and record first-seen for new IPs.
    /// IPs absent from the snapshot (LRU evicted) are pruned.
    pub fn update_from_bpf(&mut self, ips: &[(u32, DropInfo)], now_wall: u64) {
        let current: HashSet<u32> = ips.iter().map(|(ip, _)| *ip).collect();

        // Prune entries no longer in BPF map.
        self.entries.retain(|ip, _| current.contains(ip));

        for &(ip, ref info) in ips {
            let entry = self.entries.entry(ip).or_insert_with(|| IpEntry {
                prev_count: info.count,
                peak_pps: 0,
                first_seen_wall: now_wall,
                ports: HashSet::new(),
            });

            // PPS = (count - prev_count) / interval
            let delta = info.count.saturating_sub(entry.prev_count);
            let pps = if self.interval_secs > 0 {
                delta / self.interval_secs
            } else {
                delta
            };
            if pps > entry.peak_pps {
                entry.peak_pps = pps;
            }
            entry.prev_count = info.count;
        }
    }

    /// Record a port seen from the ringbuf for the given IP.
    /// No-op if the IP is not tracked or port cap reached.
    pub fn observe_port(&mut self, ip_nbo: u32, port: u16) {
        if port == 0 {
            return;
        }
        if let Some(entry) = self.entries.get_mut(&ip_nbo) {
            if entry.ports.len() < PORT_CAP {
                entry.ports.insert(port);
            }
        }
    }

    /// Build enriched snapshot rows for persistence.
    ///
    /// Each row carries the BPF cumulative count, the tracked peak PPS,
    /// first-seen wall time, resolved ASN, and accumulated ports.
    pub fn build_snapshot_rows(
        &self,
        ips: &[(u32, DropInfo)],
        asn_table: Option<&AsnTable>,
    ) -> Vec<SnapshotRow> {
        ips.iter()
            .map(|(ip, info)| {
                let ip_hbo = u32::from_be(*ip);
                let (peak_pps, first_seen_wall, ports) =
                    if let Some(entry) = self.entries.get(ip) {
                        (
                            entry.peak_pps,
                            entry.first_seen_wall,
                            entry.ports.iter().copied().collect(),
                        )
                    } else {
                        (0, 0, Vec::new())
                    };
                let asn = asn_table
                    .and_then(|t| t.lookup(ip_hbo))
                    .map(|e| e.asn.clone())
                    .unwrap_or_default();
                SnapshotRow {
                    ip_nbo: *ip,
                    count: info.count,
                    peak_pps,
                    first_seen_wall,
                    ports,
                    asn,
                }
            })
            .collect()
    }

    /// Remove an IP from the tracker (e.g., on TTL expiry).
    pub fn remove(&mut self, ip_nbo: u32) {
        self.entries.remove(&ip_nbo);
    }
}

/// Build blacklist snapshot rows from BPF `blacklist_cnt` map data.
pub fn build_blacklist_rows(
    ips: &[(u32, DropInfo)],
    asn_table: Option<&AsnTable>,
) -> Vec<crate::persist::BlacklistRow> {
    ips.iter()
        .map(|(ip, info)| {
            let ip_hbo = u32::from_be(*ip);
            let asn = asn_table
                .and_then(|t| t.lookup(ip_hbo))
                .map(|e| e.asn.clone())
                .unwrap_or_default();
            crate::persist::BlacklistRow {
                ip_nbo: *ip,
                count: info.count,
                asn,
            }
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_drop_info(count: u64) -> DropInfo {
        DropInfo { last_seen: 0, count }
    }

    #[test]
    fn test_new_ip_recorded() {
        let mut tracker = IpTracker::new(5);
        let ips = vec![(1u32, make_drop_info(100))];
        tracker.update_from_bpf(&ips, 1000);

        assert!(tracker.entries.contains_key(&1));
        assert_eq!(tracker.entries[&1].first_seen_wall, 1000);
        assert_eq!(tracker.entries[&1].prev_count, 100);
    }

    #[test]
    fn test_pps_computation() {
        let mut tracker = IpTracker::new(5);

        // First tick: baseline
        let ips = vec![(1u32, make_drop_info(100))];
        tracker.update_from_bpf(&ips, 1000);
        assert_eq!(tracker.entries[&1].peak_pps, 0); // No delta on first tick

        // Second tick: 50 new drops in 5s = 10 PPS
        let ips = vec![(1u32, make_drop_info(150))];
        tracker.update_from_bpf(&ips, 1005);
        assert_eq!(tracker.entries[&1].peak_pps, 10);

        // Third tick: 25 new drops in 5s = 5 PPS (peak stays at 10)
        let ips = vec![(1u32, make_drop_info(175))];
        tracker.update_from_bpf(&ips, 1010);
        assert_eq!(tracker.entries[&1].peak_pps, 10);
    }

    #[test]
    fn test_pruning_absent_ips() {
        let mut tracker = IpTracker::new(5);
        let ips = vec![(1u32, make_drop_info(100)), (2u32, make_drop_info(200))];
        tracker.update_from_bpf(&ips, 1000);
        assert_eq!(tracker.entries.len(), 2);

        // Next tick: IP 2 evicted from BPF
        let ips = vec![(1u32, make_drop_info(150))];
        tracker.update_from_bpf(&ips, 1005);
        assert_eq!(tracker.entries.len(), 1);
        assert!(!tracker.entries.contains_key(&2));
    }

    #[test]
    fn test_observe_port() {
        let mut tracker = IpTracker::new(5);
        let ips = vec![(1u32, make_drop_info(100))];
        tracker.update_from_bpf(&ips, 1000);

        tracker.observe_port(1, 80);
        tracker.observe_port(1, 443);
        tracker.observe_port(1, 80); // duplicate
        assert_eq!(tracker.entries[&1].ports.len(), 2);
    }

    #[test]
    fn test_observe_port_cap() {
        let mut tracker = IpTracker::new(5);
        let ips = vec![(1u32, make_drop_info(100))];
        tracker.update_from_bpf(&ips, 1000);

        for p in 1..=(PORT_CAP as u16 + 10) {
            tracker.observe_port(1, p);
        }
        assert_eq!(tracker.entries[&1].ports.len(), PORT_CAP);
    }

    #[test]
    fn test_observe_port_zero_ignored() {
        let mut tracker = IpTracker::new(5);
        let ips = vec![(1u32, make_drop_info(100))];
        tracker.update_from_bpf(&ips, 1000);

        tracker.observe_port(1, 0);
        assert!(tracker.entries[&1].ports.is_empty());
    }

    #[test]
    fn test_observe_port_unknown_ip() {
        let mut tracker = IpTracker::new(5);
        tracker.observe_port(99, 80); // No-op, IP not tracked
        assert!(!tracker.entries.contains_key(&99));
    }

    #[test]
    fn test_remove() {
        let mut tracker = IpTracker::new(5);
        let ips = vec![(1u32, make_drop_info(100))];
        tracker.update_from_bpf(&ips, 1000);
        assert!(tracker.entries.contains_key(&1));

        tracker.remove(1);
        assert!(!tracker.entries.contains_key(&1));
    }

    #[test]
    fn test_build_snapshot_rows() {
        let mut tracker = IpTracker::new(5);
        let ip = 0x0A000001u32.to_be();
        let ips = vec![(ip, make_drop_info(100))];
        tracker.update_from_bpf(&ips, 1000);

        // Simulate second tick with higher count
        let ips = vec![(ip, make_drop_info(200))];
        tracker.update_from_bpf(&ips, 1005);

        tracker.observe_port(ip, 80);
        tracker.observe_port(ip, 443);

        let rows = tracker.build_snapshot_rows(&ips, None);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ip_nbo, ip);
        assert_eq!(rows[0].count, 200);
        assert_eq!(rows[0].peak_pps, 20); // (200-100)/5
        assert_eq!(rows[0].first_seen_wall, 1000);
        assert_eq!(rows[0].ports.len(), 2);
    }

    #[test]
    fn test_build_blacklist_rows() {
        let ip = 0x0A000001u32.to_be();
        let ips = vec![(ip, make_drop_info(500))];
        let rows = build_blacklist_rows(&ips, None);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ip_nbo, ip);
        assert_eq!(rows[0].count, 500);
    }
}
