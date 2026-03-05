// SPDX-License-Identifier: GPL-2.0-only
//! PPS computation and top-K sender extraction.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::net::Ipv4Addr;

use serde::Serialize;

use crate::asn_table::AsnTable;
use crate::bpf::DropInfo;

#[derive(Debug, Serialize)]
pub struct TelemetrySnapshot {
    pub timestamp_secs: u64,
    pub total_drops: u64,
    pub pps: u64,
    pub drop_ips_count: usize,
    pub blacklist_active: u32,
    pub rb_fail_cnt: u64,
    pub top_senders: Vec<TopSender>,
}

#[derive(Debug, Serialize)]
pub struct TopSender {
    pub ip: String,
    pub count: u64,
    pub asn: String,
    pub country: String,
    pub as_name: String,
}

/// Tracks delta across ticks for PPS computation.
pub struct MetricsState {
    last_total_drops: Option<u64>,
    interval_secs: u64,
}

impl MetricsState {
    pub fn new(interval_secs: u64) -> Self {
        Self {
            last_total_drops: None,
            interval_secs,
        }
    }

    /// Compute PPS from the delta since last tick.  Returns 0 on the first tick.
    pub fn compute_pps(&mut self, current: u64) -> u64 {
        let pps = match self.last_total_drops {
            Some(prev) if self.interval_secs > 0 => current.saturating_sub(prev) / self.interval_secs,
            _ => 0,
        };
        self.last_total_drops = Some(current);
        pps
    }
}

/// Extract the top-K senders by drop count using a min-heap.
/// IPs are converted from network byte order to host byte order for ASN lookup.
pub fn top_k_senders(entries: &[(u32, DropInfo)], k: usize, asn_table: Option<&AsnTable>) -> Vec<TopSender> {
    if k == 0 || entries.is_empty() {
        return Vec::new();
    }

    // Min-heap of (count, ip_nbo) — keeps the K largest.
    let mut heap: BinaryHeap<Reverse<(u64, u32)>> = BinaryHeap::with_capacity(k + 1);

    for &(ip_nbo, ref info) in entries {
        if heap.len() < k {
            heap.push(Reverse((info.count, ip_nbo)));
        } else if let Some(&Reverse((min_count, _))) = heap.peek() {
            if info.count > min_count {
                heap.pop();
                heap.push(Reverse((info.count, ip_nbo)));
            }
        }
    }

    // Drain heap into a vec sorted by count descending.
    let mut result: Vec<(u64, u32)> = heap.into_iter().map(|Reverse(pair)| pair).collect();
    result.sort_by(|a, b| b.0.cmp(&a.0));

    result
        .into_iter()
        .map(|(count, ip_nbo)| {
            let ip_hbo = u32::from_be(ip_nbo);
            let (asn, country, as_name) = asn_table
                .and_then(|t| t.lookup(ip_hbo))
                .map(|e| (e.asn.clone(), e.country.clone(), e.as_name.clone()))
                .unwrap_or_default();
            TopSender {
                ip: Ipv4Addr::from(ip_hbo).to_string(),
                count,
                asn,
                country,
                as_name,
            }
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_pps_first_tick_is_zero() {
        let mut state = MetricsState::new(5);
        assert_eq!(state.compute_pps(1000), 0);
    }

    #[test]
    fn test_pps_second_tick() {
        let mut state = MetricsState::new(5);
        state.compute_pps(1000);
        assert_eq!(state.compute_pps(1500), 100); // (1500-1000)/5
    }

    #[test]
    fn test_pps_stable_no_change() {
        let mut state = MetricsState::new(5);
        state.compute_pps(1000);
        assert_eq!(state.compute_pps(1000), 0);
    }

    #[test]
    fn test_top_k_empty() {
        let result = top_k_senders(&[], 5, None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_top_k_zero_k() {
        let entries = vec![(
            0x01020304u32.to_be(),
            DropInfo {
                last_seen: 0,
                count: 10,
            },
        )];
        let result = top_k_senders(&entries, 0, None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_top_k_fewer_than_k() {
        let entries = vec![
            (
                0x01020304u32.to_be(),
                DropInfo {
                    last_seen: 0,
                    count: 10,
                },
            ),
            (
                0x05060708u32.to_be(),
                DropInfo {
                    last_seen: 0,
                    count: 20,
                },
            ),
        ];
        let result = top_k_senders(&entries, 5, None);
        assert_eq!(result.len(), 2);
        // Sorted descending by count
        assert_eq!(result[0].count, 20);
        assert_eq!(result[1].count, 10);
    }

    #[test]
    fn test_top_k_exact() {
        let entries = vec![
            (
                0x0A000001u32.to_be(),
                DropInfo {
                    last_seen: 0,
                    count: 100,
                },
            ),
            (
                0x0A000002u32.to_be(),
                DropInfo {
                    last_seen: 0,
                    count: 200,
                },
            ),
            (
                0x0A000003u32.to_be(),
                DropInfo {
                    last_seen: 0,
                    count: 50,
                },
            ),
        ];
        let result = top_k_senders(&entries, 3, None);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].count, 200);
        assert_eq!(result[1].count, 100);
        assert_eq!(result[2].count, 50);
    }

    #[test]
    fn test_top_k_overflow() {
        let entries = vec![
            (
                0x0A000001u32.to_be(),
                DropInfo {
                    last_seen: 0,
                    count: 10,
                },
            ),
            (
                0x0A000002u32.to_be(),
                DropInfo {
                    last_seen: 0,
                    count: 200,
                },
            ),
            (
                0x0A000003u32.to_be(),
                DropInfo {
                    last_seen: 0,
                    count: 50,
                },
            ),
            (
                0x0A000004u32.to_be(),
                DropInfo {
                    last_seen: 0,
                    count: 300,
                },
            ),
            (0x0A000005u32.to_be(), DropInfo { last_seen: 0, count: 1 }),
        ];
        let result = top_k_senders(&entries, 2, None);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].count, 300);
        assert_eq!(result[1].count, 200);
    }

    #[test]
    fn test_ip_byte_order_conversion() {
        // 10.0.0.1 in host byte order = 0x0A000001
        let ip_nbo = 0x0A000001u32.to_be();
        let entries = vec![(
            ip_nbo,
            DropInfo {
                last_seen: 0,
                count: 42,
            },
        )];
        let result = top_k_senders(&entries, 1, None);
        assert_eq!(result[0].ip, "10.0.0.1");
    }
}
