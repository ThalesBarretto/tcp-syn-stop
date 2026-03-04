// SPDX-License-Identifier: GPL-2.0-only
//! Domain types for system state and telemetry.
//!
//! These types are used by the UI for rendering and by JSON serialization.
//! Live data is now sourced from pinned BPF maps (via `bpf.rs`), not from
//! the daemon's Unix socket.  The wire-format types (MetricsV6 etc.) have
//! been removed.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metrics {
    pub total_drops: u64,
    pub latest_pps: u64,
    pub active_blocks: u32,
    pub blacklist_active: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attacker {
    pub ip: String,
    pub asn: String,
    pub count: u64,
    pub peak_pps: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IfaceInfo {
    pub name: String,
    pub native: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortStat {
    pub port: u16,
    pub hits: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Instrumentation {
    pub ringbuf_reserve_fails: u64,
    pub heap_utilization: u32,
    pub heap_capacity: u32,
    pub sched_utilization: u32,
    pub sched_tombstones: u32,
    pub heap_drop_total: u64,
    pub tick_ringbuf_us: u32,
    pub tick_metrics_us: u32,
    pub tick_ttl_us: u32,
    pub tick_intel_flush_us: u32,
    pub tick_autoban_us: u32,
    pub tick_publish_us: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemState {
    pub uptime_secs: u64,
    pub metrics: Metrics,
    pub top_attackers: Vec<Attacker>,
    pub top_ports: Vec<PortStat>,
    pub ifaces: Vec<IfaceInfo>,
    pub instrumentation: Instrumentation,
}

#[allow(dead_code)]
pub fn parse_cstr(buf: &[u8]) -> String {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_cstr_clean_buffer() {
        let mut buf = [0u8; 32];
        buf[..5].copy_from_slice(b"AS123");
        assert_eq!(parse_cstr(&buf), "AS123");
    }

    #[test]
    fn parse_cstr_stale_bytes_after_null() {
        let mut buf = *b"CLOUDFLARE\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        buf[..4].copy_from_slice(b"AS1\0");
        let broken = String::from_utf8_lossy(&buf).trim_matches('\0').to_string();
        assert_ne!(
            broken, "AS1",
            "trim_matches is broken for stale bytes \u{2014} confirms the bug"
        );
        assert_eq!(parse_cstr(&buf), "AS1");
    }

    #[test]
    fn parse_cstr_no_null_uses_full_buffer() {
        let buf = [b'X'; 32];
        assert_eq!(parse_cstr(&buf).len(), 32);
    }

    #[test]
    fn parse_cstr_empty_buffer() {
        let buf = [0u8; 32];
        assert_eq!(parse_cstr(&buf), "");
    }
}
