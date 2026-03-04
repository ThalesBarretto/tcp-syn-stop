// SPDX-License-Identifier: GPL-2.0-only
//! Human-readable and JSON output for telemetry snapshots.

use log::info;

use crate::metrics::TelemetrySnapshot;

/// Log a human-readable summary at INFO level.
pub fn log_report(snap: &TelemetrySnapshot) {
    let top_str: String = snap
        .top_attackers
        .iter()
        .map(|a| {
            if a.asn.is_empty() {
                format!("{}({})", a.ip, a.count)
            } else {
                format!("{}({},{} {})", a.ip, a.count, a.asn, a.as_name)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");

    info!(
        "PPS={} total_drops={} drop_ips={} blacklist={} rb_fail={} top=[{}]",
        snap.pps, snap.total_drops, snap.drop_ips_count, snap.blacklist_active, snap.rb_fail_cnt, top_str
    );
}

/// Serialize snapshot as a single JSON line.
pub fn json_report(snap: &TelemetrySnapshot) -> String {
    serde_json::to_string(snap).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::metrics::TopAttacker;

    fn sample_snap() -> TelemetrySnapshot {
        TelemetrySnapshot {
            timestamp_secs: 1700000000,
            total_drops: 5000,
            pps: 100,
            drop_ips_count: 42,
            blacklist_active: 3,
            rb_fail_cnt: 0,
            top_attackers: vec![TopAttacker {
                ip: "10.0.0.1".to_string(),
                count: 500,
                asn: "AS1234".to_string(),
                country: "US".to_string(),
                as_name: "EXAMPLE-NET".to_string(),
            }],
        }
    }

    #[test]
    fn test_json_roundtrip() {
        let snap = sample_snap();
        let json = json_report(&snap);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["pps"], 100);
        assert_eq!(parsed["total_drops"], 5000);
        assert_eq!(parsed["top_attackers"][0]["ip"], "10.0.0.1");
        assert_eq!(parsed["top_attackers"][0]["asn"], "AS1234");
    }
}
