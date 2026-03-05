// SPDX-License-Identifier: GPL-2.0-only
//! SQLite-backed attack forensics — drilldown and ROI analysis.
//!
//! Queries the `drop_intel` table to build aggregated views: per-IP drilldown
//! within a neighborhood and ROI time-series (packets mitigated / CPU seconds
//! saved). Reason breakdown and blacklist drop counts are now computed from
//! BPF maps in `app.rs`.

use anyhow::Result;
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ForensicsState {
    pub roi_rows: Vec<(String, i64, f64)>, // (hour, pkts_mitigated, cpu_secs_saved)
    pub roi_totals: (i64, f64),
    /// Unix timestamp of the most recent SNAPSHOT row (for DB freshness check).
    pub latest_snapshot_ts: Option<i64>,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Neighborhood {
    pub subnet_cidr: String,
    pub asn: String,
    pub as_name: String,
    pub country: String,
    pub rir_country: String,
    pub bot_count: i64,
    pub total_impact: i64,
    pub start_ip: u32,
    pub end_ip: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwarmEntry {
    pub ip: String,
    pub asn: String,
    pub as_name: String,
    pub country: String,
    pub rir_country: String,
    pub total_drops: u64,
    pub last_seen_ago: String,
    pub last_seen_ns: u64,
    pub reason: String,
}

pub struct DrilldownState {
    pub neighborhood: Neighborhood,
    pub as_name: String,
    pub ips: Vec<DrilldownIp>,
    pub port_diversity: usize,
}

pub struct DrilldownIp {
    pub ip: String,
    pub drop_count: i64,
    pub peak_pps: i64,
    pub dest_ports: Vec<u16>,
    #[allow(dead_code)]
    pub first_seen: String,
    #[allow(dead_code)]
    pub last_seen: String,
}

pub fn fetch_forensics(db_path: &str) -> Result<ForensicsState> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    fetch_forensics_from_conn(&conn)
}

fn fetch_forensics_from_conn(conn: &Connection) -> Result<ForensicsState> {
    let mut roi_rows = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT hour, pkts_mitigated, cpu_secs_saved \
             FROM v_shield_roi ORDER BY hour DESC LIMIT 24;",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, f64>(2)?))
        })?;
        for row in rows {
            roi_rows.push(row?);
        }
    }

    let roi_totals = {
        let mut stmt = conn.prepare(
            "SELECT COALESCE(SUM(pkts_mitigated),0), \
                    COALESCE(SUM(cpu_secs_saved),0.0) FROM v_shield_roi;",
        )?;
        stmt.query_row([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, f64>(1)?)))?
    };

    // Latest SNAPSHOT timestamp for DB freshness monitoring
    let latest_snapshot_ts: Option<i64> = conn
        .prepare("SELECT MAX(ts_last) FROM drop_intel WHERE reason='SNAPSHOT'")
        .and_then(|mut stmt| stmt.query_row([], |row| row.get(0)))
        .unwrap_or(None);

    Ok(ForensicsState {
        roi_rows,
        roi_totals,
        latest_snapshot_ts,
    })
}

pub fn fetch_drilldown(db_path: &str, neighborhood: &Neighborhood) -> Result<DrilldownState> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;

    let as_name = neighborhood.as_name.clone();

    // Use the indexed src_ip_int column (B-tree on host-byte-order u32) to
    // restrict the scan to IPs within the neighborhood's ASN range.  This
    // replaces the previous approach of scanning the entire drop_intel table
    // and filtering in Rust, which became O(n) on the full table — a problem
    // on long-running systems where drop_intel grows monotonically (100K–1M
    // rows).  The BETWEEN on an indexed INTEGER column gives O(log n) seek +
    // O(k) scan over matching rows only.
    let mut stmt = conn.prepare(
        "SELECT src_ip, \
                SUM(CASE WHEN reason IN ('SNAPSHOT','BLACKLIST') \
                    THEN drop_count ELSE 0 END), \
                MAX(peak_pps), \
                GROUP_CONCAT(DISTINCT CASE WHEN dest_port > 0 THEN dest_port END), \
                MIN(ts_start), MAX(ts_last) \
         FROM drop_intel \
         WHERE src_ip_int BETWEEN ?1 AND ?2 \
         GROUP BY src_ip \
         ORDER BY SUM(CASE WHEN reason IN ('SNAPSHOT','BLACKLIST') \
                      THEN drop_count ELSE 0 END) DESC",
    )?;

    let start = neighborhood.start_ip;
    let end = neighborhood.end_ip;
    let mut ips = Vec::new();
    let mut all_ports = std::collections::HashSet::new();

    let rows = stmt.query_map(params![start as i64, end as i64], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2).unwrap_or(0),
            row.get::<_, String>(3).unwrap_or_default(),
            row.get::<_, i64>(4).unwrap_or(0),
            row.get::<_, i64>(5).unwrap_or(0),
        ))
    })?;

    for row in rows {
        let (ip_str, drops, peak, ports_csv, ts_start, ts_last) = row?;
        let dest_ports: Vec<u16> = ports_csv.split(',').filter_map(|s| s.trim().parse().ok()).collect();
        for &p in &dest_ports {
            all_ports.insert(p);
        }
        ips.push(DrilldownIp {
            ip: ip_str,
            drop_count: drops,
            peak_pps: peak,
            dest_ports,
            first_seen: crate::time_fmt::format_unix_ts(ts_start),
            last_seen: crate::time_fmt::format_unix_ts(ts_last),
        });
    }

    Ok(DrilldownState {
        neighborhood: neighborhood.clone(),
        as_name,
        port_diversity: all_ports.len(),
        ips,
    })
}


#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rusqlite::params;
    use std::net::Ipv4Addr;

    /// Creates an in-memory DB with the real daemon schema (drop_intel + views)
    /// plus the asns table for proper ASN subnet lookups.
    fn setup_v3_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS drop_intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_start INTEGER, ts_last INTEGER,
                src_ip TEXT, src_ip_int INTEGER, src_mask INTEGER,
                asn TEXT, dest_port INTEGER,
                reason TEXT, drop_count INTEGER, peak_pps INTEGER
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_intel_active
                ON drop_intel (src_ip, dest_port, reason);
            CREATE TABLE IF NOT EXISTS asns (
                start_ip INTEGER, end_ip INTEGER, asn TEXT, country TEXT, as_name TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_ips ON asns (start_ip, end_ip);
            DROP VIEW IF EXISTS v_shield_roi;
            CREATE VIEW v_shield_roi AS
                SELECT strftime('%Y-%m-%d %H:00:00', ts_start, 'unixepoch') as hour,
                SUM(drop_count) as pkts_mitigated,
                ROUND(SUM(drop_count) * 0.000002, 2) as cpu_secs_saved
                FROM drop_intel
                WHERE reason IN ('SNAPSHOT', 'BLACKLIST')
                GROUP BY hour;",
        )
        .unwrap();
        conn
    }

    /// Helper: insert a drop_intel row using the real v3 schema columns.
    fn insert_intel(conn: &Connection, ts: i64, ip: &str, asn: &str, port: i32, reason: &str, drops: i64) {
        let ip_int: Option<i64> = ip.parse::<Ipv4Addr>().ok().map(|a| u32::from(a) as i64);
        conn.execute(
            "INSERT INTO drop_intel (ts_start, ts_last, src_ip, src_ip_int, src_mask, asn, dest_port, reason, drop_count, peak_pps) \
             VALUES (?1, ?1, ?2, ?3, 32, ?4, ?5, ?6, ?7, 0)",
            params![ts, ip, ip_int, asn, port, reason, drops],
        ).unwrap();
    }

    /// Helper: insert an ASN range. start/end are host-byte-order u32 integers.
    fn insert_asn(conn: &Connection, start_ip: u32, end_ip: u32, asn: &str, country: &str) {
        conn.execute(
            "INSERT INTO asns (start_ip, end_ip, asn, country) VALUES (?1, ?2, ?3, ?4)",
            params![start_ip as i64, end_ip as i64, asn, country],
        )
        .unwrap();
    }

    #[test]
    fn test_forensics_empty_db() {
        let conn = setup_v3_db();
        let fs = fetch_forensics_from_conn(&conn).unwrap();
        assert!(fs.roi_rows.is_empty());
        assert_eq!(fs.roi_totals, (0, 0.0));
    }

    // --- ROI tests (unchanged, still use v_shield_roi view) ---

    #[test]
    fn test_forensics_roi_rows() {
        let conn = setup_v3_db();
        let hour1 = 1700000000_i64;
        let hour2 = hour1 + 3600;
        insert_intel(&conn, hour1, "10.0.0.1", "AS1", 80, "SNAPSHOT", 100);
        insert_intel(&conn, hour1 + 600, "10.0.0.2", "AS1", 80, "SNAPSHOT", 200);
        insert_intel(&conn, hour2, "10.0.0.3", "AS1", 80, "SNAPSHOT", 300);
        let fs = fetch_forensics_from_conn(&conn).unwrap();
        assert_eq!(fs.roi_rows.len(), 2);
        assert!(fs.roi_rows[0].0 > fs.roi_rows[1].0);
        assert_eq!(fs.roi_rows[0].1, 300);
        assert_eq!(fs.roi_rows[1].1, 300);
    }

    #[test]
    fn test_forensics_roi_totals() {
        let conn = setup_v3_db();
        let ts = 1700000000_i64;
        insert_intel(&conn, ts, "10.0.0.1", "AS1", 80, "SNAPSHOT", 100);
        insert_intel(&conn, ts + 600, "10.0.0.2", "AS1", 80, "SNAPSHOT", 200);
        insert_intel(&conn, ts + 7200, "10.0.0.3", "AS1", 80, "SNAPSHOT", 300);
        let fs = fetch_forensics_from_conn(&conn).unwrap();
        assert_eq!(fs.roi_totals.0, 600);
        assert!(fs.roi_totals.1 < 0.01);
    }

    #[test]
    fn test_forensics_roi_limit() {
        let conn = setup_v3_db();
        let base_ts = 1700000000_i64;
        for i in 0..30 {
            conn.execute(
                "INSERT INTO drop_intel (ts_start, ts_last, src_ip, src_mask, asn, dest_port, reason, drop_count, peak_pps) \
                 VALUES (?1, ?1, '10.0.0.1', 32, 'AS1', ?2, 'SNAPSHOT', 100, 0)",
                params![base_ts + i * 3600, i],
            ).unwrap();
        }
        let fs = fetch_forensics_from_conn(&conn).unwrap();
        assert_eq!(fs.roi_rows.len(), 24);
    }

    #[test]
    fn test_forensics_roi_hour_format() {
        let conn = setup_v3_db();
        insert_intel(&conn, 1700000000, "10.0.0.1", "AS1", 80, "SNAPSHOT", 100);
        let fs = fetch_forensics_from_conn(&conn).unwrap();
        assert_eq!(fs.roi_rows.len(), 1);
        assert_eq!(fs.roi_rows[0].0, "2023-11-14 22:00:00");
    }

    #[test]
    fn test_fetch_drilldown_basic() {
        let conn = setup_v3_db();
        let ts = 1700000000_i64;
        insert_asn(&conn, 0x0A000000, 0x0A0000FF, "AS1234", "US");
        conn.execute("UPDATE asns SET as_name = 'TEST-NET' WHERE asn = 'AS1234'", [])
            .unwrap();
        insert_intel(&conn, ts, "10.0.0.1", "AS1234", 80, "SNAPSHOT", 100);
        insert_intel(&conn, ts, "10.0.0.2", "AS1234", 443, "SNAPSHOT", 200);
        let hood = Neighborhood {
            subnet_cidr: "10.0.0.0/24".into(),
            asn: "AS1234".into(),
            as_name: "TEST-NET".into(),
            country: "US".into(),
            rir_country: String::new(),
            bot_count: 2,
            total_impact: 300,
            start_ip: 0x0A000000,
            end_ip: 0x0A0000FF,
        };
        // fetch_drilldown needs a file path; use temp db
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let tmp_path = tmp.path().to_str().unwrap();
        // Copy in-memory DB to temp file
        conn.execute("VACUUM INTO ?1", [tmp_path]).unwrap();
        let dd = fetch_drilldown(tmp_path, &hood).unwrap();
        assert_eq!(dd.as_name, "TEST-NET");
        assert_eq!(dd.ips.len(), 2);
        assert_eq!(dd.ips[0].drop_count, 200); // sorted DESC
        assert_eq!(dd.ips[1].drop_count, 100);
    }

    #[test]
    fn test_forensics_latest_snapshot_ts() {
        let conn = setup_v3_db();
        let ts1 = 1700000000_i64;
        let ts2 = 1700003600_i64;
        insert_intel(&conn, ts1, "10.0.0.1", "AS1", 80, "SNAPSHOT", 100);
        insert_intel(&conn, ts2, "10.0.0.2", "AS1", 80, "SNAPSHOT", 200);
        let fs = fetch_forensics_from_conn(&conn).unwrap();
        assert_eq!(fs.latest_snapshot_ts, Some(ts2));
    }

    #[test]
    fn test_forensics_latest_snapshot_ts_empty() {
        let conn = setup_v3_db();
        let fs = fetch_forensics_from_conn(&conn).unwrap();
        assert_eq!(fs.latest_snapshot_ts, None);
    }

    #[test]
    fn test_forensics_latest_snapshot_ts_ignores_sampled() {
        let conn = setup_v3_db();
        insert_intel(&conn, 1700000000, "10.0.0.1", "AS1", 80, "SAMPLED", 100);
        let fs = fetch_forensics_from_conn(&conn).unwrap();
        assert_eq!(fs.latest_snapshot_ts, None); // SAMPLED rows excluded
    }

    #[test]
    fn test_drilldown_empty_neighborhood() {
        // Neighborhood IP range has no matching IPs in drop_intel
        let conn = setup_v3_db();
        let ts = 1700000000_i64;
        // IPs are in a different range than the neighborhood
        insert_intel(&conn, ts, "192.168.1.1", "AS9", 80, "SNAPSHOT", 100);
        let hood = Neighborhood {
            subnet_cidr: "10.0.0.0/24".into(),
            asn: "AS1234".into(),
            as_name: "TEST".into(),
            country: "US".into(),
            rir_country: String::new(),
            bot_count: 0,
            total_impact: 0,
            start_ip: 0x0A000000,
            end_ip: 0x0A0000FF,
        };
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let tmp_path = tmp.path().to_str().unwrap();
        conn.execute("VACUUM INTO ?1", [tmp_path]).unwrap();
        let dd = fetch_drilldown(tmp_path, &hood).unwrap();
        assert!(dd.ips.is_empty());
        assert_eq!(dd.port_diversity, 0);
    }

}
