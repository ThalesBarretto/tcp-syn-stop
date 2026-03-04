// SPDX-License-Identifier: GPL-2.0-only
//! Async SQLite persistence — mpsc channel + dedicated writer thread.
//!
//! Mirrors the C daemon's `dbio.c` pattern: ASN resolution happens on
//! the main thread, then pre-resolved rows are enqueued to a writer
//! thread that owns its own SQLite connection (WAL mode).

use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};

use log::{error, info, warn};
use rusqlite::{params, Connection};

use crate::autoban::{BanAction, DeactivateAction};
use crate::ttl::ExpiredRow;

/// Pre-resolved intel row for persistence.
pub struct IntelRow {
    pub ip: u32,    // network byte order
    pub port: u16,
    pub count: u32,
    pub asn: String,
}

/// Enriched snapshot row — authoritative per-IP counts from BPF maps.
pub struct SnapshotRow {
    pub ip_nbo: u32,
    pub count: u64,
    pub peak_pps: u64,
    pub first_seen_wall: u64,
    pub ports: Vec<u16>,
    pub asn: String,
}

/// Blacklist snapshot row — per-IP blacklist drop counts from BPF maps.
pub struct BlacklistRow {
    pub ip_nbo: u32,
    pub count: u64,
    pub asn: String,
}

/// Messages sent to the writer thread.
pub enum PersistMsg {
    Intel { rows: Vec<IntelRow>, ts: u64 },
    Snapshot { rows: Vec<SnapshotRow>, ts: u64 },
    BlacklistSnapshot { rows: Vec<BlacklistRow>, ts: u64 },
    AutobanUpsert { rows: Vec<BanAction> },
    AutobanDeactivate { rows: Vec<DeactivateAction> },
    TtlExpire { rows: Vec<ExpiredRow>, ts: u64 },
    Shutdown,
}

/// Bounded channel capacity.  Sized for worst-case: 60s tick sends up
/// to 4 messages (Intel, Snapshot, BlacklistSnapshot, AutobanUpsert)
/// plus 5s ticks send TtlExpire and AutobanDeactivate.  64 slots
/// provides ~15 ticks of backpressure before dropping telemetry.
const CHANNEL_CAP: usize = 64;

/// Handle to the writer thread.
pub struct PersistHandle {
    tx: mpsc::SyncSender<PersistMsg>,
    handle: Option<JoinHandle<()>>,
}

impl PersistHandle {
    /// Spawn the writer thread.  `db_path` is the daemon's SQLite database.
    pub fn new(db_path: &str) -> Self {
        let (tx, rx) = mpsc::sync_channel(CHANNEL_CAP);
        let path = db_path.to_string();
        let handle = thread::spawn(move || writer_thread(rx, &path));
        Self {
            tx,
            handle: Some(handle),
        }
    }

    /// Non-blocking send.  Drops telemetry if the writer thread falls behind.
    pub fn send(&self, msg: PersistMsg) {
        if let Err(e) = self.tx.try_send(msg) {
            warn!("persist: channel full or disconnected, dropping message: {e}");
        }
    }

    /// Send shutdown and join the writer thread.
    pub fn shutdown(mut self) {
        // Shutdown uses blocking send to ensure delivery.
        let _ = self.tx.send(PersistMsg::Shutdown);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Standalone function: read active autobans from SQLite at startup.
/// Called before the writer thread owns the connection.
/// Returns `(net_addr, prefix_len, asn, offense_count, ban_end_wall, last_offense)`.
pub fn restore_autobans(db_path: &str) -> Vec<(u32, u32, String, i32, u64, u64)> {
    let conn = match Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(c) => c,
        Err(e) => {
            warn!("persist: cannot open {db_path} for autoban restore: {e}");
            return Vec::new();
        }
    };

    // Table may not exist yet on first run.
    let mut stmt = match conn.prepare(
        "SELECT net_addr, prefix_len, asn, offense_count, ban_end, last_offense \
         FROM autoban_history WHERE active = 1",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let rows = match stmt.query_map([], |row| {
        Ok((
            row.get::<_, u32>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i32>(3)?,
            row.get::<_, u64>(4)?,
            row.get::<_, u64>(5)?,
        ))
    }) {
        Ok(r) => r,
        Err(e) => {
            warn!("persist: autoban restore query failed: {e}");
            return Vec::new();
        }
    };

    let mut result = Vec::new();
    for row in rows {
        match row {
            Ok(r) => result.push(r),
            Err(e) => warn!("persist: skipping bad autoban row: {e}"),
        }
    }
    if !result.is_empty() {
        info!("persist: loaded {} active autoban(s) from database", result.len());
    }
    result
}

// ── Writer thread ────────────────────────────────────────────────────

// Receiver is intentionally moved into the thread (ownership transfer, not borrow).
#[allow(clippy::needless_pass_by_value)]
fn writer_thread(rx: mpsc::Receiver<PersistMsg>, db_path: &str) {
    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            error!("persist: cannot open {db_path}: {e}");
            return;
        }
    };
    if let Err(e) = conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;") {
        warn!("persist: WAL pragma failed: {e}");
    }
    if let Err(e) = init_schema(&conn) {
        error!("persist: schema init failed: {e}");
        return;
    }

    for msg in &rx {
        match msg {
            PersistMsg::Intel { rows, ts } => write_intel(&conn, &rows, ts),
            PersistMsg::Snapshot { rows, ts } => write_snapshot(&conn, &rows, ts),
            PersistMsg::BlacklistSnapshot { rows, ts } => write_blacklist_snapshot(&conn, &rows, ts),
            PersistMsg::AutobanUpsert { rows } => write_autoban_upsert(&conn, &rows),
            PersistMsg::AutobanDeactivate { rows } => write_autoban_deactivate(&conn, &rows),
            PersistMsg::TtlExpire { rows, ts } => write_ttl_expire(&conn, &rows, ts),
            PersistMsg::Shutdown => break,
        }
    }
}

fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
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
         CREATE INDEX IF NOT EXISTS idx_intel_src_ip_int
           ON drop_intel (src_ip_int);
         BEGIN;
         DROP VIEW IF EXISTS v_shield_roi;
         CREATE VIEW v_shield_roi AS
           SELECT strftime('%Y-%m-%d %H:00:00', ts_start, 'unixepoch') as hour,
                  SUM(drop_count) as pkts_mitigated,
                  ROUND(SUM(drop_count) * 0.000002, 2) as cpu_secs_saved
           FROM drop_intel
           WHERE reason IN ('SNAPSHOT', 'BLACKLIST')
           GROUP BY hour;
         COMMIT;
         CREATE TABLE IF NOT EXISTS autoban_history (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           net_addr INTEGER NOT NULL, prefix_len INTEGER NOT NULL,
           asn TEXT NOT NULL, ban_start INTEGER NOT NULL,
           ban_end INTEGER NOT NULL, ban_duration INTEGER NOT NULL,
           offense_count INTEGER NOT NULL, last_offense INTEGER NOT NULL,
           active INTEGER NOT NULL DEFAULT 1
         );
         CREATE UNIQUE INDEX IF NOT EXISTS idx_autoban_active_prefix
           ON autoban_history (net_addr, prefix_len) WHERE active = 1;",
    )
}

fn write_intel(conn: &Connection, rows: &[IntelRow], ts: u64) {
    if rows.is_empty() {
        return;
    }
    let tx = match conn.unchecked_transaction() {
        Ok(t) => t,
        Err(e) => {
            warn!("persist: intel transaction begin failed: {e}");
            return;
        }
    };
    {
        let mut stmt = match tx.prepare_cached(
            "INSERT INTO drop_intel (ts_start, ts_last, src_ip, src_ip_int, src_mask, asn, dest_port, reason, drop_count, peak_pps) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
             ON CONFLICT(src_ip, dest_port, reason) DO UPDATE SET \
               ts_last = excluded.ts_last, \
               src_ip_int = excluded.src_ip_int, \
               drop_count = drop_intel.drop_count + excluded.drop_count, \
               peak_pps = MAX(drop_intel.peak_pps, excluded.peak_pps)",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("persist: intel prepare failed: {e}");
                return;
            }
        };

        for row in rows {
            let ip_hbo = u32::from_be(row.ip);
            let ip_str = Ipv4Addr::from(ip_hbo).to_string();
            if let Err(e) = stmt.execute(params![
                ts,            // ts_start
                ts,            // ts_last
                ip_str,        // src_ip
                ip_hbo,        // src_ip_int
                32,            // src_mask (single IP)
                row.asn,       // asn
                row.port,      // dest_port
                "SAMPLED",     // reason
                row.count,     // drop_count
                0,             // peak_pps (not tracked per-event)
            ]) {
                warn!("persist: intel upsert failed for {ip_str}: {e}");
            }
        }
    }
    if let Err(e) = tx.commit() {
        warn!("persist: intel commit failed: {e}");
    }
}

fn write_snapshot(conn: &Connection, rows: &[SnapshotRow], ts: u64) {
    if rows.is_empty() {
        return;
    }
    let tx = match conn.unchecked_transaction() {
        Ok(t) => t,
        Err(e) => {
            warn!("persist: snapshot transaction begin failed: {e}");
            return;
        }
    };
    {
        let mut stmt = match tx.prepare_cached(
            "INSERT INTO drop_intel (ts_start, ts_last, src_ip, src_ip_int, src_mask, asn, dest_port, reason, drop_count, peak_pps) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 'SNAPSHOT', ?7, ?8) \
             ON CONFLICT(src_ip, dest_port, reason) DO UPDATE SET \
               ts_last = excluded.ts_last, \
               src_ip_int = excluded.src_ip_int, \
               drop_count = excluded.drop_count, \
               peak_pps = MAX(drop_intel.peak_pps, excluded.peak_pps)",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("persist: snapshot prepare failed: {e}");
                return;
            }
        };

        // Insert SAMPLED port-discovery rows (additive, dest_port > 0).
        let mut port_stmt = match tx.prepare_cached(
            "INSERT INTO drop_intel (ts_start, ts_last, src_ip, src_ip_int, src_mask, asn, dest_port, reason, drop_count, peak_pps) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'SAMPLED', 1, 0) \
             ON CONFLICT(src_ip, dest_port, reason) DO UPDATE SET \
               ts_last = excluded.ts_last",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("persist: snapshot port prepare failed: {e}");
                return;
            }
        };

        for row in rows {
            let ip_hbo = u32::from_be(row.ip_nbo);
            let ip_str = Ipv4Addr::from(ip_hbo).to_string();
            let ts_start = if row.first_seen_wall > 0 { row.first_seen_wall } else { ts };
            if let Err(e) = stmt.execute(params![
                ts_start,       // ts_start (first-seen wall time)
                ts,             // ts_last
                ip_str,         // src_ip
                ip_hbo,         // src_ip_int
                32,             // src_mask
                row.asn,        // asn
                row.count,      // drop_count (BPF cumulative — replaces)
                row.peak_pps,   // peak_pps
            ]) {
                warn!("persist: snapshot upsert failed for {ip_str}: {e}");
            }

            // Persist each observed port as a SAMPLED row for port discovery.
            for &port in &row.ports {
                if let Err(e) = port_stmt.execute(params![
                    ts_start,
                    ts,
                    ip_str,
                    ip_hbo,
                    32,
                    row.asn,
                    port,
                ]) {
                    warn!("persist: snapshot port upsert failed for {ip_str}:{port}: {e}");
                }
            }
        }
    }
    if let Err(e) = tx.commit() {
        warn!("persist: snapshot commit failed: {e}");
    }
}

fn write_blacklist_snapshot(conn: &Connection, rows: &[BlacklistRow], ts: u64) {
    if rows.is_empty() {
        return;
    }
    let tx = match conn.unchecked_transaction() {
        Ok(t) => t,
        Err(e) => {
            warn!("persist: blacklist_snapshot transaction begin failed: {e}");
            return;
        }
    };
    {
        let mut stmt = match tx.prepare_cached(
            "INSERT INTO drop_intel (ts_start, ts_last, src_ip, src_ip_int, src_mask, asn, dest_port, reason, drop_count, peak_pps) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 'BLACKLIST', ?7, 0) \
             ON CONFLICT(src_ip, dest_port, reason) DO UPDATE SET \
               ts_last = excluded.ts_last, \
               src_ip_int = excluded.src_ip_int, \
               drop_count = excluded.drop_count",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("persist: blacklist_snapshot prepare failed: {e}");
                return;
            }
        };

        for row in rows {
            let ip_hbo = u32::from_be(row.ip_nbo);
            let ip_str = Ipv4Addr::from(ip_hbo).to_string();
            if let Err(e) = stmt.execute(params![
                ts,          // ts_start
                ts,          // ts_last
                ip_str,      // src_ip
                ip_hbo,      // src_ip_int
                32,          // src_mask
                row.asn,     // asn
                row.count,   // drop_count (BPF cumulative — replaces)
            ]) {
                warn!("persist: blacklist_snapshot upsert failed for {ip_str}: {e}");
            }
        }
    }
    if let Err(e) = tx.commit() {
        warn!("persist: blacklist_snapshot commit failed: {e}");
    }
}

fn write_autoban_upsert(conn: &Connection, rows: &[BanAction]) {
    if rows.is_empty() {
        return;
    }
    let mut stmt = match conn.prepare_cached(
        "INSERT INTO autoban_history (net_addr, prefix_len, asn, ban_start, ban_end, ban_duration, offense_count, last_offense, active) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1) \
         ON CONFLICT (net_addr, prefix_len) WHERE active = 1 DO UPDATE SET \
           ban_start = excluded.ban_start, \
           ban_end = excluded.ban_end, \
           ban_duration = excluded.ban_duration, \
           offense_count = excluded.offense_count, \
           last_offense = excluded.last_offense",
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!("persist: autoban upsert prepare failed: {e}");
            return;
        }
    };

    for row in rows {
        #[allow(clippy::cast_possible_truncation)]
        let ban_start = row.ban_end_wall.saturating_sub(row.ban_duration as u64);
        if let Err(e) = stmt.execute(params![
            row.net_addr,
            row.prefix_len,
            row.asn,
            ban_start,
            row.ban_end_wall,
            row.ban_duration,
            row.offense_count,
            row.ban_end_wall, // last_offense = ban time
        ]) {
            warn!(
                "persist: autoban upsert failed for {}/{}: {e}",
                Ipv4Addr::from(row.net_addr),
                row.prefix_len
            );
        }
    }
}

fn write_autoban_deactivate(conn: &Connection, rows: &[DeactivateAction]) {
    if rows.is_empty() {
        return;
    }
    let mut stmt = match conn.prepare_cached(
        "UPDATE autoban_history SET active = 0 WHERE net_addr = ?1 AND prefix_len = ?2 AND active = 1",
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!("persist: autoban deactivate prepare failed: {e}");
            return;
        }
    };

    for row in rows {
        if let Err(e) = stmt.execute(params![row.net_addr, row.prefix_len]) {
            warn!(
                "persist: autoban deactivate failed for {}/{}: {e}",
                Ipv4Addr::from(row.net_addr),
                row.prefix_len
            );
        }
    }
}

fn write_ttl_expire(conn: &Connection, rows: &[ExpiredRow], ts: u64) {
    if rows.is_empty() {
        return;
    }
    let tx = match conn.unchecked_transaction() {
        Ok(t) => t,
        Err(e) => {
            warn!("persist: ttl_expire transaction begin failed: {e}");
            return;
        }
    };
    {
        let mut stmt = match tx.prepare_cached(
            "INSERT INTO drop_intel (ts_start, ts_last, src_ip, src_ip_int, src_mask, asn, dest_port, reason, drop_count, peak_pps) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
             ON CONFLICT(src_ip, dest_port, reason) DO UPDATE SET \
               ts_last = excluded.ts_last, \
               src_ip_int = excluded.src_ip_int, \
               drop_count = drop_intel.drop_count + excluded.drop_count, \
               peak_pps = MAX(drop_intel.peak_pps, excluded.peak_pps)",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("persist: ttl_expire prepare failed: {e}");
                return;
            }
        };

        for row in rows {
            let ip_hbo = u32::from_be(row.ip);
            let ip_str = Ipv4Addr::from(ip_hbo).to_string();
            if let Err(e) = stmt.execute(params![
                ts,          // ts_start
                ts,          // ts_last
                ip_str,      // src_ip
                ip_hbo,      // src_ip_int
                32,          // src_mask
                row.asn,     // asn
                0,           // dest_port (not tracked in TTL expiry)
                "EXPIRED",   // reason
                row.count,   // drop_count
                0,           // peak_pps
            ]) {
                warn!("persist: ttl_expire upsert failed for {ip_str}: {e}");
            }
        }
    }
    if let Err(e) = tx.commit() {
        warn!("persist: ttl_expire commit failed: {e}");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn mem_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn test_init_schema_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        init_schema(&conn).unwrap(); // second call should not fail
    }

    #[test]
    fn test_write_intel_basic() {
        let conn = mem_db();
        let rows = vec![
            IntelRow { ip: 0x0A000001u32.to_be(), port: 80, count: 5, asn: "AS1234".into() },
            IntelRow { ip: 0x0A000002u32.to_be(), port: 443, count: 3, asn: "AS5678".into() },
        ];
        write_intel(&conn, &rows, 1000);

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM drop_intel", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 2);

        let (ip, dc, reason): (String, i64, String) = conn
            .query_row(
                "SELECT src_ip, drop_count, reason FROM drop_intel WHERE dest_port = 80",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(ip, "10.0.0.1");
        assert_eq!(dc, 5);
        assert_eq!(reason, "SAMPLED");
    }

    #[test]
    fn test_write_intel_upsert_additive() {
        let conn = mem_db();
        let rows = vec![IntelRow { ip: 0x0A000001u32.to_be(), port: 80, count: 5, asn: "AS1".into() }];
        write_intel(&conn, &rows, 1000);
        write_intel(&conn, &rows, 2000);

        let dc: i64 = conn
            .query_row("SELECT drop_count FROM drop_intel WHERE src_ip = '10.0.0.1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(dc, 10); // 5 + 5
    }

    #[test]
    fn test_write_autoban_upsert() {
        let conn = mem_db();
        let rows = vec![BanAction {
            net_addr: 0x0A000000,
            prefix_len: 24,
            asn: "AS1234".into(),
            offense_count: 1,
            ban_duration: 300,
            ban_end_wall: 1300,
        }];
        write_autoban_upsert(&conn, &rows);

        let (na, pl, active): (u32, u32, i32) = conn
            .query_row("SELECT net_addr, prefix_len, active FROM autoban_history", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(na, 0x0A000000);
        assert_eq!(pl, 24);
        assert_eq!(active, 1);
    }

    #[test]
    fn test_write_autoban_deactivate() {
        let conn = mem_db();
        // Insert first
        let bans = vec![BanAction {
            net_addr: 0x0A000000,
            prefix_len: 24,
            asn: "AS1234".into(),
            offense_count: 1,
            ban_duration: 300,
            ban_end_wall: 1300,
        }];
        write_autoban_upsert(&conn, &bans);

        // Deactivate
        let deacts = vec![DeactivateAction {
            net_addr: 0x0A000000,
            prefix_len: 24,
            asn: "AS1234".into(),
        }];
        write_autoban_deactivate(&conn, &deacts);

        let active: i32 = conn
            .query_row("SELECT active FROM autoban_history WHERE net_addr = ?", [0x0A000000u32], |r| r.get(0))
            .unwrap();
        assert_eq!(active, 0);
    }

    #[test]
    fn test_write_ttl_expire() {
        let conn = mem_db();
        let rows = vec![ExpiredRow { ip: 0x0A000001u32.to_be(), count: 42, asn: "AS9999".into() }];
        write_ttl_expire(&conn, &rows, 5000);

        let (reason, dc): (String, i64) = conn
            .query_row(
                "SELECT reason, drop_count FROM drop_intel WHERE src_ip = '10.0.0.1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(reason, "EXPIRED");
        assert_eq!(dc, 42);
    }

    #[test]
    fn test_write_intel_empty() {
        let conn = mem_db();
        write_intel(&conn, &[], 1000); // Should not panic or error
    }

    #[test]
    fn test_write_snapshot_basic() {
        let conn = mem_db();
        let rows = vec![SnapshotRow {
            ip_nbo: 0x0A000001u32.to_be(),
            count: 500,
            peak_pps: 42,
            first_seen_wall: 900,
            ports: vec![80, 443],
            asn: "AS1234".into(),
        }];
        write_snapshot(&conn, &rows, 1000);

        let (reason, dc, pps, ts_start): (String, i64, i64, i64) = conn
            .query_row(
                "SELECT reason, drop_count, peak_pps, ts_start FROM drop_intel WHERE dest_port = 0 AND reason = 'SNAPSHOT'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(reason, "SNAPSHOT");
        assert_eq!(dc, 500);
        assert_eq!(pps, 42);
        assert_eq!(ts_start, 900); // first_seen_wall used as ts_start

        // Port discovery rows
        let port_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM drop_intel WHERE reason = 'SAMPLED'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(port_count, 2);
    }

    #[test]
    fn test_write_snapshot_replaces_count() {
        let conn = mem_db();
        let rows = vec![SnapshotRow {
            ip_nbo: 0x0A000001u32.to_be(),
            count: 100,
            peak_pps: 10,
            first_seen_wall: 900,
            ports: vec![],
            asn: "AS1".into(),
        }];
        write_snapshot(&conn, &rows, 1000);

        // Second write with higher cumulative count — should replace, not add
        let rows2 = vec![SnapshotRow {
            ip_nbo: 0x0A000001u32.to_be(),
            count: 300,
            peak_pps: 5,
            first_seen_wall: 900,
            ports: vec![],
            asn: "AS1".into(),
        }];
        write_snapshot(&conn, &rows2, 2000);

        let (dc, pps): (i64, i64) = conn
            .query_row(
                "SELECT drop_count, peak_pps FROM drop_intel WHERE reason = 'SNAPSHOT'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(dc, 300); // Replaced (not 100 + 300)
        assert_eq!(pps, 10); // MAX(10, 5) = 10
    }

    #[test]
    fn test_write_blacklist_snapshot_basic() {
        let conn = mem_db();
        let rows = vec![BlacklistRow {
            ip_nbo: 0x0A000001u32.to_be(),
            count: 999,
            asn: "AS5678".into(),
        }];
        write_blacklist_snapshot(&conn, &rows, 2000);

        let (reason, dc): (String, i64) = conn
            .query_row(
                "SELECT reason, drop_count FROM drop_intel WHERE src_ip = '10.0.0.1' AND reason = 'BLACKLIST'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(reason, "BLACKLIST");
        assert_eq!(dc, 999);
    }

    #[test]
    fn test_write_blacklist_snapshot_replaces_count() {
        let conn = mem_db();
        let rows = vec![BlacklistRow {
            ip_nbo: 0x0A000001u32.to_be(),
            count: 100,
            asn: "AS1".into(),
        }];
        write_blacklist_snapshot(&conn, &rows, 1000);
        let rows2 = vec![BlacklistRow {
            ip_nbo: 0x0A000001u32.to_be(),
            count: 500,
            asn: "AS1".into(),
        }];
        write_blacklist_snapshot(&conn, &rows2, 2000);

        let dc: i64 = conn
            .query_row(
                "SELECT drop_count FROM drop_intel WHERE reason = 'BLACKLIST'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(dc, 500); // Replaced, not 600
    }

    #[test]
    fn test_v_shield_roi_filters_reasons() {
        let conn = mem_db();
        // SNAPSHOT row — should be included in ROI
        let snap = vec![SnapshotRow {
            ip_nbo: 0x0A000001u32.to_be(),
            count: 100,
            peak_pps: 10,
            first_seen_wall: 1700000000,
            ports: vec![],
            asn: "AS1".into(),
        }];
        write_snapshot(&conn, &snap, 1700000000);

        // SAMPLED row — should be excluded from ROI
        let intel = vec![IntelRow {
            ip: 0x0A000002u32.to_be(),
            port: 80,
            count: 50,
            asn: "AS2".into(),
        }];
        write_intel(&conn, &intel, 1700000000);

        // EXPIRED row — should be included in ROI
        let expired = vec![ExpiredRow {
            ip: 0x0A000003u32.to_be(),
            count: 25,
            asn: "AS3".into(),
        }];
        write_ttl_expire(&conn, &expired, 1700000000);

        let total: i64 = conn
            .query_row("SELECT SUM(pkts_mitigated) FROM v_shield_roi", [], |r| r.get(0))
            .unwrap();
        // SNAPSHOT(100) only — SAMPLED and EXPIRED excluded to prevent
        // double-counting with SNAPSHOT's cumulative REPLACE semantics.
        assert_eq!(total, 100);
    }
}
