// SPDX-License-Identifier: GPL-2.0-only
//! In-memory RIR delegation lookup table with sorted Vec and LRU cache.
//!
//! Loads RIR delegation data from the SQLite `rir_delegations` table into a
//! sorted `Vec<RirEntry>` keyed by IP range.  Lookups use binary search with
//! an LRU cache (2048 entries) to amortize repeated lookups.

use lru::LruCache;
use rusqlite::{Connection, OpenFlags};
use std::cell::RefCell;
use std::num::NonZeroUsize;

pub struct RirEntry {
    pub start: u32,
    pub end: u32,
    pub country: String,
    pub registry: String,
}

const CACHE_CAP: usize = 2048;

pub struct RirTable {
    entries: Vec<RirEntry>,
    cache: RefCell<LruCache<u32, Option<usize>>>,
}

/// Intermediate data loaded in a background thread (Send-safe, no RefCell).
pub struct RirTableData {
    pub entries: Vec<RirEntry>,
}

impl RirTable {
    pub fn from_data(data: RirTableData) -> Self {
        RirTable {
            entries: data.entries,
            #[allow(clippy::unwrap_used)]
            cache: RefCell::new(LruCache::new(NonZeroUsize::new(CACHE_CAP).unwrap())),
        }
    }

    pub fn load_data_from_conn(conn: &Connection) -> Option<RirTableData> {
        let mut stmt = conn
            .prepare(
                "SELECT start_ip, end_ip, country, registry \
                 FROM rir_delegations ORDER BY start_ip",
            )
            .ok()?;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let entries: Vec<RirEntry> = stmt
            .query_map([], |row| {
                Ok(RirEntry {
                    start: row.get::<_, i64>(0)? as u32,
                    end: row.get::<_, i64>(1)? as u32,
                    country: row.get::<_, String>(2)?,
                    registry: row.get::<_, String>(3)?,
                })
            })
            .ok()?
            .filter_map(Result::ok)
            .collect();
        if entries.is_empty() {
            return None;
        }
        Some(RirTableData { entries })
    }

    pub fn load_data(db_path: &str) -> Option<RirTableData> {
        let conn = match Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(c) => c,
            Err(_) => return None,
        };
        Self::load_data_from_conn(&conn)
    }

    /// Find the entry whose range contains `ip` (host-byte-order u32).
    pub fn lookup(&self, ip: u32) -> Option<&RirEntry> {
        if let Some(&cached) = self.cache.borrow_mut().get(&ip) {
            return cached.map(|idx| &self.entries[idx]);
        }

        let idx = self.entries.partition_point(|e| e.start <= ip);
        let result = if idx > 0 && self.entries[idx - 1].end >= ip {
            Some(idx - 1)
        } else {
            None
        };

        self.cache.borrow_mut().put(ip, result);
        result.map(|idx| &self.entries[idx])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE rir_delegations (
                start_ip INTEGER NOT NULL, end_ip INTEGER NOT NULL,
                country TEXT NOT NULL, registry TEXT NOT NULL
            );
            CREATE INDEX idx_rir_ips ON rir_delegations (start_ip, end_ip);",
        )
        .unwrap();
        conn
    }

    fn insert_rir(conn: &Connection, start: u32, end: u32, cc: &str, reg: &str) {
        conn.execute(
            "INSERT INTO rir_delegations (start_ip, end_ip, country, registry) VALUES (?1, ?2, ?3, ?4)",
            params![start as i64, end as i64, cc, reg],
        )
        .unwrap();
    }

    #[test]
    fn test_lookup_hit() {
        let conn = setup_db();
        insert_rir(&conn, 0x0A000000, 0x0A0000FF, "FR", "ripencc");
        let data = RirTable::load_data_from_conn(&conn).unwrap();
        let table = RirTable::from_data(data);
        let entry = table.lookup(0x0A000001).unwrap();
        assert_eq!(entry.country, "FR");
        assert_eq!(entry.registry, "ripencc");
    }

    #[test]
    fn test_lookup_miss() {
        let conn = setup_db();
        insert_rir(&conn, 0x0A000000, 0x0A0000FF, "FR", "ripencc");
        let data = RirTable::load_data_from_conn(&conn).unwrap();
        let table = RirTable::from_data(data);
        assert!(table.lookup(0x0B000000).is_none());
    }

    #[test]
    fn test_lookup_boundary() {
        let conn = setup_db();
        insert_rir(&conn, 0x0A000000, 0x0A0000FF, "DE", "ripencc");
        let data = RirTable::load_data_from_conn(&conn).unwrap();
        let table = RirTable::from_data(data);
        assert!(table.lookup(0x0A000000).is_some());
        assert!(table.lookup(0x0A0000FF).is_some());
        assert!(table.lookup(0x0A000100).is_none());
    }

    #[test]
    fn test_empty_table() {
        let conn = setup_db();
        assert!(RirTable::load_data_from_conn(&conn).is_none());
    }

    #[test]
    fn test_multiple_ranges() {
        let conn = setup_db();
        insert_rir(&conn, 0x0A000000, 0x0A00FFFF, "US", "arin");
        insert_rir(&conn, 0xC0A80000, 0xC0A800FF, "FR", "ripencc");
        let data = RirTable::load_data_from_conn(&conn).unwrap();
        let table = RirTable::from_data(data);
        assert_eq!(table.lookup(0x0A000001).unwrap().country, "US");
        assert_eq!(table.lookup(0xC0A80010).unwrap().country, "FR");
        assert!(table.lookup(0x0B000000).is_none());
    }

    #[test]
    fn test_cache_returns_same_result() {
        let conn = setup_db();
        insert_rir(&conn, 0x0A000000, 0x0A0000FF, "JP", "apnic");
        let data = RirTable::load_data_from_conn(&conn).unwrap();
        let table = RirTable::from_data(data);
        let e1 = table.lookup(0x0A000001).unwrap();
        let e2 = table.lookup(0x0A000001).unwrap();
        assert_eq!(e1.country, e2.country);
    }
}
