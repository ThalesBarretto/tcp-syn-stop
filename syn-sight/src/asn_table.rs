// SPDX-License-Identifier: GPL-2.0-only
//! In-memory ASN lookup table with sorted Vec and LRU cache.
//!
//! Loads all ~515K rows from the SQLite `asns` table once at startup into a
//! sorted `Vec<AsnEntry>` keyed by IP range. Lookups use binary search to find
//! the containing range, with an LRU cache (2048 entries) to amortize repeated
//! lookups for the same IP. Also provides `find_all_by_asn` for collecting all
//! CIDR ranges belonging to an ASN, and `range_to_cidr` for converting
//! contiguous integer ranges into minimal CIDR notation.

use lru::LruCache;
use rusqlite::{Connection, OpenFlags};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::num::NonZeroUsize;

pub struct AsnSearchResult {
    pub asn: String,
    pub as_name: String,
    pub country: String,
    pub range_count: usize,
}

pub struct AsnEntry {
    pub start: u32,
    pub end: u32,
    pub asn: String,
    pub country: String,
    pub as_name: String,
}

/// Max cached IP lookups. The active attacker set is bounded by
/// MAX_AUTOBAN_IPS (16) in the daemon, but drop_ips holds up to 65536
/// entries, so size the cache for realistic working-set access.
const CACHE_CAP: usize = 2048;

pub struct AsnTable {
    entries: Vec<AsnEntry>,
    /// IP → index into `entries` (or None for misses). Avoids repeated binary
    /// searches for the same attacker IPs across refresh cycles.
    cache: RefCell<LruCache<u32, Option<usize>>>,
    /// ASN → indices into `entries`. Built at load time for O(k) lookups
    /// instead of O(n) linear scans.
    asn_index: HashMap<String, Vec<usize>>,
    /// Cache hit/miss counters for observability.
    cache_hits: Cell<u64>,
    cache_misses: Cell<u64>,
}

/// Intermediate data loaded in a background thread (Send-safe, no RefCell).
pub struct AsnTableData {
    pub entries: Vec<AsnEntry>,
    pub asn_index: HashMap<String, Vec<usize>>,
}

impl AsnTable {
    /// Convert background-loaded data into a full AsnTable with LRU cache.
    pub fn from_data(data: AsnTableData) -> Self {
        AsnTable {
            entries: data.entries,
            #[allow(clippy::unwrap_used)] // CACHE_CAP is a non-zero constant
            cache: RefCell::new(LruCache::new(NonZeroUsize::new(CACHE_CAP).unwrap())),
            asn_index: data.asn_index,
            cache_hits: Cell::new(0),
            cache_misses: Cell::new(0),
        }
    }

    /// Load raw data (Send-safe) from a SQLite connection.
    pub fn load_data_from_conn(conn: &Connection) -> Option<AsnTableData> {
        let mut stmt = conn
            .prepare(
                "SELECT start_ip, end_ip, asn, COALESCE(country,''), COALESCE(as_name,'') \
                 FROM asns ORDER BY start_ip",
            )
            .ok()?;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let entries: Vec<AsnEntry> = stmt
            .query_map([], |row| {
                Ok(AsnEntry {
                    start: row.get::<_, i64>(0)? as u32,
                    end: row.get::<_, i64>(1)? as u32,
                    asn: row.get::<_, String>(2)?,
                    country: row.get::<_, String>(3)?,
                    as_name: row.get::<_, String>(4)?,
                })
            })
            .ok()?
            .filter_map(Result::ok)
            .collect();
        if entries.is_empty() {
            return None;
        }

        let mut asn_index: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, entry) in entries.iter().enumerate() {
            asn_index.entry(entry.asn.clone()).or_default().push(i);
        }

        Some(AsnTableData { entries, asn_index })
    }

    /// Load data from a file path (Send-safe).
    /// Returns None if the file is missing, corrupt, or the `asns` table is empty.
    /// Errors are printed to stderr so the user can diagnose load failures.
    pub fn load_data(db_path: &str) -> Option<AsnTableData> {
        let conn = match Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("asn_table: failed to open {}: {}", db_path, e);
                return None;
            }
        };
        let result = Self::load_data_from_conn(&conn);
        if result.is_none() {
            eprintln!("asn_table: {} opened but asns table is empty or unreadable", db_path);
        }
        result
    }

    #[cfg(test)]
    pub(crate) fn load_from_conn(conn: &Connection) -> Option<Self> {
        Self::load_data_from_conn(conn).map(Self::from_data)
    }

    /// Find the entry whose range contains `ip` (host-byte-order u32).
    /// Results are LRU-cached so repeat lookups for the same attacker IP
    /// across refresh cycles are O(1) instead of O(log n) binary search.
    pub fn lookup(&self, ip: u32) -> Option<&AsnEntry> {
        if let Some(&cached) = self.cache.borrow_mut().get(&ip) {
            self.cache_hits.set(self.cache_hits.get() + 1);
            return cached.map(|idx| &self.entries[idx]);
        }

        self.cache_misses.set(self.cache_misses.get() + 1);
        let idx = self.entries.partition_point(|e| e.start <= ip);
        let result = if idx > 0 && self.entries[idx - 1].end >= ip {
            Some(idx - 1)
        } else {
            None
        };

        self.cache.borrow_mut().put(ip, result);
        result.map(|idx| &self.entries[idx])
    }

    /// Returns the cache hit percentage, or `None` if no lookups have occurred.
    pub fn cache_hit_pct(&self) -> Option<f64> {
        let hits = self.cache_hits.get();
        let misses = self.cache_misses.get();
        let total = hits + misses;
        if total == 0 {
            return None;
        }
        #[allow(clippy::cast_precision_loss)]
        Some((hits as f64 / total as f64) * 100.0)
    }

    /// Fuzzy-search AS names, returning deduplicated results ranked by score.
    pub fn fuzzy_search(&self, query: &str, max_results: usize) -> Vec<AsnSearchResult> {
        use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
        use nucleo_matcher::{Config, Matcher, Utf32Str};

        if query.is_empty() {
            return Vec::new();
        }

        let mut matcher = Matcher::new(Config::DEFAULT);
        let pattern = Pattern::parse(query, CaseMatching::Ignore, Normalization::Smart);

        // Score each entry, deduplicate by ASN (keep best score per ASN)
        let mut best_per_asn: std::collections::HashMap<&str, (u32, usize)> = std::collections::HashMap::new();
        let mut buf = Vec::new();

        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.as_name.is_empty() {
                continue;
            }
            buf.clear();
            let haystack = Utf32Str::new(&entry.as_name, &mut buf);
            if let Some(score) = pattern.score(haystack, &mut matcher) {
                let existing = best_per_asn.entry(&entry.asn).or_insert((0, idx));
                if score > existing.0 {
                    *existing = (score, idx);
                }
            }
        }

        // Sort by score DESC, take top N
        let mut scored: Vec<(&str, u32, usize)> = best_per_asn
            .into_iter()
            .map(|(asn, (score, idx))| (asn, score, idx))
            .collect();
        scored.sort_by(|a, b| b.1.cmp(&a.1));
        scored.truncate(max_results);

        // Build results with range counts
        scored
            .into_iter()
            .map(|(_, _, idx)| {
                let entry = &self.entries[idx];
                let range_count = self.asn_index.get(&entry.asn).map_or(0, Vec::len);
                AsnSearchResult {
                    asn: entry.asn.clone(),
                    as_name: entry.as_name.clone(),
                    country: entry.country.clone(),
                    range_count,
                }
            })
            .collect()
    }

    /// Find all IP ranges belonging to a given ASN, returned as CIDR strings.
    /// Uses the pre-built ASN index for O(k) lookup instead of O(n) scan.
    pub fn find_all_by_asn(&self, asn: &str) -> Vec<String> {
        let indices = match self.asn_index.get(asn) {
            Some(v) => v,
            None => return Vec::new(),
        };
        indices
            .iter()
            .map(|&i| {
                let e = &self.entries[i];
                let plen = range_to_cidr(e.start, e.end);
                let mask = if plen == 0 { 0 } else { !((1u32 << (32 - plen)) - 1) };
                let net = e.start & mask;
                format!("{}/{}", std::net::Ipv4Addr::from(net), plen)
            })
            .collect()
    }
}

/// Port of range_to_cidr() from src/utils.c — finds the largest CIDR block
/// that is aligned to `start` and fits within [start, end].
pub fn range_to_cidr(start: u32, end: u32) -> u32 {
    if start == end {
        return 32;
    }
    let diff = start ^ end;
    let mut plen = diff.leading_zeros();
    while plen < 32 {
        let block_bits = 32 - plen;
        let mask = if block_bits == 32 {
            0
        } else {
            !((1u32 << block_bits) - 1)
        };
        let block_last = start as u64 + ((1u64 << block_bits) - 1);
        if (start & mask) == start && block_last <= end as u64 {
            break;
        }
        plen += 1;
    }
    plen
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE asns (
                start_ip INTEGER, end_ip INTEGER, asn TEXT, country TEXT, as_name TEXT
            );
            CREATE INDEX idx_ips ON asns (start_ip, end_ip);",
        )
        .unwrap();
        conn
    }

    fn insert_asn(conn: &Connection, start_ip: u32, end_ip: u32, asn: &str, country: &str) {
        conn.execute(
            "INSERT INTO asns (start_ip, end_ip, asn, country) VALUES (?1, ?2, ?3, ?4)",
            params![start_ip as i64, end_ip as i64, asn, country],
        )
        .unwrap();
    }

    // --- range_to_cidr tests ---

    #[test]
    fn test_range_to_cidr_single_ip() {
        assert_eq!(range_to_cidr(0x01020304, 0x01020304), 32);
    }

    #[test]
    fn test_range_to_cidr_exact_24() {
        // 1.2.3.0 - 1.2.3.255 = /24
        assert_eq!(range_to_cidr(0x01020300, 0x010203FF), 24);
    }

    #[test]
    fn test_range_to_cidr_exact_16() {
        // 10.0.0.0 - 10.0.255.255 = /16
        assert_eq!(range_to_cidr(0x0A000000, 0x0A00FFFF), 16);
    }

    #[test]
    fn test_range_to_cidr_non_aligned() {
        // 1.2.3.1 - 1.2.3.14 → non-aligned, falls back to /32
        assert_eq!(range_to_cidr(0x01020301, 0x0102030E), 32);
    }

    // --- AsnTable lookup tests ---

    #[test]
    fn test_lookup_hit() {
        let conn = setup_db();
        insert_asn(&conn, 0x0A000000, 0x0A0000FF, "AS1234", "US");
        let table = AsnTable::load_from_conn(&conn).unwrap();
        let entry = table.lookup(0x0A000001).unwrap();
        assert_eq!(entry.asn, "AS1234");
        assert_eq!(entry.country, "US");
    }

    #[test]
    fn test_lookup_boundary() {
        let conn = setup_db();
        insert_asn(&conn, 0x0A000000, 0x0A0000FF, "AS1234", "US");
        let table = AsnTable::load_from_conn(&conn).unwrap();
        // Start boundary
        let start = table.lookup(0x0A000000).unwrap();
        assert_eq!(start.asn, "AS1234");
        // End boundary
        let end = table.lookup(0x0A0000FF).unwrap();
        assert_eq!(end.asn, "AS1234");
    }

    #[test]
    fn test_lookup_miss() {
        let conn = setup_db();
        insert_asn(&conn, 0x0A000000, 0x0A0000FF, "AS1234", "US");
        let table = AsnTable::load_from_conn(&conn).unwrap();
        // Before range
        assert!(table.lookup(0x09FFFFFF).is_none());
        // After range
        assert!(table.lookup(0x0A000100).is_none());
    }

    #[test]
    fn test_load_empty_table() {
        let conn = setup_db();
        assert!(AsnTable::load_from_conn(&conn).is_none());
    }

    #[test]
    fn test_lookup_multiple_ranges() {
        let conn = setup_db();
        insert_asn(&conn, 0x0A000000, 0x0A00FFFF, "AS1111", "US"); // 10.0.0.0/16
        insert_asn(&conn, 0xC0A80000, 0xC0A800FF, "AS2222", "DE"); // 192.168.0.0/24
        let table = AsnTable::load_from_conn(&conn).unwrap();
        let e1 = table.lookup(0x0A000001).unwrap();
        assert_eq!(e1.asn, "AS1111");
        let e2 = table.lookup(0xC0A80010).unwrap();
        assert_eq!(e2.asn, "AS2222");
        // Gap between ranges
        assert!(table.lookup(0x0B000000).is_none());
    }

    #[test]
    fn test_lookup_cache_returns_same_result() {
        let conn = setup_db();
        insert_asn(&conn, 0x0A000000, 0x0A0000FF, "AS1234", "US");
        let table = AsnTable::load_from_conn(&conn).unwrap();
        // First call populates cache, second hits it
        let e1 = table.lookup(0x0A000001).unwrap();
        let e2 = table.lookup(0x0A000001).unwrap();
        assert_eq!(e1.asn, e2.asn);
        assert_eq!(e1.country, e2.country);
    }

    #[test]
    fn test_find_all_by_asn() {
        let conn = setup_db();
        insert_asn(&conn, 0x0A000000, 0x0A0000FF, "AS1234", "US"); // 10.0.0.0/24
        insert_asn(&conn, 0x0A010000, 0x0A0100FF, "AS1234", "US"); // 10.1.0.0/24
        insert_asn(&conn, 0xC0A80000, 0xC0A800FF, "AS9999", "DE"); // 192.168.0.0/24
        let table = AsnTable::load_from_conn(&conn).unwrap();
        let cidrs = table.find_all_by_asn("AS1234");
        assert_eq!(cidrs.len(), 2);
        assert!(cidrs.contains(&"10.0.0.0/24".to_string()));
        assert!(cidrs.contains(&"10.1.0.0/24".to_string()));
        // Different ASN not included
        assert!(table.find_all_by_asn("AS9999").len() == 1);
        assert!(table.find_all_by_asn("ASXXXX").is_empty());
    }

    #[test]
    fn test_fuzzy_search_basic() {
        let conn = setup_db();
        conn.execute(
            "INSERT INTO asns (start_ip, end_ip, asn, country, as_name) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![0x0A000000i64, 0x0A0000FFi64, "AS13335", "US", "CLOUDFLARE-NET"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO asns (start_ip, end_ip, asn, country, as_name) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![0xC0A80000i64, 0xC0A800FFi64, "AS16509", "US", "AMAZON-02"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO asns (start_ip, end_ip, asn, country, as_name) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![0xAC100000i64, 0xAC1000FFi64, "AS15169", "US", "GOOGLE"],
        )
        .unwrap();
        let table = AsnTable::load_from_conn(&conn).unwrap();
        let results = table.fuzzy_search("CLOUD", 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].asn, "AS13335");
        assert_eq!(results[0].as_name, "CLOUDFLARE-NET");
    }

    #[test]
    fn test_lookup_cache_stale_after_reload() {
        let conn = setup_db();
        insert_asn(&conn, 0x0A000000, 0x0A0000FF, "AS_OLD", "US");
        let table1 = AsnTable::load_from_conn(&conn).unwrap();
        // Populate cache
        let e1 = table1.lookup(0x0A000001).unwrap();
        assert_eq!(e1.asn, "AS_OLD");
        // Simulate DB update: new table with different data
        conn.execute("DELETE FROM asns", []).unwrap();
        insert_asn(&conn, 0x0A000000, 0x0A0000FF, "AS_NEW", "DE");
        let table2 = AsnTable::load_from_conn(&conn).unwrap();
        // New table has fresh cache — should return new data
        let e2 = table2.lookup(0x0A000001).unwrap();
        assert_eq!(e2.asn, "AS_NEW");
        assert_eq!(e2.country, "DE");
    }

    #[test]
    fn test_range_to_cidr_start_equals_end() {
        // Already tested in test_range_to_cidr_single_ip, but using different IP
        assert_eq!(range_to_cidr(0xC0A80001, 0xC0A80001), 32);
    }
}
