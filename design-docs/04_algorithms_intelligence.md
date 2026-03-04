# Algorithms & Intelligence

## 1. High-Performance TTL Expiry (`syn-intel`)
`syn-intel` manages tens of thousands of dynamic blocks. To maintain performance, it uses a **Min-Heap** + **scheduled-expiry hash table** for TTL management.

### The Problem with O(n)
A traditional approach iterates through the entire eBPF map every few seconds. At 65,000 entries, this consumes excessive CPU and cache bandwidth.

### The Min-Heap Solution ($O(k \log n)$)
1.  **Scheduling**: When the BPF tracepoint fires a `NEW_BLOCK` event, `syn-intel` receives it via ringbuf and adds it to a min-heap, keyed by `now() + TTL`.
2.  **Processing**: Every tick, `syn-intel` only pops entries from the heap where `expire_at <= current_time`.
3.  **Reschedule**: If a blocked IP's `last_seen` timestamp in the BPF map shows recent activity, `syn-intel` re-inserts it into the heap rather than deleting.
4.  **Lazy deletion**: Each tracked IP has exactly one authoritative `expire_at` in the sched hash table. Stale heap duplicates (from reschedules) are silently skipped on pop.
5.  **Scaling**: The cost is proportional only to the number of *expired* entries ($k$), not the total number of blocks ($n$).

### Sched Hash Table
An open-addressing hash table (131K slots, Knuth multiplicative hash, linear probing) maps each IP to its current `expire_at`. Tombstone-based deletion with compaction after 25% tombstone fill.

## 2. ASN Lookup System
To enable "Neighborhood Defense," `syn-intel` must know which network segment an IP belongs to.

### In-Memory AsnTable
-   **Loading**: At startup, `syn-intel` loads the full `asns` table (~515K rows) from SQLite into a sorted `Vec<AsnEntry>`.
-   **Lookup**: Binary search on `[start_ip, end_ip]` ranges — $O(\log n)$, microsecond-level.
-   **Caching**: An LRU cache (2048 entries) sits in front of binary search. Cache hits are $O(1)$. Hit/miss counters (`Cell<u64>`) track cache effectiveness; `syn-sight` displays the hit percentage in the Live tab footer to surface "cache-breaking" attacks.
-   **CIDR alignment**: `range_to_cidr(start, end)` computes the tightest prefix length from a numeric range.

### Why Not Per-Query SQLite?
The AsnTable approach eliminates per-IP SQLite queries during the hot path. With 65K active blocks, the old approach would issue 65K SQL queries per 60s tick. The in-memory table + LRU cache reduces this to zero SQL queries during normal operation.

## 3. ASN Auto-Ban Logic (`syn-intel`)
The Auto-Ban system escalates defenses from individual IPs to entire network prefixes.

### Offense Table
A 256-slot open-addressing hash table (Knuth multiplicative, linear probing) tracks per-prefix offense history: offense count, last offense time, ban end times (wall-clock for persistence, monotonic for heap comparison).

### Trigger Mechanism
-   On each tick, `syn-intel` groups active blocked IPs by ASN prefix.
-   If the count of unique IPs per prefix exceeds `autoban_threshold` (default: 5), the prefix is banned.

### Exponential Backoff
Ban duration follows `min(base × 2^(n-1), cap)`:
-   First offense: 300s (5 minutes).
-   Second: 600s, third: 1200s, ... up to `max_duration` (default: 86400s).

### Decay Window
If a prefix has no new offenses for `decay_window` seconds (default: 86400), its offense count resets to 0.

### Expiry Heap
A 512-cap min-heap tracks ban expirations. Lazy deletion guards against stale entries (ban_end_mono mismatch). Expired bans are removed from the BPF blacklist LPM trie.

## 4. BPF Map Iteration
`syn-intel` reads the `drop_ips` LRU_HASH map every tick to gather active block data.

### BTF-Powered CO-RE Map Access
The `drop_info` struct (value type of `drop_ips`) has its field offsets resolved from BTF at runtime rather than hardcoded in Rust. At startup, `syn-intel` queries the map's `btf_id` and `btf_value_type_id` via `bpf_map_info`, loads the BTF blob from the kernel, and walks the struct members to discover byte offsets for `last_seen` and `count` by name. This makes the Rust code resilient to C struct layout changes. If BTF is unavailable (older kernel, BPF loaded without BTF debug info), it falls back to the known hardcoded layout.

### Batch Iteration
On kernels >= 5.6, uses `bpf_map_lookup_batch` (256 entries per syscall) for efficient bulk reads. The raw value bytes are decoded via the BTF-resolved layout. Falls back to key-by-key iteration (`map.keys()` + individual `lookup()`) on older kernels that return `EINVAL` or `ENOSYS`.

## 5. Intelligence Persistence
Attack data is persisted to SQLite for forensic analysis by `syn-sight`.

### Async SPSC Queue
ASN resolution happens on the main thread (the LRU cache is not thread-safe). Resolved rows are enqueued to a dedicated SQLite writer thread via a 16-slot SPSC circular buffer (mutex + condvar). The writer thread owns its own SQLite connection in WAL mode, ensuring main-thread latency is bounded.
