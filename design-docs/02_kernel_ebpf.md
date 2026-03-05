# Kernel-Space Design: eBPF Engine

## 1. Overview
The kernel-space component consists of two high-performance programs that interact via shared maps. It leverages **CO-RE (Compile Once, Run Everywhere)** to ensure the same binary can run on multiple kernel versions without modification.

## 2. XDP Filter: `xdp_drop_spoofed_syns`
This program is the suite's "front line," running at the earliest point in the NIC driver.

### Processing Logic
1.  **Parsing**: Extracts Ethernet, IPv4, and TCP headers. Packets that are not TCP or IPv4 are passed immediately to minimize overhead.
2.  **Whitelist Check**: Matches the source IP against the `whitelist` LPM trie. If matched, the packet is passed.
3.  **Blacklist Check**: Matches against the `blacklist` LPM trie (contains static blocks and dynamic ASN bans).
4.  **Dynamic Block Check**: Lookups the source IP in the `drop_ips` LRU hash map.
5.  **Drop Execution**:
    -   If a block is found, the program:
        -   **Atomically Increments** the per-CPU counter in `drop_cnt`.
        -   **Per-port accounting**: Atomically increments the `port_drop_counts` hash map entry for the destination port (network byte order key). Creates the entry on first hit.
        -   **Updates** the `last_seen` timestamp in the `drop_ips` map.
        -   **Rate-limited sample**: At most one drop event per CPU per millisecond is sent to the userspace `ringbuf` via a per-CPU token bucket (`rl_map`), guaranteeing full fidelity at low PPS and bounded overhead under flood.
        -   **Returns** `XDP_DROP`.
6.  **No Stateless ACK Clearing**: Only `SYN && !ACK` packets are filtered. All other TCP packets (`ACK`, data, `FIN`) pass unconditionally. Blocked IPs expire via `syn-intel`'s TTL heap. Stateless ACK-based eviction of `drop_ips` entries was removed because spoofed `ACK` packets would trivially bypass the filter.

## 3. Tracepoint: `tp__tcp_retransmit_synack`
This program acts as the suite's "intelligence gatherer," identifying spoofed sources by monitoring the kernel's SYN-ACK retransmission path via the **stable tracing ABI**.

### Logic
-   **Trigger**: Attaches to `tracepoint/tcp/tcp_retransmit_synack`. This tracepoint fires when the kernel retransmits a SYN-ACK because it hasn't received an ACK from the client.
-   **Detection**: Since legitimate clients almost always ACK the first SYN-ACK, a retransmission is a high-confidence signal that the original `SYN` was spoofed or part of a reflection attack.
-   **Action**: The program reads `daddr` directly from the tracepoint context struct (`trace_event_raw_tcp_retransmit_synack`) and adds it to the `drop_ips` map. No `BPF_CORE_READ` through internal kernel structs is needed.
-   **Notification**: Emits a `REASON_NEW_BLOCK` event to the ringbuffer so userspace can schedule a TTL expiry in its min-heap.

## 4. Map Topology

| Map Name | Type | Purpose | Max Entries |
| :--- | :--- | :--- | :--- |
| `whitelist` | `LPM_TRIE` | CIDR blocks that are never blocked. | 131,072 |
| `blacklist` | `LPM_TRIE` | Static blocks and dynamic ASN Auto-Bans. | 131,072 |
| `drop_ips` | `LRU_HASH` | Dynamic list of actively blocked spoofers. | 65,536 |
| `blacklist_cnt`| `LRU_HASH` | Per-IP drop counters for blacklisted sources. | 65,536 |
| `drop_cnt` | `PERCPU_ARRAY` | Lockless global packet drop counter. | 1 |
| `rb_fail_cnt` | `PERCPU_ARRAY` | Ringbuf reservation failure counter. | 1 |
| `rb` | `RINGBUF` | High-speed event channel to `syn-intel`. | 1,048,576 |
| `rl_map` | `PERCPU_ARRAY` | Per-CPU rate-limit timestamp for ringbuf sampling. | 1 |
| `port_drop_counts`| `HASH` | Per-port drop counter (u16 key → u64 value). | 65,536 |
| `ignored_ports`| `HASH` | Destination ports to exclude from filtering. | 256 |

## 5. Performance Engineering
-   **Atomic Counting**: Uses `__sync_fetch_and_add` for the `drop_cnt` map, ensuring 100% accurate metrics without the overhead of userspace locks.
-   **Per-CPU Arrays**: Used for metrics to ensure that multiple CPU cores never contend for the same memory, maximizing cache locality.
-   **Per-CPU Token Bucket**: Drop events are rate-limited to the ringbuf via `rl_map`, a `PERCPU_ARRAY` that stores the last sample timestamp per CPU. At most one event per CPU per millisecond (`SAMPLE_INTERVAL_NS = 1,000,000 ns`) is emitted, giving deterministic O(N_cpus × 1K) events/sec worst-case. This replaces probabilistic 1% sampling: every drop is captured at low PPS, while ringbuf pressure is capped under flood.
-   **Ringbuffer Overflows**: The ringbuffer is sized significantly larger than the rate-limited event rate. If the buffer fills, the kernel increments `rb_fail_cnt` and drops events (prioritizing filtering over logging). `syn-intel` monitors this counter.
-   **LPM Tries**: Uses the Longest Prefix Match algorithm for CIDR support, allowing the system to handle thousands of subnet blocks with $O(\log n)$ lookup complexity.
