# Failure Analysis & Theoretical Limits

This document provides a rigorous analysis of the system's behavior under extreme conditions, saturation points, and edge cases. This section is intended for academic review to demonstrate a deep understanding of the underlying eBPF and kernel mechanisms.

## 1. RingBuffer Saturation & Event Loss

The `rb` map is a `BPF_MAP_TYPE_RINGBUF` sized at 1MB (1,048,576 bytes).

### Theoretical Event Capacity
Each `struct event` is 8 bytes (32-bit IP + 16-bit Port + 8-bit Reason + padding).
Including ringbuffer overhead (8-byte header per record), each event consumes 16 bytes.
- **Max capacity**: ~65,536 events before the buffer must be drained by `syn-intel`.

### At what PPS does it drop?
- **Userspace Polling**: `syn-intel` polls the ringbuffer every 100ms in a non-blocking loop.
- **Limit**: If the kernel produces more than 655,360 events per second, the buffer will overflow between polls.
- **Mitigation**: The XDP path uses a **per-CPU token bucket** (`rl_map`, `PERCPU_ARRAY`) for `REASON_BLACKLIST` and `REASON_DYNAMIC` events. Each CPU emits at most one event per millisecond (`SAMPLE_INTERVAL_NS = 1,000,000 ns`). On an 8-CPU system, worst-case output is 8K events/sec × 16 bytes/event = ~128 KB/sec against the 1 MB ringbuf polled every 100 ms — that's ~800 events per poll cycle, well within the ~65K slot capacity. The buffer never overflows under any PPS. `REASON_NEW_BLOCK` events (from the tracepoint) are not rate-limited as they are critical for TTL scheduling.
- **Failure Mode**: When the buffer is full, `bpf_ringbuf_reserve` returns `NULL`. The kernel increments the `rb_fail_cnt` (a PERCPU_ARRAY) and silently drops the log event. **Packet filtering performance remains unaffected**, but telemetry and Auto-Ban intelligence will be degraded.

## 2. BPF Map Saturation

### `drop_ips` (LRU Hash)
- **Size**: 65,536 entries.
- **Behavior**: Being an `LRU_HASH`, the map never "fills up" in a way that returns an error. When the capacity is reached, the kernel automatically evicts the **Least Recently Used** entry to make room for the new one.
- **Consequence**: Under a massive attack from >65k unique IPs, the system will exhibit "thrashing." Older attackers will be unblocked prematurely to make room for newer ones. This is a graceful degradation that prevents memory exhaustion.

### `blacklist` (LPM Trie)
- **Size**: 4,096 entries.
- **Behavior**: Unlike the LRU hash, an `LPM_TRIE` is a fixed-size tree. If `syn-intel` attempts to insert a 4,097th subnet block (via Auto-Ban), the BPF syscall will return `-ENOSPC`.
- **Consequence**: New Auto-Bans will fail to apply. `syn-intel` logs a `warn!` but continues running. Existing blocks remain active.

## 3. Clock Anomalies & Monotonicity

### Clock Drift & Jumps
A common failure in distributed systems is the use of `SystemTime` (wall clock), which can jump backwards (NTP adjustments) or forwards (Leap seconds).
- **The Solution**: Both the BPF program (`bpf_ktime_get_ns()`) and `syn-intel` (`CLOCK_MONOTONIC` via `libc::clock_gettime`) use the kernel's monotonic clock for TTL and ban timing.
- **Wall-clock usage**: `syn-intel` uses wall-clock (`SystemTime`) only for persistence fields (`ban_end_wall`, `last_offense`) that must survive restarts. Monotonic timestamps are recomputed from remaining duration on restore.
- **Result**: The "Time Since Boot" is used for all runtime timing. If the system administrator changes the date/time of the server, packet filtering TTLs are **unaffected**. The system is immune to NTP-induced race conditions.

### Clock Overflow
The monotonic clock is a 64-bit nanosecond counter.
- **Limit**: $2^{64}$ nanoseconds $\approx$ 584 years.
- **Consequence**: Theoretical limit only; not a concern for operational lifespans.

## 4. Userspace Heap Saturation

`syn-intel` manages two heaps:

### TTL Heap
- **Capacity**: 131,072 entries (2x the BPF `drop_ips` map size to allow for lazy duplicates).
- **Failure Mode**: If more than 131k `NEW_BLOCK` events arrive before `syn-intel` can expire them, the heap will drop new entries and increment `heap_drop_total`.
- **Recovery**: The autoban evaluator iterates the full `drop_ips` map every tick and calls `ensure_tracked()` for each IP, repairing any entries missed due to heap overflow or ringbuf drops.

### Autoban Expiry Heap
- **Capacity**: 512 entries (matching the 256-slot offense table, with room for lazy duplicates).
- **Failure Mode**: If full, new autoban expirations cannot be scheduled. `syn-intel` logs a warning. The ban is applied to the BPF map but won't auto-expire — it would persist until service restart.

## 5. CPU & Interrupt Storms (Receiver Livelock)

At extremely high packet rates (e.g., 10M+ PPS), the CPU can enter a state of **Receiver Livelock**.
- **Mechanics**: The CPU spends 100% of its cycles in the XDP program (SoftIRQ context) dropping packets. Since `syn-intel` runs at a lower priority than kernel SoftIRQs, it may be "starved" of CPU.
- **Consequence**: `syn-intel` stops polling the ringbuffer, the ringbuffer overflows, and TTLs stop expiring. `tcp_syn_stop`'s watchdog heartbeat may also be delayed, but XDP filtering continues at wire-speed.
- **Mitigation**: This is an inherent property of Linux networking. Using XDP-Drop is the most efficient possible way to handle this; any other method (iptables, userspace sockets) would cause the system to collapse at much lower PPS.
