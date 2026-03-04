# Userspace Architecture

## 1. Overview
The userspace side of the suite is split into two services: a minimal C daemon (`tcp_syn_stop`) that handles BPF lifecycle, and a Rust policy engine (`syn-intel`) that owns all intelligence logic.

## 2. `tcp_syn_stop` — BPF Loader (~250 lines)
The C daemon is deliberately minimal. Its responsibilities are:

### Startup Sequence
1.  Open and load the BPF skeleton (`tcp_syn_stop.bpf.c`).
2.  Pin all maps to bpffs (`/sys/fs/bpf/tcp_syn_stop/`).
3.  Load whitelist and blacklist from config files into LPM trie maps.
4.  Attach XDP to each specified interface.
5.  Attach the tracepoint program.
6.  Send `sd_notify(READY=1)`.
7.  Write PID file to `/run/tcp_syn_stop/tcp_syn_stop.pid`.
8.  Drop capabilities to `CAP_BPF + CAP_NET_ADMIN` via libcap.

### Main Loop
A simple 5-second sleep loop that:
-   Sends `sd_notify(WATCHDOG=1)` heartbeats.
-   Checks XDP liveness on each interface (re-attaches if detached).
-   Handles SIGHUP: reloads whitelist/blacklist config files (rate-limited to 30s).

### What It Does NOT Do
The daemon does not poll the ringbuffer, manage TTLs, run autoban logic, perform ASN lookups, write to SQLite, or serve metrics. All of that is `syn-intel`'s responsibility.

## 3. `syn-intel` — Policy Engine (Rust)
The Rust binary handles all policy, persistence, and intelligence logic.

### Startup
1.  Open pinned BPF maps from bpffs.
2.  **BTF Layout Resolution**: Queries the `drop_ips` map's BTF metadata to discover `drop_info` field offsets (`last_seen`, `count`) at runtime, making the Rust code resilient to C struct layout changes. Falls back to hardcoded offsets if the kernel or map has no BTF.
3.  Load ASN table from SQLite into memory (`AsnTable`: sorted Vec + LRU cache).
4.  Restore active autoban state from the database.
5.  Attach to the BPF ringbuffer for `NEW_BLOCK` events.

### Tick Loop (default 5s)
Each tick:
1.  **Ringbuf drain**: Process any pending `NEW_BLOCK` events — schedule TTL expiry in the min-heap.
2.  **TTL expiry**: Pop expired entries from the heap, check BPF `last_seen` for recent activity, reschedule if still active, otherwise delete from `drop_ips` map.
3.  **Map iteration**: Read all entries from `drop_ips` using batch iteration (256/syscall, fallback to key-by-key on older kernels). Sum PERCPU drop counters.
4.  **Autoban evaluate**: Group active blocked IPs by ASN prefix. If any prefix exceeds the threshold, insert the CIDR into the BPF blacklist LPM trie and push to the autoban expiry heap.
5.  **Autoban expire**: Pop expired bans, delete from BPF blacklist.
6.  **Persist**: Enqueue intelligence rows and autoban state changes to the async SPSC writer thread.

### Async Persistence (SPSC Queue)
ASN resolution happens on the main thread (the LRU cache is not thread-safe). Resolved rows are enqueued to a dedicated writer thread via a 16-slot SPSC circular buffer with mutex+condvar. The writer thread owns its own SQLite connection in WAL mode.

### Threading Model
-   **Main thread**: Ringbuf polling, TTL management, autoban evaluation, map reads.
-   **Writer thread**: SQLite persistence only, blocked on condvar when idle.

## 4. libnftables Integration
The BPF loader uses the native **`libnftables` API** (not `system()`) for nftables sync during config reload.
-   **Injection prevention**: CIDRs are reconstructed from parsed integers into canonical form — no user-supplied strings reach nftables.
-   **Atomic sync**: Sets are flushed and repopulated in a single transaction during SIGHUP reload.

## 5. System Integration
-   **Readiness (`sd_notify`)**: `tcp_syn_stop` signals `READY=1` after BPF programs are attached.
-   **Heartbeat (Watchdog)**: Sends `WATCHDOG=1` every 5 seconds. Systemd restarts the process if it hangs (15s timeout).
-   **Logging**: `tcp_syn_stop` auto-detects syslog vs TTY; `syn-intel` uses `env_logger`.
-   **Hot Reload (SIGHUP)**: Triggers whitelist/blacklist reload. Rate-limited to 30 seconds to prevent abuse.
-   **Capability Dropping**: After startup, `tcp_syn_stop` drops to `CAP_BPF + CAP_NET_ADMIN` and sets `NO_NEW_PRIVS`.
-   **Service Isolation**: `syn-intel` runs as `_syn_intel` user with `CAP_BPF + CAP_SYS_ADMIN`, full systemd sandbox.
