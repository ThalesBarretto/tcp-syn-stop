# Design Documentation: tcp-syn-stop suite

This directory contains the comprehensive technical design and architectural specifications for the `tcp-syn-stop` eBPF defense suite. Current version is tracked in the root `VERSION` file.

## Documentation Structure Plan

### 1. [System Overview](01_system_overview.md)
- **High-Level Goals**: Protection against volumetric SYN floods and reflection attacks.
- **3-Tier Defense Architecture**:
    - Tier 1: Kernel-level eBPF (XDP/Tracepoints).
    - Tier 2: ASN Auto-Ban (Neighborhood Defense) via `syn-intel`.
    - Tier 3: `nftables` Rate-Limiting.
- **Component Decomposition**: `tcp_syn_stop` (BPF loader), `syn-intel` (policy engine), `syn-sight` (TUI).
- **Data Flow Diagram**: From packet arrival at the NIC to visualization in the TUI.

### 2. [Kernel-Space Design (eBPF)](02_kernel_ebpf.md)
- **XDP Program (`xdp_drop_spoofed_syns`)**: Logic for wire-speed filtering, atomic counting, and ringbuf sampling.
- **Tracepoint Program (`tp__tcp_retransmit_synack`)**: Detection of spoofed victims via SYN-ACK retransmission monitoring.
- **Map Topologies**: Detailed breakdown of `LPM_TRIE` (CIDR), `LRU_HASH` (dynamic blocks), `PERCPU_ARRAY` (metrics), and `RINGBUF`.

### 3. [Userspace Architecture](03_userspace_daemon.md)
- **`tcp_syn_stop` (BPF Loader)**: Minimal C daemon — loads skeleton, attaches XDP, pins maps, monitors liveness, reloads config on SIGHUP. Drops to `CAP_BPF + CAP_NET_ADMIN` after startup.
- **`syn-intel` (Policy Engine)**: Rust binary — ringbuf consumer, TTL min-heap, autoban with exponential backoff, SQLite persistence via async SPSC queue.
- **System Integration**: Systemd `Type=notify`, Watchdog heartbeats, dedicated `_syn_intel` user, capability dropping.

### 4. [Algorithms & Intelligence](04_algorithms_intelligence.md)
- **TTL Expiration**: $O(k \log n)$ Min-Heap with lazy-deletion sched hash (in `syn-intel`).
- **ASN Lookup**: In-memory `AsnTable` with binary search + LRU cache (loaded from SQLite at startup).
- **Auto-Ban Logic**: Open-addressing offense table + exponential backoff with decay (in `syn-intel`).
- **BPF Map Iteration**: Batch iteration (256 entries/syscall) with key-by-key fallback.

### 5. [Observability & TUI (`syn-sight`)](05_observability_tui.md)
- **Data Sources**: Direct BPF map reads (`drop_cnt`, `drop_ips`, `blacklist_cnt`, `port_drop_counts`) and SQLite queries.
- **Rust Architecture**: `ratatui` rendering, 3-tab layout (Live, Forensics, Lists), in-memory `AsnTable`.
- **Observability Features**: EMA-smoothed PPS sparklines, segmented health bar (BPF/RB/Fetch), iceberg visibility, fetch latency & freshness indicator, DogStatsD UDP export (`--statsd-addr`).
- **Static Distribution**: Zero-dependency portability via MUSL static linking.

### 6. [Infrastructure & Lifecycle](06_infrastructure_lifecycle.md)
- **Build Environment**: Containerized build pipeline using `release.Dockerfile`.
- **Release Engineering**: Automating Debian packaging and GCS repository synchronization.
- **Security Posture**: Systemd sandboxing (`ProtectSystem=strict`), capability dropping, dedicated service user.

### 7. [Failure Analysis & Theoretical Limits](07_failure_analysis.md)
- **RingBuffer Saturation**: Analysis of event limits and per-CPU token bucket rate-limiting.
- **BPF Map Satiation**: Graceful LRU eviction vs. fixed-size LPM Trie `-ENOSPC` conditions.
- **Clock Anomalies**: Immunity to system clock jumps via `CLOCK_MONOTONIC`.
- **Heap Saturation**: `syn-intel` heap capacity (131K) and autoban reconciliation.
