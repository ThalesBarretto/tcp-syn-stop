# System Overview: tcp-syn-stop suite

## 1. Introduction
The `tcp-syn-stop` suite is a carrier-grade, eBPF-powered network security appliance designed to mitigate volumetric TCP SYN flood and reflection attacks at wire-speed. The architecture separates concerns into a minimal BPF loader, a Rust policy engine, and a Rust TUI for observability.

## 2. The Threat Model
Volumetric SYN floods target the stateful nature of the TCP three-way handshake.
-   **Spoofed Floods**: Remote hosts send millions of SYN packets with fake source IPs. The kernel allocates "SYN queues" for each, leading to memory exhaustion.
-   **Reflection Attacks**: Malicious actors trick third-party servers into "reflecting" traffic toward a victim.
-   **The traditional failure**: Standard firewalls (`iptables`, `nftables`) operate after the kernel has already performed significant processing (interrupt handling, sk_buff allocation), which consumes 100% CPU during high-PPS floods even if the packets are eventually dropped.

## 3. 3-Tier Defense Architecture
This suite implements a "Defense in Depth" strategy across three distinct layers:

### Tier 1: Kernel-Level eBPF (The Steel Gate)
-   **Hook Point**: XDP (eXpress Data Path) at the NIC driver level.
-   **Mechanism**: Packets are inspected and dropped before any kernel memory (`sk_buff`) is allocated.
-   **Logic**: Drops packets from blacklisted IPs and dynamically identified spoofed sources.
-   **Benefit**: Can handle 1M+ PPS with negligible CPU impact.

### Tier 2: ASN Auto-Ban (Neighborhood Defense)
-   **Mechanism**: If multiple attacking IPs are detected within the same autonomous system (ASN), `syn-intel` blacklists the entire CIDR prefix.
-   **Logic**: Uses a tight CIDR alignment algorithm to ensure the ban covers the sender's neighborhood without causing collateral damage to adjacent networks. Bans escalate with exponential backoff and decay after a quiet window.
-   **Benefit**: Neutralizes botnets and distributed attacks by escalating from individual IPs to entire network segments.

### Tier 3: nftables Secondary Shield (The Policy Layer)
-   **Mechanism**: Standard Linux `nftables` rules.
-   **Logic**: Provides rate-limiting for non-spoofed (real IP) senders and secondary UDP flood protection for sensitive ports.
-   **Benefit**: Ensures that even "legitimate" traffic cannot overwhelm the application layer.

## 4. Logical Components
The suite is composed of three interconnected systems:

1.  **`tcp_syn_stop.bpf.c`**: The kernel-side engine. Implements the high-speed XDP filter and the SYN-ACK retransmission tracepoint.
2.  **`tcp_syn_stop` (C daemon)**: Minimal BPF loader. Loads the BPF skeleton, pins maps to bpffs, attaches XDP to interfaces, monitors liveness, and reloads whitelist/blacklist on SIGHUP. Drops capabilities after startup.
3.  **`syn-intel` (Rust)**: Policy engine. Consumes ringbuf events, manages TTL expiry via min-heap, evaluates autoban thresholds, and persists intelligence to SQLite via an async SPSC queue.
4.  **`syn-sight` (Rust)**: Observability TUI. Reads BPF maps directly for live telemetry and queries SQLite for forensic analysis.

## 5. High-Level Data Flow
```text
[ PACKET ARRIVAL ]
       |
       v
[ XDP FILTER (Tier 1) ] ----> [ DROP ] (Atomic Counter + Per-Port Counter)
       |                         |
       | (Pass)                  +--> [ RINGBUF EVENT ] (Rate-Limited Sample)
       v                                     |
[ TRACEPOINT (SYN-ACK) ]                     v
       |                          [ syn-intel (Policy Engine) ]
       | (Retransmission detected)           |
       v                                     +--> [ SQLITE DB ] (Intelligence)
[ DYNAMIC BLOCK MAP ] <----------------------+--> [ AUTOBAN ] (Tier 2)
       ^                                     |
       | (Pinned BPF maps)                   v
       +-- [ syn-sight TUI ] (Direct map reads + SQLite queries)
```

## 6. Core Design Goals
-   **Separation of Concerns**: The BPF loader runs as root with minimal logic; policy and persistence run as a dedicated unprivileged user.
-   **Zero-Lock Performance**: Telemetry and metrics are managed via PERCPU maps — no userspace locks in the data path.
-   **Surgical Precision**: Blocks only verified spoofers and malicious subnets while whitelisting trusted infrastructure.
-   **High Portability**: Using eBPF CO-RE and static Rust binaries ensures the suite runs across different kernel versions and distributions without local compilers. `syn-intel` extends this with BTF-powered map access — struct field offsets are resolved by name at runtime, eliminating silent breakage from C layout drift.
