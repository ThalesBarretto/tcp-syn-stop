<img width="1408" height="768" alt="kapybara_vps" src="https://github.com/user-attachments/assets/28e84723-0a5a-4273-b5f8-54990355eab3" />

# eBPF TCP SYN Flood Protection Suite

> A high-performance, enterprise-grade defense suite leveraging **libbpf**, **CO-RE**, and **Rust**.
> Current version is tracked in the [`VERSION`](VERSION) file.

This project provides a robust, 3-tier defense architecture designed to protect Linux servers from volumetric floods (TCP SYN, UDP garbage, Reflection Attacks) before they impact the system's CPU and networking stack.

## Components

The suite consists of three components:
1.  **`tcp_syn_stop`**: Minimal C/eBPF daemon — loads BPF programs, attaches XDP to interfaces, pins maps, monitors liveness, and reloads whitelist/blacklist on SIGHUP.
2.  **`syn-intel`**: Rust policy engine — consumes BPF ringbuf events, manages TTL expiry (min-heap), autoban (prefix offense tracking + exponential backoff), and persists intelligence to SQLite.
3.  **`syn-sight`**: Rust TUI — reads BPF maps and the SQLite database directly for real-time and forensic visualization.

---

## Architecture & How It Works

### Tier 1: Kernel-Level eBPF (XDP & Tracepoint)
Operates at the lowest level of the network stack (the NIC driver), dropping malicious traffic at wire-speed.
-   **Tracepoint (`tcp/tcp_retransmit_synack`)**: Detects spoofed-source SYN floods by catching SYN-ACK retransmissions — when our kernel retransmits a SYN-ACK to a destination that never completes the handshake, that destination is a forged source address. The IP is added to the dynamic block map.
-   **XDP Filter**: Drops subsequent SYNs from dynamically flagged IPs and all traffic from manually blacklisted CIDRs at wire speed, before `sk_buff` allocation or conntrack. Every drop is atomically counted in the kernel for 100% accurate metrics.

### Tier 2: ASN Auto-Ban (Neighborhood Watch)
If multiple flooding IPs belong to the same ASN prefix, `syn-intel` automatically blacklists the **entire prefix** using a tight CIDR alignment algorithm. Bans escalate with exponential backoff and decay after a quiet window.

### Tier 3: nftables Secondary Shield
Provides rate-limiting for non-spoofed attackers and UDP flood protection for sensitive ports (like VPN 443).

---

## Real-Time Observability

### `syn-sight` Dashboard
The suite includes a modern Rust-based TUI that reads BPF maps and the SQLite database directly. Cycle between tabs with `Tab`.

A persistent **HUD** (health bar + Total PPS sparkline + separator) spans the top 3 rows across all tabs, so the operator never loses attack context when switching views. Tables use rounded borders (`╭──╮`), modals use double borders (`╔══╗`), and metadata labels use `DIM` styling to create visual depth.

#### Live Tab
-   **Attack Pulse**: Per-ASN PPS sparklines with **velocity coloring** — Red (rising), Yellow (steady), Green (falling). No color legend needed; color encodes threat trend.
-   **Active Swarm**: Real-time table of top attacking IPs and ASNs. Shows iceberg indicator when truncated (e.g., "1000 of 45231 IPs").
-   **Target Heatmap**: Top 10 targeted ports with exact drop counts from BPF `port_drop_counts` map.
-   **Surgical Preview**: Footer shows what `b` would do for the selected IP (`[b] block 203.0.113.42/32 (AS13335)`).
-   **Instrumentation**: Fetch latency, ASN cache hit rate, render latency, and data freshness.
<img width="1920" height="1200" alt="image" src="https://github.com/user-attachments/assets/814d49ee-0dcd-4f75-b85f-aba586de0a22" />


#### Forensics Tab
-   **Bad Neighborhoods**: Subnet clusters ranked by attack impact, with ASN name and country. Sort by Impact, Country, or Name with `s`.
-   **Drilldown**: Press `Enter` on a neighborhood to see per-IP detail within that subnet, including port diversity.
-   **ROI Analysis**: Toggle between chart and table views (`v`) showing packets mitigated and CPU seconds saved over time.
-   **Reason Breakdown**: Visual bars showing BLACKLIST vs DYNAMIC drop proportions.
<img width="1920" height="1200" alt="image" src="https://github.com/user-attachments/assets/45b9d6cc-46ac-406f-96ce-4d86f1fff497" />



#### Lists Tab
-   **Whitelist/Blacklist Editor**: Side-by-side view of both config files with ASN and country columns. Switch focus with `Left`/`Right`.
-   **Add Entry**: Press `a` to open the CIDR input modal with validation matching the daemon's rules.
-   **Delete Entry**: Press `d` to remove the selected entry (with confirmation).
-   Changes are saved atomically and a SIGHUP is sent to the daemon for hot reload.

#### Keyboard Shortcuts

| Key | Context | Action |
|-----|---------|--------|
| `Tab` | Global | Cycle tabs: Live → Forensics → Lists |
| `q` | Global | Quit |
| `?` | Global | Toggle help overlay |
| `b` | Live / Forensics | Block — scope picker: IP /32, subnet, or all ASN ranges |
| `w` | Live / Forensics | Whitelist — same scope picker |
| `f` | Live | Hide/show blacklisted IPs from swarm |
| `g` | Live | Toggle per-IP ↔ per-ASN aggregate view |
| `s` | Forensics | Cycle neighborhood sort: Impact → Country → Name |
| `v` | Forensics | Toggle ROI view: chart ↔ table |
| `f` | Forensics | Cycle neighborhood time window filter |
| `t` | Forensics | Cycle bot classification threshold |
| `Enter` | Forensics neighborhoods | Open per-IP drilldown |
| `Esc` | Any modal | Close overlay |
| `/` | Global | Open ASN search |
| `a` | Lists | Add entry to focused list |
| `d` / `Delete` | Lists | Delete selected entry |
| `s` | Lists | Save list entries in sorted order |
| `c` | Lists | Remove redundant/overlapping entries |
| `Left`/`Right` | Lists | Switch whitelist/blacklist focus |
| `Up`/`Down` | Tables | Navigate rows |

**Usage:**
```bash
sudo syn-sight

# With DogStatsD metrics export
sudo syn-sight --statsd-addr 127.0.0.1:8125

# ASCII mode for terminals without Unicode support
sudo syn-sight --ascii
```

**`syn-sight` Arguments:**
-   `--pin-dir <path>`: BPF pin directory (default: `/sys/fs/bpf/tcp_syn_stop`).
-   `-i, --interval <ms>`: Polling interval in milliseconds (default: 1000).
-   `--db-path <path>`: SQLite database path (default: `/opt/tcp_syn_stop/ip2asn.db`).
-   `--statsd-addr <host:port>`: Enable DogStatsD UDP export (disabled by default).
-   `--ascii`: Use ASCII characters instead of Unicode block elements for sparklines.
-   `--json`: Output current state as JSON and exit (single-shot, no TUI).
-   `-h, --help`: Print help.

---

## Installation & Usage

### Prerequisites
- Linux Kernel 5.8+
- `libbpf-dev`, `libelf-dev`, `zlib1g-dev`, `libnftables-dev`, `libcap-dev`
- `nftables`

### Automated Build Pipeline (Recommended)
To ensure a consistent, repeatable build environment regardless of your host OS (e.g., Arch, Fedora), use the provided containerized pipeline:

```bash
# Build and package at current version
./release.sh

# Bump debian revision (4.0-2 → 4.0-3), commit, tag, then build
./release.sh --bump

# Bump minor version (4.0-2 → 4.1-1)
./release.sh --bump --minor

# Bump major version (4.0-2 → 5.0-1)
./release.sh --bump --major

# Build and publish to GCS repository
./release.sh --publish

# Combine: bump + build + publish
./release.sh --bump --publish
```
This script automatically handles the Debian-based build environment, C dependencies, and static Rust compilation. When `--bump` is used, it updates the `VERSION` file, creates a git commit, and tags the release as `vX.Y-Z`.

### Versioning

The single source of truth is the `VERSION` file in the repo root (format: `MAJOR.MINOR-REVISION`). The Makefile reads it at build time and injects it into the `.deb` control file and the man page. Never edit version numbers anywhere else.

### Manual Build from Source
If you prefer to build directly on a Debian-compatible host:
```bash
make
```

### Running
The suite uses two systemd services:
```bash
# Start the BPF loader (loads XDP, pins maps, monitors liveness)
sudo systemctl enable --now tcp_syn_stop

# Start the policy engine (TTL expiry, autoban, persistence)
sudo systemctl enable --now syn-intel
```

Or manually:
```bash
# Terminal 1: BPF loader
sudo ./tcp_syn_stop -i eth0

# Terminal 2: Policy engine
sudo ./syn-intel --ttl 60 --autoban-threshold 5
```

### `tcp_syn_stop` Arguments
-   `-i, --interface <iface>`: Network interface to protect (repeatable, max 8).
-   `-w, --whitelist <file>`: Path to whitelist.conf (default: `/etc/tcp_syn_stop/whitelist.conf`).
-   `-b, --blacklist <file>`: Path to blacklist.conf (default: `/etc/tcp_syn_stop/blacklist.conf`).
-   `-l, --logfile <file>`: Log to file instead of stdout/syslog.
-   `-v, --verbose`: Enable debug logging and libbpf output.

### `syn-intel` Arguments
-   `--ttl <secs>`: Dynamic block duration in seconds (default: 60).
-   `--interval <secs>`: Tick interval in seconds (default: 5).
-   `--autoban-threshold <n>`: Unique IPs/ASN to trigger prefix ban (default: 5).
-   `--autoban-duration <secs>`: Base ban duration (default: 300).
-   `--autoban-max-duration <secs>`: Max ban duration cap (default: 86400).
-   `--autoban-decay-window <secs>`: Quiet time to reset offense count (default: 86400).
-   `--json`: Emit structured JSON logs.
-   `-v, --verbose`: Enable debug logging.

---

## Operations

### Hot Reload
Reload whitelist/blacklist without dropping the filter:
```bash
sudo pkill -HUP tcp_syn_stop
```

### System Integration
The project includes two hardened **systemd** unit files:
-   **`tcp_syn_stop.service`**: Runs as root with `ProtectSystem=full`, drops to `CAP_BPF + CAP_NET_ADMIN` after startup via libcap. Watchdog heartbeat every 5s. Uses `NoNewPrivileges`, `PrivateDevices`, `MemoryDenyWriteExecute`.
-   **`syn-intel.service`**: Runs as root with `ProtectSystem=full`. Sandboxed with `NoNewPrivileges`, `PrivateDevices`, `MemoryDenyWriteExecute`, and kernel protection directives.

---

## Theoretical Limits & Failure Modes

This system is designed for high-performance production environments. Its failure modes are predictable and documented for academic review:

### 1. Throughput & Event Loss
- **Filtering**: XDP drops packets at wire-speed (millions of PPS). This never fails unless the CPU is 100% saturated by the NIC's SoftIRQ (Receiver Livelock).
- **Logging**: The RingBuffer can handle ~655,000 events/second. If exceeded, the kernel increments `rb_fail_cnt` and drops logs, but **filtering remains active**.
- **Sampling**: A per-CPU token bucket rate-limits drop events to at most one per CPU per millisecond, giving deterministic bounded overhead under flood while capturing every drop at low PPS.

### 2. Map Saturation
- **Dynamic Blocks (`drop_ips`)**: Uses an **LRU Hash** (65,536 entries). When full, the oldest attacker is evicted to make room for the newest. The system degrades gracefully by "forgetting" old attackers.
- **Auto-Bans (`blacklist`)**: Uses an **LPM Trie** (4,096 entries). If full, new subnet blocks return `-ENOSPC`. Existing blocks are unaffected.

### 3. Clock & Consistency
- **Monotonicity**: Uses `CLOCK_MONOTONIC` (`bpf_ktime_get_ns`) for all TTL and timing logic. The system is immune to system clock jumps, NTP adjustments, or leap seconds.
- **Persistence**: TTLs are managed by `syn-intel` via an $O(\log n)$ Min-Heap (131K capacity), ensuring that even with 65,000 active blocks, expiry checks consume negligible CPU.

For a deep dive into these limits, see [Design Doc 07: Failure Analysis](design-docs/07_failure_analysis.md).

---

## Why XDP — Not Just nftables + conntrack

A natural question: Linux already has nftables and nf_conntrack for stateful packet filtering. Why add BPF?

### The conntrack exhaustion problem

SYN floods are specifically devastating to nf_conntrack because every SYN creates a conntrack entry in `SYN_RECV` state. The default `nf_conntrack_max` is typically 65,536–262,144, and each entry costs ~300 bytes of kernel memory. A SYN flood at even 100K PPS fills the table in seconds. When the table is full, the kernel drops **all** new connections — legitimate ones included. That conntrack table collapse is the actual denial-of-service, not bandwidth saturation.

Tuning `nf_conntrack_max` higher trades memory for headroom but degrades hash table performance. Lowering `nf_conntrack_tcp_timeout_syn_recv` risks dropping slow legitimate clients. `tcp_syncookies` avoids SYN queue exhaustion but still burns CPU on cookie generation (SipHash per SYN) and every SYN still traverses the full network stack — `sk_buff` allocation, netfilter traversal, conntrack lookup — before the cookie is even computed. At 10M PPS this per-packet overhead is the bottleneck, not the queue. Note: since Linux 2.6.26, syncookies encode window scaling, SACK, and ECN in the TCP timestamp field, so TCP option degradation is no longer a concern for modern peers.

### What XDP buys

Packets dropped at XDP never reach the kernel networking stack. No `sk_buff` allocation (~300–500 bytes per packet, cache-hostile at scale), no netfilter traversal, and critically — **no conntrack entry**. The conntrack table stays healthy for legitimate connections. This is the real value: not raw PPS throughput, but protecting the stateful layer from exhaustion.

### Why the tracepoint approach matters

**The reflection attack.** An attacker sends millions of SYNs to our server with forged source IPs — the victim's addresses. Our kernel, seeing valid SYNs, dutifully replies with SYN-ACKs to each spoofed source. The victim — who never sent any SYN — receives a flood of unsolicited SYN-ACKs from *our* server. Our server has become an unwitting reflector, amplifying the attack. Meanwhile, our SYN queue and conntrack table fill up with half-open connections that will never complete, degrading our own service.

**Detection via the kernel's TCP state machine.** nftables-only detection is inherently blunt. Rate-limiting `ct state new` is a global threshold that punishes legitimate clients and attackers equally. `nft meters` can do per-IP rate limiting, but the meter table itself becomes an exhaustion vector under spoofed-source floods.

The `tcp/tcp_retransmit_synack` tracepoint exploits the kernel's own retransmission logic as a spoofed-source oracle. When our kernel sends a SYN-ACK and the remote end never ACKs, the kernel retransmits the SYN-ACK after a full RTO timeout. That retransmission fires the tracepoint — and the destination IP in that retransmit is the spoofed victim's address. A legitimate slow client completes the handshake before the retransmit timer fires. A spoofed source never will. The false-positive rate is essentially zero by construction, which no rate-limiting rule can match.

Once detected, the victim's IP is inserted into the `drop_ips` BPF map, and the XDP filter silently drops all subsequent SYNs bearing that forged source — stopping both our own resource exhaustion and the reflected SYN-ACK flood hitting the victim.

### What this program cannot replace

nftables remains essential for:
- **Stateful filtering** — XDP has no connection state; "allow ESTABLISHED,RELATED" requires conntrack.
- **NAT** — SNAT/DNAT is a netfilter function.
- **Complex policy** — "allow SSH from management VLAN, HTTPS from anywhere, drop the rest" is nftables' domain.
- **Protocol helpers** — FTP, SIP, and other multi-connection protocols need ct helpers.

The architecture uses both: XDP as the high-performance first stage that keeps the stateful layer healthy under pressure, nftables as the full-featured firewall behind it. The `ip saddr @blacklisted_sources drop` rule in nftables is a redundant backstop — defense in depth.

### When this complexity is justified

If SYN floods stay under ~50K PPS, `syncookies` plus sensible nftables rules plus tuned conntrack timeouts are sufficient. The complexity cost of a BPF-based system (compilation toolchain, BTF dependencies, capability requirements, three cooperating daemons) pays for itself when attack volume threatens conntrack stability or when surgical per-IP blocking is needed without collateral damage to legitimate traffic. The program fills the gap between "syncookies can handle it" and "you need commercial DDoS mitigation."

---
