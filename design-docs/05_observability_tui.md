# Observability & TUI (syn-sight)

## 1. Data Sources
`syn-sight` reads telemetry directly from two sources — no intermediary daemon protocol is needed:

### BPF Map Reads
-   **`drop_cnt`** (PERCPU_ARRAY): Summed across all CPUs for total drop count and PPS calculation.
-   **`drop_ips`** (LRU_HASH): Iterated for active blocked IPs (the "Active Swarm" table).
-   **`blacklist_cnt`** (LRU_HASH): Key count for active blacklist entries.
-   **`rb_fail_cnt`** (PERCPU_ARRAY): Summed for ringbuf overflow counter.
-   **`port_drop_counts`** (HASH): Iterated for per-port drop counts (Target Heatmap, top 10 by volume). Opened optionally — graceful fallback if map not yet pinned.

Maps are opened via `MapHandle::from_pinned_path()` from the bpffs pin directory (`/sys/fs/bpf/tcp_syn_stop/`).

### SQLite Database
-   **`drop_intel`**: Historical per-IP drop records for forensic neighborhood analysis.
-   **`autoban_state`**: Active and historical ban records.
-   **`asns`**: ASN table loaded into memory as `AsnTable` (sorted Vec + LRU cache, same as `syn-intel`).

## 2. Rust TUI Architecture
The `syn-sight` tool is a terminal dashboard built with **Rust** and **Ratatui**.

### Core Engine
-   **Live tab**: Reads BPF maps once per tick (default 1000ms). Computes PPS delta with **EMA smoothing** (α=0.3) on both global and per-ASN sparklines to reduce jitter. Ranks top senders by drop count and reads exact per-port drop counts from the `port_drop_counts` BPF map. Tracks fetch latency and data freshness.
-   **Forensics tab**: Queries SQLite at 30s intervals via a background thread (non-blocking `mpsc` channel, same pattern as ASN table loading). Computes bad neighborhoods by grouping IPs into ASN-aligned subnets, calculates ROI (packets mitigated × CPU-seconds saved), and produces reason breakdowns.
-   **Lists tab**: Reads whitelist/blacklist config files, displays with ASN and country columns from AsnTable. Supports add/delete with CIDR validation, atomic file save, and SIGHUP to daemon.

### Persistent HUD
A 3-row header persists across all three tabs, providing continuous situational awareness even when the operator deep-dives into Forensics or Lists:
-   **Row 0**: Segmented health bar (BPF/RB/Fetch) + status. Labels use `DIM` modifier so values pop.
-   **Row 1**: Total PPS sparkline — the aggregate attack intensity is always visible.
-   **Row 2**: Horizontal rule separator (`─`, DIM DarkGray) — anchors the HUD above tab content.

### Tab Layout (3 tabs, cycle with `Tab`)
1.  **Live**: Interface status, velocity-colored per-ASN PPS sparklines (Red=rising, Yellow=steady, Green=falling), active swarm table with ASN name, CC, and RIR "Reg" columns (with iceberg truncation indicator and blacklist filter), per-ASN aggregate toggle (`g`), target heatmap (BPF-backed exact counts), surgical preview + instrumentation footer.
2.  **Forensics**: Bad neighborhoods table (55%, sortable by Impact/Country/Name), ROI chart/table toggle (45%), reason breakdown bars, drilldown modal.
3.  **Lists**: Side-by-side whitelist/blacklist editor with ASN, CC, and RIR "Reg" columns. Features include: three-level sort (CC → ASN → CIDR numeric) with `[s]` save sorted (atomic tmp+rename); CIDR deduplication with `cidr_contains()` containment checks; cross-list conflict detection; `[c]` cleanup for redundant entries; `flock`-based advisory locking for concurrent TUI safety; `inotify` watcher reloads lists when another session modifies config files.

### Fuzzy Find
Press `/` on the Live or Lists tab to open a search bar at the bottom of the screen. Typing matches entries using `nucleo-matcher` (fuzzy scoring) across IP/CIDR, ASN, name, CC, and RIR fields. Results are ranked by score. `Up`/`Down` navigate matches, `Enter` commits the selection (jumps to that row), `Esc` restores the original scroll position. On the Lists tab, `Left`/`Right` switch between whitelist and blacklist while the search bar is open. The search bar shows match count (e.g., `/ cloud_ (3 of 847)`). On the Live tab, fuzzy find results refresh each tick as the swarm data updates.

### ASN Database Search
Press `n` to open a modal that fuzzy-searches the full ASN database (~515K entries). Mark multiple ASNs with `Space`, then `Enter` to add all their CIDR ranges to the whitelist or blacklist.

### Context-Aware Block/Whitelist
Press `b` or `w` on any selected entry (swarm IP, neighborhood, drilldown IP) to open a scope picker popup: block/whitelist the individual IP (/32), its subnet, or all CIDRs for its ASN. Changes are deduplicated, appended to the config file, and SIGHUP is sent.

## 3. Engineering for Distribution
To ensure the TUI runs on any Linux distribution, it uses **Static MUSL Linking**.

-   **Target**: `x86_64-unknown-linux-musl`
-   **Bundled Libraries**: `rusqlite` is bundled to avoid external dependencies on `libsqlite3`.
-   **Result**: A standalone binary that runs on any modern Linux kernel.

## 4. Observability Features

### Segmented Health Bar (in Persistent HUD)
A seven-segment indicator in the persistent HUD header, visible on all tabs:
-   **BPF**: Green if map reads succeed, Red if `fetch_data()` returned an error.
-   **RB**: Green if `rb_fail_cnt == 0`; Yellow if loss < 1%; Red if ≥ 1%. Shows loss percentage.
-   **Map%**: Drop IPs LRU utilization as percentage of the 65,536 cap. Yellow >50%, Red >90%.
-   **DB**: Freshness of the latest SNAPSHOT row from syn-intel. Green <120s, Yellow <600s, Red ≥600s.
-   **Cfg**: Config validation — counts CIDR parse errors in whitelist/blacklist files. Green if 0 errors, Red otherwise.
-   **Sync**: Transient segment after list writes + SIGHUP. Shows `Sync:N..` (Yellow) while verifying pending entries via LPM trie point-lookups, `Sync:OK` (Green) flash for 3 ticks on confirmation. Removes use 8s grace timeout (LPM can't verify absence).
-   **Fetch**: Green if latency < 100ms; Yellow if < 500ms; Red if ≥ 500ms.

### EMA Smoothing
Exponential Moving Average (α=0.3) applied to both global PPS and per-ASN PPS sparklines, reducing visual jitter from bursty traffic patterns while preserving trend visibility.

### Iceberg Visibility
When the active swarm table is truncated (capped at 1000 rows), the title shows `"Active Swarm (1000 of 45231 IPs)"` so operators know the full scale of the attack.

### Fetch Latency, Render Latency, Cache Hit Rate & Freshness
The footer displays `fetch: Xus (Y% hit) | render: Zus | Wms ago`. The fetch latency shows BPF map iteration cost; the render latency shows the cost of `terminal.draw()` (widget rendering + diff + flush); the cache hit percentage reveals whether the attack is "cache-breaking" (thousands of unique ASNs causing LRU eviction); the staleness counter distinguishes "zero PPS" (quiet) from "frozen UI" (fetch stuck or process starved). Cache hit rate is omitted when the ASN table is not loaded.

### DogStatsD Export
Optional `--statsd-addr host:port` flag enables UDP export of 12 metrics per tick. Hand-rolled StatsD protocol (no external crate). Non-blocking `send_to` — if the collector is down, sends silently fail with no impact on the 1s tick budget.

| Metric | Type | Description |
| :--- | :--- | :--- |
| `tcp_syn_stop.pps` | gauge | EMA-smoothed packets per second |
| `tcp_syn_stop.total_drops` | counter | Raw per-tick drop delta (monotonic counter for backend rate computation) |
| `tcp_syn_stop.active_blocks` | gauge | Dynamic block count |
| `tcp_syn_stop.blacklist_active` | gauge | Blacklist entry count |
| `tcp_syn_stop.rb_fail_cnt` | gauge | Ringbuf reservation failures |
| `tcp_syn_stop.fetch_latency_us` | gauge | BPF map read latency in microseconds |
| `tcp_syn_stop.render_latency_us` | gauge | UI render latency in microseconds |
| `tcp_syn_stop.drop_ips_total` | gauge | Total IPs across both BPF maps |
| `tcp_syn_stop.drop_ips_util_pct` | gauge | Drop IPs LRU utilization percentage |
| `tcp_syn_stop.db_freshness_s` | gauge | Seconds since last SNAPSHOT row from syn-intel |
| `tcp_syn_stop.config_errors` | gauge | CIDR parse errors in whitelist/blacklist files |
| `tcp_syn_stop.sync_pending` | gauge | Pending BPF sync operations after SIGHUP |

### Minimum Terminal Size Guard
If the terminal is smaller than 80x24, the render function displays a red warning message and skips all widget rendering. This prevents silent data truncation during incident response — the operator sees an explicit size requirement rather than a degraded layout with missing information.

### ASCII Sparkline Fallback
The `--ascii` flag replaces Unicode block elements (`▁▂▃▄▅▆▇█`) with ASCII characters (`. - = #`) in sparkline visualizations. This ensures usability in emergency SSH sessions where UTF-8 rendering may be broken (legacy terminals, serial consoles, misconfigured locale). The sparkline labels and numeric values remain identical in both modes.

### Semantic Sparkline Coloring
Per-ASN sparklines are colored by **impact velocity** rather than a fixed palette:
-   **Red**: PPS rising (current EMA > previous by >20%) — attack intensifying, demands attention.
-   **Yellow**: PPS steady (within 20%) — sustained attack, stable.
-   **Green**: PPS falling (current EMA < previous by >20%) — attack subsiding.
-   **DarkGray**: Inactive (both current and previous EMA near zero).

This eliminates "color as noise" — colors encode data (threat trend), not arbitrary identity.

### Surgical Preview
The Live tab footer previews what the `b` (block) key would do for the currently selected swarm entry: `[b] block 203.0.113.42/32 (AS13335)`. This reduces cognitive load by showing the scope before the operator opens the picker modal. The preview updates as the operator scrolls through the swarm table.

## 5. Visual Design

### Theme Architecture
A centralized `Theme` struct (`ui/theme.rs`) defines semantic colors (primary, danger, warning, success, muted, text) and border types (table: Rounded, modal: Double). Currently compile-time defaults; designed as the foundation for future runtime theming (Dark/Light/High-Contrast from TOML).

### Border Hierarchy
Visual depth is communicated through border type variation:
-   **Rounded** (`╭──╮`): Tables and data containers (~19 sites) — warmth, distinguishes content from terminal window.
-   **Double** (`╔══╗`): Modals and overlays (~6 sites) — high-contrast emphasis signals interactive overlay.
-   **None**: HUD — flat status bar feel, separated by horizontal rule instead of border.

### Typography
Two text modifiers create visual depth:
-   **BOLD**: Headers, active values, pulsing sparklines.
-   **DIM**: Metadata labels ("BPF:", "Fetch:"), footer metrics, horizontal rule. Pushes secondary information back so primary data pops.

### Color Pulse
When an ASN sparkline transitions to "rising" velocity (Red), the entire sparkline row receives `BOLD` emphasis for 3 ticks, then returns to normal weight. This draws the operator's eye to intensifying threats without the visual jitter of color flashes. Implemented via `asn_bold_ticks: HashMap<String, u8>` decremented each tick.

### Footer Information Architecture
The Live tab footer uses a left/right split: action hints and surgical preview left-aligned (normal DarkGray), performance metrics right-aligned (`DIM` DarkGray). This separates "what can I do?" from "how is the tool performing?"

## 6. Operational Usage
-   **Permissions**: Requires root or `CAP_BPF` to read pinned BPF maps.
-   **Performance**: Consumes <1% CPU even when monitoring million-PPS floods.
