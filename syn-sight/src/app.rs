// SPDX-License-Identifier: GPL-2.0-only
//! Core application state and event loop orchestration.
//!
//! `App` owns all runtime state: the active tab, live metrics, forensics data,
//! list editor state, and overlay modals (ASN search, add-action, drilldown).
//! Data fetch scheduling (forensics refresh, metrics socket reads) and file I/O
//! for whitelist/blacklist config changes are coordinated here.

use crate::asn_table::{self, AsnTable, AsnTableData};
use crate::bpf;
use crate::bpf::BpfMaps;
use crate::ui::theme::Theme;
use crate::forensics;
use crate::forensics::SwarmEntry;
use crate::protocol::{Attacker, IfaceInfo, Instrumentation, Metrics, SystemState};
use crate::time_fmt;
use anyhow::{anyhow, Result};
use ratatui::style::Color;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::forensics::ForensicsState;

#[derive(Debug, PartialEq)]
pub enum Tab {
    Live,
    Forensics,
    Lists,
}

#[derive(Debug, PartialEq)]
pub enum RoiViewMode {
    Chart,
    Table,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SwarmView {
    PerIP,
    PerASN,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SwarmAsnEntry {
    pub asn: String,
    pub as_name: String,
    pub country: String,
    pub ip_count: usize,
    pub total_drops: u64,
    pub last_seen_ns: u64,
    pub has_blacklist: bool,
    pub has_dynamic: bool,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ListsFocus {
    Whitelist,
    Blacklist,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum InputMode {
    Normal,
    Editing,
    ConfirmDelete,
    ConfirmCleanup,
}

pub struct ListEntry {
    pub cidr: String,
    pub asn: String,
    pub as_name: String,
    pub country: String,
}

pub struct BlacklistEntry {
    pub cidr: String,
    pub drop_count: u64,
    pub asn: String,
    pub as_name: String,
    pub country: String,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum NeighborhoodSort {
    Impact,
    Country,
    Name,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TimeWindow {
    FiveMin,
    OneHour,
    TwentyFourHour,
}

impl TimeWindow {
    pub fn next(self) -> Self {
        match self {
            Self::FiveMin => Self::OneHour,
            Self::OneHour => Self::TwentyFourHour,
            Self::TwentyFourHour => Self::FiveMin,
        }
    }

    pub fn as_ns(self) -> u64 {
        match self {
            Self::FiveMin => 5 * 60 * 1_000_000_000,
            Self::OneHour => 60 * 60 * 1_000_000_000,
            Self::TwentyFourHour => 24 * 60 * 60 * 1_000_000_000,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::FiveMin => "5m",
            Self::OneHour => "1h",
            Self::TwentyFourHour => "24h",
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum BotThreshold {
    One,
    Two,
    Five,
}

impl BotThreshold {
    pub fn next(self) -> Self {
        match self {
            Self::One => Self::Two,
            Self::Two => Self::Five,
            Self::Five => Self::One,
        }
    }

    pub fn value(self) -> i64 {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Five => 5,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::One => ">1",
            Self::Two => ">2",
            Self::Five => ">5",
        }
    }
}

pub struct AsnSearchState {
    pub query: String,
    pub results: Vec<asn_table::AsnSearchResult>,
    pub scroll: usize,
    pub marked: std::collections::HashSet<usize>,
    pub query_changed_at: Option<Instant>,
}

pub struct AddActionState {
    pub target: ListsFocus,
    pub ip_cidr: Option<String>,
    pub subnet_cidr: Option<String>,
    pub asn_label: String,
    pub asn_cidrs: Vec<String>,
}

pub struct SubnetPickerState {
    pub target: ListsFocus,
    pub asn_label: String,
    pub cidrs: Vec<String>,
    pub scroll: usize,
    pub marked: std::collections::HashSet<usize>,
}

/// A config-file entry awaiting BPF map confirmation after SIGHUP.
#[derive(Clone)]
pub(crate) struct PendingSync {
    pub cidr: String,
    pub list: ListsFocus,
    pub op: SyncOp,
    pub created_at: Instant,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum SyncOp {
    Add,
    Remove,
}

/// Aggregate sync status for the health bar.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum SyncStatus {
    /// No pending sync operations.
    Idle,
    /// Waiting for BPF maps to reflect N pending entries.
    Pending(usize),
    /// All entries confirmed; ticks remaining for the "OK" flash.
    Confirmed(u8),
}

/// Inotify watcher for whitelist/blacklist config files.
///
/// Watches the parent directories of both config files for `IN_MOVED_TO`,
/// `IN_MODIFY`, and `IN_CREATE` events.  Atomic renames (used by
/// `remove_from_file` and `rewrite_sorted`) fire `IN_MOVED_TO` on the
/// directory; `append_to_file` fires `IN_MODIFY` on the file itself.
///
/// The inotify fd is set non-blocking so `poll_changed()` can be called
/// every tick without stalling the event loop.
pub(crate) struct ListFileWatcher {
    fd: i32,
    whitelist_name: String,
    blacklist_name: String,
}

impl ListFileWatcher {
    /// Set up inotify watches on the parent directories of both config paths.
    /// Returns `None` if inotify cannot be initialised (non-fatal).
    pub fn new(whitelist_path: &str, blacklist_path: &str) -> Option<Self> {
        use std::path::Path;

        // SAFETY: inotify_init1 is a standard Linux syscall.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return None;
        }

        let wl_dir = Path::new(whitelist_path).parent().unwrap_or(Path::new("/"));
        let bl_dir = Path::new(blacklist_path).parent().unwrap_or(Path::new("/"));

        let mask = libc::IN_MOVED_TO | libc::IN_MODIFY | libc::IN_CREATE;

        // Watch whitelist directory.
        let wl_dir_c = std::ffi::CString::new(wl_dir.to_str().unwrap_or("/")).ok()?;
        // SAFETY: valid fd, valid path, standard flags.
        let ret = unsafe { libc::inotify_add_watch(fd, wl_dir_c.as_ptr(), mask) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return None;
        }

        // Watch blacklist directory (skip if same as whitelist dir).
        if bl_dir != wl_dir {
            let bl_dir_c = std::ffi::CString::new(bl_dir.to_str().unwrap_or("/")).ok()?;
            let ret = unsafe { libc::inotify_add_watch(fd, bl_dir_c.as_ptr(), mask) };
            if ret < 0 {
                // Non-fatal: whitelist dir is still watched.
            }
        }

        let whitelist_name = Path::new(whitelist_path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let blacklist_name = Path::new(blacklist_path)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();

        Some(Self {
            fd,
            whitelist_name,
            blacklist_name,
        })
    }

    /// Non-blocking check: returns `true` if any watched config file was
    /// modified since the last call.  Drains all pending inotify events.
    pub fn poll_changed(&self) -> bool {
        // inotify_event is 16 bytes + variable name; 512 bytes handles many events.
        let mut buf = [0u8; 512];
        let mut changed = false;

        loop {
            // SAFETY: valid fd, valid buffer, standard read.
            let n = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            #[allow(clippy::cast_sign_loss)]
            let n = n as usize;

            let mut offset = 0;
            while offset + std::mem::size_of::<libc::inotify_event>() <= n {
                // SAFETY: inotify guarantees aligned inotify_event structs in the buffer.
                let event = unsafe {
                    &*(buf.as_ptr().add(offset).cast::<libc::inotify_event>())
                };
                #[allow(clippy::cast_sign_loss)]
                let name_len = event.len as usize;
                let total = std::mem::size_of::<libc::inotify_event>() + name_len;

                if name_len > 0 {
                    let name_start = offset + std::mem::size_of::<libc::inotify_event>();
                    let name_end = (name_start + name_len).min(n);
                    let name_bytes = &buf[name_start..name_end];
                    let name = std::ffi::CStr::from_bytes_until_nul(name_bytes)
                        .map(|c| c.to_string_lossy())
                        .unwrap_or_default();
                    if name == self.whitelist_name.as_str()
                        || name == self.blacklist_name.as_str()
                    {
                        changed = true;
                    }
                }

                offset += total;
            }
        }

        changed
    }
}

impl Drop for ListFileWatcher {
    fn drop(&mut self) {
        // SAFETY: valid fd from inotify_init1.
        unsafe { libc::close(self.fd) };
    }
}

pub const ASN_PALETTE: [Color; 8] = [
    Color::Red,
    Color::Yellow,
    Color::Green,
    Color::Cyan,
    Color::Blue,
    Color::Magenta,
    Color::LightRed,
    Color::LightGreen,
];

pub struct App {
    pub(crate) bpf_maps: Option<BpfMaps>,
    pub(crate) db_path: String,
    pub(crate) state: Option<SystemState>,
    pub(crate) pps_history: VecDeque<u64>,
    pub(crate) max_pps: u64,
    pub(crate) active_tab: Tab,
    pub(crate) forensics: Option<ForensicsState>,
    pub(crate) forensics_error: Option<String>,
    pub(crate) forensics_last_fetch: Option<Instant>,
    // Swarm table (BPF map-backed)
    pub(crate) swarm_entries: Vec<SwarmEntry>,
    pub(crate) swarm_scroll: usize,
    pub(crate) swarm_view: SwarmView,
    pub(crate) swarm_asn_filter: Option<String>,
    pub(crate) swarm_agg_entries: Vec<SwarmAsnEntry>,
    pub(crate) swarm_agg_scroll: usize,
    // BPF-backed reason breakdown (DYNAMIC / BLACKLIST totals)
    pub(crate) reason_breakdown: Vec<(String, u64)>,
    // BPF-backed per-CIDR blacklist drop counts
    pub(crate) blacklist_drop_counts: HashMap<String, u64>,
    // Forensics tab state
    pub(crate) neighborhoods: Vec<forensics::Neighborhood>,
    pub(crate) neighborhood_time_window: TimeWindow,
    pub(crate) neighborhood_bot_threshold: BotThreshold,
    pub(crate) neighborhood_scroll: usize,
    pub(crate) roi_view_mode: RoiViewMode,
    pub(crate) neighborhood_sort: NeighborhoodSort,
    pub(crate) drilldown: Option<forensics::DrilldownState>,
    pub(crate) drilldown_scroll: usize,
    // In-memory ASN lookup table (loaded once from SQLite)
    pub(crate) asn_table: Option<AsnTable>,
    pub(crate) asn_load_rx: Option<mpsc::Receiver<AsnTableData>>,
    // Per-ASN PPS tracking + BPF PPS delta
    pub(crate) asn_countries: HashMap<String, String>,
    pub(crate) asn_names: HashMap<String, String>,
    pub(crate) prev_attacker_counts: HashMap<String, u64>,
    pub(crate) prev_total_drops: u64,
    pub(crate) prev_total_drops_bpf: u64,
    pub(crate) asn_pps_history: HashMap<String, VecDeque<f64>>,
    pub(crate) asn_palette: Vec<(String, Color)>,
    // Lists tab state
    pub(crate) whitelist_path: String,
    pub(crate) blacklist_path: String,
    pub(crate) whitelist_entries: Vec<ListEntry>,
    pub(crate) blacklist_entries: Vec<BlacklistEntry>,
    pub(crate) add_action: Option<AddActionState>,
    pub(crate) subnet_picker: Option<SubnetPickerState>,
    pub(crate) asn_search: Option<AsnSearchState>,
    pub(crate) show_help: bool,
    // EMA smoothing
    pub(crate) pps_ema: f64,
    pub(crate) asn_pps_ema: HashMap<String, f64>,
    pub(crate) asn_pps_prev_ema: HashMap<String, f64>,
    // Iceberg visibility
    pub(crate) drop_ips_total: usize,
    // Fetch latency & freshness
    pub(crate) last_fetch_us: u32,
    pub(crate) last_fetch_at: Instant,
    // BPF health (tracks whether last fetch succeeded)
    pub(crate) bpf_fetch_ok: bool,
    // DogStatsD export
    pub(crate) statsd_socket: Option<(UdpSocket, String)>,
    // ASN cache observability
    pub(crate) asn_cache_hit_pct: Option<f64>,
    // Background forensics fetch
    pub(crate) forensics_rx: Option<mpsc::Receiver<Result<ForensicsState, String>>>,
    // UI render latency
    pub(crate) last_render_us: u32,
    // ASCII sparkline fallback
    pub(crate) use_ascii: bool,
    // Visual theme (foundation for future runtime theming)
    #[allow(dead_code)]
    pub(crate) theme: Theme,
    // Color pulse: ticks remaining for BOLD emphasis on rising ASNs
    pub(crate) asn_bold_ticks: HashMap<String, u8>,
    // Session timing + attack state
    pub(crate) session_start: Instant,
    pub(crate) last_attack_end: Option<Instant>,
    pub(crate) attack_active: bool,
    pub(crate) any_key_pressed: bool,
    // Port classification suggestion (computed from heatmap data)
    pub(crate) port_suggestion: Option<String>,
    // Truecolor terminal detection (COLORTERM env)
    pub(crate) truecolor: bool,
    // Blacklist filter: hide already-dealt-with IPs from swarm
    pub(crate) hide_blacklisted: bool,
    pub(crate) lists_focus: ListsFocus,
    pub(crate) whitelist_scroll: usize,
    pub(crate) blacklist_scroll: usize,
    pub(crate) lists_input_mode: InputMode,
    pub(crate) lists_input_buf: String,
    pub(crate) lists_status_msg: Option<(String, Instant)>,
    pub(crate) cleanup_candidates: Vec<String>,
    // Production robustness metrics
    pub(crate) drop_ips_util_pct: f64,
    pub(crate) db_freshness_s: Option<u64>,
    pub(crate) config_errors: Vec<String>,
    // BPF sync verification
    pub(crate) pending_syncs: Vec<PendingSync>,
    pub(crate) sync_status: SyncStatus,
    // Inotify watcher for external config file changes
    pub(crate) list_watcher: Option<ListFileWatcher>,
}

pub fn should_refresh_forensics(last: Option<Instant>, now: Instant) -> bool {
    match last {
        None => true,
        Some(t) => now.duration_since(t) >= Duration::from_secs(30),
    }
}

impl App {
    pub fn new(bpf_maps: Option<BpfMaps>, db_path: String, whitelist_path: String, blacklist_path: String) -> App {
        let list_watcher = ListFileWatcher::new(&whitelist_path, &blacklist_path);
        App {
            bpf_maps,
            db_path,
            state: None,
            pps_history: VecDeque::with_capacity(100),
            max_pps: 1,
            active_tab: Tab::Live,
            forensics: None,
            forensics_error: None,
            forensics_last_fetch: None,
            swarm_entries: Vec::new(),
            swarm_scroll: 0,
            swarm_view: SwarmView::PerIP,
            swarm_asn_filter: None,
            swarm_agg_entries: Vec::new(),
            swarm_agg_scroll: 0,
            asn_table: None,
            asn_load_rx: None,
            reason_breakdown: Vec::new(),
            blacklist_drop_counts: HashMap::new(),
            neighborhoods: Vec::new(),
            neighborhood_time_window: TimeWindow::OneHour,
            neighborhood_bot_threshold: BotThreshold::Two,
            neighborhood_scroll: 0,
            roi_view_mode: RoiViewMode::Chart,
            neighborhood_sort: NeighborhoodSort::Impact,
            drilldown: None,
            drilldown_scroll: 0,
            asn_countries: HashMap::new(),
            asn_names: HashMap::new(),
            prev_attacker_counts: HashMap::new(),
            prev_total_drops: 0,
            prev_total_drops_bpf: 0,
            asn_pps_history: HashMap::new(),
            asn_palette: Vec::new(),
            whitelist_path,
            blacklist_path,
            whitelist_entries: Vec::new(),
            blacklist_entries: Vec::new(),
            add_action: None,
            subnet_picker: None,
            asn_search: None,
            show_help: false,
            pps_ema: 0.0,
            asn_pps_ema: HashMap::new(),
            asn_pps_prev_ema: HashMap::new(),
            drop_ips_total: 0,
            last_fetch_us: 0,
            last_fetch_at: Instant::now(),
            bpf_fetch_ok: true,
            statsd_socket: None,
            asn_cache_hit_pct: None,
            forensics_rx: None,
            last_render_us: 0,
            use_ascii: false,
            theme: Theme::default(),
            asn_bold_ticks: HashMap::new(),
            session_start: Instant::now(),
            last_attack_end: None,
            attack_active: false,
            any_key_pressed: false,
            port_suggestion: None,
            truecolor: std::env::var("COLORTERM")
                .map(|v| v == "truecolor" || v == "24bit")
                .unwrap_or(false),
            hide_blacklisted: false,
            lists_focus: ListsFocus::Blacklist,
            whitelist_scroll: 0,
            blacklist_scroll: 0,
            lists_input_mode: InputMode::Normal,
            lists_input_buf: String::new(),
            lists_status_msg: None,
            cleanup_candidates: Vec::new(),
            drop_ips_util_pct: 0.0,
            db_freshness_s: None,
            config_errors: Vec::new(),
            pending_syncs: Vec::new(),
            sync_status: SyncStatus::Idle,
            list_watcher,
        }
    }

    pub fn record_pps(&mut self, pps: u64) {
        self.pps_history.push_back(pps);
        if self.pps_history.len() > 100 {
            self.pps_history.pop_front();
        }
        if pps > self.max_pps {
            self.max_pps = pps;
        }
    }

    pub fn fetch_data(&mut self) -> Result<()> {
        let start = Instant::now();

        let result = self.fetch_data_inner();

        #[allow(clippy::cast_possible_truncation)]
        {
            self.last_fetch_us = start.elapsed().as_micros() as u32;
        }
        self.last_fetch_at = Instant::now();
        self.bpf_fetch_ok = result.is_ok();

        result
    }

    fn fetch_data_inner(&mut self) -> Result<()> {
        let maps = self.bpf_maps.as_ref().ok_or_else(|| anyhow!("BPF maps not available"))?;

        let total_drops = maps.read_drop_cnt()?;
        let drop_ips = maps.iter_drop_ips()?;
        let blacklist_ips = maps.iter_blacklist_cnt()?;
        #[allow(clippy::cast_possible_truncation)]
        let active_blocks = drop_ips.len() as u32;
        #[allow(clippy::cast_possible_truncation)]
        let blacklist_active = blacklist_ips.len() as u32;
        let rb_fail = maps.read_rb_fail_cnt()?;

        // PPS: delta of total_drops between ticks.
        let pps = if self.prev_total_drops_bpf > 0 {
            total_drops.saturating_sub(self.prev_total_drops_bpf)
        } else {
            0
        };
        self.prev_total_drops_bpf = total_drops;

        // EMA smoothing on PPS
        const EMA_ALPHA: f64 = 0.3;
        self.pps_ema = EMA_ALPHA * (pps as f64) + (1.0 - EMA_ALPHA) * self.pps_ema;

        let top_attackers = top_k_attackers(&drop_ips, 5, self.asn_table.as_ref());

        // Top ports from BPF port_drop_counts map
        let top_ports = match maps.iter_port_counts() {
            Ok(mut port_counts) => {
                port_counts.sort_by(|a, b| b.1.cmp(&a.1));
                port_counts
                    .into_iter()
                    .take(10)
                    .map(|(port_nbo, count)| {
                        use crate::protocol::PortStat;
                        PortStat {
                            port: u16::from_be(port_nbo),
                            hits: count,
                        }
                    })
                    .collect()
            }
            Err(_) => vec![],
        };

        let new_state = SystemState {
            uptime_secs: 0,
            metrics: Metrics {
                total_drops,
                latest_pps: pps,
                active_blocks,
                blacklist_active,
            },
            top_attackers,
            top_ports,
            ifaces: bpf::detect_xdp_ifaces()
                .into_iter()
                .map(|(name, native)| IfaceInfo { name, native })
                .collect(),
            instrumentation: Instrumentation {
                ringbuf_reserve_fails: rb_fail,
                ..Default::default()
            },
        };

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        self.record_pps(self.pps_ema as u64);

        // PPS transition tracking: detect attack start/end
        if pps > 0 {
            self.attack_active = true;
        } else if self.attack_active {
            self.last_attack_end = Some(Instant::now());
            self.attack_active = false;
        }

        // Port classification suggestion from heatmap data
        self.port_suggestion = {
            let top = &new_state.top_ports;
            let total_port_hits: u64 = top.iter().map(|p| p.hits).sum();
            if total_port_hits > 0 {
                if let Some(first) = top.first() {
                    if first.hits > total_port_hits * 80 / 100 {
                        #[allow(clippy::cast_precision_loss)]
                        let pct = first.hits as f64 / total_port_hits as f64 * 100.0;
                        Some(format!("Port {} targeted ({:.0}%)", first.port, pct))
                    } else if top.len() >= 5 && first.hits < total_port_hits * 30 / 100 {
                        Some("Indiscriminate flood".into())
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };

        self.state = Some(new_state);

        // Map utilization: drop_ips LRU is capped at 65536 entries
        const MAX_DROP_IPS: f64 = 65536.0;
        self.drop_ips_util_pct = (active_blocks as f64 / MAX_DROP_IPS) * 100.0;

        // Build swarm from BPF maps (filtered_total = iceberg count respecting blacklist filter)
        // ASN aggregation happens on the full set before per-IP truncation.
        let now_ns = time_fmt::clock_boottime_ns();
        let (swarm, filtered_total, agg) = build_swarm_entries(
            &drop_ips, &blacklist_ips, now_ns,
            self.asn_table.as_ref(), 1000, self.hide_blacklisted,
        );
        self.swarm_entries = swarm;
        self.drop_ips_total = filtered_total;
        self.swarm_agg_entries = agg;

        // Clamp per-IP scroll using effective (filtered) length
        let eff_len = self.effective_swarm_len();
        if eff_len == 0 {
            self.swarm_scroll = 0;
        } else if self.swarm_scroll >= eff_len {
            self.swarm_scroll = eff_len - 1;
        }

        // Clamp aggregate scroll
        if self.swarm_agg_entries.is_empty() {
            self.swarm_agg_scroll = 0;
        } else if self.swarm_agg_scroll >= self.swarm_agg_entries.len() {
            self.swarm_agg_scroll = self.swarm_agg_entries.len() - 1;
        }

        // Build neighborhoods from BPF maps
        self.neighborhoods = build_neighborhoods(
            &drop_ips,
            &blacklist_ips,
            now_ns,
            self.neighborhood_time_window.as_ns(),
            self.neighborhood_bot_threshold.value(),
            self.asn_table.as_ref(),
            self.neighborhood_sort,
        );
        if self.neighborhood_scroll >= self.neighborhoods.len() && !self.neighborhoods.is_empty() {
            self.neighborhood_scroll = self.neighborhoods.len() - 1;
        }

        // Reason breakdown from BPF maps
        let dynamic_total: u64 = drop_ips.iter().map(|(_, di)| di.count).sum();
        let blacklist_total: u64 = blacklist_ips.iter().map(|(_, di)| di.count).sum();
        let mut breakdown = Vec::new();
        if dynamic_total > 0 {
            breakdown.push(("DYNAMIC".to_string(), dynamic_total));
        }
        if blacklist_total > 0 {
            breakdown.push(("BLACKLIST".to_string(), blacklist_total));
        }
        breakdown.sort_by(|a, b| b.1.cmp(&a.1));
        self.reason_breakdown = breakdown;

        // Per-CIDR blacklist drop counts from BPF maps
        self.blacklist_drop_counts =
            build_blacklist_drop_counts(&blacklist_ips, &self.blacklist_entries);

        // ASN cache hit rate (after all lookups in this tick)
        self.asn_cache_hit_pct = self.asn_table.as_ref().and_then(AsnTable::cache_hit_pct);

        Ok(())
    }

    /// Start loading AsnTable in a background thread (non-blocking).
    pub fn load_asn_table_async(&mut self) {
        if self.asn_table.is_some() || self.asn_load_rx.is_some() {
            return; // Already loaded or loading
        }
        let db_path = self.db_path.clone();
        let (tx, rx) = mpsc::channel();
        self.asn_load_rx = Some(rx);
        std::thread::spawn(move || {
            if let Some(data) = AsnTable::load_data(&db_path) {
                let _ = tx.send(data);
            }
        });
    }

    /// Check if background load is complete (non-blocking).
    pub fn poll_asn_table(&mut self) {
        if let Some(ref rx) = self.asn_load_rx {
            if let Ok(data) = rx.try_recv() {
                self.asn_table = Some(AsnTable::from_data(data));
                self.asn_load_rx = None;
            }
        }
    }

    /// Returns true if ASN table is currently loading in background.
    pub fn is_asn_loading(&self) -> bool {
        self.asn_load_rx.is_some()
    }

    pub fn fetch_forensics(&mut self) -> Result<()> {
        if !should_refresh_forensics(self.forensics_last_fetch, Instant::now()) {
            return Ok(());
        }
        self.fetch_forensics_inner();
        Ok(())
    }

    pub fn fetch_forensics_now(&mut self) -> Result<()> {
        self.fetch_forensics_inner();
        Ok(())
    }

    fn fetch_forensics_inner(&mut self) {
        match forensics::fetch_forensics(&self.db_path) {
            Ok(fs) => {
                self.update_db_freshness(fs.latest_snapshot_ts);
                self.forensics = Some(fs);
                self.forensics_error = None;
            }
            Err(e) => {
                self.forensics_error = Some(e.to_string());
            }
        }
        self.forensics_last_fetch = Some(Instant::now());
    }

    /// Compute DB freshness from the latest SNAPSHOT timestamp.
    #[allow(clippy::cast_sign_loss)]
    fn update_db_freshness(&mut self, latest_ts: Option<i64>) {
        if let Some(ts) = latest_ts {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.db_freshness_s = Some(now.saturating_sub(ts as u64));
        } else {
            self.db_freshness_s = None;
        }
    }

    pub fn force_forensics_refresh(&mut self) {
        self.forensics_last_fetch = None;
        self.forensics_rx = None;
    }

    /// Spawn a background thread to fetch forensics data (non-blocking).
    pub fn fetch_forensics_async(&mut self) {
        if !should_refresh_forensics(self.forensics_last_fetch, Instant::now()) {
            return;
        }
        if self.forensics_rx.is_some() {
            return; // fetch already in flight
        }
        let db_path = self.db_path.clone();
        let (tx, rx) = mpsc::channel();
        self.forensics_rx = Some(rx);
        // Mark as fetched immediately to prevent re-spawning on next tick
        self.forensics_last_fetch = Some(Instant::now());
        std::thread::spawn(move || {
            let result = forensics::fetch_forensics(&db_path)
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
        });
    }

    /// Poll for completed background forensics fetch (non-blocking).
    pub fn poll_forensics(&mut self) {
        if let Some(ref rx) = self.forensics_rx {
            if let Ok(result) = rx.try_recv() {
                match result {
                    Ok(fs) => {
                        self.update_db_freshness(fs.latest_snapshot_ts);
                        self.forensics = Some(fs);
                        self.forensics_error = None;
                    }
                    Err(e) => {
                        self.forensics_error = Some(e);
                    }
                }
                self.forensics_rx = None;
            }
        }
    }

    pub fn run_asn_search(&mut self) {
        if let Some(ref mut search) = self.asn_search {
            if search.query.is_empty() {
                search.results.clear();
                search.scroll = 0;
                return;
            }
            if let Some(table) = &self.asn_table {
                search.results = table.fuzzy_search(&search.query, 50);
                if search.scroll >= search.results.len() && !search.results.is_empty() {
                    search.scroll = search.results.len() - 1;
                } else if search.results.is_empty() {
                    search.scroll = 0;
                }
            }
        }
    }

    pub fn sort_neighborhoods(&mut self) {
        match self.neighborhood_sort {
            NeighborhoodSort::Impact => {
                self.neighborhoods
                    .sort_by(|a, b| b.total_impact.cmp(&a.total_impact));
            }
            NeighborhoodSort::Country => {
                self.neighborhoods
                    .sort_by(|a, b| a.country.cmp(&b.country).then(b.total_impact.cmp(&a.total_impact)));
            }
            NeighborhoodSort::Name => {
                self.neighborhoods
                    .sort_by(|a, b| a.as_name.cmp(&b.as_name).then(b.total_impact.cmp(&a.total_impact)));
            }
        }
    }

    pub fn effective_swarm_entries(&self) -> Vec<&SwarmEntry> {
        match &self.swarm_asn_filter {
            Some(asn) => self.swarm_entries.iter().filter(|e| e.asn == *asn).collect(),
            None => self.swarm_entries.iter().collect(),
        }
    }

    pub fn effective_swarm_len(&self) -> usize {
        match &self.swarm_asn_filter {
            Some(asn) => self.swarm_entries.iter().filter(|e| e.asn == *asn).count(),
            None => self.swarm_entries.len(),
        }
    }

    pub fn swarm_scroll_down(&mut self) {
        let len = self.effective_swarm_len();
        if len > 0 && self.swarm_scroll < len - 1 {
            self.swarm_scroll += 1;
        }
    }

    pub fn swarm_scroll_up(&mut self) {
        if self.swarm_scroll > 0 {
            self.swarm_scroll -= 1;
        }
    }

    pub fn swarm_agg_scroll_down(&mut self) {
        let len = self.swarm_agg_entries.len();
        if len > 0 && self.swarm_agg_scroll < len - 1 {
            self.swarm_agg_scroll += 1;
        }
    }

    pub fn swarm_agg_scroll_up(&mut self) {
        if self.swarm_agg_scroll > 0 {
            self.swarm_agg_scroll -= 1;
        }
    }

    pub fn build_add_action_from_asn(&self, target: ListsFocus, asn: &str) -> Option<AddActionState> {
        if asn.is_empty() || asn == "Unknown" {
            return None;
        }
        let asn_cidrs = self
            .asn_table
            .as_ref()
            .map(|t| t.find_all_by_asn(asn))
            .unwrap_or_default();
        if asn_cidrs.is_empty() {
            return None;
        }
        let first_cidr = asn_cidrs.first().cloned();
        Some(AddActionState {
            target,
            ip_cidr: None,
            subnet_cidr: first_cidr,
            asn_label: asn.to_string(),
            asn_cidrs,
        })
    }

    pub fn neighborhood_scroll_down(&mut self) {
        let len = self.neighborhoods.len();
        if len > 0 && self.neighborhood_scroll < len - 1 {
            self.neighborhood_scroll += 1;
        }
    }

    pub fn neighborhood_scroll_up(&mut self) {
        if self.neighborhood_scroll > 0 {
            self.neighborhood_scroll -= 1;
        }
    }

    pub fn drilldown_scroll_down(&mut self) {
        let len = self.drilldown.as_ref().map_or(0, |d| d.ips.len());
        if len > 0 && self.drilldown_scroll < len - 1 {
            self.drilldown_scroll += 1;
        }
    }

    pub fn drilldown_scroll_up(&mut self) {
        if self.drilldown_scroll > 0 {
            self.drilldown_scroll -= 1;
        }
    }

    pub fn lists_scroll_down(&mut self) {
        match self.lists_focus {
            ListsFocus::Whitelist => {
                if !self.whitelist_entries.is_empty() && self.whitelist_scroll < self.whitelist_entries.len() - 1 {
                    self.whitelist_scroll += 1;
                }
            }
            ListsFocus::Blacklist => {
                if !self.blacklist_entries.is_empty() && self.blacklist_scroll < self.blacklist_entries.len() - 1 {
                    self.blacklist_scroll += 1;
                }
            }
        }
    }

    pub fn lists_scroll_up(&mut self) {
        match self.lists_focus {
            ListsFocus::Whitelist => {
                if self.whitelist_scroll > 0 {
                    self.whitelist_scroll -= 1;
                }
            }
            ListsFocus::Blacklist => {
                if self.blacklist_scroll > 0 {
                    self.blacklist_scroll -= 1;
                }
            }
        }
    }

    pub fn load_lists(&mut self) {
        use crate::validation::parse_cidr;

        // Validate config files for health bar
        let (_, wl_errors) = crate::validation::validate_config_file(&self.whitelist_path);
        let (_, bl_errors) = crate::validation::validate_config_file(&self.blacklist_path);
        self.config_errors = [wl_errors, bl_errors].concat();

        let raw_wl = Self::read_cidr_file(&self.whitelist_path);
        self.whitelist_entries = raw_wl
            .into_iter()
            .map(|cidr| {
                let (asn, as_name, country) = self.lookup_cidr_asn(&cidr);
                ListEntry { cidr, asn, as_name, country }
            })
            .collect();
        self.whitelist_entries.sort_by(|a, b| {
            a.country.cmp(&b.country)
                .then_with(|| a.asn.cmp(&b.asn))
                .then_with(|| {
                    let pa = parse_cidr(&a.cidr).unwrap_or((0, 0));
                    let pb = parse_cidr(&b.cidr).unwrap_or((0, 0));
                    pa.cmp(&pb)
                })
        });

        let raw_bl = Self::read_cidr_file(&self.blacklist_path);
        self.blacklist_entries = raw_bl
            .into_iter()
            .map(|cidr| {
                let drop_count = self.blacklist_drop_counts.get(&cidr).copied().unwrap_or(0);
                let (asn, as_name, country) = self.lookup_cidr_asn(&cidr);
                BlacklistEntry {
                    cidr,
                    drop_count,
                    asn,
                    as_name,
                    country,
                }
            })
            .collect();
        self.blacklist_entries.sort_by(|a, b| {
            a.country.cmp(&b.country)
                .then_with(|| a.asn.cmp(&b.asn))
                .then_with(|| {
                    let pa = parse_cidr(&a.cidr).unwrap_or((0, 0));
                    let pb = parse_cidr(&b.cidr).unwrap_or((0, 0));
                    pa.cmp(&pb)
                })
        });
    }

    pub fn lookup_cidr_asn(&self, cidr: &str) -> (String, String, String) {
        let ip_str = cidr.split('/').next().unwrap_or("");
        if let Ok(addr) = ip_str.parse::<Ipv4Addr>() {
            if let Some(entry) = self.asn_table.as_ref().and_then(|t| t.lookup(u32::from(addr))) {
                return (entry.asn.clone(), entry.as_name.clone(), entry.country.clone());
            }
        }
        (String::new(), String::new(), String::new())
    }

    fn read_cidr_file(path: &str) -> Vec<String> {
        match std::fs::read_to_string(path) {
            Ok(content) => content
                .lines()
                .map(|l| l.split('#').next().unwrap_or("").trim())
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Rewrite the focused list file in the current (sorted) in-memory order.
    /// Acquire an exclusive advisory lock on `{path}.lock`.
    ///
    /// Returns the lock-file `File` as a guard — the lock is released when
    /// it is dropped.  Uses `LOCK_NB` so a second TUI session gets an
    /// immediate error instead of blocking.
    fn try_lock_list(path: &str) -> Result<std::fs::File, String> {
        use std::os::unix::io::AsRawFd;

        let lock_path = format!("{path}.lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| format!("Cannot create lock file: {e}"))?;

        // SAFETY: valid fd, standard POSIX flock flags.
        let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            Err("List locked by another session".to_string())
        } else {
            Ok(lock_file)
        }
    }

    pub fn rewrite_sorted(&mut self) {
        use std::io::Write;
        let (path, cidrs): (String, Vec<String>) = match self.lists_focus {
            ListsFocus::Whitelist => (
                self.whitelist_path.clone(),
                self.whitelist_entries.iter().map(|e| e.cidr.clone()).collect(),
            ),
            ListsFocus::Blacklist => (
                self.blacklist_path.clone(),
                self.blacklist_entries.iter().map(|e| e.cidr.clone()).collect(),
            ),
        };
        let _lock = match Self::try_lock_list(&path) {
            Ok(guard) => guard,
            Err(msg) => { self.set_lists_status(&msg); return; }
        };
        let tmp = format!("{}.tmp", path);
        match std::fs::File::create(&tmp) {
            Ok(mut f) => {
                for cidr in &cidrs {
                    if let Err(e) = writeln!(f, "{}", cidr) {
                        self.set_lists_status(&format!("Write failed: {}", e));
                        let _ = std::fs::remove_file(&tmp);
                        return;
                    }
                }
                if let Err(e) = std::fs::rename(&tmp, &path) {
                    self.set_lists_status(&format!("Rename failed: {}", e));
                    let _ = std::fs::remove_file(&tmp);
                    return;
                }
                let label = match self.lists_focus {
                    ListsFocus::Whitelist => "whitelist",
                    ListsFocus::Blacklist => "blacklist",
                };
                self.send_sighup();
                self.load_lists();
                self.set_lists_status(&format!("Rewrote {} sorted ({} entries)", label, cidrs.len()));
            }
            Err(e) => self.set_lists_status(&format!("Open failed: {}", e)),
        }
    }

    pub fn append_to_file(&mut self, target: &ListsFocus, lines: &[String]) {
        use std::io::Write;
        let path = match target {
            ListsFocus::Whitelist => &self.whitelist_path,
            ListsFocus::Blacklist => &self.blacklist_path,
        };
        let _lock = match Self::try_lock_list(path) {
            Ok(guard) => guard,
            Err(msg) => { self.set_lists_status(&msg); return; }
        };
        match std::fs::OpenOptions::new().append(true).create(true).open(path) {
            Ok(mut f) => {
                for line in lines {
                    if let Err(e) = writeln!(f, "{}", line) {
                        self.set_lists_status(&format!("Write failed: {}", e));
                        return;
                    }
                }
                self.send_sighup();
                self.load_lists();
                self.record_pending_adds(*target, lines);
            }
            Err(e) => self.set_lists_status(&format!("Open failed: {}", e)),
        }
    }

    pub fn remove_from_file(&mut self, target: &ListsFocus, cidr: &str) {
        let path = match target {
            ListsFocus::Whitelist => self.whitelist_path.clone(),
            ListsFocus::Blacklist => self.blacklist_path.clone(),
        };
        let _lock = match Self::try_lock_list(&path) {
            Ok(guard) => guard,
            Err(msg) => { self.set_lists_status(&msg); return; }
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                self.set_lists_status(&format!("Read failed: {}", e));
                return;
            }
        };
        let filtered: Vec<&str> = content
            .lines()
            .filter(|line| {
                let parsed = line.split('#').next().unwrap_or("").trim();
                parsed != cidr
            })
            .collect();
        let tmp = format!("{}.tmp", path);
        if let Err(e) = std::fs::write(&tmp, filtered.join("\n") + "\n") {
            self.set_lists_status(&format!("Write failed: {}", e));
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            self.set_lists_status(&format!("Rename failed: {}", e));
            let _ = std::fs::remove_file(&tmp);
            return;
        }
        self.send_sighup();
        self.load_lists();
        self.record_pending_remove(*target, cidr);
    }

    pub fn build_add_action_from_ip(&self, target: ListsFocus, ip: &str, asn: &str) -> Option<AddActionState> {
        let ip_cidr = Some(format!("{}/32", ip));

        let (subnet_cidr, asn_label, asn_cidrs) = if let Some(table) = &self.asn_table {
            if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                if let Some(entry) = table.lookup(u32::from(addr)) {
                    let plen = asn_table::range_to_cidr(entry.start, entry.end);
                    let mask = if plen == 0 { 0 } else { !((1u32 << (32 - plen)) - 1) };
                    let net = entry.start & mask;
                    let subnet = format!("{}/{}", Ipv4Addr::from(net), plen);
                    let all = table.find_all_by_asn(&entry.asn);
                    (Some(subnet), entry.asn.clone(), all)
                } else {
                    (None, asn.to_string(), Vec::new())
                }
            } else {
                (None, asn.to_string(), Vec::new())
            }
        } else {
            (None, asn.to_string(), Vec::new())
        };

        Some(AddActionState {
            target,
            ip_cidr,
            subnet_cidr,
            asn_label,
            asn_cidrs,
        })
    }

    pub fn build_add_action_from_neighborhood(
        &self,
        target: ListsFocus,
        hood: &forensics::Neighborhood,
    ) -> Option<AddActionState> {
        let asn_cidrs = self
            .asn_table
            .as_ref()
            .map(|t| t.find_all_by_asn(&hood.asn))
            .unwrap_or_default();

        Some(AddActionState {
            target,
            ip_cidr: None,
            subnet_cidr: Some(hood.subnet_cidr.clone()),
            asn_label: hood.asn.clone(),
            asn_cidrs,
        })
    }

    /// Check CIDRs for cross-list conflicts and same-list containment.
    /// Returns `(accepted, status_msg)`. Accepted may be fewer than input.
    fn check_cidr_overlaps(
        &self,
        target: ListsFocus,
        cidrs: Vec<String>,
    ) -> (Vec<String>, Option<String>) {
        use crate::validation::cidr_contains;

        let (same_cidrs, other_cidrs, other_label): (Vec<&str>, Vec<&str>, &str) = match target {
            ListsFocus::Whitelist => (
                self.whitelist_entries.iter().map(|e| e.cidr.as_str()).collect(),
                self.blacklist_entries.iter().map(|e| e.cidr.as_str()).collect(),
                "blacklist",
            ),
            ListsFocus::Blacklist => (
                self.blacklist_entries.iter().map(|e| e.cidr.as_str()).collect(),
                self.whitelist_entries.iter().map(|e| e.cidr.as_str()).collect(),
                "whitelist",
            ),
        };

        // Exact-match dedup
        let cidrs: Vec<String> = cidrs
            .into_iter()
            .filter(|c| !same_cidrs.contains(&c.as_str()))
            .collect();
        if cidrs.is_empty() {
            return (vec![], Some("All entries already in list".into()));
        }

        // Cross-list conflict (overlap in either direction)
        for c in &cidrs {
            for other in &other_cidrs {
                if cidr_contains(other, c) || cidr_contains(c, other) {
                    return (
                        vec![],
                        Some(format!("{} conflicts with {} entry {}", c, other_label, other)),
                    );
                }
            }
        }

        // Same-list containment: blocked if already covered
        for c in &cidrs {
            for existing in &same_cidrs {
                if cidr_contains(existing, c) {
                    return (
                        vec![],
                        Some(format!("{} already covered by {}", c, existing)),
                    );
                }
            }
        }

        // Superset advisory: count how many existing entries the new ones subsume
        let subsumed: usize = same_cidrs
            .iter()
            .filter(|existing| cidrs.iter().any(|c| cidr_contains(c, existing)))
            .count();

        let advisory = if subsumed > 0 {
            Some(format!(
                "subsumes {} existing — [c] to clean up",
                subsumed
            ))
        } else {
            None
        };

        (cidrs, advisory)
    }

    pub fn add_entries_to_list_direct(&mut self, target: ListsFocus, cidrs: Vec<String>) {
        let (accepted, msg) = self.check_cidr_overlaps(target, cidrs);

        if accepted.is_empty() {
            self.set_lists_status(&msg.unwrap_or_else(|| "All entries already in list".into()));
            return;
        }

        let count = accepted.len();
        let label = match target {
            ListsFocus::Whitelist => "whitelist",
            ListsFocus::Blacklist => "blacklist",
        };
        self.append_to_file(&target, &accepted);
        let status = match msg {
            Some(advisory) => format!("Added {} to {} ({})", count, label, advisory),
            None => format!("Added {} entry(ies) to {}", count, label),
        };
        self.set_lists_status(&status);
    }

    pub fn add_entries_to_list(&mut self, cidrs: Vec<String>) {
        let target = match &self.add_action {
            Some(a) => match a.target {
                ListsFocus::Whitelist => ListsFocus::Whitelist,
                ListsFocus::Blacklist => ListsFocus::Blacklist,
            },
            None => return,
        };

        let (accepted, msg) = self.check_cidr_overlaps(target, cidrs);

        if accepted.is_empty() {
            self.set_lists_status(&msg.unwrap_or_else(|| "All entries already in list".into()));
            self.add_action = None;
            return;
        }

        let count = accepted.len();
        let label = match target {
            ListsFocus::Whitelist => "whitelist",
            ListsFocus::Blacklist => "blacklist",
        };
        self.append_to_file(&target, &accepted);
        let status = match msg {
            Some(advisory) => format!("Added {} to {} ({})", count, label, advisory),
            None => format!("Added {} entry(ies) to {}", count, label),
        };
        self.set_lists_status(&status);
        self.add_action = None;
    }

    /// Scan focused list for entries that are strict subsets of a broader entry.
    pub fn cleanup_redundant(&mut self) {
        use crate::validation::cidr_contains;

        let cidrs: Vec<String> = match self.lists_focus {
            ListsFocus::Whitelist => self.whitelist_entries.iter().map(|e| e.cidr.clone()).collect(),
            ListsFocus::Blacklist => self.blacklist_entries.iter().map(|e| e.cidr.clone()).collect(),
        };

        let mut redundant = Vec::new();
        for (i, inner) in cidrs.iter().enumerate() {
            for (j, outer) in cidrs.iter().enumerate() {
                if i != j && cidr_contains(outer, inner) && !cidr_contains(inner, outer) {
                    redundant.push(inner.clone());
                    break;
                }
            }
        }

        if redundant.is_empty() {
            self.set_lists_status("No redundant entries");
        } else {
            self.cleanup_candidates = redundant;
            self.lists_input_mode = InputMode::ConfirmCleanup;
        }
    }

    /// Execute the pending cleanup: remove all candidates from file.
    pub fn execute_cleanup(&mut self) {
        let target = self.lists_focus;
        for cidr in std::mem::take(&mut self.cleanup_candidates) {
            self.remove_from_file(&target, &cidr);
        }
        self.lists_input_mode = InputMode::Normal;
    }

    fn send_sighup(&mut self) {
        let pid_path = "/run/tcp_syn_stop/syn-intel.pid";
        match std::fs::read_to_string(pid_path) {
            Ok(content) => {
                if let Ok(pid) = content.trim().parse::<u32>() {
                    match std::process::Command::new("kill")
                        .args(["-HUP", &pid.to_string()])
                        .output()
                    {
                        Ok(out) if out.status.success() => {
                            self.set_lists_status("Saved & reload signal sent to syn-intel");
                        }
                        Ok(out) => {
                            let err = String::from_utf8_lossy(&out.stderr);
                            self.set_lists_status(&format!("Saved, but signal failed: {}", err.trim()));
                        }
                        Err(e) => self.set_lists_status(&format!("Saved, but kill failed: {}", e)),
                    }
                } else {
                    self.set_lists_status("Saved, but PID file unreadable");
                }
            }
            Err(_) => self.set_lists_status("Saved, but syn-intel PID file not found"),
        }
    }

    fn set_lists_status(&mut self, msg: &str) {
        self.lists_status_msg = Some((msg.to_string(), Instant::now()));
    }

    pub fn clear_stale_status(&mut self) {
        if let Some((_, ts)) = &self.lists_status_msg {
            if ts.elapsed() >= Duration::from_secs(5) {
                self.lists_status_msg = None;
            }
        }
    }

    // ── BPF sync verification ────────────────────────────────────────

    /// Record CIDRs that were just appended to a config file.
    fn record_pending_adds(&mut self, list: ListsFocus, cidrs: &[String]) {
        let now = Instant::now();
        for cidr in cidrs {
            self.pending_syncs.push(PendingSync {
                cidr: cidr.clone(),
                list,
                op: SyncOp::Add,
                created_at: now,
            });
        }
        self.sync_status = SyncStatus::Pending(self.pending_syncs.len());
    }

    /// Record a CIDR that was just removed from a config file.
    fn record_pending_remove(&mut self, list: ListsFocus, cidr: &str) {
        self.pending_syncs.push(PendingSync {
            cidr: cidr.to_string(),
            list,
            op: SyncOp::Remove,
            created_at: Instant::now(),
        });
        self.sync_status = SyncStatus::Pending(self.pending_syncs.len());
    }

    /// Check pending entries against BPF LPM trie maps.
    ///
    /// - Adds: confirmed when the LPM lookup finds the prefix.
    /// - Removes: use grace-period timeout (LPM longest-prefix match
    ///   cannot reliably verify absence when broader prefixes exist).
    /// - All entries time out after 8 seconds regardless.
    pub fn verify_pending_syncs(&mut self) {
        const GRACE_PERIOD: Duration = Duration::from_secs(8);

        let maps = self.bpf_maps.as_ref();

        self.pending_syncs.retain(|entry| {
            if entry.created_at.elapsed() >= GRACE_PERIOD {
                return false;
            }
            if entry.op == SyncOp::Remove {
                return true; // Can't verify absence via LPM; let timeout handle it.
            }
            // SyncOp::Add — verify via BPF point lookup.
            if let Some(maps) = maps {
                if let Some((net_addr, prefix_len)) = crate::validation::parse_cidr(&entry.cidr) {
                    let is_wl = entry.list == ListsFocus::Whitelist;
                    if let Some(true) = maps.lpm_lookup(is_wl, net_addr, prefix_len as u32) {
                        return false; // Confirmed in BPF map.
                    }
                }
            }
            true // Not yet confirmed; keep waiting.
        });

        // Update aggregate status.
        if self.pending_syncs.is_empty() {
            if let SyncStatus::Pending(_) = self.sync_status {
                self.sync_status = SyncStatus::Confirmed(3);
            }
        } else {
            self.sync_status = SyncStatus::Pending(self.pending_syncs.len());
        }
    }

    /// Check inotify for external config file changes and reload if needed.
    pub fn poll_list_changes(&mut self) {
        let changed = self.list_watcher.as_ref().is_some_and(ListFileWatcher::poll_changed);
        if changed {
            self.load_lists();
        }
    }

    /// Count down the "Confirmed" display ticks.  Called once per tick.
    pub fn tick_sync_status(&mut self) {
        match self.sync_status {
            SyncStatus::Confirmed(0) => self.sync_status = SyncStatus::Idle,
            SyncStatus::Confirmed(n) => self.sync_status = SyncStatus::Confirmed(n - 1),
            _ => {}
        }
    }

    /// Initialize DogStatsD UDP socket for metrics export.
    pub fn init_statsd(&mut self, addr: &str) {
        match UdpSocket::bind("0.0.0.0:0") {
            Ok(sock) => {
                sock.set_nonblocking(true).ok();
                self.statsd_socket = Some((sock, addr.to_string()));
            }
            Err(e) => eprintln!("warning: cannot bind statsd UDP socket: {e}"),
        }
    }

    /// Emit current metrics as DogStatsD gauges over UDP.
    pub fn emit_statsd(&self) {
        let (sock, addr) = match &self.statsd_socket {
            Some(s) => s,
            None => return,
        };
        let state = match &self.state {
            Some(s) => s,
            None => return,
        };
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let payload = format!(
            "tcp_syn_stop.pps:{}|g\n\
             tcp_syn_stop.total_drops:{}|c\n\
             tcp_syn_stop.active_blocks:{}|g\n\
             tcp_syn_stop.blacklist_active:{}|g\n\
             tcp_syn_stop.rb_fail_cnt:{}|g\n\
             tcp_syn_stop.fetch_latency_us:{}|g\n\
             tcp_syn_stop.render_latency_us:{}|g\n\
             tcp_syn_stop.drop_ips_total:{}|g\n\
             tcp_syn_stop.drop_ips_util_pct:{:.1}|g\n\
             tcp_syn_stop.db_freshness_s:{}|g\n\
             tcp_syn_stop.config_errors:{}|g\n\
             tcp_syn_stop.sync_pending:{}|g\n",
            self.pps_ema as u64,
            state.metrics.latest_pps,
            state.metrics.active_blocks,
            state.metrics.blacklist_active,
            state.instrumentation.ringbuf_reserve_fails,
            self.last_fetch_us,
            self.last_render_us,
            self.drop_ips_total,
            self.drop_ips_util_pct,
            self.db_freshness_s.unwrap_or(0),
            self.config_errors.len(),
            self.pending_syncs.len(),
        );
        // Non-blocking send — silently ignore failures
        let _ = sock.send_to(payload.as_bytes(), addr);
    }

    /// Returns true if the ASN sparkline should be BOLD (rising pulse, 3-tick emphasis).
    pub fn asn_is_pulsing(&self, asn: &str) -> bool {
        self.asn_bold_ticks.get(asn).copied().unwrap_or(0) > 0
    }

    /// Return a semantic color for an ASN sparkline based on PPS velocity.
    /// Rising (>20% increase) = Red, Steady = Yellow, Falling = Green.
    pub fn asn_velocity_color(&self, asn: &str) -> Color {
        let curr = self.asn_pps_ema.get(asn).copied().unwrap_or(0.0);
        let prev = self.asn_pps_prev_ema.get(asn).copied().unwrap_or(0.0);
        if prev < 1.0 && curr < 1.0 {
            return Color::DarkGray;
        }
        let ratio = if prev > 0.0 { curr / prev } else if curr > 0.0 { 2.0 } else { 1.0 };
        if ratio > 1.2 {
            Color::Red
        } else if ratio < 0.8 {
            Color::Green
        } else {
            Color::Yellow
        }
    }

    /// Look up country code for an ASN (populated from swarm entries).
    pub fn asn_country(&self, asn: &str) -> &str {
        self.asn_countries.get(asn).map(String::as_str).unwrap_or("")
    }

    pub fn asn_name(&self, asn: &str) -> &str {
        self.asn_names.get(asn).map(String::as_str).unwrap_or("")
    }

    pub fn update_asn_pps(&mut self) {
        let state = match &self.state {
            Some(s) => s,
            None => return,
        };

        let total_drops = state.metrics.total_drops;

        // Only process when total_drops changes (daemon flushes every ~5s)
        if total_drops == self.prev_total_drops {
            return;
        }

        // Build current snapshot from swarm_entries: IP → count, IP → ASN
        let mut current: HashMap<String, u64> = HashMap::new();
        let mut ip_to_asn: HashMap<String, String> = HashMap::new();
        for e in &self.swarm_entries {
            current.insert(e.ip.clone(), e.total_drops);
            let asn = if e.asn.is_empty() { "Unknown" } else { &e.asn };
            ip_to_asn.insert(e.ip.clone(), asn.to_string());
            // Track country + name per ASN for sparkline labels.
            self.asn_countries.entry(asn.to_string()).or_insert_with(|| e.country.clone());
            self.asn_names.entry(asn.to_string()).or_insert_with(|| e.as_name.clone());
        }

        // Compute per-IP deltas, then group by ASN
        let mut asn_deltas: HashMap<String, f64> = HashMap::new();
        for (ip, &count) in &current {
            let prev = self.prev_attacker_counts.get(ip).copied().unwrap_or(0);
            if count > prev {
                let asn = ip_to_asn.get(ip).cloned().unwrap_or_else(|| "Unknown".into());
                *asn_deltas.entry(asn).or_insert(0.0) += (count - prev) as f64;
            }
        }

        // Push per-ASN PPS to history; push 0.0 for inactive ASNs
        let all_asns: Vec<String> = self
            .asn_pps_history
            .keys()
            .cloned()
            .chain(asn_deltas.keys().cloned())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        const EMA_ALPHA: f64 = 0.3;
        for asn in &all_asns {
            let raw_pps = asn_deltas.get(asn).copied().unwrap_or(0.0);
            let prev_ema = self.asn_pps_ema.get(asn).copied().unwrap_or(0.0);
            self.asn_pps_prev_ema.insert(asn.clone(), prev_ema);
            let ema = EMA_ALPHA * raw_pps + (1.0 - EMA_ALPHA) * prev_ema;
            self.asn_pps_ema.insert(asn.clone(), ema);
            let history = self
                .asn_pps_history
                .entry(asn.clone())
                .or_insert_with(|| VecDeque::with_capacity(100));
            history.push_back(ema);
            if history.len() > 100 {
                history.pop_front();
            }
        }

        // Color pulse: detect ASNs that just transitioned to "rising" velocity
        // and give them 3 ticks of BOLD emphasis.
        for asn in &all_asns {
            let color = self.asn_velocity_color(asn);
            if color == Color::Red {
                // Only set pulse if not already pulsing (avoid resetting countdown)
                self.asn_bold_ticks.entry(asn.clone()).or_insert(3);
            }
        }
        // Decrement all pulse counters; remove expired ones
        self.asn_bold_ticks.retain(|_, ticks| {
            *ticks = ticks.saturating_sub(1);
            *ticks > 0
        });

        // Prune stale ASNs (all zeros for 50+ ticks)
        self.asn_pps_history.retain(|_, hist| {
            if hist.len() < 50 {
                return true;
            }
            let tail = hist.iter().rev().take(50);
            tail.clone().any(|&v| v > 0.0)
        });

        // Maintain stable color palette
        for asn in self.asn_pps_history.keys() {
            if !self.asn_palette.iter().any(|(a, _)| a == asn) {
                let idx = self.asn_palette.len() % ASN_PALETTE.len();
                self.asn_palette.push((asn.clone(), ASN_PALETTE[idx]));
            }
        }
        self.asn_palette
            .retain(|(asn, _)| self.asn_pps_history.contains_key(asn));

        self.prev_attacker_counts = current;
        self.prev_total_drops = total_drops;
    }
}

/// Build swarm entries by merging `drop_ips` (Dynamic) and `blacklist_cnt` (Blacklist) BPF maps.
///
/// If an IP appears in both maps, counts are summed, last_seen is max'd, and reason = "Blacklist".
/// Per-IP results are sorted by count DESC and truncated to `max_entries`.
/// ASN aggregation is performed on the **full** filtered set before truncation so the
/// aggregate view reflects all IPs in the BPF maps, not just the visible top-N slice.
fn build_swarm_entries(
    drop_ips: &[(u32, bpf::DropInfo)],
    blacklist_ips: &[(u32, bpf::DropInfo)],
    now_ns: u64,
    asn_table: Option<&AsnTable>,
    max_entries: usize,
    hide_blacklisted: bool,
) -> (Vec<SwarmEntry>, usize, Vec<SwarmAsnEntry>) {
    // Merge into HashMap<ip_nbo, (count, last_seen, is_blacklist)>
    let mut merged: HashMap<u32, (u64, u64, bool)> = HashMap::new();

    for &(ip_nbo, ref info) in drop_ips {
        let entry = merged.entry(ip_nbo).or_insert((0, 0, false));
        entry.0 += info.count;
        entry.1 = entry.1.max(info.last_seen);
    }

    for &(ip_nbo, ref info) in blacklist_ips {
        let entry = merged.entry(ip_nbo).or_insert((0, 0, false));
        entry.0 += info.count;
        entry.1 = entry.1.max(info.last_seen);
        entry.2 = true; // present in blacklist
    }

    // Sort by count DESC, filtering blacklisted if requested
    let mut sorted: Vec<(u32, u64, u64, bool)> = merged
        .into_iter()
        .map(|(ip, (count, last_seen, is_bl))| (ip, count, last_seen, is_bl))
        .collect();
    if hide_blacklisted {
        sorted.retain(|&(_, _, _, is_bl)| !is_bl);
    }
    let filtered_total = sorted.len();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    // ASN aggregation on the FULL filtered set (before truncation)
    let mut asn_map: HashMap<String, SwarmAsnEntry> = HashMap::new();
    for &(ip_nbo, count, last_seen, is_bl) in &sorted {
        let ip_hbo = u32::from_be(ip_nbo);
        let (asn_key, as_name, country) = asn_table
            .and_then(|t| t.lookup(ip_hbo))
            .map(|e| (e.asn.clone(), e.as_name.clone(), e.country.clone()))
            .unwrap_or_default();
        let asn_key = if asn_key.is_empty() {
            "Unknown".to_string()
        } else {
            asn_key
        };
        let agg = asn_map.entry(asn_key.clone()).or_insert_with(|| SwarmAsnEntry {
            asn: asn_key,
            as_name,
            country,
            ip_count: 0,
            total_drops: 0,
            last_seen_ns: 0,
            has_blacklist: false,
            has_dynamic: false,
        });
        agg.ip_count += 1;
        agg.total_drops += count;
        agg.last_seen_ns = agg.last_seen_ns.max(last_seen);
        if is_bl {
            agg.has_blacklist = true;
        } else {
            agg.has_dynamic = true;
        }
    }
    let mut asn_entries: Vec<SwarmAsnEntry> = asn_map.into_values().collect();
    asn_entries.sort_by(|a, b| b.total_drops.cmp(&a.total_drops));

    // Truncate per-IP list for rendering
    sorted.truncate(max_entries);

    // Enrich with ASN + country, format last_seen
    let entries = sorted
        .into_iter()
        .map(|(ip_nbo, count, last_seen, is_bl)| {
            let ip_hbo = u32::from_be(ip_nbo);
            let (asn, as_name, country) = asn_table
                .and_then(|t| t.lookup(ip_hbo))
                .map(|e| (e.asn.clone(), e.as_name.clone(), e.country.clone()))
                .unwrap_or_default();
            SwarmEntry {
                ip: Ipv4Addr::from(ip_hbo).to_string(),
                asn,
                as_name,
                country,
                total_drops: count,
                last_seen_ago: time_fmt::format_ktime_ago(last_seen, now_ns),
                last_seen_ns: last_seen,
                reason: if is_bl { "Blacklist".into() } else { "Dynamic".into() },
            }
        })
        .collect();
    (entries, filtered_total, asn_entries)
}


/// Build neighborhoods by merging `drop_ips` and `blacklist_ips` BPF maps,
/// filtering by time window and grouping by ASN subnet.
fn build_neighborhoods(
    drop_ips: &[(u32, bpf::DropInfo)],
    blacklist_ips: &[(u32, bpf::DropInfo)],
    now_ns: u64,
    window_ns: u64,
    bot_threshold: i64,
    asn_table: Option<&AsnTable>,
    sort: NeighborhoodSort,
) -> Vec<forensics::Neighborhood> {
    let asn_table = match asn_table {
        Some(t) => t,
        None => return Vec::new(),
    };

    // Merge both maps into HashMap<ip_nbo, (count, last_seen)>, filtering by time window
    let cutoff = now_ns.saturating_sub(window_ns);
    let mut merged: HashMap<u32, (u64, u64)> = HashMap::new();

    for &(ip_nbo, ref info) in drop_ips {
        if info.last_seen < cutoff {
            continue;
        }
        let entry = merged.entry(ip_nbo).or_insert((0, 0));
        entry.0 += info.count;
        entry.1 = entry.1.max(info.last_seen);
    }

    for &(ip_nbo, ref info) in blacklist_ips {
        if info.last_seen < cutoff {
            continue;
        }
        let entry = merged.entry(ip_nbo).or_insert((0, 0));
        entry.0 += info.count;
        entry.1 = entry.1.max(info.last_seen);
    }

    // Group by ASN subnet
    struct SubnetAccum {
        asn: String,
        as_name: String,
        country: String,
        start_ip: u32,
        end_ip: u32,
        bot_count: i64,
        total_impact: i64,
    }
    let mut subnets: HashMap<(u32, u32), SubnetAccum> = HashMap::new();

    for (&ip_nbo, &(count, _last_seen)) in &merged {
        let ip_hbo = u32::from_be(ip_nbo);
        if let Some(asn_entry) = asn_table.lookup(ip_hbo) {
            let plen = asn_table::range_to_cidr(asn_entry.start, asn_entry.end);
            let mask = if plen == 0 { 0 } else { !((1u32 << (32 - plen)) - 1) };
            let net_addr = asn_entry.start & mask;

            let entry = subnets.entry((net_addr, plen)).or_insert_with(|| SubnetAccum {
                asn: asn_entry.asn.clone(),
                as_name: asn_entry.as_name.clone(),
                country: asn_entry.country.clone(),
                start_ip: asn_entry.start,
                end_ip: asn_entry.end,
                bot_count: 0,
                total_impact: 0,
            });
            entry.bot_count += 1;
            #[allow(clippy::cast_possible_wrap)]
            {
                entry.total_impact += count as i64;
            }
        }
    }

    // Filter by threshold, format, sort
    let mut result: Vec<forensics::Neighborhood> = subnets
        .into_iter()
        .filter(|(_, acc)| acc.bot_count > bot_threshold)
        .map(|((net_addr, plen), acc)| forensics::Neighborhood {
            subnet_cidr: format!("{}/{}", Ipv4Addr::from(net_addr), plen),
            asn: acc.asn,
            as_name: acc.as_name,
            country: acc.country,
            bot_count: acc.bot_count,
            total_impact: acc.total_impact,
            start_ip: acc.start_ip,
            end_ip: acc.end_ip,
        })
        .collect();

    match sort {
        NeighborhoodSort::Impact => {
            result.sort_by(|a, b| b.total_impact.cmp(&a.total_impact));
        }
        NeighborhoodSort::Country => {
            result.sort_by(|a, b| a.country.cmp(&b.country).then(b.total_impact.cmp(&a.total_impact)));
        }
        NeighborhoodSort::Name => {
            result.sort_by(|a, b| a.as_name.cmp(&b.as_name).then(b.total_impact.cmp(&a.total_impact)));
        }
    }

    result
}

/// Extract top-K attackers by drop count using a min-heap.
fn top_k_attackers(entries: &[(u32, bpf::DropInfo)], k: usize, asn_table: Option<&AsnTable>) -> Vec<Attacker> {
    if k == 0 || entries.is_empty() {
        return Vec::new();
    }

    let mut heap: BinaryHeap<Reverse<(u64, u32)>> = BinaryHeap::with_capacity(k + 1);
    for &(ip_nbo, ref info) in entries {
        if heap.len() < k {
            heap.push(Reverse((info.count, ip_nbo)));
        } else if let Some(&Reverse((min_count, _))) = heap.peek() {
            if info.count > min_count {
                heap.pop();
                heap.push(Reverse((info.count, ip_nbo)));
            }
        }
    }

    let mut result: Vec<(u64, u32)> = heap.into_iter().map(|Reverse(pair)| pair).collect();
    result.sort_by(|a, b| b.0.cmp(&a.0));

    result
        .into_iter()
        .map(|(count, ip_nbo)| {
            let ip_hbo = u32::from_be(ip_nbo);
            let asn = asn_table
                .and_then(|t| t.lookup(ip_hbo))
                .map(|e| e.asn.clone())
                .unwrap_or_default();
            Attacker {
                ip: Ipv4Addr::from(ip_hbo).to_string(),
                asn,
                count,
                peak_pps: 0,
            }
        })
        .collect()
}

fn parse_cidr(s: &str) -> Option<(u32, u32)> {
    let mut parts = s.split('/');
    let ip: Ipv4Addr = parts.next()?.parse().ok()?;
    let prefix: u32 = parts.next()?.parse().ok()?;
    Some((u32::from(ip), prefix))
}

/// Sum BPF `blacklist_cnt` entries per blacklist CIDR.
fn build_blacklist_drop_counts(
    blacklist_ips: &[(u32, bpf::DropInfo)],
    blacklist_entries: &[BlacklistEntry],
) -> HashMap<String, u64> {
    let mut counts = HashMap::new();
    for entry in blacklist_entries {
        let Some((net, prefix)) = parse_cidr(&entry.cidr) else {
            continue;
        };
        let mask = if prefix == 0 {
            0u32
        } else {
            !((1u32 << (32 - prefix)) - 1)
        };
        let mut total = 0u64;
        for &(ip_nbo, ref di) in blacklist_ips {
            let ip_hbo = u32::from_be(ip_nbo);
            if ip_hbo & mask == net & mask {
                total += di.count;
            }
        }
        if total > 0 {
            counts.insert(entry.cidr.clone(), total);
        }
    }
    counts
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_pps_history_append() {
        let mut app = App::new(None, String::new(), String::new(), String::new());
        app.record_pps(10);
        app.record_pps(20);
        app.record_pps(30);
        assert_eq!(app.pps_history.len(), 3);
        assert_eq!(app.pps_history[0], 10);
        assert_eq!(app.pps_history[1], 20);
        assert_eq!(app.pps_history[2], 30);
    }

    #[test]
    fn test_pps_history_cap_at_100() {
        let mut app = App::new(None, String::new(), String::new(), String::new());
        for i in 0..105 {
            app.record_pps(i);
        }
        assert_eq!(app.pps_history.len(), 100);
        assert_eq!(app.pps_history[0], 5); // first 5 were evicted
    }

    #[test]
    fn test_max_pps_tracking() {
        let mut app = App::new(None, String::new(), String::new(), String::new());
        app.record_pps(10);
        app.record_pps(50);
        app.record_pps(20);
        assert_eq!(app.max_pps, 50);
    }

    #[test]
    fn test_should_refresh_forensics_none() {
        // First fetch ever — should always refresh
        assert!(should_refresh_forensics(None, Instant::now()));
    }

    #[test]
    fn test_should_refresh_forensics_recent() {
        let last = Instant::now();
        let now = last + Duration::from_secs(10);
        assert!(!should_refresh_forensics(Some(last), now));
    }

    #[test]
    fn test_should_refresh_forensics_stale() {
        let last = Instant::now();
        let now = last + Duration::from_secs(31);
        assert!(should_refresh_forensics(Some(last), now));
    }

    #[test]
    fn test_swarm_scroll_bounds() {
        let mut app = App::new(None, String::new(), String::new(), String::new());
        // No entries — scroll should stay at 0
        app.swarm_scroll_down();
        assert_eq!(app.swarm_scroll, 0);
        app.swarm_scroll_up();
        assert_eq!(app.swarm_scroll, 0);

        // Add entries
        app.swarm_entries = vec![
            forensics::SwarmEntry {
                ip: "1.1.1.1".into(),
                asn: "AS1".into(),
                as_name: String::new(),
                country: "US".into(),
                total_drops: 100,
                last_seen_ago: "3s ago".into(),
                last_seen_ns: 0,
                reason: "Dynamic".into(),
            },
            forensics::SwarmEntry {
                ip: "2.2.2.2".into(),
                asn: "AS2".into(),
                as_name: String::new(),
                country: "DE".into(),
                total_drops: 200,
                last_seen_ago: "1s ago".into(),
                last_seen_ns: 0,
                reason: "Blacklist".into(),
            },
            forensics::SwarmEntry {
                ip: "3.3.3.3".into(),
                asn: "AS3".into(),
                as_name: String::new(),
                country: "CN".into(),
                total_drops: 300,
                last_seen_ago: "5s ago".into(),
                last_seen_ns: 0,
                reason: "Dynamic".into(),
            },
        ];
        app.swarm_scroll_down();
        assert_eq!(app.swarm_scroll, 1);
        app.swarm_scroll_down();
        assert_eq!(app.swarm_scroll, 2);
        // Can't scroll past last entry
        app.swarm_scroll_down();
        assert_eq!(app.swarm_scroll, 2);
        app.swarm_scroll_up();
        assert_eq!(app.swarm_scroll, 1);
    }

    #[test]
    fn test_neighborhood_scroll_bounds() {
        let mut app = App::new(None, String::new(), String::new(), String::new());
        // No neighborhoods — scroll should stay at 0
        app.neighborhood_scroll_down();
        assert_eq!(app.neighborhood_scroll, 0);
        app.neighborhood_scroll_up();
        assert_eq!(app.neighborhood_scroll, 0);

        // Set neighborhoods directly
        app.neighborhoods = vec![
            forensics::Neighborhood {
                subnet_cidr: "10.0.0.0/24".into(),
                asn: "AS1".into(),
                country: "US".into(),
                bot_count: 5,
                total_impact: 1000,
                start_ip: 0,
                end_ip: 0,
                as_name: String::new(),
            },
            forensics::Neighborhood {
                subnet_cidr: "10.0.1.0/24".into(),
                asn: "AS2".into(),
                country: "DE".into(),
                bot_count: 4,
                total_impact: 800,
                start_ip: 0,
                end_ip: 0,
                as_name: String::new(),
            },
            forensics::Neighborhood {
                subnet_cidr: "10.0.2.0/24".into(),
                asn: "AS3".into(),
                country: "CN".into(),
                bot_count: 3,
                total_impact: 600,
                start_ip: 0,
                end_ip: 0,
                as_name: String::new(),
            },
        ];
        app.neighborhood_scroll_down();
        assert_eq!(app.neighborhood_scroll, 1);
        app.neighborhood_scroll_down();
        assert_eq!(app.neighborhood_scroll, 2);
        // Can't scroll past last entry
        app.neighborhood_scroll_down();
        assert_eq!(app.neighborhood_scroll, 2);
        app.neighborhood_scroll_up();
        assert_eq!(app.neighborhood_scroll, 1);
    }

    #[test]
    fn test_update_asn_pps_no_state() {
        let mut app = App::new(None, String::new(), String::new(), String::new());
        app.update_asn_pps(); // Should not panic
        assert!(app.asn_pps_history.is_empty());
    }

    #[test]
    fn test_update_asn_pps_basic() {
        use crate::protocol::{Metrics, SystemState};

        let mut app = App::new(None, String::new(), String::new(), String::new());
        app.state = Some(SystemState {
            uptime_secs: 100,
            metrics: Metrics {
                total_drops: 1000,
                latest_pps: 500,
                active_blocks: 1,
                blacklist_active: 0,
            },
            top_attackers: vec![],
            top_ports: vec![],
            ifaces: vec![],
            instrumentation: Default::default(),
        });
        app.swarm_entries = vec![
            forensics::SwarmEntry {
                ip: "10.0.0.1".into(),
                asn: "AS1234".into(),
                as_name: String::new(),
                country: String::new(),
                total_drops: 600,
                last_seen_ago: "1s ago".into(),
                last_seen_ns: 0,
                reason: "Dynamic".into(),
            },
            forensics::SwarmEntry {
                ip: "10.0.0.2".into(),
                asn: "AS5678".into(),
                as_name: String::new(),
                country: String::new(),
                total_drops: 400,
                last_seen_ago: "2s ago".into(),
                last_seen_ns: 0,
                reason: "Dynamic".into(),
            },
        ];
        app.update_asn_pps();
        assert_eq!(app.asn_pps_history.len(), 2);
        assert_eq!(app.asn_pps_history["AS1234"].len(), 1);
        // EMA smoothed: 0.3 * raw + 0.7 * 0 (first sample)
        assert!((app.asn_pps_history["AS1234"][0] - 180.0).abs() < 0.01);
        assert!((app.asn_pps_history["AS5678"][0] - 120.0).abs() < 0.01);
    }

    #[test]
    fn test_update_asn_pps_skips_unchanged() {
        use crate::protocol::{Metrics, SystemState};

        let mut app = App::new(None, String::new(), String::new(), String::new());
        app.state = Some(SystemState {
            uptime_secs: 100,
            metrics: Metrics {
                total_drops: 1000,
                latest_pps: 500,
                active_blocks: 1,
                blacklist_active: 0,
            },
            top_attackers: vec![],
            top_ports: vec![],
            ifaces: vec![],
            instrumentation: Default::default(),
        });
        app.swarm_entries = vec![forensics::SwarmEntry {
            ip: "10.0.0.1".into(),
            asn: "AS1234".into(),
            as_name: String::new(),
            country: String::new(),
            total_drops: 600,
            last_seen_ago: "1s ago".into(),
            last_seen_ns: 0,
            reason: "Dynamic".into(),
        }];
        app.update_asn_pps();
        // Same total_drops — should not update
        app.update_asn_pps();
        assert_eq!(app.asn_pps_history["AS1234"].len(), 1);
    }

    #[test]
    fn test_sort_neighborhoods_by_country() {
        let mut app = App::new(None, String::new(), String::new(), String::new());
        app.neighborhoods = vec![
            forensics::Neighborhood {
                subnet_cidr: "10.0.0.0/24".into(),
                asn: "AS1".into(),
                as_name: String::new(),
                country: "US".into(),
                bot_count: 5,
                total_impact: 1000,
                start_ip: 0,
                end_ip: 0,
            },
            forensics::Neighborhood {
                subnet_cidr: "10.0.1.0/24".into(),
                asn: "AS2".into(),
                as_name: String::new(),
                country: "CN".into(),
                bot_count: 4,
                total_impact: 800,
                start_ip: 0,
                end_ip: 0,
            },
            forensics::Neighborhood {
                subnet_cidr: "10.0.2.0/24".into(),
                asn: "AS3".into(),
                as_name: String::new(),
                country: "DE".into(),
                bot_count: 3,
                total_impact: 600,
                start_ip: 0,
                end_ip: 0,
            },
        ];
        app.neighborhood_sort = NeighborhoodSort::Country;
        app.sort_neighborhoods();
        assert_eq!(app.neighborhoods[0].country, "CN");
        assert_eq!(app.neighborhoods[1].country, "DE");
        assert_eq!(app.neighborhoods[2].country, "US");
    }

    #[test]
    fn test_sort_neighborhoods_by_name() {
        let mut app = App::new(None, String::new(), String::new(), String::new());
        app.neighborhoods = vec![
            forensics::Neighborhood {
                subnet_cidr: "10.0.0.0/24".into(),
                asn: "AS1".into(),
                as_name: "ZEBRA".into(),
                country: "US".into(),
                bot_count: 5,
                total_impact: 1000,
                start_ip: 0,
                end_ip: 0,
            },
            forensics::Neighborhood {
                subnet_cidr: "10.0.1.0/24".into(),
                asn: "AS2".into(),
                as_name: "ALPHA".into(),
                country: "DE".into(),
                bot_count: 4,
                total_impact: 800,
                start_ip: 0,
                end_ip: 0,
            },
        ];
        app.neighborhood_sort = NeighborhoodSort::Name;
        app.sort_neighborhoods();
        assert_eq!(app.neighborhoods[0].as_name, "ALPHA");
        assert_eq!(app.neighborhoods[1].as_name, "ZEBRA");
    }

    #[test]
    fn test_drilldown_scroll_bounds() {
        let mut app = App::new(None, String::new(), String::new(), String::new());
        // No drilldown — scroll should not change
        app.drilldown_scroll_down();
        assert_eq!(app.drilldown_scroll, 0);

        app.drilldown = Some(forensics::DrilldownState {
            neighborhood: forensics::Neighborhood::default(),
            as_name: String::new(),
            ips: vec![
                forensics::DrilldownIp {
                    ip: "1.1.1.1".into(),
                    drop_count: 100,
                    peak_pps: 50,
                    dest_ports: vec![],
                    first_seen: String::new(),
                    last_seen: String::new(),
                },
                forensics::DrilldownIp {
                    ip: "2.2.2.2".into(),
                    drop_count: 200,
                    peak_pps: 100,
                    dest_ports: vec![],
                    first_seen: String::new(),
                    last_seen: String::new(),
                },
            ],
            port_diversity: 0,
        });
        app.drilldown_scroll_down();
        assert_eq!(app.drilldown_scroll, 1);
        app.drilldown_scroll_down();
        assert_eq!(app.drilldown_scroll, 1); // clamped
        app.drilldown_scroll_up();
        assert_eq!(app.drilldown_scroll, 0);
    }

    // --- File I/O tests ---

    #[test]
    fn test_read_cidr_file_with_comments() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            "10.0.0.0/8\n# full-line comment\n192.168.0.0/16 # inline note\n\n172.16.0.0/12\n",
        )
        .unwrap();
        let result = App::read_cidr_file(tmp.path().to_str().unwrap());
        assert_eq!(result, vec!["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]);
    }

    #[test]
    fn test_read_cidr_file_missing() {
        let result = App::read_cidr_file("/tmp/nonexistent_cidr_file_test_12345.conf");
        assert!(result.is_empty());
    }

    #[test]
    fn test_append_to_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        std::fs::write(&path, "10.0.0.0/8\n").unwrap();
        let mut app = App::new(None, String::new(), path.clone(), String::new());
        app.append_to_file(
            &ListsFocus::Whitelist,
            &["192.168.0.0/16".to_string(), "172.16.0.0/12".to_string()],
        );
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("10.0.0.0/8"));
        assert!(content.contains("192.168.0.0/16"));
        assert!(content.contains("172.16.0.0/12"));
    }

    #[test]
    fn test_remove_from_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        std::fs::write(&path, "10.0.0.0/8\n192.168.0.0/16 # keep comment line\n172.16.0.0/12\n").unwrap();
        let mut app = App::new(None, String::new(), path.clone(), String::new());
        app.remove_from_file(&ListsFocus::Whitelist, "192.168.0.0/16");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("10.0.0.0/8"));
        assert!(!content.contains("192.168.0.0/16"));
        assert!(content.contains("172.16.0.0/12"));
    }

    #[test]
    fn test_remove_from_file_not_found() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let original = "10.0.0.0/8\n172.16.0.0/12\n";
        std::fs::write(&path, original).unwrap();
        let mut app = App::new(None, String::new(), path.clone(), String::new());
        app.remove_from_file(&ListsFocus::Whitelist, "99.99.99.0/24");
        let content = std::fs::read_to_string(&path).unwrap();
        // Both original entries still present
        assert!(content.contains("10.0.0.0/8"));
        assert!(content.contains("172.16.0.0/12"));
    }

    #[test]
    fn test_remove_from_file_cleans_tmp() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        std::fs::write(&path, "10.0.0.0/8\n").unwrap();
        let mut app = App::new(None, String::new(), path.clone(), String::new());
        app.remove_from_file(&ListsFocus::Whitelist, "10.0.0.0/8");
        // The .tmp file should not exist after successful rename
        assert!(!std::path::Path::new(&format!("{}.tmp", path)).exists());
    }

    // --- build_swarm_entries tests ---

    #[test]
    fn test_build_swarm_empty_maps() {
        let (result, total, agg) = build_swarm_entries(&[], &[], 1_000_000_000, None, 1000, false);
        assert!(result.is_empty());
        assert_eq!(total, 0);
        assert!(agg.is_empty());
    }

    #[test]
    fn test_build_swarm_merge_both_maps() {
        let now = 10_000_000_000u64;
        // IP 10.0.0.1 in network byte order
        let ip_nbo = u32::to_be(0x0A000001);
        let drop_ips = vec![(
            ip_nbo,
            bpf::DropInfo {
                last_seen: now - 2_000_000_000,
                count: 100,
            },
        )];
        let blacklist_ips = vec![(
            ip_nbo,
            bpf::DropInfo {
                last_seen: now - 1_000_000_000,
                count: 50,
            },
        )];
        let (result, _, _) = build_swarm_entries(&drop_ips, &blacklist_ips, now, None, 1000, false);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ip, "10.0.0.1");
        assert_eq!(result[0].total_drops, 150); // summed
        assert_eq!(result[0].reason, "Blacklist"); // present in blacklist
        assert_eq!(result[0].last_seen_ago, "1s ago"); // max of the two
    }

    #[test]
    fn test_build_swarm_max_entries_cap() {
        let now = 10_000_000_000u64;
        let drop_ips: Vec<(u32, bpf::DropInfo)> = (1u32..=10)
            .map(|i| {
                (
                    u32::to_be(i),
                    bpf::DropInfo {
                        last_seen: now - 1_000_000_000,
                        count: u64::from(i) * 10,
                    },
                )
            })
            .collect();
        let (result, total, agg) = build_swarm_entries(&drop_ips, &[], now, None, 3, false);
        assert_eq!(result.len(), 3);
        assert_eq!(total, 10); // 10 IPs total, only 3 shown
        // ASN aggregation covers all 10 IPs (pre-truncation), not just the 3 shown
        let agg_ip_total: usize = agg.iter().map(|a| a.ip_count).sum();
        assert_eq!(agg_ip_total, 10);
        // Sorted by count DESC
        assert_eq!(result[0].total_drops, 100);
        assert_eq!(result[1].total_drops, 90);
        assert_eq!(result[2].total_drops, 80);
    }

    #[test]
    fn test_build_swarm_dynamic_only() {
        let now = 10_000_000_000u64;
        let ip_nbo = u32::to_be(0xC0A80001); // 192.168.0.1
        let drop_ips = vec![(
            ip_nbo,
            bpf::DropInfo {
                last_seen: now - 3_000_000_000,
                count: 42,
            },
        )];
        let (result, _, _) = build_swarm_entries(&drop_ips, &[], now, None, 1000, false);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].reason, "Dynamic");
        assert_eq!(result[0].last_seen_ago, "3s ago");
    }

    #[test]
    fn test_build_swarm_hide_blacklisted() {
        let now = 10_000_000_000u64;
        let ip1 = u32::to_be(0x0A000001); // 10.0.0.1
        let ip2 = u32::to_be(0x0A000002); // 10.0.0.2
        let drop_ips = vec![
            (ip1, bpf::DropInfo { last_seen: now - 1_000_000_000, count: 100 }),
            (ip2, bpf::DropInfo { last_seen: now - 1_000_000_000, count: 200 }),
        ];
        let blacklist_ips = vec![
            (ip1, bpf::DropInfo { last_seen: now - 500_000_000, count: 50 }),
        ];
        // Without filter: both IPs shown, ip1 is Blacklist
        let (result, total, _) = build_swarm_entries(&drop_ips, &blacklist_ips, now, None, 1000, false);
        assert_eq!(result.len(), 2);
        assert_eq!(total, 2);
        // With filter: only ip2 (Dynamic) survives — ASN agg also reflects filtered set
        let (result, total, agg) = build_swarm_entries(&drop_ips, &blacklist_ips, now, None, 1000, true);
        assert_eq!(result.len(), 1);
        assert_eq!(total, 1);
        assert_eq!(result[0].reason, "Dynamic");
        let agg_ip_total: usize = agg.iter().map(|a| a.ip_count).sum();
        assert_eq!(agg_ip_total, 1); // only the non-blacklisted IP
    }

    // --- ASN aggregation tests (via build_swarm_entries) ---

    #[test]
    fn test_asn_aggregation_basic() {
        // Two IPs in AS1234, one in AS5678
        let asn_table = build_test_asn_table_from_entries(&[
            (0x0A000000, 0x0A0000FF, "AS1234", "US", "TEST-NET-A"),
            (0x0B000000, 0x0B0000FF, "AS5678", "DE", "TEST-NET-B"),
        ]);
        let now = 10_000_000_000u64;
        let drop_ips = vec![
            (u32::to_be(0x0A000001), bpf::DropInfo { last_seen: now - 1_000_000_000, count: 100 }),
            (u32::to_be(0x0A000002), bpf::DropInfo { last_seen: now - 3_000_000_000, count: 50 }),
        ];
        let blacklist_ips = vec![
            (u32::to_be(0x0B000001), bpf::DropInfo { last_seen: now - 2_000_000_000, count: 200 }),
        ];
        let (_, _, agg) = build_swarm_entries(&drop_ips, &blacklist_ips, now, Some(&asn_table), 1000, false);
        assert_eq!(agg.len(), 2);
        // Sorted by total_drops DESC: AS5678=200, AS1234=150
        assert_eq!(agg[0].asn, "AS5678");
        assert_eq!(agg[0].total_drops, 200);
        assert_eq!(agg[0].ip_count, 1);
        assert!(!agg[0].has_dynamic);
        assert!(agg[0].has_blacklist);
        assert_eq!(agg[1].asn, "AS1234");
        assert_eq!(agg[1].total_drops, 150);
        assert_eq!(agg[1].ip_count, 2);
        assert!(agg[1].has_dynamic);
        assert!(!agg[1].has_blacklist);
        assert_eq!(agg[1].last_seen_ns, now - 1_000_000_000); // max of the two
    }

    #[test]
    fn test_asn_aggregation_unknown_asn() {
        // IPs with no ASN table match → grouped under "Unknown"
        let now = 10_000_000_000u64;
        let drop_ips = vec![
            (u32::to_be(0x0A000001), bpf::DropInfo { last_seen: now - 1_000_000_000, count: 100 }),
            (u32::to_be(0x0A000002), bpf::DropInfo { last_seen: now - 1_000_000_000, count: 50 }),
        ];
        let (_, _, agg) = build_swarm_entries(&drop_ips, &[], now, None, 1000, false);
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0].asn, "Unknown");
        assert_eq!(agg[0].ip_count, 2);
        assert_eq!(agg[0].total_drops, 150);
    }

    #[test]
    fn test_asn_aggregation_covers_full_set_before_truncation() {
        // 10 IPs across 2 ASNs, truncated to 3 per-IP entries.
        // ASN aggregation should still see all 10.
        let asn_table = build_test_asn_table_from_entries(&[
            (0x0A000000, 0x0A0000FF, "AS1", "US", "NET-A"),
            (0x0B000000, 0x0B0000FF, "AS2", "DE", "NET-B"),
        ]);
        let now = 10_000_000_000u64;
        let mut drop_ips: Vec<(u32, bpf::DropInfo)> = (1u32..=7)
            .map(|i| (u32::to_be(0x0A000000 + i), bpf::DropInfo { last_seen: now - 1_000_000_000, count: u64::from(i) * 10 }))
            .collect();
        for i in 1u32..=3 {
            drop_ips.push((u32::to_be(0x0B000000 + i), bpf::DropInfo { last_seen: now - 1_000_000_000, count: u64::from(i) * 100 }));
        }
        let (per_ip, total, agg) = build_swarm_entries(&drop_ips, &[], now, Some(&asn_table), 3, false);
        assert_eq!(per_ip.len(), 3);
        assert_eq!(total, 10);
        // ASN agg covers all 10 IPs
        let agg_ip_total: usize = agg.iter().map(|a| a.ip_count).sum();
        assert_eq!(agg_ip_total, 10);
        assert_eq!(agg.len(), 2);
        // AS2 has 3 IPs with 100+200+300=600 drops, AS1 has 7 IPs with 10+20+..+70=280 drops
        assert_eq!(agg[0].asn, "AS2");
        assert_eq!(agg[0].total_drops, 600);
        assert_eq!(agg[0].ip_count, 3);
        assert_eq!(agg[1].asn, "AS1");
        assert_eq!(agg[1].total_drops, 280);
        assert_eq!(agg[1].ip_count, 7);
    }

    // --- build_neighborhoods tests ---

    /// Helper: build a minimal AsnTable for testing neighborhoods.
    fn build_test_asn_table_from_entries(entries: &[(u32, u32, &str, &str, &str)]) -> AsnTable {
        let mut asn_entries = Vec::new();
        let mut asn_index: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, &(start, end, asn, country, name)) in entries.iter().enumerate() {
            asn_entries.push(asn_table::AsnEntry {
                start,
                end,
                asn: asn.to_string(),
                country: country.to_string(),
                as_name: name.to_string(),
            });
            asn_index.entry(asn.to_string()).or_default().push(i);
        }
        AsnTable::from_data(asn_table::AsnTableData {
            entries: asn_entries,
            asn_index,
        })
    }

    #[test]
    fn test_build_neighborhoods_basic() {
        // 4 IPs in one ASN range (10.0.0.0/24) → 1 neighborhood
        let asn_table =
            build_test_asn_table_from_entries(&[(0x0A000000, 0x0A0000FF, "AS1234", "US", "TEST-NET")]);
        let now = 10_000_000_000u64;
        let drop_ips: Vec<(u32, bpf::DropInfo)> = (1u32..=4)
            .map(|i| {
                (
                    u32::to_be(0x0A000000 + i),
                    bpf::DropInfo {
                        last_seen: now - 1_000_000_000,
                        count: i as u64 * 100,
                    },
                )
            })
            .collect();
        let result = build_neighborhoods(
            &drop_ips,
            &[],
            now,
            TimeWindow::OneHour.as_ns(),
            2,
            Some(&asn_table),
            NeighborhoodSort::Impact,
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].subnet_cidr, "10.0.0.0/24");
        assert_eq!(result[0].asn, "AS1234");
        assert_eq!(result[0].bot_count, 4);
        assert_eq!(result[0].total_impact, 1000);
    }

    #[test]
    fn test_build_neighborhoods_time_window_filter() {
        // IPs outside window should be excluded
        let asn_table =
            build_test_asn_table_from_entries(&[(0x0A000000, 0x0A0000FF, "AS1", "US", "TEST")]);
        let window = 5 * 60 * 1_000_000_000u64; // 5 min
        let now = window + 10_000_000_000; // must be larger than window
        let drop_ips = vec![
            // Recent — within window
            (
                u32::to_be(0x0A000001),
                bpf::DropInfo {
                    last_seen: now - 1_000_000_000,
                    count: 100,
                },
            ),
            (
                u32::to_be(0x0A000002),
                bpf::DropInfo {
                    last_seen: now - 2_000_000_000,
                    count: 100,
                },
            ),
            (
                u32::to_be(0x0A000003),
                bpf::DropInfo {
                    last_seen: now - 3_000_000_000,
                    count: 100,
                },
            ),
            // Stale — outside window
            (
                u32::to_be(0x0A000004),
                bpf::DropInfo {
                    last_seen: now - window - 1,
                    count: 100,
                },
            ),
        ];
        let result = build_neighborhoods(
            &drop_ips,
            &[],
            now,
            window,
            2,
            Some(&asn_table),
            NeighborhoodSort::Impact,
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].bot_count, 3); // only 3 within window
    }

    #[test]
    fn test_build_neighborhoods_bot_threshold() {
        // Threshold of 2: subnet with 2 bots should be filtered out (> 2 required)
        let asn_table =
            build_test_asn_table_from_entries(&[(0x0A000000, 0x0A0000FF, "AS1", "US", "TEST")]);
        let now = 10_000_000_000u64;
        let drop_ips = vec![
            (
                u32::to_be(0x0A000001),
                bpf::DropInfo {
                    last_seen: now - 1_000_000_000,
                    count: 100,
                },
            ),
            (
                u32::to_be(0x0A000002),
                bpf::DropInfo {
                    last_seen: now - 1_000_000_000,
                    count: 100,
                },
            ),
        ];
        let result = build_neighborhoods(
            &drop_ips,
            &[],
            now,
            TimeWindow::OneHour.as_ns(),
            2,
            Some(&asn_table),
            NeighborhoodSort::Impact,
        );
        assert!(result.is_empty()); // 2 bots, threshold is >2
    }

    #[test]
    fn test_build_neighborhoods_no_asn_table() {
        let now = 10_000_000_000u64;
        let drop_ips = vec![(
            u32::to_be(0x0A000001),
            bpf::DropInfo {
                last_seen: now - 1_000_000_000,
                count: 100,
            },
        )];
        let result = build_neighborhoods(
            &drop_ips,
            &[],
            now,
            TimeWindow::OneHour.as_ns(),
            0,
            None,
            NeighborhoodSort::Impact,
        );
        assert!(result.is_empty());
    }

    #[test]
    fn test_time_window_cycle() {
        assert_eq!(TimeWindow::FiveMin.next(), TimeWindow::OneHour);
        assert_eq!(TimeWindow::OneHour.next(), TimeWindow::TwentyFourHour);
        assert_eq!(TimeWindow::TwentyFourHour.next(), TimeWindow::FiveMin);
    }

    #[test]
    fn test_bot_threshold_cycle() {
        assert_eq!(BotThreshold::One.next(), BotThreshold::Two);
        assert_eq!(BotThreshold::Two.next(), BotThreshold::Five);
        assert_eq!(BotThreshold::Five.next(), BotThreshold::One);
    }

    #[test]
    fn test_parse_cidr_valid() {
        assert_eq!(parse_cidr("10.0.0.0/24"), Some((0x0A000000, 24)));
        assert_eq!(parse_cidr("192.168.1.1/32"), Some((0xC0A80101, 32)));
    }

    #[test]
    fn test_parse_cidr_invalid() {
        assert_eq!(parse_cidr("not-an-ip/24"), None);
        assert_eq!(parse_cidr("10.0.0.0"), None);
        assert_eq!(parse_cidr(""), None);
    }

    #[test]
    fn test_build_blacklist_drop_counts_basic() {
        // Two IPs in a /24 blacklist entry
        let ip1_nbo = u32::to_be(0x0A000001); // 10.0.0.1
        let ip2_nbo = u32::to_be(0x0A000002); // 10.0.0.2
        let blacklist_ips = vec![
            (ip1_nbo, bpf::DropInfo { last_seen: 0, count: 500 }),
            (ip2_nbo, bpf::DropInfo { last_seen: 0, count: 300 }),
        ];
        let entries = vec![BlacklistEntry {
            cidr: "10.0.0.0/24".to_string(),
            drop_count: 0,
            asn: String::new(),
            as_name: String::new(),
            country: String::new(),
        }];
        let counts = build_blacklist_drop_counts(&blacklist_ips, &entries);
        assert_eq!(counts.get("10.0.0.0/24").copied().unwrap_or(0), 800);
    }

    #[test]
    fn test_build_blacklist_drop_counts_no_match() {
        // IP outside the blacklist CIDR range
        let ip_nbo = u32::to_be(0xC0A80001); // 192.168.0.1
        let blacklist_ips = vec![
            (ip_nbo, bpf::DropInfo { last_seen: 0, count: 100 }),
        ];
        let entries = vec![BlacklistEntry {
            cidr: "10.0.0.0/24".to_string(),
            drop_count: 0,
            asn: String::new(),
            as_name: String::new(),
            country: String::new(),
        }];
        let counts = build_blacklist_drop_counts(&blacklist_ips, &entries);
        assert_eq!(counts.get("10.0.0.0/24"), None);
    }

    #[test]
    fn test_build_blacklist_drop_counts_host_entry() {
        // Single /32 entry
        let ip_nbo = u32::to_be(0x0A000001); // 10.0.0.1
        let blacklist_ips = vec![
            (ip_nbo, bpf::DropInfo { last_seen: 0, count: 42 }),
        ];
        let entries = vec![BlacklistEntry {
            cidr: "10.0.0.1/32".to_string(),
            drop_count: 0,
            asn: String::new(),
            as_name: String::new(),
            country: String::new(),
        }];
        let counts = build_blacklist_drop_counts(&blacklist_ips, &entries);
        assert_eq!(counts.get("10.0.0.1/32").copied().unwrap_or(0), 42);
    }
}
