// SPDX-License-Identifier: GPL-2.0-only
//! syn-intel — BPF policy engine for tcp_syn_stop.
//!
//! Consumes the BPF ringbuffer, manages TTL expiry of dynamic blocks,
//! computes telemetry (PPS, top-K attackers), and logs structured reports.

mod asn_table;
mod autoban;
mod bpf;
mod event;
mod ip_tracker;
mod metrics;
mod persist;
mod report;
mod ttl;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{fs, io, process};

use anyhow::{Context, Result};
use clap::Parser;
use libbpf_rs::RingBufferBuilder;
use log::{debug, error, info, warn};

use asn_table::AsnTable;
use autoban::{AutobanConfig, AutobanState};
use bpf::BpfMaps;
use event::{parse_event, IntelState, REASON_NEW_BLOCK};
use ip_tracker::{build_blacklist_rows, IpTracker};
use metrics::{MetricsState, TelemetrySnapshot};
use persist::{IntelRow, PersistHandle, PersistMsg};
use ttl::TtlState;

const PID_PATH: &str = "/run/tcp_syn_stop/syn-intel.pid";
const DAEMON_PID_PATH: &str = "/run/tcp_syn_stop/tcp_syn_stop.pid";

#[derive(Parser)]
#[command(about = "BPF policy engine for tcp_syn_stop")]
struct Args {
    /// Polling interval in seconds (telemetry + TTL expiry tick)
    #[arg(long, default_value_t = 5)]
    interval: u64,

    /// TTL for dynamic blocks in seconds (0 = no expiry)
    #[arg(long, default_value_t = 60)]
    ttl: u64,

    /// Path to the ip2asn SQLite database
    #[arg(long, default_value = "/opt/tcp_syn_stop/ip2asn.db")]
    db_path: String,

    /// Directory where BPF maps are pinned
    #[arg(long, default_value = "/sys/fs/bpf/tcp_syn_stop")]
    pin_dir: PathBuf,

    /// Path to daemon SQLite database for persistence (intel + autoban history)
    #[arg(long, default_value = "/opt/tcp_syn_stop/ip2asn.db")]
    persist_db: String,

    /// Min distinct IPs per prefix to trigger autoban (0 = disable autoban)
    #[arg(long, default_value_t = 5)]
    autoban_threshold: u32,

    /// Base autoban duration in seconds (first offense)
    #[arg(long, default_value_t = 300)]
    autoban_duration: u32,

    /// Maximum autoban duration in seconds (exponential cap)
    #[arg(long, default_value_t = 86400)]
    autoban_max_duration: u32,

    /// Seconds of inactivity before offense count decays to 0
    #[arg(long, default_value_t = 86400)]
    autoban_decay_window: u64,

    /// Emit one JSON line per tick instead of human-readable logs
    #[arg(long)]
    json: bool,

    /// Enable debug logging
    #[arg(short, long)]
    verbose: bool,

    /// Import ip2asn TSV file into SQLite and exit (no daemon mode)
    #[arg(long)]
    import_asn: Option<String>,
}

fn write_pid_file() -> io::Result<()> {
    let pid = process::id();
    fs::write(PID_PATH, format!("{pid}\n"))
}

fn remove_pid_file() {
    let _ = fs::remove_file(PID_PATH);
}

fn forward_sighup_to_daemon() {
    match fs::read_to_string(DAEMON_PID_PATH) {
        Ok(content) => {
            if let Ok(pid) = content.trim().parse::<i32>() {
                // SAFETY: sending a signal to a valid PID is safe.
                let ret = unsafe { libc::kill(pid, libc::SIGHUP) };
                if ret == 0 {
                    info!("forwarded SIGHUP to daemon (pid {pid})");
                } else {
                    warn!("failed to send SIGHUP to daemon (pid {pid}): {}", io::Error::last_os_error());
                }
            } else {
                warn!("daemon PID file unreadable: {DAEMON_PID_PATH}");
            }
        }
        Err(e) => warn!("daemon PID file not found ({DAEMON_PID_PATH}): {e}"),
    }
}

/// Import an ip2asn-v4.tsv file into the `asns` table of the SQLite database.
/// Uses atomic table swap (asns_new → asns) to avoid partial state.
fn import_asn_tsv(tsv_path: &str, db_path: &str) -> Result<()> {
    use rusqlite::Connection;
    use std::io::{BufRead, BufReader};
    use std::net::Ipv4Addr;

    let file = std::fs::File::open(tsv_path)
        .with_context(|| format!("cannot open TSV file: {tsv_path}"))?;
    let reader = BufReader::new(file);

    let conn = Connection::open(db_path)
        .with_context(|| format!("cannot open database: {db_path}"))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

    conn.execute("DROP TABLE IF EXISTS asns_new", [])?;
    conn.execute(
        "CREATE TABLE asns_new (
            start_ip INTEGER, end_ip INTEGER, asn TEXT, country TEXT, as_name TEXT
        )",
        [],
    )?;

    let tx = conn.unchecked_transaction()?;
    let mut stmt = tx.prepare(
        "INSERT INTO asns_new (start_ip, end_ip, asn, country, as_name) VALUES (?1, ?2, ?3, ?4, ?5)"
    )?;

    let mut count: u64 = 0;
    for line in reader.lines() {
        let line = line?;
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 5 {
            continue;
        }
        let (start_s, end_s, asn_num, country, as_name) =
            (fields[0], fields[1], fields[2], fields[3], fields[4]);
        if asn_num == "0" {
            continue; // skip unrouted
        }
        let start: u32 = start_s
            .parse::<Ipv4Addr>()
            .map(u32::from)
            .with_context(|| format!("bad start IP: {start_s}"))?;
        let end: u32 = end_s
            .parse::<Ipv4Addr>()
            .map(u32::from)
            .with_context(|| format!("bad end IP: {end_s}"))?;

        #[allow(clippy::cast_possible_wrap)]
        stmt.execute(rusqlite::params![
            start as i64,
            end as i64,
            format!("AS{asn_num}"),
            country,
            as_name,
        ])?;
        count += 1;
    }
    drop(stmt);
    tx.commit()?;

    conn.execute("DROP TABLE IF EXISTS asns", [])?;
    conn.execute("ALTER TABLE asns_new RENAME TO asns", [])?;
    conn.execute(
        "CREATE INDEX idx_ips ON asns (start_ip, end_ip)",
        [],
    )?;

    info!("Imported {count} ASN ranges from {tsv_path} into {db_path}");
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(if args.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .format_timestamp_secs()
        .init();

    // Handle --import-asn: import TSV and exit (no daemon mode)
    if let Some(tsv_path) = &args.import_asn {
        import_asn_tsv(tsv_path, &args.db_path)?;
        return Ok(());
    }

    // Register signal handlers.
    let sighup_flag = Arc::new(AtomicBool::new(false));
    let exit_flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&sighup_flag))
        .context("failed to register SIGHUP handler")?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&exit_flag))
        .context("failed to register SIGINT handler")?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&exit_flag))
        .context("failed to register SIGTERM handler")?;

    // Write PID file.
    if let Err(e) = write_pid_file() {
        warn!("failed to write PID file {PID_PATH}: {e}");
    }

    // Load ASN table — warn if missing, not fatal.
    let asn_table = match AsnTable::load_data(&args.db_path) {
        Some(data) => {
            let table = AsnTable::from_data(data);
            debug!("ASN table loaded from {}", args.db_path);
            Some(table)
        }
        None => {
            warn!("ASN table not available at {} — attacker IPs will lack ASN info", args.db_path);
            None
        }
    };

    // Open pinned BPF maps — fatal if daemon not running.
    let maps = BpfMaps::open(&args.pin_dir).context("failed to open pinned BPF maps (is the daemon running?)")?;

    let expire_ns = args.ttl.saturating_mul(1_000_000_000);

    let autoban_enabled = args.autoban_threshold > 0;
    let mut autoban_state = AutobanState::new(AutobanConfig {
        threshold: args.autoban_threshold,
        base_duration: args.autoban_duration,
        max_duration: args.autoban_max_duration,
        decay_window: args.autoban_decay_window,
    });

    // Restore active autobans from SQLite (before writer thread takes ownership).
    if autoban_enabled {
        let restore_rows = persist::restore_autobans(&args.persist_db);
        if !restore_rows.is_empty() {
            let now_mono = clock_ns();
            let now_wall = autoban::wall_clock_secs();
            autoban_state.restore(&restore_rows, &maps, now_mono, now_wall);
        }
    }

    // Spawn persistence writer thread.
    let persist_handle = PersistHandle::new(&args.persist_db);

    // TTL + Intel + Tracker state shared with ringbuf callback via Rc<RefCell<>>.
    // RingBufferBuilder::add requires FnMut + 'static; single-threaded, not Send.
    let ttl_state = Rc::new(RefCell::new(TtlState::new(expire_ns)));
    let intel_state = Rc::new(RefCell::new(IntelState::new()));
    let ip_tracker = Rc::new(RefCell::new(IpTracker::new(args.interval)));

    // Build ringbuf consumer.
    let ttl_rc = Rc::clone(&ttl_state);
    let intel_rc = Rc::clone(&intel_state);
    let tracker_rc = Rc::clone(&ip_tracker);

    let mut builder = RingBufferBuilder::new();
    builder
        .add(maps.rb_map(), move |data: &[u8]| -> i32 {
            if let Some(ev) = parse_event(data) {
                if ev.reason == REASON_NEW_BLOCK {
                    if expire_ns > 0 {
                        let now_ns = clock_ns();
                        ttl_rc.borrow_mut().schedule(ev.src_ip, now_ns);
                    }
                } else {
                    intel_rc.borrow_mut().add(ev.src_ip, ev.dest_port);
                    tracker_rc.borrow_mut().observe_port(ev.src_ip, ev.dest_port);
                }
            }
            0
        })
        .context("RingBufferBuilder::add")?;
    let rb = builder.build().context("RingBufferBuilder::build")?;

    info!(
        "syn-intel started: interval={}s, ttl={}s, autoban={}, pin_dir={}",
        args.interval,
        args.ttl,
        if autoban_enabled {
            format!("threshold={}", args.autoban_threshold)
        } else {
            "disabled".to_string()
        },
        args.pin_dir.display()
    );

    let mut metrics_state = MetricsState::new(args.interval);
    let poll_timeout = Duration::from_millis(100);
    let tick_interval = Duration::from_secs(args.interval);
    let autoban_interval = Duration::from_secs(60);
    let mut last_tick = Instant::now();
    let mut last_autoban = Instant::now();
    let mut tick_drop_ips: Option<Vec<(u32, bpf::DropInfo)>> = None;

    while !exit_flag.load(Ordering::Relaxed) {
        // SIGHUP: forward to daemon, then reinsert active autobans.
        if sighup_flag.swap(false, Ordering::Relaxed) {
            forward_sighup_to_daemon();
            if autoban_enabled {
                let now_mono = clock_ns();
                autoban_state.reinsert_active(&maps, now_mono);
            }
        }

        // Consume ringbuf events (non-blocking, up to 100ms).
        if let Err(e) = rb.poll(poll_timeout) {
            debug!("rb.poll: {e:#}");
        }

        let now = Instant::now();

        // 5s tick: TTL expiry + telemetry.
        if now.duration_since(last_tick) >= tick_interval {
            last_tick = now;

            // TTL expiry pass.
            if expire_ns > 0 {
                let now_ns = clock_ns();
                let mut expired = ttl_state.borrow_mut().expire(&maps, now_ns);
                if !expired.is_empty() {
                    debug!("TTL expired {} IPs", expired.len());
                    // Clean up tracker entries for expired IPs.
                    for row in &expired {
                        ip_tracker.borrow_mut().remove(row.ip);
                    }
                    // Resolve ASN on main thread before sending to writer.
                    for row in &mut expired {
                        let ip_hbo = u32::from_be(row.ip);
                        if let Some(entry) = asn_table.as_ref().and_then(|t| t.lookup(ip_hbo)) {
                            row.asn.clone_from(&entry.asn);
                        }
                    }
                    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                    persist_handle.send(PersistMsg::TtlExpire { rows: expired, ts });
                }
            }

            // Autoban expiry (checked every 5s tick, not just 60s).
            if autoban_enabled {
                let now_mono = clock_ns();
                let now_wall = autoban::wall_clock_secs();
                let deactivated = autoban_state.expire(&maps, now_mono, now_wall);
                if !deactivated.is_empty() {
                    debug!("autoban expired {} prefixes", deactivated.len());
                    persist_handle.send(PersistMsg::AutobanDeactivate { rows: deactivated });
                }
            }

            // Single BPF map iteration per tick — shared across
            // ip_tracker, telemetry, and (on 60s boundary) autoban/snapshot.
            match maps.iter_drop_ips() {
                Ok(drop_ips) => {
                    let now_wall = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    ip_tracker.borrow_mut().update_from_bpf(&drop_ips, now_wall);

                    match poll_tick(
                        &maps,
                        &drop_ips,
                        &mut metrics_state,
                        asn_table.as_ref(),
                        &ttl_state.borrow(),
                        &autoban_state,
                    ) {
                        Ok(snap) => {
                            if args.json {
                                println!("{}", report::json_report(&snap));
                            } else {
                                report::log_report(&snap);
                            }
                        }
                        Err(e) => {
                            error!("tick failed: {e:#}");
                        }
                    }

                    // Stash for 60s tick reuse (avoids second iteration).
                    tick_drop_ips = Some(drop_ips);
                }
                Err(e) => {
                    error!("iter_drop_ips failed: {e:#}");
                    tick_drop_ips = None;
                }
            }
        }

        // 60s tick: autoban evaluation + intel drain.
        if now.duration_since(last_autoban) >= autoban_interval {
            last_autoban = now;

            // Reuse drop_ips from the 5s tick (always fires on 60s boundary).
            if let Some(ref drop_ips) = tick_drop_ips {
                if autoban_enabled {
                    let now_mono = clock_ns();
                    let now_wall = autoban::wall_clock_secs();
                    let actions = autoban_state.evaluate(
                        drop_ips,
                        asn_table.as_ref(),
                        &maps,
                        &mut ttl_state.borrow_mut(),
                        now_mono,
                        now_wall,
                    );
                    if !actions.is_empty() {
                        debug!("autoban: {} new bans", actions.len());
                        persist_handle.send(PersistMsg::AutobanUpsert { rows: actions });
                    }
                }

                // Snapshot: authoritative per-IP counts + peak_pps from BPF maps.
                let rows = ip_tracker.borrow().build_snapshot_rows(
                    drop_ips,
                    asn_table.as_ref(),
                );
                if !rows.is_empty() {
                    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                    persist_handle.send(PersistMsg::Snapshot { rows, ts });
                }
            }

            // Drain accumulated sampled-drop intel and persist.
            let drained = intel_state.borrow_mut().drain();
            if !drained.is_empty() {
                let intel_rows: Vec<IntelRow> = drained
                    .into_iter()
                    .map(|((ip, port), count)| {
                        let ip_hbo = u32::from_be(ip);
                        let asn = asn_table
                            .as_ref()
                            .and_then(|t| t.lookup(ip_hbo))
                            .map(|e| e.asn.clone())
                            .unwrap_or_default();
                        IntelRow { ip, port, count, asn }
                    })
                    .collect();
                let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                persist_handle.send(PersistMsg::Intel { rows: intel_rows, ts });
            }

            // Blacklist snapshot: per-IP blacklist drop counts from BPF maps.
            if let Ok(bl_ips) = maps.iter_blacklist_cnt() {
                let rows = build_blacklist_rows(&bl_ips, asn_table.as_ref());
                if !rows.is_empty() {
                    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                    persist_handle.send(PersistMsg::BlacklistSnapshot { rows, ts });
                }
            }
        }
    }

    // Graceful shutdown.
    info!("shutting down...");
    persist_handle.shutdown();
    remove_pid_file();
    Ok(())
}

fn poll_tick(
    maps: &BpfMaps,
    drop_ips: &[(u32, bpf::DropInfo)],
    state: &mut MetricsState,
    asn_table: Option<&AsnTable>,
    ttl: &TtlState,
    autoban: &AutobanState,
) -> Result<TelemetrySnapshot> {
    let total_drops = maps.read_drop_cnt()?;
    let pps = state.compute_pps(total_drops);
    let drop_ips_count = drop_ips.len();
    let blacklist_active = maps.count_blacklist()?;
    let rb_fail_cnt = maps.read_rb_fail_cnt()?;
    let top_attackers = metrics::top_k_attackers(drop_ips, 5, asn_table);

    debug!(
        "active_blocks={} heap_size={} heap_drops={} autoban_active={}",
        ttl.active_blocks(),
        ttl.heap_size(),
        ttl.heap_drop_total(),
        autoban.active_bans()
    );

    #[allow(clippy::cast_possible_truncation)]
    let timestamp_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(TelemetrySnapshot {
        timestamp_secs,
        total_drops,
        pps,
        drop_ips_count,
        blacklist_active,
        rb_fail_cnt,
        top_attackers,
    })
}

/// Monotonic clock in nanoseconds (matches BPF `bpf_ktime_get_ns()`).
fn clock_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: CLOCK_MONOTONIC is always available.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    #[allow(clippy::cast_sign_loss)]
    {
        (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
    }
}
