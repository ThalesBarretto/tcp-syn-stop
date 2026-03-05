// SPDX-License-Identifier: GPL-2.0-only
mod app;
mod asn_table;
mod bpf;
mod forensics;
mod input;
mod protocol;
mod time_fmt;
mod ui;
mod validation;

use std::path::Path;

use app::{App, Tab};
use forensics::ForensicsState;
use protocol::SystemState;

use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::PathBuf,
    time::{Duration, Instant},
};

/// syn-sight: Real-time TUI monitor for tcp_syn_stop
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory where BPF maps are pinned
    #[arg(long, default_value = "/sys/fs/bpf/tcp_syn_stop")]
    pin_dir: PathBuf,

    /// Polling interval in milliseconds
    #[arg(short, long, default_value_t = 1000)]
    interval: u64,

    /// Path to daemon SQLite database (for Forensics tab)
    #[arg(long, default_value = "/opt/tcp_syn_stop/ip2asn.db")]
    db_path: String,

    /// Output current state as JSON and exit (single-shot, no TUI)
    #[arg(long)]
    json: bool,

    /// Path to whitelist config file
    #[arg(long, default_value = "/etc/tcp_syn_stop/whitelist.conf")]
    whitelist_path: String,

    /// Path to blacklist config file
    #[arg(long, default_value = "/etc/tcp_syn_stop/blacklist.conf")]
    blacklist_path: String,

    /// DogStatsD UDP address (e.g. 127.0.0.1:8125). Disabled when omitted.
    #[arg(long)]
    statsd_addr: Option<String>,

    /// Use ASCII characters instead of Unicode block elements for sparklines
    #[arg(long)]
    ascii: bool,
}

#[derive(Serialize, Deserialize)]
struct JsonOutput {
    live: Option<SystemState>,
    forensics: Option<ForensicsState>,
    neighborhoods: Vec<forensics::Neighborhood>,
    reason_breakdown: Vec<(String, u64)>,
}

fn open_bpf(pin_dir: &Path) -> Option<bpf::BpfMaps> {
    match bpf::BpfMaps::open(pin_dir) {
        Ok(m) => Some(m),
        Err(e) => {
            eprintln!("warning: BPF maps not available: {e:#}");
            None
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.json {
        let bpf_maps = open_bpf(&args.pin_dir);
        let mut app = App::new(bpf_maps, args.db_path, args.whitelist_path, args.blacklist_path);
        if let Some(data) = asn_table::AsnTable::load_data(&app.db_path) {
            app.asn_table = Some(asn_table::AsnTable::from_data(data));
        }
        let _ = app.fetch_data();
        let _ = app.fetch_forensics_now();
        let neighborhoods = std::mem::take(&mut app.neighborhoods);
        let reason_breakdown = std::mem::take(&mut app.reason_breakdown);
        let output = JsonOutput {
            live: app.state.take(),
            forensics: app.forensics.take(),
            neighborhoods,
            reason_breakdown,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let bpf_maps = open_bpf(&args.pin_dir);
    let mut app = App::new(bpf_maps, args.db_path, args.whitelist_path, args.blacklist_path);
    app.use_ascii = args.ascii;
    if let Some(addr) = &args.statsd_addr {
        app.init_statsd(addr);
    }
    app.load_asn_table_async();
    // First-frame fetch so the initial render is not empty
    let _ = app.fetch_data();
    app.update_asn_pps();
    let res = run_app(&mut terminal, &mut app, Duration::from_millis(args.interval));

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App, tick_rate: Duration) -> io::Result<()> {
    let mut last_tick = Instant::now();
    loop {
        let render_start = Instant::now();
        terminal.draw(|f| render(f, app))?;
        #[allow(clippy::cast_possible_truncation)]
        {
            app.last_render_us = render_start.elapsed().as_micros() as u32;
        }

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if input::handle_event(app, key.code) {
                    return Ok(());
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.poll_asn_table();
            app.poll_forensics();
            // Debounced ASN search
            if let Some(ref search) = app.asn_search {
                if let Some(changed_at) = search.query_changed_at {
                    if changed_at.elapsed() >= Duration::from_millis(150) {
                        app.run_asn_search();
                        if let Some(ref mut s) = app.asn_search {
                            s.query_changed_at = None;
                        }
                    }
                }
            }
            let _ = app.fetch_data();
            app.verify_pending_syncs();
            app.tick_sync_status();
            app.emit_statsd();
            // DB freshness is on the HUD (all tabs), so always refresh forensics.
            app.fetch_forensics_async();
            match app.active_tab {
                Tab::Live => {
                    app.update_asn_pps();
                }
                Tab::Forensics => {}
                Tab::Lists => {
                    app.clear_stale_status();
                }
            }
            last_tick = Instant::now();
        }
    }
}

fn render(f: &mut ratatui::Frame, app: &App) {
    let size = f.size();
    if size.width < 80 || size.height < 24 {
        use ratatui::{style::{Color, Style}, widgets::Paragraph};
        let msg = format!("Terminal too small: {}x{} (min 80x24)", size.width, size.height);
        f.render_widget(Paragraph::new(msg).style(Style::default().fg(Color::Red)), size);
        return;
    }

    // Persistent HUD (2 rows) + tab content
    let outer = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            ratatui::layout::Constraint::Length(3),
            ratatui::layout::Constraint::Min(20),
        ])
        .split(size);

    ui::render_hud(f, app, outer[0]);

    match app.active_tab {
        Tab::Live => ui::render_live(f, app, outer[1]),
        Tab::Forensics => ui::render_forensics(f, app, outer[1]),
        Tab::Lists => ui::render_lists(f, app, outer[1]),
    }
    if let Some(ref picker) = app.subnet_picker {
        ui::render_subnet_picker(f, picker);
    }
    if let Some(ref search) = app.asn_search {
        ui::render_asn_search(f, search);
    }
    if app.show_help {
        ui::render_help_overlay(f);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use protocol::{Attacker, Metrics};

    #[test]
    fn test_json_output_structure() {
        let output = JsonOutput {
            live: Some(SystemState {
                uptime_secs: 3600,
                metrics: Metrics {
                    total_drops: 50000,
                    latest_pps: 1500,
                    active_blocks: 3,
                    blacklist_active: 0,
                },
                top_attackers: vec![],
                top_ports: vec![],
                ifaces: vec![],
                instrumentation: Default::default(),
            }),
            forensics: None,
            neighborhoods: vec![],
            reason_breakdown: vec![],
        };
        let json = serde_json::to_string_pretty(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["live"]["uptime_secs"], 3600);
        assert_eq!(parsed["live"]["metrics"]["total_drops"], 50000);
        assert!(parsed["forensics"].is_null());
    }

    #[test]
    fn test_json_output_empty_state() {
        let output = JsonOutput {
            live: None,
            forensics: None,
            neighborhoods: vec![],
            reason_breakdown: vec![],
        };
        let json = serde_json::to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["live"].is_null());
        assert!(parsed["forensics"].is_null());
    }

    #[test]
    fn test_json_roundtrip_attackers() {
        let output = JsonOutput {
            live: Some(SystemState {
                uptime_secs: 100,
                metrics: Metrics {
                    total_drops: 0,
                    latest_pps: 0,
                    active_blocks: 0,
                    blacklist_active: 0,
                },
                top_attackers: vec![
                    Attacker {
                        ip: "10.0.0.1".into(),
                        asn: "AS1".into(),
                        count: 100,
                        peak_pps: 50,
                    },
                    Attacker {
                        ip: "10.0.0.2".into(),
                        asn: "AS2".into(),
                        count: 200,
                        peak_pps: 100,
                    },
                    Attacker {
                        ip: "10.0.0.3".into(),
                        asn: "AS3".into(),
                        count: 300,
                        peak_pps: 150,
                    },
                ],
                top_ports: vec![],
                ifaces: vec![],
                instrumentation: Default::default(),
            }),
            forensics: None,
            neighborhoods: vec![],
            reason_breakdown: vec![],
        };
        let json = serde_json::to_string(&output).unwrap();
        let roundtrip: JsonOutput = serde_json::from_str(&json).unwrap();
        let live = roundtrip.live.unwrap();
        assert_eq!(live.top_attackers.len(), 3);
        assert_eq!(live.top_attackers[0].ip, "10.0.0.1");
        assert_eq!(live.top_attackers[1].count, 200);
        assert_eq!(live.top_attackers[2].peak_pps, 150);
    }
}
