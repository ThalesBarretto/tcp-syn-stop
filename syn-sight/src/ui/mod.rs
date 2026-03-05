// SPDX-License-Identifier: GPL-2.0-only
//! UI rendering modules and shared helpers.
//!
//! Each tab has its own submodule (`live`, `forensics`, `lists`) plus a shared
//! `overlays` module for cross-tab popups (ASN search, add-action, drilldown).
//! This module provides common utilities: `format_pps` for human-readable
//! packet rates and `country_color` for consistent country-code color mapping.

mod forensics;
mod lists;
mod live;
mod overlays;
pub mod theme;

pub use forensics::render_forensics;
pub use lists::render_lists;
pub use live::render_live;
pub use overlays::render_asn_search;
pub use overlays::render_help_overlay;
pub use overlays::render_subnet_picker;

use crate::app::App;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

/// Interpolate between a dark and bright variant of a base color based on value/max ratio.
fn gradient_color(base: Color, value: u64, max: u64) -> Color {
    let t = if max > 0 { value as f64 / max as f64 } else { 0.0 };
    let t = t.clamp(0.0, 1.0);
    let (r0, g0, b0, r1, g1, b1) = match base {
        Color::Red => (100, 0, 0, 255, 60, 60),
        Color::Green => (0, 80, 0, 60, 255, 60),
        Color::Yellow => (130, 130, 0, 255, 255, 60),
        _ => (80, 80, 80, 200, 200, 200),
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let lerp = |a: u8, b: u8| -> u8 { (a as f64 + (b as f64 - a as f64) * t) as u8 };
    Color::Rgb(lerp(r0, r1), lerp(g0, g1), lerp(b0, b1))
}

/// Build a single sparkline row: `label  ▁▂▃▅▇█▅▃▁  1.5K`
///
/// Each sample maps to one of 9 Unicode block levels, auto-scaled to
/// the row's own maximum.  Direct labeling (ASN + country) avoids
/// reliance on a color legend.
pub(crate) fn sparkline_spans(label: &str, data: &[u64], color: Color, width: usize, use_ascii: bool, bold: bool, truecolor: bool) -> Line<'static> {
    const LABEL_W: usize = 12;
    const VALUE_W: usize = 7;
    let spark_width = width.saturating_sub(LABEL_W + VALUE_W);

    let current_val = data.last().copied().unwrap_or(0);
    let start = data.len().saturating_sub(spark_width);
    let visible = &data[start..];
    let max_val = visible.iter().copied().max().unwrap_or(1).max(1);

    const BARS: [char; 9] = [' ', '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}', '\u{2588}'];
    const BARS_ASCII: [char; 9] = [' ', '.', '.', '-', '-', '=', '=', '#', '#'];
    let bars = if use_ascii { &BARS_ASCII } else { &BARS };

    let val_style = if bold {
        Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let pad = spark_width.saturating_sub(visible.len());

    let mut spans: Vec<Span<'static>> = Vec::with_capacity(3 + visible.len());
    spans.push(Span::styled(
        format!("{:<LABEL_W$}", label),
        Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
    ));

    // Left-pad so sparkline right-aligns
    if pad > 0 {
        spans.push(Span::raw(" ".repeat(pad)));
    }

    if truecolor {
        // Per-character gradient: each bar gets its own Rgb color
        for &v in visible {
            let idx = (v * 8 / max_val).min(8) as usize;
            let ch = bars[idx];
            let gc = gradient_color(color, v, max_val);
            let style = if bold {
                Style::default().fg(gc).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(gc)
            };
            spans.push(Span::styled(String::from(ch), style));
        }
    } else {
        // Flat color for 16-color terminals
        let spark_str: String = visible
            .iter()
            .map(|&v| {
                let idx = (v * 8 / max_val).min(8) as usize;
                bars[idx]
            })
            .collect();
        let bar_style = if bold {
            Style::default().fg(color).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(color)
        };
        spans.push(Span::styled(spark_str, bar_style));
    }

    spans.push(Span::styled(
        format!("{:>VALUE_W$}", format_pps(current_val as f64)),
        val_style,
    ));

    Line::from(spans)
}

/// Persistent HUD: health bar + Total PPS sparkline + separator, visible on all tabs.
pub fn render_hud(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // health bar
            Constraint::Length(1), // Total PPS sparkline
            Constraint::Length(1), // horizontal rule separator
        ])
        .split(area);

    // Row 0: health bar + status
    let health_line = build_health_line(app);
    f.render_widget(Paragraph::new(health_line), rows[0]);

    // Row 1: Total PPS sparkline
    let total_data: Vec<u64> = app.pps_history.iter().copied().collect();
    let width = rows[1].width as usize;
    let line = sparkline_spans("Total PPS", &total_data, Color::Red, width, app.use_ascii, false, app.truecolor);
    f.render_widget(Paragraph::new(line), rows[1]);

    // Row 2: horizontal rule — visually anchors HUD above tab content
    let rule = "\u{2500}".repeat(rows[2].width as usize);
    let dim_rule = Style::default().fg(Color::DarkGray).add_modifier(Modifier::DIM);
    f.render_widget(Paragraph::new(Span::styled(rule, dim_rule)), rows[2]);
}

/// Build the health bar line (BPF/RB/Fetch + status).
pub(crate) fn build_health_line(app: &App) -> Line<'static> {
    let dim = Style::default().fg(Color::DarkGray).add_modifier(Modifier::DIM);
    let green = Style::default().fg(Color::Green);
    let yellow = Style::default().fg(Color::Yellow);
    let red = Style::default().fg(Color::Red);

    let (bpf_label, bpf_style) = if app.bpf_fetch_ok {
        ("OK", green)
    } else {
        ("ERR", red)
    };

    let (rb_label, rb_style) = if let Some(s) = &app.state {
        let rb_fail = s.instrumentation.ringbuf_reserve_fails;
        let drop_cnt = s.metrics.total_drops;
        if rb_fail == 0 {
            ("OK".to_string(), green)
        } else if drop_cnt > 0 {
            #[allow(clippy::cast_precision_loss)]
            let pct = (rb_fail as f64) / ((drop_cnt + rb_fail) as f64) * 100.0;
            if pct < 1.0 {
                (format!("{pct:.1}% loss"), yellow)
            } else {
                (format!("{pct:.0}% loss"), red)
            }
        } else {
            (format!("{rb_fail} fails"), yellow)
        }
    } else {
        ("--".to_string(), dim)
    };

    // Map utilization: drop_ips LRU capacity
    let (map_label, map_style) = {
        let pct = app.drop_ips_util_pct;
        if pct >= 90.0 {
            (format!("Map:{pct:.0}%"), red)
        } else if pct >= 50.0 {
            (format!("Map:{pct:.0}%"), yellow)
        } else {
            (format!("Map:{pct:.0}%"), green)
        }
    };

    // DB freshness: staleness of syn-intel SNAPSHOT rows.
    // Gate on attack_active (PPS > 0), not total_drops (cumulative, never resets).
    // syn-intel only writes SNAPSHOTs when drop_ips is non-empty, so staleness
    // during idle is expected and should not alarm.
    let (db_label, db_style) = {
        match (app.db_freshness_s, app.attack_active) {
            (_, false) => ("DB:--".to_string(), dim),
            (None, _) => ("DB:--".to_string(), dim),
            (Some(age), _) if age < 120 => ("DB:OK".to_string(), green),
            (Some(age), _) if age < 300 => (format!("DB:{age}s"), yellow),
            (Some(age), _) => (format!("DB:{age}s"), red),
        }
    };

    // Config validation: whitelist/blacklist parse errors
    let (cfg_label, cfg_style) = if app.config_errors.is_empty() {
        ("Cfg:OK".to_string(), green)
    } else {
        (format!("Cfg:{}err", app.config_errors.len()), red)
    };

    let (fetch_label, fetch_style) = {
        let us = app.last_fetch_us;
        if us < 100_000 {
            (format!("{}us", us), green)
        } else if us < 500_000 {
            (format!("{}ms", us / 1000), yellow)
        } else {
            (format!("{}ms", us / 1000), red)
        }
    };

    let asn_indicator = if app.is_asn_loading() {
        " ASN: loading..."
    } else if app.asn_table.is_some() {
        ""
    } else {
        " ASN: unavailable"
    };
    let status_text = if let Some(s) = &app.state {
        let total_blocks = s.metrics.active_blocks + s.metrics.blacklist_active;
        format!(
            "Blocks: {} ({} BL) | Total: {}{}",
            total_blocks, s.metrics.blacklist_active, s.metrics.total_drops, asn_indicator
        )
    } else {
        format!("Waiting for daemon...{}", asn_indicator)
    };

    // BPF sync status: transient indicator during config propagation
    let sync_spans: Vec<Span<'static>> = match app.sync_status {
        crate::app::SyncStatus::Idle => vec![],
        crate::app::SyncStatus::Pending(n) => vec![
            Span::styled(" Sync:", dim),
            Span::styled(
                format!("{n}.."),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
        ],
        crate::app::SyncStatus::Confirmed(_) => vec![
            Span::styled(" Sync:", dim),
            Span::styled("OK", green),
        ],
    };

    let mut spans = vec![
        Span::styled(" BPF:", dim),
        Span::styled(bpf_label, bpf_style),
        Span::styled(" RB:", dim),
        Span::styled(rb_label, rb_style),
        Span::styled(" ", dim),
        Span::styled(map_label, map_style),
        Span::styled(" ", dim),
        Span::styled(db_label, db_style),
        Span::styled(" ", dim),
        Span::styled(cfg_label, cfg_style),
    ];
    spans.extend(sync_spans);
    spans.extend([
        Span::styled(" Fetch:", dim),
        Span::styled(fetch_label, fetch_style),
        Span::styled(" | ", dim),
        Span::styled(status_text, Style::default().fg(Color::Yellow)),
    ]);

    // Ephemeral help hint for first 10 seconds or until any key is pressed
    if !app.any_key_pressed && app.session_start.elapsed() < std::time::Duration::from_secs(10) {
        spans.push(Span::styled(" [?] Help", dim));
    }

    Line::from(spans)
}

pub(crate) fn country_color(cc: &str) -> Color {
    match cc {
        "US" | "CA" | "MX" | "PR" | "BZ" | "GT" | "HN" | "SV" | "NI" | "CR" | "PA" => Color::Green,
        "BR" | "AR" | "CL" | "CO" | "PE" | "VE" | "EC" | "BO" | "PY" | "UY" => Color::Magenta,
        "GB" | "DE" | "FR" | "IT" | "ES" | "NL" | "BE" | "CH" | "AT" | "SE" | "NO" | "DK" | "FI" | "PL" | "CZ"
        | "RO" | "HU" | "PT" | "IE" | "GR" | "BG" | "HR" | "SK" | "SI" | "EE" | "LV" | "LT" | "UA" | "BY" | "MD" => {
            Color::Cyan
        }
        "RU" | "KZ" | "UZ" | "GE" | "AM" | "AZ" => Color::LightCyan,
        "CN" | "JP" | "KR" | "IN" | "AU" | "NZ" | "TW" | "HK" | "SG" | "MY" | "TH" | "VN" | "PH" | "ID" | "BD"
        | "PK" | "MM" | "KH" => Color::Yellow,
        "TR" | "IL" | "SA" | "AE" | "IR" | "IQ" | "SY" | "JO" | "LB" => Color::LightYellow,
        "ZA" | "NG" | "KE" | "EG" | "MA" | "TN" | "DZ" | "GH" | "ET" => Color::Blue,
        "None" | "" => Color::DarkGray,
        _ => Color::White,
    }
}

pub(crate) fn format_pps(v: f64) -> String {
    if v >= 1_000_000.0 {
        format!("{:.1}M", v / 1_000_000.0)
    } else if v >= 1_000.0 {
        format!("{:.1}K", v / 1_000.0)
    } else {
        format!("{:.0}", v)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_country_color_known() {
        assert_eq!(country_color("US"), Color::Green);
        assert_eq!(country_color("CN"), Color::Yellow);
        assert_eq!(country_color("RU"), Color::LightCyan);
        assert_eq!(country_color("DE"), Color::Cyan);
    }

    #[test]
    fn test_country_color_empty() {
        assert_eq!(country_color(""), Color::DarkGray);
        assert_eq!(country_color("None"), Color::DarkGray);
    }

    #[test]
    fn test_format_pps_millions() {
        assert_eq!(format_pps(1_500_000.0), "1.5M");
    }

    #[test]
    fn test_format_pps_thousands() {
        assert_eq!(format_pps(2_500.0), "2.5K");
    }

    #[test]
    fn test_format_pps_small() {
        assert_eq!(format_pps(42.0), "42");
    }

    #[test]
    fn test_format_pps_boundary_999() {
        assert_eq!(format_pps(999.0), "999");
    }

    #[test]
    fn test_format_pps_boundary_1000() {
        assert_eq!(format_pps(1000.0), "1.0K");
    }

    #[test]
    fn test_format_pps_boundary_999999() {
        assert_eq!(format_pps(999_999.0), "1000.0K");
    }

    #[test]
    fn test_format_pps_boundary_1000000() {
        assert_eq!(format_pps(1_000_000.0), "1.0M");
    }
}
