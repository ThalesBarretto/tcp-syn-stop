// SPDX-License-Identifier: GPL-2.0-only
use super::{country_color, sparkline_spans};
use crate::app::{App, SwarmView};
use crate::time_fmt;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{block::BorderType, Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

pub fn render_live(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),  // [0] Interface Bar
                Constraint::Length(10), // [1] Attack Pulse (per-ASN, Total PPS in HUD)
                Constraint::Min(10),   // [2] Tables
                Constraint::Length(1), // [3] Footer
            ]
            .as_ref(),
        )
        .split(area);

    // --- [0] INTERFACE BAR ---
    let iface_spans: Vec<Span> = if let Some(s) = &app.state {
        if s.ifaces.is_empty() {
            vec![Span::styled(
                " (no interface data) ",
                Style::default().fg(Color::DarkGray),
            )]
        } else {
            s.ifaces
                .iter()
                .map(|iface| {
                    let mode = if iface.native { "XDP/Native" } else { "XDP/Generic" };
                    let color = if iface.native { Color::Cyan } else { Color::Yellow };
                    Span::styled(
                        format!(" [ {} {} ] ", iface.name, mode),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    )
                })
                .collect()
        }
    } else {
        vec![Span::styled(
            " (no interface data) ",
            Style::default().fg(Color::DarkGray),
        )]
    };
    let iface_bar = Paragraph::new(Line::from(iface_spans))
        .block(Block::default().title(" Protected Interfaces ").borders(Borders::ALL).border_type(BorderType::Rounded));
    f.render_widget(iface_bar, chunks[0]);

    // --- [1] ATTACK PULSE — Per-ASN Small Multiples ---
    let inner_width = chunks[1].width.saturating_sub(2) as usize;
    let max_rows = chunks[1].height.saturating_sub(2) as usize;

    let mut lines: Vec<Line> = Vec::new();

    // Per-ASN rows, sorted by current PPS descending (Total PPS is in the persistent HUD)
    // Colors are semantic: Red=rising, Yellow=steady, Green=falling
    let mut asn_series: Vec<(&str, Color, Vec<u64>)> = app
        .asn_pps_history
        .iter()
        .map(|(asn, hist)| {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let data: Vec<u64> = hist.iter().map(|&v| v as u64).collect();
            let color = app.asn_velocity_color(asn);
            (asn.as_str(), color, data)
        })
        .collect();
    asn_series.sort_by(|a, b| {
        let a_last = a.2.last().copied().unwrap_or(0);
        let b_last = b.2.last().copied().unwrap_or(0);
        b_last.cmp(&a_last)
    });

    for (asn, color, data) in asn_series.iter().take(max_rows) {
        let cc = app.asn_country(asn);
        let name = app.asn_name(asn);
        let label = match (cc.is_empty(), name.is_empty()) {
            (true, true) => asn.to_string(),
            (true, false) => format!("{asn} {name}"),
            (false, true) => format!("{cc} {asn}"),
            (false, false) => format!("{cc} {asn} {name}"),
        };
        let pulsing = app.asn_is_pulsing(asn);
        lines.push(sparkline_spans(&label, data, *color, inner_width, app.use_ascii, pulsing, app.truecolor));
    }

    let pulse = Paragraph::new(lines)
        .block(Block::default().title(" Attack Pulse (PPS) ").borders(Borders::ALL).border_type(BorderType::Rounded));
    f.render_widget(pulse, chunks[1]);

    // --- [2] TABLES ---
    let table_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
        .split(chunks[2]);

    // Dispatch swarm rendering based on view mode
    match app.swarm_view {
        SwarmView::PerASN => render_swarm_aggregate(f, app, table_chunks[0]),
        SwarmView::PerIP => render_swarm_per_ip(f, app, table_chunks[0]),
    }

    // Target Heatmap
    let port_rows: Vec<Row> = if let Some(s) = &app.state {
        s.top_ports
            .iter()
            .map(|p| {
                Row::new(vec![
                    Cell::from(format!("Port {}", p.port)),
                    Cell::from(p.hits.to_string()),
                ])
            })
            .collect()
    } else {
        vec![]
    };

    let heatmap_title: Line = match &app.port_suggestion {
        Some(suggestion) => Line::from(vec![
            Span::raw(" Target Heatmap "),
            Span::styled(
                format!("— {} ", suggestion),
                Style::default().fg(Color::DarkGray).add_modifier(Modifier::DIM),
            ),
        ]),
        None => Line::from(" Target Heatmap "),
    };

    let port_table = Table::new(port_rows, [Constraint::Length(10), Constraint::Min(10)])
        .header(
            Row::new(vec!["Target", "Drops"])
                .style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))
                .bottom_margin(1),
        )
        .block(Block::default().title(heatmap_title).borders(Borders::ALL).border_type(BorderType::Rounded));
    f.render_widget(port_table, table_chunks[1]);

    // --- [3] FOOTER (left: actions, right: metrics DIM) ---
    let footer_line = if app.add_action.is_some() {
        Line::from(Span::styled(
            " [1/2/3] Select scope | [Esc] Cancel ",
            Style::default().fg(Color::DarkGray),
        ))
    } else {
        let preview = match app.swarm_view {
            SwarmView::PerASN => {
                if let Some(agg) = app.swarm_agg_entries.get(app.swarm_agg_scroll) {
                    format!(
                        " [b] block {} ({} IPs) [Enter] drill down [g] IP view",
                        agg.asn, agg.ip_count
                    )
                } else {
                    " [g] IP view".to_string()
                }
            }
            SwarmView::PerIP => {
                let entries = app.effective_swarm_entries();
                if let Some(e) = entries.get(app.swarm_scroll) {
                    let asn_info = if e.asn.is_empty() { String::new() } else { format!(" ({})", e.asn) };
                    if app.swarm_asn_filter.is_some() {
                        format!(" [b] block {}/32{} [Esc] back", e.ip, asn_info)
                    } else {
                        format!(" [b] block {}/32{} [g] ASN view", e.ip, asn_info)
                    }
                } else if app.swarm_asn_filter.is_some() {
                    " [Esc] back".to_string()
                } else {
                    " [g] ASN view".to_string()
                }
            }
        };
        let left = format!("{} [?] Help", preview);
        let staleness_ms = app.last_fetch_at.elapsed().as_millis();
        let cache_info = match app.asn_cache_hit_pct {
            Some(pct) => format!("({:.0}% hit) ", pct),
            None => String::new(),
        };
        let right = format!(
            "fetch: {}us {} render: {}us  {}ms ago ",
            app.last_fetch_us, cache_info, app.last_render_us, staleness_ms
        );
        let pad_width = chunks[3].width as usize;
        let pad = pad_width.saturating_sub(left.len() + right.len());
        Line::from(vec![
            Span::styled(left, Style::default().fg(Color::DarkGray)),
            Span::raw(" ".repeat(pad)),
            Span::styled(right, Style::default().fg(Color::DarkGray).add_modifier(Modifier::DIM)),
        ])
    };
    let footer = Paragraph::new(footer_line);
    f.render_widget(footer, chunks[3]);

    // Add-action overlay
    if let Some(action) = &app.add_action {
        super::overlays::render_add_action_modal(f, action);
    }
}

fn render_swarm_per_ip(f: &mut Frame, app: &App, area: Rect) {
    let entries = app.effective_swarm_entries();
    let entry_count = entries.len();

    let dim_hint = Style::default().fg(Color::DarkGray).add_modifier(Modifier::DIM);

    let filter_hint = if app.hide_blacklisted {
        Span::styled("[f] show blacklisted ", dim_hint)
    } else {
        Span::styled("[f] hide blacklisted ", dim_hint)
    };

    let swarm_title: Line = if let Some(ref asn) = app.swarm_asn_filter {
        Line::from(vec![
            Span::raw(format!(" Active Swarm ({} - {} IPs) ", asn, entry_count)),
            Span::styled("[Esc] back ", dim_hint),
            filter_hint,
        ])
    } else if app.drop_ips_total > app.swarm_entries.len() {
        Line::from(vec![
            Span::raw(format!(" Active Swarm ({} of {} IPs) ", app.swarm_entries.len(), app.drop_ips_total)),
            filter_hint,
        ])
    } else {
        Line::from(vec![
            Span::raw(format!(" Active Swarm ({} IPs) ", app.swarm_entries.len())),
            filter_hint,
        ])
    };

    // Empty state: show "System Secure" when no swarm entries and no ASN filter
    if entries.is_empty() && app.swarm_asn_filter.is_none() {
        let bpf_status = if app.bpf_fetch_ok { "BPF filter: Active" } else { "BPF filter: Error" };
        let bpf_color = if app.bpf_fetch_ok { Color::Green } else { Color::Red };
        let rules = app.state.as_ref().map_or(0, |s| s.metrics.active_blocks + s.metrics.blacklist_active);
        let attack_info = match app.last_attack_end {
            Some(t) => {
                let ago = t.elapsed().as_secs();
                if ago < 60 {
                    format!("Last attack mitigated: {}s ago", ago)
                } else {
                    format!("Last attack mitigated: {}m ago", ago / 60)
                }
            }
            None => "No attacks detected this session".into(),
        };
        let block = Block::default()
            .title(swarm_title)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded);
        let inner = block.inner(area);
        f.render_widget(block, area);
        let lines = vec![
            Line::from(""),
            Line::from(Span::styled("  System Secure", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(Span::styled(format!("  {bpf_status}"), Style::default().fg(bpf_color))),
            Line::from(Span::styled(format!("  Active rules: {rules}"), Style::default().fg(Color::DarkGray))),
            Line::from(Span::styled(format!("  {attack_info}"), Style::default().fg(Color::DarkGray))),
        ];
        f.render_widget(Paragraph::new(lines), inner);
        return;
    }

    let swarm_rows: Vec<Row> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let style = if i == app.swarm_scroll {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let reason_color = if e.reason == "Blacklist" {
                Color::Red
            } else {
                Color::Yellow
            };
            Row::new(vec![
                Cell::from(e.ip.as_str()),
                Cell::from(e.country.as_str()).style(Style::default().fg(country_color(&e.country))),
                if e.rir_country.is_empty() {
                    Cell::from("--").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::DIM))
                } else {
                    Cell::from(e.rir_country.as_str()).style(Style::default().fg(country_color(&e.rir_country)))
                },
                Cell::from(e.asn.as_str()),
                Cell::from(e.as_name.as_str()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(e.total_drops.to_string()),
                Cell::from(e.last_seen_ago.as_str()),
                Cell::from(e.reason.as_str()).style(Style::default().fg(reason_color)),
            ])
            .style(style)
        })
        .collect();

    let mut table_state = TableState::default();
    if entry_count > 0 {
        table_state.select(Some(app.swarm_scroll));
    }

    let table = Table::new(
        swarm_rows,
        [
            Constraint::Length(15),
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Length(10),
            Constraint::Min(8),
            Constraint::Length(12),
            Constraint::Length(9),
            Constraint::Length(9),
        ],
    )
    .header(
        Row::new(vec!["IP Address", "CC", "Reg", "ASN", "Name", "Packets", "Last Seen", "Reason"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .bottom_margin(1),
    )
    .block(Block::default().title(swarm_title).borders(Borders::ALL).border_type(BorderType::Rounded))
    .highlight_style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    f.render_stateful_widget(table, area, &mut table_state);
}

fn render_swarm_aggregate(f: &mut Frame, app: &App, area: Rect) {
    let agg_count = app.swarm_agg_entries.len();
    let total_ips: usize = app.swarm_agg_entries.iter().map(|e| e.ip_count).sum();
    let dim_hint = Style::default().fg(Color::DarkGray).add_modifier(Modifier::DIM);
    let filter_hint = if app.hide_blacklisted {
        Span::styled("[f] show blacklisted ", dim_hint)
    } else {
        Span::styled("[f] hide blacklisted ", dim_hint)
    };
    let swarm_title = Line::from(vec![
        Span::raw(format!(" Active Swarm ({} ASNs, {} IPs) ", agg_count, total_ips)),
        Span::styled("[g] IP view ", dim_hint),
        filter_hint,
    ]);

    let now_ns = time_fmt::clock_boottime_ns();

    let swarm_rows: Vec<Row> = app
        .swarm_agg_entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let style = if i == app.swarm_agg_scroll {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let reason = match (e.has_dynamic, e.has_blacklist) {
                (true, true) => "Both",
                (false, true) => "Blacklist",
                _ => "Dynamic",
            };
            let reason_color = match reason {
                "Blacklist" => Color::Red,
                "Both" => Color::Magenta,
                _ => Color::Yellow,
            };
            Row::new(vec![
                Cell::from(e.asn.as_str()),
                Cell::from(e.as_name.as_str()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(e.country.as_str()).style(Style::default().fg(country_color(&e.country))),
                if e.rir_country.is_empty() {
                    Cell::from("--").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::DIM))
                } else {
                    Cell::from(e.rir_country.as_str()).style(Style::default().fg(country_color(&e.rir_country)))
                },
                Cell::from(e.ip_count.to_string()),
                Cell::from(e.total_drops.to_string()),
                Cell::from(time_fmt::format_ktime_ago(e.last_seen_ns, now_ns)),
                Cell::from(reason).style(Style::default().fg(reason_color)),
            ])
            .style(style)
        })
        .collect();

    let mut table_state = TableState::default();
    if agg_count > 0 {
        table_state.select(Some(app.swarm_agg_scroll));
    }

    let table = Table::new(
        swarm_rows,
        [
            Constraint::Length(10),
            Constraint::Min(8),
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Length(6),
            Constraint::Length(12),
            Constraint::Length(9),
            Constraint::Length(9),
        ],
    )
    .header(
        Row::new(vec!["ASN", "Name", "CC", "Reg", "IPs", "Packets", "Last Seen", "Reason"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .bottom_margin(1),
    )
    .block(Block::default().title(swarm_title).borders(Borders::ALL).border_type(BorderType::Rounded))
    .highlight_style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    f.render_stateful_widget(table, area, &mut table_state);
}
