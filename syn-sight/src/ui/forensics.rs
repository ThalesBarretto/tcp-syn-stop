// SPDX-License-Identifier: GPL-2.0-only
use super::{country_color, format_pps};
use crate::app::{App, NeighborhoodSort, RoiViewMode};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{block::BorderType, Bar, BarChart, BarGroup, Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

pub fn render_forensics(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3), // [0] Tab title
                Constraint::Length(3), // [1] ROI totals
                Constraint::Length(4), // [2] Reason breakdown
                Constraint::Min(10),   // [3] Tables
                Constraint::Length(1), // [4] Footer
            ]
            .as_ref(),
        )
        .split(area);

    // --- [0] TAB TITLE ---
    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            " FORENSICS SUMMARY ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" | [Tab] Back to Live ", Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded));
    f.render_widget(title, chunks[0]);

    // --- [1] ROI TOTALS ---
    let (totals_text, totals_color) = if let Some(ref err) = app.forensics_error {
        (format!(" Error: {} ", err), Color::Red)
    } else if let Some(fs) = &app.forensics {
        (
            format!(
                " Packets Mitigated: {} ",
                format_pps(fs.roi_totals.0 as f64)
            ),
            Color::Green,
        )
    } else {
        (" Loading... ".to_string(), Color::DarkGray)
    };
    let totals = Paragraph::new(totals_text)
        .block(Block::default().title(" Shield ROI Totals ").borders(Borders::ALL).border_type(BorderType::Rounded))
        .style(Style::default().fg(totals_color));
    f.render_widget(totals, chunks[1]);

    // --- [2] REASON BREAKDOWN ---
    render_reason_breakdown(f, app, chunks[2]);

    // --- [3] TABLES ---
    if app.drilldown.is_some() {
        // Side-by-side: neighborhoods (40%) | drilldown detail (60%)
        let table_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)].as_ref())
            .split(chunks[3]);

        render_neighborhoods_table(f, app, table_chunks[0], true);
        render_drilldown_pane(f, app, table_chunks[1]);
    } else {
        // Normal: neighborhoods (55%) | ROI (45%)
        let table_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)].as_ref())
            .split(chunks[3]);

        render_neighborhoods_table(f, app, table_chunks[0], false);
        match app.roi_view_mode {
            RoiViewMode::Chart => render_roi_chart(f, app, table_chunks[1]),
            RoiViewMode::Table => render_roi_table(f, app, table_chunks[1]),
        }
    }

    // --- [4] FOOTER ---
    let footer_text = if app.add_action.is_some() {
        " [1/2/3] Select scope | [Esc] Cancel "
    } else if app.drilldown.is_some() {
        " [Esc] Back | [Up/Down] Scroll | [b] Block | [w] Whitelist "
    } else {
        " [q] Quit | [Tab] Live | [Up/Down] Scroll | [Enter] Drill-down | [s] Sort | [t] Threshold | [f] Window | [b] Block | [w] Whitelist | [v] Chart/Table "
    };
    let footer = Paragraph::new(footer_text).style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[4]);

    // Add-action overlay (on top of everything)
    if let Some(action) = &app.add_action {
        super::overlays::render_add_action_modal(f, action);
    }
}

fn render_roi_chart(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let bars: Vec<Bar> = if let Some(fs) = &app.forensics {
        fs.roi_rows
            .iter()
            .rev()
            .enumerate()
            .map(|(i, (hour, pkts, _))| {
                let label = if i % 4 == 0 && hour.len() >= 13 {
                    hour[11..13].to_string()
                } else {
                    String::new()
                };
                #[allow(clippy::cast_sign_loss)]
                let value = *pkts as u64;
                Bar::default()
                    .value(value)
                    .label(Line::from(label))
                    .style(Style::default().fg(Color::Green))
            })
            .collect()
    } else {
        Vec::new()
    };

    let chart = BarChart::default()
        .block(Block::default().title(" Attack Timeline (24h) ").borders(Borders::ALL).border_type(BorderType::Rounded))
        .data(BarGroup::default().bars(&bars))
        .bar_width(2)
        .bar_gap(0)
        .bar_style(Style::default().fg(Color::Green))
        .value_style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD));
    f.render_widget(chart, area);
}

fn render_roi_table(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let roi_rows: Vec<Row> = if let Some(fs) = &app.forensics {
        if fs.roi_rows.is_empty() {
            vec![Row::new(vec!["No data", ""]).style(Style::default().fg(Color::DarkGray))]
        } else {
            fs.roi_rows
                .iter()
                .map(|(hour, pkts, _)| {
                    Row::new(vec![
                        Cell::from(hour.as_str()),
                        Cell::from(pkts.to_string()),
                    ])
                })
                .collect()
        }
    } else if let Some(ref err) = app.forensics_error {
        vec![Row::new(vec![Cell::from(err.as_str()), Cell::from("")])
            .style(Style::default().fg(Color::Red))]
    } else {
        vec![Row::new(vec!["Loading...", ""]).style(Style::default().fg(Color::DarkGray))]
    };

    let roi_table = Table::new(
        roi_rows,
        [Constraint::Min(15), Constraint::Length(14)],
    )
    .header(
        Row::new(vec!["Hour", "Pkts Mitigated"])
            .style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
            .bottom_margin(1),
    )
    .block(Block::default().title(" Shield ROI (Last 24h) ").borders(Borders::ALL).border_type(BorderType::Rounded));
    f.render_widget(roi_table, area);
}

/// Render the Bad Neighborhoods table.  When `compact` is true (drilldown
/// is open), the Name and ASN columns are dropped to fit a 40% split.
fn render_neighborhoods_table(f: &mut Frame, app: &App, area: ratatui::layout::Rect, compact: bool) {
    let hood_count = app.neighborhoods.len();
    let neighborhood_rows: Vec<Row> = if app.neighborhoods.is_empty() {
        let empty_cells = if compact { 5 } else { 7 };
        let cells: Vec<&str> = std::iter::once("No data").chain(std::iter::repeat("").take(empty_cells - 1)).collect();
        vec![Row::new(cells).style(Style::default().fg(Color::DarkGray))]
    } else {
        app.neighborhoods
            .iter()
            .enumerate()
            .map(|(i, hood)| {
                let style = if i == app.neighborhood_scroll {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                if compact {
                    Row::new(vec![
                        Cell::from(hood.subnet_cidr.as_str()),
                        Cell::from(hood.country.as_str()).style(Style::default().fg(country_color(&hood.country))),
                        if hood.rir_country.is_empty() {
                            Cell::from("--").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::DIM))
                        } else {
                            Cell::from(hood.rir_country.as_str()).style(Style::default().fg(country_color(&hood.rir_country)))
                        },
                        Cell::from(hood.bot_count.to_string()),
                        Cell::from(hood.total_impact.to_string()),
                    ])
                    .style(style)
                } else {
                    let name_trunc: String = hood.as_name.chars().take(20).collect();
                    Row::new(vec![
                        Cell::from(hood.subnet_cidr.as_str()),
                        Cell::from(hood.country.as_str()).style(Style::default().fg(country_color(&hood.country))),
                        if hood.rir_country.is_empty() {
                            Cell::from("--").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::DIM))
                        } else {
                            Cell::from(hood.rir_country.as_str()).style(Style::default().fg(country_color(&hood.rir_country)))
                        },
                        Cell::from(hood.asn.as_str()),
                        Cell::from(name_trunc),
                        Cell::from(hood.bot_count.to_string()),
                        Cell::from(hood.total_impact.to_string()),
                    ])
                    .style(style)
                }
            })
            .collect()
    };

    let mut hood_table_state = TableState::default();
    if hood_count > 0 {
        hood_table_state.select(Some(app.neighborhood_scroll));
    }

    let sort_indicator = match app.neighborhood_sort {
        NeighborhoodSort::Impact => "Impact",
        NeighborhoodSort::Country => "Country",
        NeighborhoodSort::Name => "Name",
    };

    let title = format!(
        " Neighborhoods [\u{2193}{}] {} bots{} ",
        sort_indicator,
        app.neighborhood_time_window.label(),
        app.neighborhood_bot_threshold.label(),
    );

    let neighborhood_table = if compact {
        Table::new(
            neighborhood_rows,
            [
                Constraint::Min(10),
                Constraint::Length(4),
                Constraint::Length(4),
                Constraint::Length(5),
                Constraint::Length(8),
            ],
        )
        .header(
            Row::new(vec!["Subnet", "CC", "Reg", "Bots", "Impact"])
                .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                .bottom_margin(1),
        )
    } else {
        Table::new(
            neighborhood_rows,
            [
                Constraint::Min(14),
                Constraint::Length(4),
                Constraint::Length(4),
                Constraint::Length(10),
                Constraint::Length(20),
                Constraint::Length(5),
                Constraint::Length(10),
            ],
        )
        .header(
            Row::new(vec!["Subnet", "CC", "Reg", "ASN", "Name", "Bots", "Impact"])
                .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                .bottom_margin(1),
        )
    };

    let neighborhood_table = neighborhood_table
        .block(Block::default().title(title).borders(Borders::ALL).border_type(BorderType::Rounded))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(neighborhood_table, area, &mut hood_table_state);
}

/// Render the drilldown detail as an inline pane (replaces the old modal overlay).
fn render_drilldown_pane(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let dd = match &app.drilldown {
        Some(dd) => dd,
        None => return,
    };

    let pane_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(1), // summary
            Constraint::Min(5),    // IP table
        ])
        .split(area);

    // Header
    let as_label = if dd.as_name.is_empty() {
        dd.neighborhood.asn.clone()
    } else {
        format!("{} ({})", dd.neighborhood.asn, dd.as_name)
    };
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {} ", as_label),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} {} ", dd.neighborhood.subnet_cidr, dd.neighborhood.country),
            Style::default().fg(Color::White),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded));
    f.render_widget(header, pane_chunks[0]);

    // Summary line
    let summary = Paragraph::new(format!(
        " {} IPs | {} drops | {} ports ",
        dd.ips.len(),
        dd.ips.iter().map(|ip| ip.drop_count).sum::<i64>(),
        dd.port_diversity
    ))
    .style(Style::default().fg(Color::Yellow));
    f.render_widget(summary, pane_chunks[1]);

    // IP table
    let scroll = app.drilldown_scroll;
    let ip_rows: Vec<Row> = dd
        .ips
        .iter()
        .enumerate()
        .map(|(i, ip)| {
            let ports_str = ip
                .dest_ports
                .iter()
                .take(5)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let style = if i == scroll {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(ip.ip.as_str()),
                Cell::from(ip.drop_count.to_string()),
                Cell::from(ip.peak_pps.to_string()),
                Cell::from(ports_str),
            ])
            .style(style)
        })
        .collect();

    let ip_table = Table::new(
        ip_rows,
        [
            Constraint::Min(12),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(14),
        ],
    )
    .header(
        Row::new(vec!["IP", "Drops", "PPS", "Ports"])
            .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
            .bottom_margin(1),
    )
    .block(Block::default().title(" Source IPs ").borders(Borders::ALL).border_type(BorderType::Rounded))
    .highlight_style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let mut table_state = TableState::default();
    if !dd.ips.is_empty() {
        table_state.select(Some(scroll));
    }
    f.render_stateful_widget(ip_table, pane_chunks[2], &mut table_state);
}

fn render_reason_breakdown(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let breakdown = &app.reason_breakdown;

    if breakdown.is_empty() {
        let empty = Paragraph::new(" No drop data ")
            .block(Block::default().title(" Drop Reasons ").borders(Borders::ALL).border_type(BorderType::Rounded))
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(empty, area);
        return;
    }

    let grand_total: u64 = breakdown.iter().map(|(_, c)| c).sum();
    let inner_width = area.width.saturating_sub(2) as usize; // borders

    let mut lines: Vec<Line> = Vec::new();
    for (reason, count) in breakdown {
        let pct = if grand_total > 0 {
            (*count as f64 / grand_total as f64) * 100.0
        } else {
            0.0
        };
        let color = match reason.as_str() {
            "BLACKLIST" => Color::Red,
            _ => Color::Yellow,
        };
        // Label (12 chars padded) + bar + count
        let label = format!(" {:<11}", reason);
        let count_str = format!(" {:>8} ({:.0}%) ", count, pct);
        let bar_space = inner_width.saturating_sub(label.len() + count_str.len());
        let filled = if grand_total > 0 {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                (bar_space as f64 * *count as f64 / grand_total as f64) as usize
            }
        } else {
            0
        };
        let bar: String = "\u{2588}".repeat(filled);
        let pad: String = " ".repeat(bar_space.saturating_sub(filled));
        lines.push(Line::from(vec![
            Span::styled(label, Style::default().fg(Color::White)),
            Span::styled(bar, Style::default().fg(color)),
            Span::raw(pad),
            Span::styled(count_str, Style::default().fg(Color::White)),
        ]));
    }

    let para = Paragraph::new(lines).block(Block::default().title(" Drop Reasons ").borders(Borders::ALL).border_type(BorderType::Rounded));
    f.render_widget(para, area);
}
