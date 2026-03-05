// SPDX-License-Identifier: GPL-2.0-only
use super::country_color;
use crate::app::{AddActionState, AsnSearchState, ListsFocus};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{block::BorderType, Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

pub fn render_asn_search(f: &mut Frame, search: &AsnSearchState) {
    use ratatui::widgets::Clear;

    let frame = f.size();
    let hm = 6u16.min(frame.width / 4);
    let vm = 3u16.min(frame.height / 4);
    let area = ratatui::layout::Rect {
        x: frame.x + hm,
        y: frame.y + vm,
        width: frame.width.saturating_sub(hm * 2),
        height: frame.height.saturating_sub(vm * 2),
    };
    f.render_widget(Clear, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // input
            Constraint::Min(5),    // results
            Constraint::Length(1), // footer
        ])
        .split(area);

    // Input field
    let input = Paragraph::new(format!(" / {}_ ", search.query))
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .title(" Search ASN Database ")
                .borders(Borders::ALL).border_type(BorderType::Double)
                .border_style(Style::default().fg(Color::Yellow)),
        );
    f.render_widget(input, chunks[0]);

    // Results table
    let marked_count = search.marked.len();
    let result_rows: Vec<Row> = if search.results.is_empty() {
        if search.query.is_empty() {
            vec![Row::new(vec!["", "Type to search...", "", "", ""]).style(Style::default().fg(Color::DarkGray))]
        } else {
            vec![Row::new(vec!["", "No matches", "", "", ""]).style(Style::default().fg(Color::DarkGray))]
        }
    } else {
        search
            .results
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let is_marked = search.marked.contains(&i);
                let mark = if is_marked { "\u{25cf}" } else { " " }; // filled circle or space
                let style = if i == search.scroll {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else if is_marked {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::from(mark),
                    Cell::from(r.as_name.as_str()),
                    Cell::from(r.asn.as_str()),
                    Cell::from(r.country.as_str()).style(Style::default().fg(country_color(&r.country))),
                    Cell::from(r.range_count.to_string()),
                ])
                .style(style)
            })
            .collect()
    };

    let mut table_state = TableState::default();
    if !search.results.is_empty() {
        table_state.select(Some(search.scroll));
    }

    let title = if marked_count > 0 {
        format!(" {} selected ", marked_count)
    } else {
        String::new()
    };

    let results_table = Table::new(
        result_rows,
        [
            Constraint::Length(2),
            Constraint::Min(25),
            Constraint::Length(10),
            Constraint::Length(4),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(vec!["", "Name", "ASN", "CC", "Ranges"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .bottom_margin(1),
    )
    .block(Block::default().title(title).borders(Borders::ALL).border_type(BorderType::Double))
    .highlight_style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );
    f.render_stateful_widget(results_table, chunks[1], &mut table_state);

    // Footer
    let footer = Paragraph::new(" [Tab] Mark | [A-b] Block | [A-w] Whitelist | [Esc] Cancel | [Up/Down] Scroll ")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[2]);
}

fn cidr_size(cidr: &str) -> String {
    let prefix_len: u32 = cidr
        .rsplit('/')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32);
    let count: u64 = 1u64 << (32u32.saturating_sub(prefix_len));
    if count >= 1_000_000 {
        format!("{:.1}M IPs", count as f64 / 1_000_000.0)
    } else if count >= 1_000 {
        format!("{:.1}K IPs", count as f64 / 1_000.0)
    } else {
        format!("{} IPs", count)
    }
}

pub fn render_subnet_picker(f: &mut Frame, picker: &crate::app::SubnetPickerState) {
    use ratatui::widgets::Clear;

    let frame = f.size();
    let hm = 6u16.min(frame.width / 4);
    let vm = 3u16.min(frame.height / 4);
    let area = ratatui::layout::Rect {
        x: frame.x + hm,
        y: frame.y + vm,
        width: frame.width.saturating_sub(hm * 2),
        height: frame.height.saturating_sub(vm * 2),
    };
    f.render_widget(Clear, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(5),    // table
            Constraint::Length(1), // footer
        ])
        .split(area);

    // Header
    let marked_count = picker.marked.len();
    let header_text = format!(
        " Select ranges from {} ({} prefixes, {} selected) ",
        picker.asn_label,
        picker.cidrs.len(),
        marked_count
    );
    let header = Paragraph::new(header_text)
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .borders(Borders::ALL).border_type(BorderType::Double)
                .border_style(Style::default().fg(Color::Yellow)),
        );
    f.render_widget(header, chunks[0]);

    // Table
    let rows: Vec<Row> = picker
        .cidrs
        .iter()
        .enumerate()
        .map(|(i, cidr)| {
            let is_marked = picker.marked.contains(&i);
            let mark = if is_marked { "\u{25cf}" } else { " " };
            let style = if i == picker.scroll {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else if is_marked {
                Style::default().fg(Color::Green)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(mark),
                Cell::from(cidr.as_str()),
                Cell::from(cidr_size(cidr)),
            ])
            .style(style)
        })
        .collect();

    let mut table_state = TableState::default();
    if !picker.cidrs.is_empty() {
        table_state.select(Some(picker.scroll));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(2),
            Constraint::Min(20),
            Constraint::Length(12),
        ],
    )
    .header(
        Row::new(vec!["", "CIDR", "Size"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .bottom_margin(1),
    )
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Double))
    .highlight_style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    f.render_stateful_widget(table, chunks[1], &mut table_state);

    // Footer
    let footer = Paragraph::new(
        " [Tab] Mark | [Enter] Add marked/current | [A-a] Select all | [Esc] Cancel ",
    )
    .style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[2]);
}

pub(crate) fn asn_cidrs_examples(cidrs: &[String]) -> String {
    if cidrs.is_empty() {
        return String::new();
    }
    let examples: Vec<&str> = cidrs.iter().take(3).map(String::as_str).collect();
    let suffix = if cidrs.len() > 3 { ", ..." } else { "" };
    format!(", e.g. {}{}", examples.join(", "), suffix)
}

pub(crate) fn render_add_action_modal(f: &mut Frame, action: &AddActionState) {
    use ratatui::widgets::Clear;

    let frame_area = f.size();
    let w = 50u16.min(frame_area.width.saturating_sub(4));
    let h = 10u16.min(frame_area.height.saturating_sub(4));
    let x = frame_area.x + (frame_area.width.saturating_sub(w)) / 2;
    let y = frame_area.y + (frame_area.height.saturating_sub(h)) / 2;
    let area = ratatui::layout::Rect {
        x,
        y,
        width: w,
        height: h,
    };
    f.render_widget(Clear, area);

    let title = match action.target {
        ListsFocus::Whitelist => " Add to Whitelist ",
        ListsFocus::Blacklist => " Add to Blacklist ",
    };

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(""));

    if let Some(ref ip) = action.ip_cidr {
        // IP context: 3 options
        lines.push(Line::from(vec![
            Span::styled("  [1] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(format!("IP only:  {}", ip)),
        ]));
        if let Some(ref subnet) = action.subnet_cidr {
            lines.push(Line::from(vec![
                Span::styled("  [2] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw(format!("Subnet:   {}  ({})", subnet, action.asn_label)),
            ]));
        }
        if !action.asn_cidrs.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("  [3] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw(format!(
                    "All {} ranges  ({} prefixes{})",
                    action.asn_label,
                    action.asn_cidrs.len(),
                    asn_cidrs_examples(&action.asn_cidrs)
                )),
            ]));
        }
    } else {
        // Neighborhood context: 2 options
        if let Some(ref subnet) = action.subnet_cidr {
            lines.push(Line::from(vec![
                Span::styled("  [1] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw(format!("Subnet:  {}", subnet)),
            ]));
        }
        if !action.asn_cidrs.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("  [2] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw(format!(
                    "All {} ranges  ({} prefixes{})",
                    action.asn_label,
                    action.asn_cidrs.len(),
                    asn_cidrs_examples(&action.asn_cidrs)
                )),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  [Esc] Cancel",
        Style::default().fg(Color::DarkGray),
    )));

    let popup = Paragraph::new(lines).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL).border_type(BorderType::Double)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    f.render_widget(popup, area);
}

pub fn render_help_overlay(f: &mut Frame) {
    use ratatui::widgets::Clear;

    let frame = f.size();
    let hm = 6u16.min(frame.width / 4);
    let vm = 3u16.min(frame.height / 4);
    let area = ratatui::layout::Rect {
        x: frame.x + hm,
        y: frame.y + vm,
        width: frame.width.saturating_sub(hm * 2),
        height: frame.height.saturating_sub(vm * 2),
    };
    f.render_widget(Clear, area);

    let bold = Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD);
    let dim = Style::default().fg(Color::DarkGray);
    let key = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
    let desc = Style::default().fg(Color::White);

    let lines = vec![
        Line::from(Span::styled(" GLOBAL", bold)),
        Line::from(vec![
            Span::styled("  Tab       ", key), Span::styled("Cycle tabs (Live/Forensics/Lists)", desc),
        ]),
        Line::from(vec![
            Span::styled("  q         ", key), Span::styled("Quit", desc),
        ]),
        Line::from(vec![
            Span::styled("  ?         ", key), Span::styled("Toggle this help", desc),
        ]),
        Line::from(vec![
            Span::styled("  /         ", key), Span::styled("Fuzzy find in current table", desc),
        ]),
        Line::from(vec![
            Span::styled("  n         ", key), Span::styled("ASN database search", desc),
        ]),
        Line::from(vec![
            Span::styled("  b / w     ", key), Span::styled("Block / Whitelist selected", desc),
        ]),
        Line::from(vec![
            Span::styled("  Up/Down   ", key), Span::styled("Scroll current list", desc),
        ]),
        Line::from(Span::raw("")),
        Line::from(Span::styled(" LIVE", bold)),
        Line::from(vec![
            Span::styled("  g         ", key), Span::styled("Toggle ASN aggregate / IP view", desc),
        ]),
        Line::from(vec![
            Span::styled("  Enter     ", key), Span::styled("Drill into ASN (aggregate view)", desc),
        ]),
        Line::from(vec![
            Span::styled("  Esc       ", key), Span::styled("Clear ASN filter", desc),
        ]),
        Line::from(Span::raw("")),
        Line::from(Span::styled(" FORENSICS", bold)),
        Line::from(vec![
            Span::styled("  Enter     ", key), Span::styled("Drill down into neighborhood", desc),
        ]),
        Line::from(vec![
            Span::styled("  Esc       ", key), Span::styled("Close drilldown", desc),
        ]),
        Line::from(vec![
            Span::styled("  s         ", key), Span::styled("Cycle sort (Impact/Country/Name)", desc),
        ]),
        Line::from(vec![
            Span::styled("  t         ", key), Span::styled("Cycle bot threshold (>1/>2/>5)", desc),
        ]),
        Line::from(vec![
            Span::styled("  f         ", key), Span::styled("Cycle time window (5m/1h/24h)", desc),
        ]),
        Line::from(vec![
            Span::styled("  v         ", key), Span::styled("Toggle ROI chart/table", desc),
        ]),
        Line::from(Span::raw("")),
        Line::from(Span::styled(" LISTS", bold)),
        Line::from(vec![
            Span::styled("  a         ", key), Span::styled("Add CIDR entry", desc),
        ]),
        Line::from(vec![
            Span::styled("  d         ", key), Span::styled("Delete selected entry", desc),
        ]),
        Line::from(vec![
            Span::styled("  Left/Right", key), Span::styled("  Switch whitelist/blacklist", desc),
        ]),
    ];

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(1)])
        .split(area);

    let help = Paragraph::new(lines).block(
        Block::default()
            .title(" Keyboard Reference ")
            .borders(Borders::ALL).border_type(BorderType::Double)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(help, chunks[0]);

    let footer = Paragraph::new(" [Esc] Close ").style(dim);
    f.render_widget(footer, chunks[1]);
}
