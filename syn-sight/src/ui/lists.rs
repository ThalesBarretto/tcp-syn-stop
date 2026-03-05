// SPDX-License-Identifier: GPL-2.0-only
use super::country_color;
use crate::app::{App, InputMode, ListsFocus};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{block::BorderType, Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

pub fn render_lists(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3), // [0] Title
                Constraint::Length(3), // [1] Input / status bar
                Constraint::Min(10),   // [2] Tables
                Constraint::Length(1), // [3] Footer
            ]
            .as_ref(),
        )
        .split(area);

    // --- [0] TITLE ---
    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            " LIST MANAGEMENT ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" | [Tab] Switch view ", Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded));
    f.render_widget(title, chunks[0]);

    // --- [1] INPUT / STATUS ---
    let input_content = match app.lists_input_mode {
        InputMode::Editing => {
            let cursor = format!(" Add CIDR: {}_ ", app.lists_input_buf);
            Paragraph::new(cursor)
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::ALL).title(" Input "))
        }
        InputMode::ConfirmDelete => {
            let selected = match app.lists_focus {
                ListsFocus::Whitelist => app
                    .whitelist_entries
                    .get(app.whitelist_scroll)
                    .map(|e| e.cidr.as_str())
                    .unwrap_or_default(),
                ListsFocus::Blacklist => app
                    .blacklist_entries
                    .get(app.blacklist_scroll)
                    .map(|e| e.cidr.as_str())
                    .unwrap_or_default(),
            };
            Paragraph::new(format!(" Delete {}? [y/n] ", selected))
                .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded))
        }
        InputMode::ConfirmCleanup => {
            let count = app.cleanup_candidates.len();
            let preview: String = app.cleanup_candidates.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
            let suffix = if count > 5 { format!(", ... ({} total)", count) } else { String::new() };
            Paragraph::new(format!(" Remove {} redundant? [y/n]: {}{} ", count, preview, suffix))
                .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded))
        }
        InputMode::Normal => {
            let msg = app
                .lists_status_msg
                .as_ref()
                .map(|(m, _)| format!(" {} ", m))
                .unwrap_or_else(|| " Ready ".to_string());
            let color = if app.lists_status_msg.is_some() {
                Color::Green
            } else {
                Color::DarkGray
            };
            Paragraph::new(msg)
                .style(Style::default().fg(color))
                .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded))
        }
    };
    f.render_widget(input_content, chunks[1]);

    // --- [2] TABLES (50/50 split) ---
    let table_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(chunks[2]);

    // Whitelist table
    let wl_rows: Vec<Row> = if app.whitelist_entries.is_empty() {
        vec![Row::new(vec!["(empty)", "", "", "", ""]).style(Style::default().fg(Color::DarkGray))]
    } else {
        app.whitelist_entries
            .iter()
            .map(|entry| {
                Row::new(vec![
                    Cell::from(entry.cidr.as_str()),
                    Cell::from(entry.country.as_str()),
                    if entry.rir_country.is_empty() {
                        Cell::from("--").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::DIM))
                    } else {
                        Cell::from(entry.rir_country.as_str()).style(Style::default().fg(country_color(&entry.rir_country)))
                    },
                    Cell::from(entry.asn.as_str()),
                    Cell::from(entry.as_name.as_str()).style(Style::default().fg(Color::DarkGray)),
                ])
            })
            .collect()
    };

    let wl_border = if app.lists_focus == ListsFocus::Whitelist {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };
    let wl_table = Table::new(
        wl_rows,
        [Constraint::Min(14), Constraint::Length(4), Constraint::Length(4), Constraint::Length(10), Constraint::Min(8)],
    )
    .header(
        Row::new(vec!["CIDR", "CC", "Reg", "ASN", "Name"])
            .style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
            .bottom_margin(1),
    )
    .highlight_style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::Green)
            .add_modifier(Modifier::BOLD),
    )
    .block(
        Block::default()
            .title(format!(" Whitelist ({}) ", app.whitelist_entries.len()))
            .borders(Borders::ALL)
            .border_style(wl_border),
    );
    let mut wl_state = TableState::default();
    if app.lists_focus == ListsFocus::Whitelist && !app.whitelist_entries.is_empty() {
        wl_state.select(Some(app.whitelist_scroll));
    }
    f.render_stateful_widget(wl_table, table_chunks[0], &mut wl_state);

    // Blacklist table
    let bl_rows: Vec<Row> = if app.blacklist_entries.is_empty() {
        vec![Row::new(vec!["(empty)", "", "", "", "", ""]).style(Style::default().fg(Color::DarkGray))]
    } else {
        app.blacklist_entries
            .iter()
            .map(|entry| {
                Row::new(vec![
                    Cell::from(entry.cidr.as_str()),
                    Cell::from(entry.country.as_str()),
                    if entry.rir_country.is_empty() {
                        Cell::from("--").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::DIM))
                    } else {
                        Cell::from(entry.rir_country.as_str()).style(Style::default().fg(country_color(&entry.rir_country)))
                    },
                    Cell::from(entry.asn.as_str()),
                    Cell::from(entry.as_name.as_str()).style(Style::default().fg(Color::DarkGray)),
                    Cell::from(entry.drop_count.to_string()),
                ])
            })
            .collect()
    };

    let bl_border = if app.lists_focus == ListsFocus::Blacklist {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };
    let bl_table = Table::new(
        bl_rows,
        [
            Constraint::Min(14),
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Length(10),
            Constraint::Min(8),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(vec!["CIDR", "CC", "Reg", "ASN", "Name", "Drops"])
            .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
            .bottom_margin(1),
    )
    .highlight_style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::Red)
            .add_modifier(Modifier::BOLD),
    )
    .block(
        Block::default()
            .title(format!(" Blacklist ({}) ", app.blacklist_entries.len()))
            .borders(Borders::ALL)
            .border_style(bl_border),
    );
    let mut bl_state = TableState::default();
    if app.lists_focus == ListsFocus::Blacklist && !app.blacklist_entries.is_empty() {
        bl_state.select(Some(app.blacklist_scroll));
    }
    f.render_stateful_widget(bl_table, table_chunks[1], &mut bl_state);

    // --- [3] FOOTER ---
    let footer_text = match app.lists_input_mode {
        InputMode::Editing => " [Enter] Save | [Esc] Cancel ",
        InputMode::ConfirmDelete | InputMode::ConfirmCleanup => " [y] Confirm | [n] Cancel ",
        InputMode::Normal => " [a] Add | [d] Delete | [c] Clean up | [s] Save sorted | [Left/Right] Switch | [Up/Down] Scroll ",
    };
    let footer = Paragraph::new(footer_text).style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, chunks[3]);
}
