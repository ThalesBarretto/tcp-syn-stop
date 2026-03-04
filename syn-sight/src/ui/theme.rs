// SPDX-License-Identifier: GPL-2.0-only
//! Centralized theme definition for consistent visual styling.

use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::block::BorderType;

#[allow(dead_code)]
pub struct Theme {
    pub primary: Color,
    pub danger: Color,
    pub warning: Color,
    pub success: Color,
    pub muted: Color,
    pub text: Color,
    pub table_border: BorderType,
    pub modal_border: BorderType,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            primary: Color::Cyan,
            danger: Color::Red,
            warning: Color::Yellow,
            success: Color::Green,
            muted: Color::DarkGray,
            text: Color::White,
            table_border: BorderType::Rounded,
            modal_border: BorderType::Double,
        }
    }
}

#[allow(dead_code)]
impl Theme {
    /// Dimmed label style for metadata (e.g., "BPF:", "Fetch:").
    pub fn label(&self) -> Style {
        Style::default()
            .fg(self.muted)
            .add_modifier(Modifier::DIM)
    }

    /// Header style for section titles and table headers.
    pub fn header(&self) -> Style {
        Style::default()
            .fg(self.primary)
            .add_modifier(Modifier::BOLD)
    }
}
