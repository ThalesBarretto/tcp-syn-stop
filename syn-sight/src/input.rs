// SPDX-License-Identifier: GPL-2.0-only
//! Keyboard event routing and input handling.
//!
//! Modal interception order: ASN search > add-action popup > Lists tab input.
//! If no modal is active, all remaining keys (global and tab-specific) are
//! dispatched through a single flat match, with internal tab guards on keys
//! like `s`, `v`, `a`, `d` that only apply to specific tabs.

use crate::app::{self, App, InputMode, ListsFocus, NeighborhoodSort, RoiViewMode, SwarmView, Tab};
use crate::forensics;
use crossterm::event::KeyCode;
use std::time::Instant;

/// Top-level key dispatch. Returns true if the app should quit.
pub fn handle_event(app: &mut App, key: KeyCode) -> bool {
    // Any keypress dismisses the ephemeral help hint
    app.any_key_pressed = true;

    // Help overlay intercepts all keys except Esc (to close)
    if app.show_help {
        if key == KeyCode::Esc || key == KeyCode::Char('?') {
            app.show_help = false;
        }
        return false;
    }

    // ASN search modal intercepts all keys
    if app.asn_search.is_some() {
        handle_asn_search(app, key);
    // Subnet picker modal intercepts all keys
    } else if app.subnet_picker.is_some() {
        handle_subnet_picker(app, key);
    // Add-action popup intercepts all keys
    } else if app.add_action.is_some() {
        handle_add_action(app, key);
    // Lists tab modal input
    } else if app.active_tab == Tab::Lists && app.lists_input_mode != InputMode::Normal {
        handle_lists_input(app, key);
    } else {
        match key {
            KeyCode::Char('q') => return true,
            KeyCode::Tab => {
                app.active_tab = match app.active_tab {
                    Tab::Live => Tab::Forensics,
                    Tab::Forensics => Tab::Lists,
                    Tab::Lists => Tab::Live,
                };
                if app.active_tab == Tab::Forensics {
                    app.load_asn_table_async();
                    app.force_forensics_refresh();
                    let _ = app.fetch_forensics();
                }
                if app.active_tab == Tab::Lists {
                    app.load_lists();
                }
            }
            KeyCode::Down => match app.active_tab {
                Tab::Live => match app.swarm_view {
                    SwarmView::PerASN => app.swarm_agg_scroll_down(),
                    SwarmView::PerIP => app.swarm_scroll_down(),
                },
                Tab::Forensics => {
                    if app.drilldown.is_some() {
                        app.drilldown_scroll_down();
                    } else {
                        app.neighborhood_scroll_down();
                    }
                }
                Tab::Lists => app.lists_scroll_down(),
            },
            KeyCode::Up => match app.active_tab {
                Tab::Live => match app.swarm_view {
                    SwarmView::PerASN => app.swarm_agg_scroll_up(),
                    SwarmView::PerIP => app.swarm_scroll_up(),
                },
                Tab::Forensics => {
                    if app.drilldown.is_some() {
                        app.drilldown_scroll_up();
                    } else {
                        app.neighborhood_scroll_up();
                    }
                }
                Tab::Lists => app.lists_scroll_up(),
            },
            KeyCode::Enter => {
                if app.active_tab == Tab::Live && app.swarm_view == SwarmView::PerASN {
                    if let Some(agg) = app.swarm_agg_entries.get(app.swarm_agg_scroll) {
                        app.swarm_asn_filter = Some(agg.asn.clone());
                        app.swarm_view = SwarmView::PerIP;
                        app.swarm_scroll = 0;
                    }
                } else if app.active_tab == Tab::Forensics {
                    if let Some(hood) = app.neighborhoods.get(app.neighborhood_scroll) {
                        if let Ok(dd) = forensics::fetch_drilldown(&app.db_path, hood) {
                            app.drilldown = Some(dd);
                            app.drilldown_scroll = 0;
                        }
                    }
                }
            }
            KeyCode::Esc => {
                if app.active_tab == Tab::Live && app.swarm_asn_filter.is_some() {
                    app.swarm_asn_filter = None;
                    app.swarm_view = SwarmView::PerASN;
                    app.swarm_agg_scroll = 0;
                } else if app.drilldown.is_some() {
                    app.drilldown = None;
                }
            }
            KeyCode::Char('g') => {
                if app.active_tab == Tab::Live {
                    app.swarm_view = match app.swarm_view {
                        SwarmView::PerIP => SwarmView::PerASN,
                        SwarmView::PerASN => SwarmView::PerIP,
                    };
                    app.swarm_scroll = 0;
                    app.swarm_agg_scroll = 0;
                    app.swarm_asn_filter = None;
                }
            }
            KeyCode::Char('f') => {
                if app.active_tab == Tab::Live {
                    app.hide_blacklisted = !app.hide_blacklisted;
                } else if app.active_tab == Tab::Forensics && app.drilldown.is_none() {
                    app.neighborhood_time_window = app.neighborhood_time_window.next();
                    app.neighborhood_scroll = 0;
                }
            }
            KeyCode::Char('b') | KeyCode::Char('w') => {
                if app.active_tab == Tab::Live || app.active_tab == Tab::Forensics {
                    let target = if key == KeyCode::Char('b') {
                        ListsFocus::Blacklist
                    } else {
                        ListsFocus::Whitelist
                    };
                    app.add_action = build_add_action_for_context(app, target);
                }
            }
            KeyCode::Char('v') => {
                if app.active_tab == Tab::Forensics && app.drilldown.is_none() {
                    app.roi_view_mode = match app.roi_view_mode {
                        RoiViewMode::Chart => RoiViewMode::Table,
                        RoiViewMode::Table => RoiViewMode::Chart,
                    };
                }
            }
            KeyCode::Char('s') => {
                if app.active_tab == Tab::Forensics && app.drilldown.is_none() {
                    app.neighborhood_sort = match app.neighborhood_sort {
                        NeighborhoodSort::Impact => NeighborhoodSort::Country,
                        NeighborhoodSort::Country => NeighborhoodSort::Name,
                        NeighborhoodSort::Name => NeighborhoodSort::Impact,
                    };
                    app.sort_neighborhoods();
                    app.neighborhood_scroll = 0;
                } else if app.active_tab == Tab::Lists {
                    app.rewrite_sorted();
                }
            }
            KeyCode::Char('t') => {
                if app.active_tab == Tab::Forensics && app.drilldown.is_none() {
                    app.neighborhood_bot_threshold = app.neighborhood_bot_threshold.next();
                    app.neighborhood_scroll = 0;
                }
            }
            KeyCode::Char('a') => {
                if app.active_tab == Tab::Lists {
                    app.lists_input_mode = InputMode::Editing;
                    app.lists_input_buf.clear();
                }
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                if app.active_tab == Tab::Lists {
                    let has_entry = match app.lists_focus {
                        ListsFocus::Whitelist => !app.whitelist_entries.is_empty(),
                        ListsFocus::Blacklist => !app.blacklist_entries.is_empty(),
                    };
                    if has_entry {
                        app.lists_input_mode = InputMode::ConfirmDelete;
                    }
                }
            }
            KeyCode::Char('c') => {
                if app.active_tab == Tab::Lists {
                    app.cleanup_redundant();
                }
            }
            KeyCode::Char('?') => {
                app.show_help = true;
            }
            KeyCode::Char('/') => {
                app.asn_search = Some(app::AsnSearchState {
                    query: String::new(),
                    results: Vec::new(),
                    scroll: 0,
                    marked: std::collections::HashSet::new(),
                    query_changed_at: None,
                });
            }
            KeyCode::Left => {
                if app.active_tab == Tab::Lists {
                    app.lists_focus = ListsFocus::Whitelist;
                }
            }
            KeyCode::Right => {
                if app.active_tab == Tab::Lists {
                    app.lists_focus = ListsFocus::Blacklist;
                }
            }
            _ => {}
        }
    }
    false
}

fn handle_lists_input(app: &mut App, key: KeyCode) {
    match app.lists_input_mode {
        InputMode::Editing => match key {
            KeyCode::Enter => {
                let input = app.lists_input_buf.clone();
                match crate::validation::validate_cidr(&input) {
                    Ok(cidr) => {
                        let focus = app.lists_focus;
                        app.add_entries_to_list_direct(focus, vec![cidr]);
                        app.lists_input_mode = InputMode::Normal;
                        app.lists_input_buf.clear();
                    }
                    Err(e) => {
                        app.lists_status_msg = Some((format!("Invalid: {}", e), Instant::now()));
                    }
                }
            }
            KeyCode::Esc => {
                app.lists_input_mode = InputMode::Normal;
                app.lists_input_buf.clear();
            }
            KeyCode::Backspace => {
                app.lists_input_buf.pop();
            }
            KeyCode::Char(c) => {
                app.lists_input_buf.push(c);
            }
            _ => {}
        },
        InputMode::ConfirmDelete => match key {
            KeyCode::Char('y') => {
                let cidr = match app.lists_focus {
                    ListsFocus::Whitelist => app.whitelist_entries.get(app.whitelist_scroll).map(|e| e.cidr.clone()),
                    ListsFocus::Blacklist => app.blacklist_entries.get(app.blacklist_scroll).map(|e| e.cidr.clone()),
                };
                if let Some(cidr) = cidr {
                    let focus = app.lists_focus;
                    app.remove_from_file(&focus, &cidr);
                    // Clamp scroll after reload
                    match app.lists_focus {
                        ListsFocus::Whitelist => {
                            if app.whitelist_scroll > 0 && app.whitelist_scroll >= app.whitelist_entries.len() {
                                app.whitelist_scroll = app.whitelist_entries.len().saturating_sub(1);
                            }
                        }
                        ListsFocus::Blacklist => {
                            if app.blacklist_scroll > 0 && app.blacklist_scroll >= app.blacklist_entries.len() {
                                app.blacklist_scroll = app.blacklist_entries.len().saturating_sub(1);
                            }
                        }
                    }
                }
                app.lists_input_mode = InputMode::Normal;
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                app.lists_input_mode = InputMode::Normal;
            }
            _ => {}
        },
        InputMode::ConfirmCleanup => match key {
            KeyCode::Char('y') => {
                app.execute_cleanup();
                // Clamp scroll after cleanup
                match app.lists_focus {
                    ListsFocus::Whitelist => {
                        if app.whitelist_scroll > 0 && app.whitelist_scroll >= app.whitelist_entries.len() {
                            app.whitelist_scroll = app.whitelist_entries.len().saturating_sub(1);
                        }
                    }
                    ListsFocus::Blacklist => {
                        if app.blacklist_scroll > 0 && app.blacklist_scroll >= app.blacklist_entries.len() {
                            app.blacklist_scroll = app.blacklist_entries.len().saturating_sub(1);
                        }
                    }
                }
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                app.cleanup_candidates.clear();
                app.lists_input_mode = InputMode::Normal;
            }
            _ => {}
        },
        InputMode::Normal => {} // shouldn't reach here
    }
}

fn handle_subnet_picker(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc => {
            app.subnet_picker = None;
        }
        KeyCode::Down => {
            if let Some(ref mut picker) = app.subnet_picker {
                if !picker.cidrs.is_empty() && picker.scroll < picker.cidrs.len() - 1 {
                    picker.scroll += 1;
                }
            }
        }
        KeyCode::Up => {
            if let Some(ref mut picker) = app.subnet_picker {
                if picker.scroll > 0 {
                    picker.scroll -= 1;
                }
            }
        }
        KeyCode::Char(' ') => {
            if let Some(ref mut picker) = app.subnet_picker {
                if !picker.cidrs.is_empty() {
                    let idx = picker.scroll;
                    if picker.marked.contains(&idx) {
                        picker.marked.remove(&idx);
                    } else {
                        picker.marked.insert(idx);
                    }
                    // Advance to next row for quick multi-select
                    if picker.scroll < picker.cidrs.len() - 1 {
                        picker.scroll += 1;
                    }
                }
            }
        }
        KeyCode::Char('a') => {
            // Toggle select-all
            if let Some(ref mut picker) = app.subnet_picker {
                if picker.marked.len() == picker.cidrs.len() {
                    picker.marked.clear();
                } else {
                    picker.marked = (0..picker.cidrs.len()).collect();
                }
            }
        }
        KeyCode::Enter => {
            if let Some(picker) = app.subnet_picker.take() {
                let selected: Vec<String> = if picker.marked.is_empty() {
                    // Add current row if none marked
                    picker.cidrs.get(picker.scroll).cloned().into_iter().collect()
                } else {
                    let mut indices: Vec<usize> = picker.marked.iter().copied().collect();
                    indices.sort();
                    indices.into_iter().filter_map(|i| picker.cidrs.get(i).cloned()).collect()
                };
                if !selected.is_empty() {
                    app.add_entries_to_list_direct(picker.target, selected);
                }
            }
        }
        _ => {}
    }
}

fn handle_asn_search(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Esc => {
            app.asn_search = None;
        }
        KeyCode::Char(' ') => {
            // Toggle mark on current result
            if let Some(ref mut search) = app.asn_search {
                if !search.results.is_empty() {
                    let idx = search.scroll;
                    if search.marked.contains(&idx) {
                        search.marked.remove(&idx);
                    } else {
                        search.marked.insert(idx);
                    }
                    // Advance to next row for quick multi-select
                    if search.scroll < search.results.len() - 1 {
                        search.scroll += 1;
                    }
                }
            }
        }
        KeyCode::Char(c) => {
            if let Some(ref mut search) = app.asn_search {
                search.query.push(c);
                search.marked.clear();
                search.query_changed_at = Some(Instant::now());
            }
        }
        KeyCode::Backspace => {
            if let Some(ref mut search) = app.asn_search {
                search.query.pop();
                search.marked.clear();
                search.query_changed_at = Some(Instant::now());
            }
        }
        KeyCode::Down => {
            if let Some(ref mut search) = app.asn_search {
                if !search.results.is_empty() && search.scroll < search.results.len() - 1 {
                    search.scroll += 1;
                }
            }
        }
        KeyCode::Up => {
            if let Some(ref mut search) = app.asn_search {
                if search.scroll > 0 {
                    search.scroll -= 1;
                }
            }
        }
        KeyCode::Enter => {
            // Collect marked results (or just the current one if none marked)
            let action = if let Some(ref search) = app.asn_search {
                let selected_indices: Vec<usize> = if search.marked.is_empty() {
                    vec![search.scroll]
                } else {
                    let mut v: Vec<usize> = search.marked.iter().copied().collect();
                    v.sort();
                    v
                };

                // Merge all CIDRs from all selected ASNs
                let mut all_cidrs = Vec::new();
                let mut labels = Vec::new();
                for &idx in &selected_indices {
                    if let Some(result) = search.results.get(idx) {
                        let cidrs = app
                            .asn_table
                            .as_ref()
                            .map(|t| t.find_all_by_asn(&result.asn))
                            .unwrap_or_default();
                        all_cidrs.extend(cidrs);
                        labels.push(result.asn.clone());
                    }
                }

                if !all_cidrs.is_empty() {
                    let asn_label = if labels.len() == 1 {
                        labels[0].clone()
                    } else {
                        format!("{} ASNs", labels.len())
                    };
                    let first_cidr = all_cidrs.first().cloned();
                    Some(app::AddActionState {
                        target: ListsFocus::Blacklist,
                        ip_cidr: None,
                        subnet_cidr: first_cidr,
                        asn_label,
                        asn_cidrs: all_cidrs,
                    })
                } else {
                    None
                }
            } else {
                None
            };
            if action.is_some() {
                app.asn_search = None;
                app.add_action = action;
            }
        }
        _ => {}
    }
}

fn build_add_action_for_context(app: &App, target: ListsFocus) -> Option<app::AddActionState> {
    match app.active_tab {
        Tab::Live => {
            if app.swarm_view == SwarmView::PerASN {
                if let Some(agg) = app.swarm_agg_entries.get(app.swarm_agg_scroll) {
                    app.build_add_action_from_asn(target, &agg.asn)
                } else {
                    None
                }
            } else {
                let entries = app.effective_swarm_entries();
                if let Some(entry) = entries.get(app.swarm_scroll) {
                    app.build_add_action_from_ip(target, &entry.ip, &entry.asn)
                } else {
                    None
                }
            }
        }
        Tab::Forensics => {
            if let Some(dd) = &app.drilldown {
                // Drilldown open: use selected IP
                if let Some(ip_entry) = dd.ips.get(app.drilldown_scroll) {
                    app.build_add_action_from_ip(target, &ip_entry.ip, &dd.neighborhood.asn)
                } else {
                    None
                }
            } else if let Some(hood) = app.neighborhoods.get(app.neighborhood_scroll) {
                // Neighborhood selected
                app.build_add_action_from_neighborhood(target, hood)
            } else {
                None
            }
        }
        Tab::Lists => None,
    }
}

fn handle_add_action(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char('1') => {
            let cidrs = if let Some(ref action) = app.add_action {
                if let Some(ref cidr) = action.ip_cidr {
                    vec![cidr.clone()]
                } else if let Some(ref cidr) = action.subnet_cidr {
                    // Neighborhood context: option 1 = subnet
                    vec![cidr.clone()]
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };
            if !cidrs.is_empty() {
                app.add_entries_to_list(cidrs);
            }
        }
        KeyCode::Char('2') => {
            if let Some(ref action) = app.add_action {
                if action.ip_cidr.is_some() {
                    // IP context: option 2 = subnet
                    let cidrs: Vec<String> = action.subnet_cidr.iter().cloned().collect();
                    if !cidrs.is_empty() {
                        app.add_entries_to_list(cidrs);
                    }
                } else if !action.asn_cidrs.is_empty() {
                    // Neighborhood context: option 2 = all ASN ranges
                    if action.asn_cidrs.len() > 1 {
                        let target = action.target;
                        let asn_label = action.asn_label.clone();
                        let cidrs = action.asn_cidrs.clone();
                        app.add_action = None;
                        app.subnet_picker = Some(app::SubnetPickerState {
                            target,
                            asn_label,
                            cidrs,
                            scroll: 0,
                            marked: std::collections::HashSet::new(),
                        });
                    } else {
                        let cidrs = action.asn_cidrs.clone();
                        app.add_entries_to_list(cidrs);
                    }
                }
            }
        }
        KeyCode::Char('3') => {
            if let Some(ref action) = app.add_action {
                if action.ip_cidr.is_some() && !action.asn_cidrs.is_empty() {
                    if action.asn_cidrs.len() > 1 {
                        // Open subnet picker for multi-range ASNs
                        let target = action.target;
                        let asn_label = action.asn_label.clone();
                        let cidrs = action.asn_cidrs.clone();
                        app.add_action = None;
                        app.subnet_picker = Some(app::SubnetPickerState {
                            target,
                            asn_label,
                            cidrs,
                            scroll: 0,
                            marked: std::collections::HashSet::new(),
                        });
                    } else {
                        let cidrs = action.asn_cidrs.clone();
                        app.add_entries_to_list(cidrs);
                    }
                }
            }
        }
        KeyCode::Esc => {
            app.add_action = None;
        }
        _ => {}
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_app() -> App {
        App::new(None, String::new(), String::new(), String::new())
    }

    #[test]
    fn test_handle_event_quit() {
        let mut app = test_app();
        assert!(handle_event(&mut app, KeyCode::Char('q')));
    }

    #[test]
    fn test_handle_event_tab_cycle() {
        let mut app = test_app();
        assert_eq!(app.active_tab, Tab::Live);
        handle_event(&mut app, KeyCode::Tab);
        assert_eq!(app.active_tab, Tab::Forensics);
        handle_event(&mut app, KeyCode::Tab);
        assert_eq!(app.active_tab, Tab::Lists);
        handle_event(&mut app, KeyCode::Tab);
        assert_eq!(app.active_tab, Tab::Live);
    }

    #[test]
    fn test_handle_event_scroll_live() {
        let mut app = test_app();
        app.swarm_entries = vec![
            crate::forensics::SwarmEntry {
                ip: "1.1.1.1".into(),
                asn: "AS1".into(),
                as_name: String::new(),
                country: "US".into(),
                total_drops: 100,
                last_seen_ago: "3s ago".into(),
                last_seen_ns: 0,
                reason: "Dynamic".into(),
            },
            crate::forensics::SwarmEntry {
                ip: "2.2.2.2".into(),
                asn: "AS2".into(),
                as_name: String::new(),
                country: "DE".into(),
                total_drops: 200,
                last_seen_ago: "1s ago".into(),
                last_seen_ns: 0,
                reason: "Blacklist".into(),
            },
        ];
        assert_eq!(app.swarm_scroll, 0);
        handle_event(&mut app, KeyCode::Down);
        assert_eq!(app.swarm_scroll, 1);
        handle_event(&mut app, KeyCode::Down);
        assert_eq!(app.swarm_scroll, 1); // clamped
        handle_event(&mut app, KeyCode::Up);
        assert_eq!(app.swarm_scroll, 0);
    }

    #[test]
    fn test_handle_event_sort_forensics() {
        let mut app = test_app();
        app.active_tab = Tab::Forensics;
        assert_eq!(app.neighborhood_sort, NeighborhoodSort::Impact);
        handle_event(&mut app, KeyCode::Char('s'));
        assert_eq!(app.neighborhood_sort, NeighborhoodSort::Country);
        handle_event(&mut app, KeyCode::Char('s'));
        assert_eq!(app.neighborhood_sort, NeighborhoodSort::Name);
        handle_event(&mut app, KeyCode::Char('s'));
        assert_eq!(app.neighborhood_sort, NeighborhoodSort::Impact);
    }

    #[test]
    fn test_handle_event_search_open_close() {
        let mut app = test_app();
        assert!(app.asn_search.is_none());
        handle_event(&mut app, KeyCode::Char('/'));
        assert!(app.asn_search.is_some());
        handle_event(&mut app, KeyCode::Esc);
        assert!(app.asn_search.is_none());
    }

    #[test]
    fn test_handle_lists_input_editing_esc() {
        let mut app = test_app();
        app.active_tab = Tab::Lists;
        app.lists_input_mode = InputMode::Editing;
        app.lists_input_buf = "10.0.0".into();
        handle_event(&mut app, KeyCode::Esc);
        assert_eq!(app.lists_input_mode, InputMode::Normal);
        assert!(app.lists_input_buf.is_empty());
    }

    #[test]
    fn test_handle_asn_search_mark_toggle() {
        let mut app = test_app();
        app.asn_search = Some(app::AsnSearchState {
            query: "test".into(),
            results: vec![
                crate::asn_table::AsnSearchResult {
                    asn: "AS1".into(),
                    as_name: "Test1".into(),
                    country: "US".into(),
                    range_count: 1,
                },
                crate::asn_table::AsnSearchResult {
                    asn: "AS2".into(),
                    as_name: "Test2".into(),
                    country: "DE".into(),
                    range_count: 2,
                },
            ],
            scroll: 0,
            marked: std::collections::HashSet::new(),
            query_changed_at: None,
        });
        handle_event(&mut app, KeyCode::Char(' '));
        let search = app.asn_search.as_ref().unwrap();
        assert!(search.marked.contains(&0));
        assert_eq!(search.scroll, 1);
    }

    #[test]
    fn test_handle_add_action_esc() {
        let mut app = test_app();
        app.add_action = Some(app::AddActionState {
            target: ListsFocus::Blacklist,
            ip_cidr: Some("1.1.1.1/32".into()),
            subnet_cidr: None,
            asn_label: "AS1".into(),
            asn_cidrs: vec![],
        });
        handle_event(&mut app, KeyCode::Esc);
        assert!(app.add_action.is_none());
    }

    // --- Add-action scope picker tests ---

    #[test]
    fn test_add_action_scope_1_ip() {
        // IP context: pressing '1' selects the IP /32
        let wl = tempfile::NamedTempFile::new().unwrap();
        let bl = tempfile::NamedTempFile::new().unwrap();
        let mut app = App::new(
            None,
            String::new(),
            wl.path().to_str().unwrap().to_string(),
            bl.path().to_str().unwrap().to_string(),
        );
        app.add_action = Some(app::AddActionState {
            target: ListsFocus::Blacklist,
            ip_cidr: Some("1.2.3.4/32".into()),
            subnet_cidr: Some("1.2.3.0/24".into()),
            asn_label: "AS1".into(),
            asn_cidrs: vec!["1.2.0.0/16".into()],
        });
        handle_event(&mut app, KeyCode::Char('1'));
        assert!(app.add_action.is_none()); // consumed
        let content = std::fs::read_to_string(bl.path()).unwrap();
        assert!(content.contains("1.2.3.4/32"));
        assert!(!content.contains("1.2.3.0/24"));
    }

    #[test]
    fn test_add_action_scope_2_subnet() {
        // IP context: pressing '2' selects the subnet
        let wl = tempfile::NamedTempFile::new().unwrap();
        let bl = tempfile::NamedTempFile::new().unwrap();
        let mut app = App::new(
            None,
            String::new(),
            wl.path().to_str().unwrap().to_string(),
            bl.path().to_str().unwrap().to_string(),
        );
        app.add_action = Some(app::AddActionState {
            target: ListsFocus::Blacklist,
            ip_cidr: Some("1.2.3.4/32".into()),
            subnet_cidr: Some("1.2.3.0/24".into()),
            asn_label: "AS1".into(),
            asn_cidrs: vec!["1.2.0.0/16".into()],
        });
        handle_event(&mut app, KeyCode::Char('2'));
        assert!(app.add_action.is_none());
        let content = std::fs::read_to_string(bl.path()).unwrap();
        assert!(content.contains("1.2.3.0/24"));
        assert!(!content.contains("1.2.3.4/32"));
    }

    #[test]
    fn test_add_action_scope_3_asn() {
        // IP context: pressing '3' selects all ASN CIDRs
        let wl = tempfile::NamedTempFile::new().unwrap();
        let bl = tempfile::NamedTempFile::new().unwrap();
        let mut app = App::new(
            None,
            String::new(),
            wl.path().to_str().unwrap().to_string(),
            bl.path().to_str().unwrap().to_string(),
        );
        app.add_action = Some(app::AddActionState {
            target: ListsFocus::Blacklist,
            ip_cidr: Some("1.2.3.4/32".into()),
            subnet_cidr: Some("1.2.3.0/24".into()),
            asn_label: "AS1".into(),
            asn_cidrs: vec!["1.2.0.0/16".into(), "5.6.0.0/16".into()],
        });
        handle_event(&mut app, KeyCode::Char('3'));
        // With >1 CIDRs, subnet picker opens instead of direct add
        assert!(app.add_action.is_none());
        assert!(app.subnet_picker.is_some());
        let picker = app.subnet_picker.as_ref().unwrap();
        assert_eq!(picker.cidrs.len(), 2);
        assert_eq!(picker.cidrs[0], "1.2.0.0/16");
        assert_eq!(picker.cidrs[1], "5.6.0.0/16");
    }

    #[test]
    fn test_add_action_scope_3_asn_single_direct() {
        // IP context: pressing '3' with 1 CIDR adds directly (no picker)
        let wl = tempfile::NamedTempFile::new().unwrap();
        let bl = tempfile::NamedTempFile::new().unwrap();
        let mut app = App::new(
            None,
            String::new(),
            wl.path().to_str().unwrap().to_string(),
            bl.path().to_str().unwrap().to_string(),
        );
        app.add_action = Some(app::AddActionState {
            target: ListsFocus::Blacklist,
            ip_cidr: Some("1.2.3.4/32".into()),
            subnet_cidr: Some("1.2.3.0/24".into()),
            asn_label: "AS1".into(),
            asn_cidrs: vec!["1.2.0.0/16".into()],
        });
        handle_event(&mut app, KeyCode::Char('3'));
        assert!(app.add_action.is_none());
        assert!(app.subnet_picker.is_none());
        let content = std::fs::read_to_string(bl.path()).unwrap();
        assert!(content.contains("1.2.0.0/16"));
    }

    #[test]
    fn test_subnet_picker_select_all_and_add() {
        let wl = tempfile::NamedTempFile::new().unwrap();
        let bl = tempfile::NamedTempFile::new().unwrap();
        let mut app = App::new(
            None,
            String::new(),
            wl.path().to_str().unwrap().to_string(),
            bl.path().to_str().unwrap().to_string(),
        );
        app.subnet_picker = Some(app::SubnetPickerState {
            target: ListsFocus::Blacklist,
            asn_label: "AS1".into(),
            cidrs: vec!["1.2.0.0/16".into(), "5.6.0.0/16".into()],
            scroll: 0,
            marked: std::collections::HashSet::new(),
        });
        handle_event(&mut app, KeyCode::Char('a'));
        assert_eq!(app.subnet_picker.as_ref().unwrap().marked.len(), 2);
        handle_event(&mut app, KeyCode::Enter);
        assert!(app.subnet_picker.is_none());
        let content = std::fs::read_to_string(bl.path()).unwrap();
        assert!(content.contains("1.2.0.0/16"));
        assert!(content.contains("5.6.0.0/16"));
    }

    #[test]
    fn test_subnet_picker_esc_dismisses() {
        let mut app = test_app();
        app.subnet_picker = Some(app::SubnetPickerState {
            target: ListsFocus::Blacklist,
            asn_label: "AS1".into(),
            cidrs: vec!["1.2.0.0/16".into()],
            scroll: 0,
            marked: std::collections::HashSet::new(),
        });
        handle_event(&mut app, KeyCode::Esc);
        assert!(app.subnet_picker.is_none());
    }

    #[test]
    fn test_subnet_picker_enter_current_if_none_marked() {
        let wl = tempfile::NamedTempFile::new().unwrap();
        let bl = tempfile::NamedTempFile::new().unwrap();
        let mut app = App::new(
            None,
            String::new(),
            wl.path().to_str().unwrap().to_string(),
            bl.path().to_str().unwrap().to_string(),
        );
        app.subnet_picker = Some(app::SubnetPickerState {
            target: ListsFocus::Blacklist,
            asn_label: "AS1".into(),
            cidrs: vec!["1.2.0.0/16".into(), "5.6.0.0/16".into()],
            scroll: 1,
            marked: std::collections::HashSet::new(),
        });
        handle_event(&mut app, KeyCode::Enter);
        assert!(app.subnet_picker.is_none());
        let content = std::fs::read_to_string(bl.path()).unwrap();
        assert!(!content.contains("1.2.0.0/16"));
        assert!(content.contains("5.6.0.0/16"));
    }

    #[test]
    fn test_subnet_picker_space_marks_and_advances() {
        let mut app = test_app();
        app.subnet_picker = Some(app::SubnetPickerState {
            target: ListsFocus::Blacklist,
            asn_label: "AS1".into(),
            cidrs: vec!["1.0.0.0/8".into(), "2.0.0.0/8".into(), "3.0.0.0/8".into()],
            scroll: 0,
            marked: std::collections::HashSet::new(),
        });
        handle_event(&mut app, KeyCode::Char(' '));
        let picker = app.subnet_picker.as_ref().unwrap();
        assert!(picker.marked.contains(&0));
        assert_eq!(picker.scroll, 1);
    }

    #[test]
    fn test_delete_confirm_y() {
        let wl = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(wl.path(), "10.0.0.0/8\n192.168.0.0/16\n").unwrap();
        let bl = tempfile::NamedTempFile::new().unwrap();
        let mut app = App::new(
            None,
            String::new(),
            wl.path().to_str().unwrap().to_string(),
            bl.path().to_str().unwrap().to_string(),
        );
        app.load_lists();
        app.active_tab = Tab::Lists;
        app.lists_focus = ListsFocus::Whitelist;
        app.whitelist_scroll = 0;
        app.lists_input_mode = InputMode::ConfirmDelete;
        handle_event(&mut app, KeyCode::Char('y'));
        assert_eq!(app.lists_input_mode, InputMode::Normal);
        let content = std::fs::read_to_string(wl.path()).unwrap();
        assert!(!content.contains("10.0.0.0/8"));
        assert!(content.contains("192.168.0.0/16"));
    }

    #[test]
    fn test_delete_confirm_n() {
        let mut app = test_app();
        app.active_tab = Tab::Lists;
        app.lists_input_mode = InputMode::ConfirmDelete;
        handle_event(&mut app, KeyCode::Char('n'));
        assert_eq!(app.lists_input_mode, InputMode::Normal);
    }

    #[test]
    fn test_lists_backspace() {
        let mut app = test_app();
        app.active_tab = Tab::Lists;
        app.lists_input_mode = InputMode::Editing;
        app.lists_input_buf = "10.0.0".into();
        handle_event(&mut app, KeyCode::Backspace);
        assert_eq!(app.lists_input_buf, "10.0.");
    }

    #[test]
    fn test_lists_char_input() {
        let mut app = test_app();
        app.active_tab = Tab::Lists;
        app.lists_input_mode = InputMode::Editing;
        app.lists_input_buf.clear();
        handle_event(&mut app, KeyCode::Char('1'));
        handle_event(&mut app, KeyCode::Char('0'));
        handle_event(&mut app, KeyCode::Char('.'));
        assert_eq!(app.lists_input_buf, "10.");
    }

    #[test]
    fn test_handle_event_threshold_cycle() {
        use crate::app::BotThreshold;
        let mut app = test_app();
        app.active_tab = Tab::Forensics;
        assert_eq!(app.neighborhood_bot_threshold, BotThreshold::Two);
        handle_event(&mut app, KeyCode::Char('t'));
        assert_eq!(app.neighborhood_bot_threshold, BotThreshold::Five);
        handle_event(&mut app, KeyCode::Char('t'));
        assert_eq!(app.neighborhood_bot_threshold, BotThreshold::One);
        handle_event(&mut app, KeyCode::Char('t'));
        assert_eq!(app.neighborhood_bot_threshold, BotThreshold::Two);
    }

    #[test]
    fn test_handle_event_window_cycle() {
        use crate::app::TimeWindow;
        let mut app = test_app();
        app.active_tab = Tab::Forensics;
        assert_eq!(app.neighborhood_time_window, TimeWindow::OneHour);
        handle_event(&mut app, KeyCode::Char('f'));
        assert_eq!(app.neighborhood_time_window, TimeWindow::TwentyFourHour);
        handle_event(&mut app, KeyCode::Char('f'));
        assert_eq!(app.neighborhood_time_window, TimeWindow::FiveMin);
        handle_event(&mut app, KeyCode::Char('f'));
        assert_eq!(app.neighborhood_time_window, TimeWindow::OneHour);
    }

    // --- Swarm ASN aggregate view tests ---

    fn make_swarm_entry(ip: &str, asn: &str, country: &str, drops: u64, reason: &str) -> crate::forensics::SwarmEntry {
        crate::forensics::SwarmEntry {
            ip: ip.into(),
            asn: asn.into(),
            as_name: String::new(),
            country: country.into(),
            total_drops: drops,
            last_seen_ago: "1s ago".into(),
            last_seen_ns: 5_000_000_000,
            reason: reason.into(),
        }
    }

    #[test]
    fn test_g_toggles_swarm_view() {
        let mut app = test_app();
        assert_eq!(app.swarm_view, SwarmView::PerIP);
        handle_event(&mut app, KeyCode::Char('g'));
        assert_eq!(app.swarm_view, SwarmView::PerASN);
        handle_event(&mut app, KeyCode::Char('g'));
        assert_eq!(app.swarm_view, SwarmView::PerIP);
    }

    #[test]
    fn test_g_ignored_on_non_live_tabs() {
        let mut app = test_app();
        app.active_tab = Tab::Forensics;
        handle_event(&mut app, KeyCode::Char('g'));
        assert_eq!(app.swarm_view, SwarmView::PerIP);

        app.active_tab = Tab::Lists;
        handle_event(&mut app, KeyCode::Char('g'));
        assert_eq!(app.swarm_view, SwarmView::PerIP);
    }

    #[test]
    fn test_enter_drills_into_asn() {
        let mut app = test_app();
        app.swarm_entries = vec![
            make_swarm_entry("1.1.1.1", "AS1", "US", 100, "Dynamic"),
            make_swarm_entry("2.2.2.2", "AS1", "US", 50, "Dynamic"),
            make_swarm_entry("3.3.3.3", "AS2", "DE", 200, "Blacklist"),
        ];
        app.swarm_agg_entries = vec![
            app::SwarmAsnEntry {
                asn: "AS2".into(),
                as_name: String::new(),
                country: "DE".into(),
                ip_count: 1,
                total_drops: 200,
                last_seen_ns: 5_000_000_000,
                has_blacklist: true,
                has_dynamic: false,
            },
            app::SwarmAsnEntry {
                asn: "AS1".into(),
                as_name: String::new(),
                country: "US".into(),
                ip_count: 2,
                total_drops: 150,
                last_seen_ns: 5_000_000_000,
                has_blacklist: false,
                has_dynamic: true,
            },
        ];
        app.swarm_view = SwarmView::PerASN;
        app.swarm_agg_scroll = 0;

        handle_event(&mut app, KeyCode::Enter);
        assert_eq!(app.swarm_view, SwarmView::PerIP);
        assert_eq!(app.swarm_asn_filter.as_deref(), Some("AS2"));
        assert_eq!(app.swarm_scroll, 0);
    }

    #[test]
    fn test_esc_clears_filter() {
        let mut app = test_app();
        app.swarm_asn_filter = Some("AS1".into());
        app.swarm_view = SwarmView::PerIP;

        handle_event(&mut app, KeyCode::Esc);
        assert!(app.swarm_asn_filter.is_none());
        assert_eq!(app.swarm_view, SwarmView::PerASN);
        assert_eq!(app.swarm_agg_scroll, 0);
    }

    #[test]
    fn test_esc_no_filter_does_nothing_on_live() {
        let mut app = test_app();
        app.swarm_view = SwarmView::PerIP;
        app.swarm_asn_filter = None;

        handle_event(&mut app, KeyCode::Esc);
        // Should not change view (no filter to clear)
        assert_eq!(app.swarm_view, SwarmView::PerIP);
    }

    #[test]
    fn test_scroll_in_aggregate_view() {
        let mut app = test_app();
        app.swarm_view = SwarmView::PerASN;
        app.swarm_agg_entries = vec![
            app::SwarmAsnEntry {
                asn: "AS1".into(),
                as_name: String::new(),
                country: "US".into(),
                ip_count: 2,
                total_drops: 300,
                last_seen_ns: 0,
                has_blacklist: false,
                has_dynamic: true,
            },
            app::SwarmAsnEntry {
                asn: "AS2".into(),
                as_name: String::new(),
                country: "DE".into(),
                ip_count: 1,
                total_drops: 100,
                last_seen_ns: 0,
                has_blacklist: true,
                has_dynamic: false,
            },
        ];
        assert_eq!(app.swarm_agg_scroll, 0);
        handle_event(&mut app, KeyCode::Down);
        assert_eq!(app.swarm_agg_scroll, 1);
        handle_event(&mut app, KeyCode::Down);
        assert_eq!(app.swarm_agg_scroll, 1); // clamped
        handle_event(&mut app, KeyCode::Up);
        assert_eq!(app.swarm_agg_scroll, 0);
    }
}
