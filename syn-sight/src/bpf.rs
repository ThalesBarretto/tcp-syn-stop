// SPDX-License-Identifier: GPL-2.0-only
//! Read-only pinned BPF map access for the TUI.
//!
//! Opens the same pinned maps as the daemon and syn-intel, but only
//! provides read methods — no writes to drop_ips or blacklist.

use std::path::Path;

use anyhow::{Context, Result};
use libbpf_rs::{MapCore, MapFlags, MapHandle};

/// Value stored in `drop_ips` and `blacklist_cnt` LRU maps.
#[repr(C)]
pub struct DropInfo {
    pub last_seen: u64,
    pub count: u64,
}

/// LPM trie key — must match `struct lpm_key` in `tcp_syn_stop.bpf.c`.
#[repr(C)]
struct LpmKey {
    prefixlen: u32,
    ip: u32, // network byte order
}

/// Handles to pinned BPF maps (read-only).
pub struct BpfMaps {
    drop_cnt: MapHandle,
    drop_ips: MapHandle,
    blacklist_cnt: MapHandle,
    rb_fail_cnt: MapHandle,
    port_drop_counts: Option<MapHandle>,
    whitelist_lpm: Option<MapHandle>,
    blacklist_lpm: Option<MapHandle>,
}

impl BpfMaps {
    /// Open pinned maps from `pin_dir`.
    pub fn open(pin_dir: &Path) -> Result<Self> {
        let open_map = |name: &str| -> Result<MapHandle> {
            let path = pin_dir.join(name);
            MapHandle::from_pinned_path(&path)
                .with_context(|| format!("cannot open pinned map at {}", path.display()))
        };

        let port_drop_counts = open_map("port_drop_counts").ok();
        let whitelist_lpm = open_map("whitelist").ok();
        let blacklist_lpm = open_map("blacklist").ok();

        Ok(Self {
            drop_cnt: open_map("drop_cnt")?,
            drop_ips: open_map("drop_ips")?,
            blacklist_cnt: open_map("blacklist_cnt")?,
            rb_fail_cnt: open_map("rb_fail_cnt")?,
            port_drop_counts,
            whitelist_lpm,
            blacklist_lpm,
        })
    }

    /// Read `drop_cnt` (PERCPU_ARRAY): sum u64 values across all CPUs.
    pub fn read_drop_cnt(&self) -> Result<u64> {
        sum_percpu_u64(&self.drop_cnt, "drop_cnt")
    }

    /// Read `rb_fail_cnt` (PERCPU_ARRAY): sum across all CPUs.
    pub fn read_rb_fail_cnt(&self) -> Result<u64> {
        sum_percpu_u64(&self.rb_fail_cnt, "rb_fail_cnt")
    }

    /// Iterate `drop_ips` (LRU_HASH) and collect all `(ip_nbo, DropInfo)` pairs.
    pub fn iter_drop_ips(&self) -> Result<Vec<(u32, DropInfo)>> {
        let mut entries = Vec::new();
        for key_bytes in self.drop_ips.keys() {
            if key_bytes.len() < 4 {
                continue;
            }
            let ip_nbo = u32::from_ne_bytes(key_bytes[..4].try_into().expect("checked"));
            if let Some(val) = self
                .drop_ips
                .lookup(&key_bytes, MapFlags::ANY)
                .context("lookup in drop_ips")?
            {
                if val.len() >= 16 {
                    entries.push((
                        ip_nbo,
                        DropInfo {
                            last_seen: u64::from_ne_bytes(val[..8].try_into().expect("checked")),
                            count: u64::from_ne_bytes(val[8..16].try_into().expect("checked")),
                        },
                    ));
                }
            }
        }
        Ok(entries)
    }

    /// Iterate `port_drop_counts` (HASH) and collect all `(port_nbo, count)` pairs.
    /// Returns port in network byte order (as stored by BPF).
    pub fn iter_port_counts(&self) -> Result<Vec<(u16, u64)>> {
        let map = match &self.port_drop_counts {
            Some(m) => m,
            None => return Ok(Vec::new()),
        };
        let mut entries = Vec::new();
        for key_bytes in map.keys() {
            if key_bytes.len() < 2 {
                continue;
            }
            let port_nbo = u16::from_ne_bytes(key_bytes[..2].try_into().expect("checked"));
            if let Some(val) = map
                .lookup(&key_bytes, MapFlags::ANY)
                .context("lookup in port_drop_counts")?
            {
                if val.len() >= 8 {
                    let count = u64::from_ne_bytes(val[..8].try_into().expect("checked"));
                    entries.push((port_nbo, count));
                }
            }
        }
        Ok(entries)
    }

    /// Iterate `blacklist_cnt` (LRU_HASH) and collect all `(ip_nbo, DropInfo)` pairs.
    pub fn iter_blacklist_cnt(&self) -> Result<Vec<(u32, DropInfo)>> {
        let mut entries = Vec::new();
        for key_bytes in self.blacklist_cnt.keys() {
            if key_bytes.len() < 4 {
                continue;
            }
            let ip_nbo = u32::from_ne_bytes(key_bytes[..4].try_into().expect("checked"));
            if let Some(val) = self
                .blacklist_cnt
                .lookup(&key_bytes, MapFlags::ANY)
                .context("lookup in blacklist_cnt")?
            {
                if val.len() >= 16 {
                    entries.push((
                        ip_nbo,
                        DropInfo {
                            last_seen: u64::from_ne_bytes(val[..8].try_into().expect("checked")),
                            count: u64::from_ne_bytes(val[8..16].try_into().expect("checked")),
                        },
                    ));
                }
            }
        }
        Ok(entries)
    }

    /// Check whether a CIDR prefix is present in the whitelist or blacklist
    /// LPM trie.  Used to verify that the daemon has processed a config
    /// reload after SIGHUP.
    ///
    /// `net_addr_hbo` is the network address in host byte order (as returned
    /// by `validation::parse_cidr`).  Returns `None` if the map handle is
    /// unavailable (daemon not running).
    pub fn lpm_lookup(&self, is_whitelist: bool, net_addr_hbo: u32, prefix_len: u32) -> Option<bool> {
        let map = if is_whitelist {
            self.whitelist_lpm.as_ref()?
        } else {
            self.blacklist_lpm.as_ref()?
        };
        let key = LpmKey {
            prefixlen: prefix_len,
            ip: net_addr_hbo.to_be(),
        };
        let key_bytes = unsafe {
            std::slice::from_raw_parts(
                (&key as *const LpmKey).cast::<u8>(),
                std::mem::size_of::<LpmKey>(),
            )
        };
        match map.lookup(key_bytes, MapFlags::ANY) {
            Ok(Some(_)) => Some(true),
            Ok(None) => Some(false),
            Err(_) => None,
        }
    }
}

/// Scan network interfaces for XDP program attachments.
/// Returns `(name, native)` for each interface with an XDP program.
pub fn detect_xdp_ifaces() -> Vec<(String, bool)> {
    let mut result = Vec::new();
    let entries = match std::fs::read_dir("/sys/class/net") {
        Ok(e) => e,
        Err(_) => return result,
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "lo" {
            continue;
        }
        let ifindex = unsafe { libc::if_nametoindex(std::ffi::CString::new(name.as_str()).unwrap_or_default().as_ptr()) };
        if ifindex == 0 {
            continue;
        }
        #[allow(clippy::cast_possible_wrap)]
        let idx = ifindex as i32;

        // Check native (DRV) mode first, then generic (SKB) mode.
        let mut prog_id: u32 = 0;
        let drv_flags = libbpf_rs::libbpf_sys::XDP_FLAGS_DRV_MODE as i32;
        let ret = unsafe { libbpf_rs::libbpf_sys::bpf_xdp_query_id(idx, drv_flags, &mut prog_id) };
        if ret == 0 && prog_id != 0 {
            result.push((name, true));
            continue;
        }

        prog_id = 0;
        let skb_flags = libbpf_rs::libbpf_sys::XDP_FLAGS_SKB_MODE as i32;
        let ret = unsafe { libbpf_rs::libbpf_sys::bpf_xdp_query_id(idx, skb_flags, &mut prog_id) };
        if ret == 0 && prog_id != 0 {
            result.push((name, false));
        }
    }
    result
}

fn sum_percpu_u64(map: &MapHandle, name: &str) -> Result<u64> {
    let key = 0u32.to_ne_bytes();
    let per_cpu = map
        .lookup_percpu(&key, MapFlags::ANY)
        .with_context(|| format!("lookup_percpu on {name}"))?
        .unwrap_or_default();

    let mut total: u64 = 0;
    for cpu_val in &per_cpu {
        if cpu_val.len() >= 8 {
            total += u64::from_ne_bytes(cpu_val[..8].try_into().expect("checked"));
        }
    }
    Ok(total)
}
