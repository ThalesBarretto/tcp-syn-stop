// SPDX-License-Identifier: GPL-2.0-only
//! Open pinned BPF maps and provide typed access.
//!
//! Maps are opened via `MapHandle::from_pinned_path()`.
//! IPs stay in network byte order at this layer — callers convert via
//! `u32::from_be()` before ASN lookup (matches C daemon's `ntohl()`).

use std::os::fd::AsFd as _;
use std::os::unix::io::AsRawFd as _;
use std::path::Path;

use anyhow::{Context, Result};
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use log::{info, warn};

/// Value stored in the `drop_ips` and `blacklist_cnt` LRU maps.
pub struct DropInfo {
    pub last_seen: u64,
    pub count: u64,
}

/// LPM trie key — must match `struct lpm_key` in `tcp_syn_stop.bpf.c`.
#[repr(C)]
pub struct LpmKey {
    pub prefixlen: u32,
    pub ip: u32,
}

const _: () = assert!(std::mem::size_of::<LpmKey>() == 8);

/// Field offsets for `drop_info`, resolved from BTF at runtime.
struct DropInfoLayout {
    last_seen_off: usize,
    count_off: usize,
    value_size: usize,
}

impl DropInfoLayout {
    /// Fallback when BTF is unavailable (matches current C layout).
    const HARDCODED: Self = Self {
        last_seen_off: 0,
        count_off: 8,
        value_size: 16,
    };

    fn read(&self, val: &[u8]) -> Option<DropInfo> {
        if val.len() < self.last_seen_off + 8 || val.len() < self.count_off + 8 {
            return None;
        }
        Some(DropInfo {
            last_seen: u64::from_ne_bytes(val[self.last_seen_off..][..8].try_into().ok()?),
            count: u64::from_ne_bytes(val[self.count_off..][..8].try_into().ok()?),
        })
    }
}

/// Resolve `drop_info` field offsets from BPF map BTF metadata.
///
/// Falls back to `DropInfoLayout::HARDCODED` if the kernel/map has no BTF.
fn resolve_drop_info_layout(map: &MapHandle) -> Result<DropInfoLayout> {
    let map_info = map.info().context("map info for BTF resolution")?;
    let btf_id = map_info.info.btf_id;
    let value_type_id = map_info.info.btf_value_type_id;

    if btf_id == 0 || value_type_id == 0 {
        return Ok(DropInfoLayout::HARDCODED);
    }

    // RAII guard for btf__free.
    struct BtfGuard(*mut libbpf_sys::btf);
    impl Drop for BtfGuard {
        fn drop(&mut self) {
            unsafe { libbpf_sys::btf__free(self.0) }
        }
    }

    let btf = unsafe { libbpf_sys::btf__load_from_kernel_by_id(btf_id) };
    if btf.is_null() {
        return Ok(DropInfoLayout::HARDCODED);
    }
    let _guard = BtfGuard(btf);

    let ty = unsafe { libbpf_sys::btf__type_by_id(btf, value_type_id) };
    if ty.is_null() {
        return Ok(DropInfoLayout::HARDCODED);
    }

    let ty = unsafe { &*ty };
    let vlen = (ty.info & 0xffff) as usize;
    let members = unsafe {
        let base =
            (ty as *const libbpf_sys::btf_type).add(1) as *const libbpf_sys::btf_member;
        std::slice::from_raw_parts(base, vlen)
    };

    let mut last_seen_off = None;
    let mut count_off = None;

    for m in members {
        let name = unsafe { libbpf_sys::btf__name_by_offset(btf, m.name_off) };
        if name.is_null() {
            continue;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(name) };
        match name.to_bytes() {
            b"last_seen" => last_seen_off = Some((m.offset / 8) as usize),
            b"count" => count_off = Some((m.offset / 8) as usize),
            _ => {}
        }
    }

    Ok(DropInfoLayout {
        last_seen_off: last_seen_off.context("BTF: missing 'last_seen' field")?,
        count_off: count_off.context("BTF: missing 'count' field")?,
        value_size: map_info.info.value_size as usize,
    })
}

/// Handles to pinned BPF maps.
pub struct BpfMaps {
    drop_cnt: MapHandle,
    drop_ips: MapHandle,
    blacklist_cnt: MapHandle,
    blacklist: MapHandle,
    rb_fail_cnt: MapHandle,
    rb: MapHandle,
    drop_info_layout: DropInfoLayout,
}

impl BpfMaps {
    /// Open pinned maps from `pin_dir`.
    /// Fails with a descriptive error if the daemon is not running.
    pub fn open(pin_dir: &Path) -> Result<Self> {
        let open_map = |name: &str| -> Result<MapHandle> {
            let path = pin_dir.join(name);
            MapHandle::from_pinned_path(&path)
                .with_context(|| format!("cannot open pinned map at {}", path.display()))
        };

        let drop_ips = open_map("drop_ips")?;

        let drop_info_layout = resolve_drop_info_layout(&drop_ips).unwrap_or_else(|e| {
            warn!("BTF resolution failed ({e:#}), using hardcoded drop_info layout");
            DropInfoLayout::HARDCODED
        });

        info!(
            "drop_info layout: last_seen@{}, count@{}, size={}",
            drop_info_layout.last_seen_off,
            drop_info_layout.count_off,
            drop_info_layout.value_size,
        );

        Ok(Self {
            drop_cnt: open_map("drop_cnt")?,
            drop_ips,
            blacklist_cnt: open_map("blacklist_cnt")?,
            blacklist: open_map("blacklist")?,
            rb_fail_cnt: open_map("rb_fail_cnt")?,
            rb: open_map("rb")?,
            drop_info_layout,
        })
    }

    /// Borrow the `rb` map handle for `RingBufferBuilder`.
    pub fn rb_map(&self) -> &MapHandle {
        &self.rb
    }

    /// Read `drop_cnt` (PERCPU_ARRAY): sum u64 values across all CPUs.
    pub fn read_drop_cnt(&self) -> Result<u64> {
        sum_percpu_u64(&self.drop_cnt, "drop_cnt")
    }

    /// Read `rb_fail_cnt` (PERCPU_ARRAY): sum u64 values across all CPUs.
    pub fn read_rb_fail_cnt(&self) -> Result<u64> {
        sum_percpu_u64(&self.rb_fail_cnt, "rb_fail_cnt")
    }

    /// Iterate `drop_ips` (LRU_HASH) and collect all (ip_nbo, DropInfo) pairs.
    pub fn iter_drop_ips(&self) -> Result<Vec<(u32, DropInfo)>> {
        iter_lru_hash(&self.drop_ips, &self.drop_info_layout, "drop_ips")
    }

    /// Iterate `blacklist_cnt` (LRU_HASH) and collect all (ip_nbo, DropInfo) pairs.
    pub fn iter_blacklist_cnt(&self) -> Result<Vec<(u32, DropInfo)>> {
        iter_lru_hash(&self.blacklist_cnt, &self.drop_info_layout, "blacklist_cnt")
    }

    /// Count entries in `blacklist_cnt` (LRU_HASH).
    pub fn count_blacklist(&self) -> Result<u32> {
        let mut count: u32 = 0;
        for _key in self.blacklist_cnt.keys() {
            count += 1;
        }
        Ok(count)
    }

    /// Look up a single IP in `drop_ips`.  IP is in network byte order.
    pub fn lookup_drop_ip(&self, ip_nbo: u32) -> Result<Option<DropInfo>> {
        let key = ip_nbo.to_ne_bytes();
        match self.drop_ips.lookup(&key, MapFlags::ANY).context("lookup_drop_ip")? {
            Some(val) => Ok(self.drop_info_layout.read(&val)),
            None => Ok(None),
        }
    }

    /// Delete an IP from `drop_ips`.  IP is in network byte order.
    pub fn delete_drop_ip(&self, ip_nbo: u32) -> Result<()> {
        let key = ip_nbo.to_ne_bytes();
        self.drop_ips.delete(&key).context("delete_drop_ip")
    }

    /// Insert a prefix into the `blacklist` LPM trie.
    pub fn update_blacklist(&self, net_addr_nbo: u32, prefix_len: u32) -> Result<()> {
        let key = LpmKey {
            prefixlen: prefix_len,
            ip: net_addr_nbo,
        };
        let key_bytes =
            unsafe { std::slice::from_raw_parts((&key as *const LpmKey).cast::<u8>(), std::mem::size_of::<LpmKey>()) };
        let val = [1u8];
        self.blacklist
            .update(key_bytes, &val, MapFlags::ANY)
            .context("update_blacklist")
    }

    /// Delete a prefix from the `blacklist` LPM trie.
    pub fn delete_blacklist(&self, net_addr_nbo: u32, prefix_len: u32) -> Result<()> {
        let key = LpmKey {
            prefixlen: prefix_len,
            ip: net_addr_nbo,
        };
        let key_bytes =
            unsafe { std::slice::from_raw_parts((&key as *const LpmKey).cast::<u8>(), std::mem::size_of::<LpmKey>()) };
        self.blacklist.delete(key_bytes).context("delete_blacklist")
    }
}

/// Read a single-element PERCPU_ARRAY map (key=0) and sum u64 values.
fn sum_percpu_u64(map: &MapHandle, name: &str) -> Result<u64> {
    let key = 0u32.to_ne_bytes();
    let per_cpu = map
        .lookup_percpu(&key, MapFlags::ANY)
        .with_context(|| format!("lookup_percpu on {name}"))?
        .unwrap_or_default();

    let mut total: u64 = 0;
    for cpu_val in &per_cpu {
        if cpu_val.len() >= 8 {
            let v = u64::from_ne_bytes(cpu_val[..8].try_into().expect("slice length checked above"));
            total += v;
        }
    }
    Ok(total)
}

/// Iterate an LRU_HASH map with u32 keys and DropInfo values.
///
/// Tries batch iteration first (256 entries per syscall, available on
/// kernels >= 5.6).  Falls back to key-by-key iteration on `EINVAL` or
/// `ENOSYS` (batch on LRU_HASH not supported).
fn iter_lru_hash(
    map: &MapHandle,
    layout: &DropInfoLayout,
    name: &str,
) -> Result<Vec<(u32, DropInfo)>> {
    match iter_lru_hash_batch(map, layout) {
        Ok(entries) => return Ok(entries),
        Err(e) => {
            let raw = e.downcast_ref::<std::io::Error>().map(std::io::Error::raw_os_error);
            if raw == Some(Some(libc::EINVAL)) || raw == Some(Some(libc::ENOSYS)) {
                // Kernel doesn't support batch on this map type — fall back.
            } else {
                return Err(e).with_context(|| format!("batch iter on {name}"));
            }
        }
    }

    iter_lru_hash_keybykey(map, layout, name)
}

/// Batch iteration: 256 entries per `bpf_map_lookup_batch` syscall.
fn iter_lru_hash_batch(
    map: &MapHandle,
    layout: &DropInfoLayout,
) -> Result<Vec<(u32, DropInfo)>> {
    const BATCH_SIZE: u32 = 256;

    let fd = map.as_fd().as_raw_fd();
    let opts = libbpf_sys::bpf_map_batch_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_map_batch_opts>() as u64,
        elem_flags: 0,
        flags: 0,
    };

    let mut entries = Vec::new();
    let mut keys = vec![0u32; BATCH_SIZE as usize];
    let mut values = vec![0u8; BATCH_SIZE as usize * layout.value_size];

    let mut in_batch: u32 = 0;
    let mut out_batch: u32 = 0;
    let mut first = true;

    loop {
        let mut count = BATCH_SIZE;

        let in_ptr = if first {
            std::ptr::null_mut()
        } else {
            &mut in_batch as *mut u32 as *mut std::ffi::c_void
        };

        let ret = unsafe {
            libbpf_sys::bpf_map_lookup_batch(
                fd,
                in_ptr,
                &mut out_batch as *mut u32 as *mut std::ffi::c_void,
                keys.as_mut_ptr().cast(),
                values.as_mut_ptr().cast(),
                &mut count,
                &opts,
            )
        };

        // Collect returned entries.
        for (&key, chunk) in keys[..count as usize]
            .iter()
            .zip(values.chunks_exact(layout.value_size))
        {
            if let Some(info) = layout.read(chunk) {
                entries.push((key, info));
            }
        }

        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                // Iteration complete.
                break;
            }
            return Err(err.into());
        }

        first = false;
        in_batch = out_batch;
    }

    Ok(entries)
}

/// Fallback key-by-key iteration for kernels without batch support.
fn iter_lru_hash_keybykey(
    map: &MapHandle,
    layout: &DropInfoLayout,
    name: &str,
) -> Result<Vec<(u32, DropInfo)>> {
    let mut entries = Vec::new();

    for key_bytes in map.keys() {
        if key_bytes.len() < 4 {
            continue;
        }
        let ip_nbo = u32::from_ne_bytes(key_bytes[..4].try_into().expect("slice length checked above"));

        if let Some(val_bytes) = map
            .lookup(&key_bytes, MapFlags::ANY)
            .with_context(|| format!("lookup in {name}"))?
        {
            if let Some(info) = layout.read(&val_bytes) {
                entries.push((ip_nbo, info));
            }
        }
        // Key disappeared between keys() and lookup() — LRU eviction, skip.
    }

    Ok(entries)
}
