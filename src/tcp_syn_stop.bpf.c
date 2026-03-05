// SPDX-License-Identifier: GPL-2.0-only
/*
 * tcp_syn_stop.bpf.c — eBPF programs for SYN flood detection and filtering
 *
 * Two-pronged strategy:
 *   1. Tracepoint on tcp/tcp_retransmit_synack — detects spoofed reflection
 *      victims via the stable kernel tracing ABI.  Fires only after the
 *      kernel's full RTO expires, so legitimate slow clients that eventually
 *      complete the handshake are never blocked.  On first insertion into
 *      drop_ips (BPF_NOEXIST), a REASON_NEW_BLOCK event is sent to userspace
 *      via ringbuf for immediate TTL scheduling.
 *
 *   2. XDP filter (xdp_drop_spoofed_syns) — wire-speed packet filtering.
 *      Two-tier drop semantics after L3 whitelist check:
 *        a. Manual blacklist (blacklist.conf) → full L3 drop: ALL packets
 *           (TCP, UDP, ICMP) from blacklisted CIDRs are dropped at XDP.
 *           Operator intent when manually blacklisting is total severance.
 *        b. Dynamic drop_ips (tracepoint-populated) → SYN-only drop:
 *           these IPs are only proven bad for half-open SYN abuse and may
 *           have legitimate established connections.
 *      Whitelist always wins over both tiers (checked first, all protocols).
 *      Blocked IPs expire via syn-intel's TTL heap — no stateless ACK
 *      clearing, which would let spoofed ACKs trivially evict entries.
 *
 * Metrics: every drop increments a PERCPU_ARRAY counter for 100% accurate
 * aggregate PPS. Individual drop events are rate-limited to the ringbuf
 * (at most one per CPU per millisecond) via a per-CPU token bucket,
 * guaranteeing full fidelity at low PPS and bounded overhead under flood.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES_LRU       65536
#define MAX_ENTRIES_WHITELIST 131072
#define MAX_ENTRIES_BLACKLIST 131072
#define SAMPLE_INTERVAL_NS   1000000   /* 1ms — max ~1K events/sec/CPU */
#define ETH_P_IP 0x0800

// Value for the drop_ips map (includes precise counting)
struct drop_info {
    u64 last_seen;
    u64 count;
};

// Define the LPM Trie Key struct (needed for CIDR matching)
struct lpm_key {
    u32 prefixlen;
    u32 ip;
};

// 1. Map for active spoofed targets (LRU Hash)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES_LRU);
    __type(key, u32);
    __type(value, struct drop_info);
} drop_ips SEC(".maps");

// 1b. Per-IP accounting for blacklist hits (LRU Hash)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES_LRU);
    __type(key, u32);
    __type(value, struct drop_info);
} blacklist_cnt SEC(".maps");

// 2. Whitelist map (LPM Trie)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ENTRIES_WHITELIST);
    __type(key, struct lpm_key);
    __type(value, u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whitelist SEC(".maps");

// 3. Blacklist map (LPM Trie)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ENTRIES_BLACKLIST);
    __type(key, struct lpm_key);
    __type(value, u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blacklist SEC(".maps");

// 4. Ignored ports (Hash)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u16);
    __type(value, u8);
} ignored_ports SEC(".maps");

// 5. PERCPU Array for zero-lock metrics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} drop_cnt SEC(".maps");

// 6. Ringbuf reserve failure counter (self-instrumentation)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} rb_fail_cnt SEC(".maps");

// 7. Per-CPU rate-limit timestamp for ringbuf sampling
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} rl_map SEC(".maps");

// 8. Per-port drop counter (Target Heatmap)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u16);
    __type(value, u64);
} port_drop_counts SEC(".maps");

// 9. Ringbuffer for sampled drop events
struct event {
    u32 src_ip;
    u16 dest_port;
    u8 reason;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} rb SEC(".maps");

#define REASON_BLACKLIST  1
#define REASON_DYNAMIC    2
#define REASON_NEW_BLOCK  3

// --- Tracepoint for SYN-ACK retransmissions (stable kernel ABI) ---
SEC("tracepoint/tcp/tcp_retransmit_synack")
int tp__tcp_retransmit_synack(struct trace_event_raw_tcp_retransmit_synack *ctx) {
    u32 dest_ip;
    bpf_probe_read_kernel(&dest_ip, sizeof(dest_ip), &ctx->daddr);

    u16 sport;
    bpf_probe_read_kernel(&sport, sizeof(sport), &ctx->sport);

    // Check whitelist before blocking
    struct lpm_key wkey = {.prefixlen = 32, .ip = dest_ip};
    if (bpf_map_lookup_elem(&whitelist, &wkey))
        return 0;

    struct drop_info info = {
        .last_seen = bpf_ktime_get_ns(),
        .count = 1,
    };

    /* BPF_NOEXIST: only insert for genuinely new entries.
     * XDP already refreshes last_seen for IPs already in the map.
     * On success, notify userspace via ringbuf so it can schedule expiry. */
    if (bpf_map_update_elem(&drop_ips, &dest_ip, &info, BPF_NOEXIST) == 0) {
        struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            e->src_ip    = dest_ip;
            e->dest_port = bpf_ntohs(sport);
            e->reason    = REASON_NEW_BLOCK;
            bpf_ringbuf_submit(e, 0);
        } else {
            u32 rk = 0;
            u64 *rc = bpf_map_lookup_elem(&rb_fail_cnt, &rk);
            if (rc) *rc += 1;
        }
    }

    return 0;
}

// --- XDP Program to drop spoofed SYNs ---
SEC("xdp")
int xdp_drop_spoofed_syns(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    /* ── L3 checks: whitelist / blacklist (all protocols) ──────── */
    u32 src_ip = ip->saddr;

    /* Whitelist always wins — checked first, all protocols. */
    struct lpm_key wkey = {.prefixlen = 32, .ip = src_ip};
    if (bpf_map_lookup_elem(&whitelist, &wkey))
        return XDP_PASS;

    /* Manual blacklist: full L3 drop (all protocols, all ports).
     * Operator intent when blacklisting is total severance — a blacklist
     * that only blocks SYNs leaves ACK floods, scans, and established
     * connections from the source untouched. */
    struct lpm_key bkey = {.prefixlen = 32, .ip = src_ip};
    if (bpf_map_lookup_elem(&blacklist, &bkey)) {
        /* Per-IP blacklist accounting */
        struct drop_info *bl_val = bpf_map_lookup_elem(&blacklist_cnt, &src_ip);
        if (bl_val) {
            bl_val->last_seen = bpf_ktime_get_ns();
            __sync_fetch_and_add(&bl_val->count, 1);
        } else {
            struct drop_info bl_new = {
                .last_seen = bpf_ktime_get_ns(),
                .count     = 1,
            };
            /* BPF_NOEXIST may fail if another CPU won the race
             * and inserted the entry first.  Re-lookup and
             * increment so we never silently drop a count. */
            if (bpf_map_update_elem(&blacklist_cnt, &src_ip, &bl_new, BPF_NOEXIST) != 0) {
                bl_val = bpf_map_lookup_elem(&blacklist_cnt, &src_ip);
                if (bl_val) {
                    bl_val->last_seen = bpf_ktime_get_ns();
                    __sync_fetch_and_add(&bl_val->count, 1);
                }
            }
        }

        /* Global drop counter */
        u32 cnt_key = 0;
        u64 *cnt = bpf_map_lookup_elem(&drop_cnt, &cnt_key);
        if (cnt)
            *cnt += 1;

        /* Rate-limited ringbuf sample (dest_port=0: L3 drop, no port context) */
        u64 now = bpf_ktime_get_ns();
        u32 rl_key = 0;
        u64 *last_sample = bpf_map_lookup_elem(&rl_map, &rl_key);
        if (last_sample && (now - *last_sample) > SAMPLE_INTERVAL_NS) {
            *last_sample = now;
            struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
            if (e) {
                e->src_ip    = src_ip;
                e->dest_port = 0;
                e->reason    = REASON_BLACKLIST;
                bpf_ringbuf_submit(e, 0);
            } else {
                u32 rk = 0;
                u64 *rc = bpf_map_lookup_elem(&rb_fail_cnt, &rk);
                if (rc) *rc += 1;
            }
        }

        return XDP_DROP;
    }

    /* Non-TCP traffic passes (blacklist already handled above) */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    if (ip->ihl < 5)
        return XDP_PASS;

    struct tcphdr *tcp = (void*)ip + ip->ihl * 4;
    if ((void*)(tcp + 1) > data_end)
        return XDP_PASS;

    u16 dest_port = tcp->dest;
    if (bpf_map_lookup_elem(&ignored_ports, &dest_port))
        return XDP_PASS;

    if (tcp->syn && !tcp->ack) {
        /* Dynamic drop: SYN-only, populated by tcp_retransmit_synack tracepoint.
         * These IPs are only proven bad for half-open SYN abuse; they may have
         * legitimate established connections — so only SYNs are filtered. */
        struct drop_info *val = bpf_map_lookup_elem(&drop_ips, &src_ip);
        if (val) {
            val->last_seen = bpf_ktime_get_ns();
            __sync_fetch_and_add(&val->count, 1);

            u32 key = 0;
            u64 *cnt = bpf_map_lookup_elem(&drop_cnt, &key);
            if (cnt) *cnt += 1;

            /* Per-port drop counter (TCP port heatmap) */
            {
                u64 *port_cnt = bpf_map_lookup_elem(&port_drop_counts, &dest_port);
                if (port_cnt) {
                    __sync_fetch_and_add(port_cnt, 1);
                } else {
                    u64 one = 1;
                    bpf_map_update_elem(&port_drop_counts, &dest_port, &one, BPF_ANY);
                }
            }

            /* Rate-limited sample: at most one event per SAMPLE_INTERVAL_NS per CPU */
            {
                u64 now = bpf_ktime_get_ns();
                u32 rl_key = 0;
                u64 *last_sample = bpf_map_lookup_elem(&rl_map, &rl_key);
                if (last_sample && (now - *last_sample) > SAMPLE_INTERVAL_NS) {
                    *last_sample = now;
                    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
                    if (e) {
                        e->src_ip    = src_ip;
                        e->dest_port = bpf_ntohs(dest_port);
                        e->reason    = REASON_DYNAMIC;
                        bpf_ringbuf_submit(e, 0);
                    } else {
                        u32 rk = 0;
                        u64 *rc = bpf_map_lookup_elem(&rb_fail_cnt, &rk);
                        if (rc) *rc += 1;
                    }
                }
            }
            return XDP_DROP;
        }
    }
    /* No ACK-based clearing: spoofed ACKs would trivially evict entries
     * from drop_ips, letting subsequent SYNs bypass the filter.
     * Non-SYN TCP (ACK, data, FIN) passes unconditionally — only
     * SYN-without-ACK is filtered.  Blocked IPs expire naturally
     * via syn-intel's TTL heap. */

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
