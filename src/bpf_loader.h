// SPDX-License-Identifier: GPL-2.0-only
#ifndef BPF_LOADER_H
#define BPF_LOADER_H

#include <stdbool.h>
#include <linux/types.h>
#include "tcp_syn_stop.skel.h"

/* Value stored in the drop_ips LRU map */
struct drop_info {
    __u64 last_seen;
    __u64 count;
};

/* Ringbuf event emitted by the BPF programs */
struct event {
    __u32 src_ip;
    __u16 dest_port;
    __u8  reason;
};

#define REASON_BLACKLIST  1
#define REASON_DYNAMIC    2
#define REASON_NEW_BLOCK  3

/* Maximum number of network interfaces the daemon can protect simultaneously. */
#define MAX_IFACES 8

struct iface_state {
    char name[16];
    unsigned int prog_id;
    bool native;
    struct bpf_link *link;
};

/* Attach the XDP program to the interface described by iface, trying native
 * mode first and falling back to generic (SKB) mode.  Populates iface->prog_id,
 * iface->native, and iface->link. Returns 0 on success. */
__attribute__((cold, warn_unused_result))
int bpf_loader_attach_xdp(struct tcp_syn_stop_bpf *skel, struct iface_state *iface);

/* Query whether our XDP program is still attached to iface->name.  If it was 
 * detached by an external agent, re-attach it.  Returns true if a re-attach 
 * was performed. */
bool bpf_loader_check_liveness(struct tcp_syn_stop_bpf *skel, struct iface_state *iface);

/* Base directory for BPF map pin paths on bpffs. */
#define BPF_PIN_BASE_DIR "/sys/fs/bpf/tcp_syn_stop"

/* Set pin paths on all BPF maps (call between __open and __load).
 * Removes stale pins from a previous crash, then sets pin_path on each
 * map so libbpf auto-pins during __load().  Returns 0 or -errno. */
__attribute__((cold, warn_unused_result))
int bpf_loader_pin_maps(struct tcp_syn_stop_bpf *skel);

/* After bpf_object__load() pins the maps, fix group ownership so that
 * the _syn_intel user (in group tcp_syn_stop) can read them.  Call once
 * after __load() succeeds.  Returns 0 (warnings are logged, not fatal). */
__attribute__((cold))
int bpf_loader_fix_map_permissions(void);

/* Unpin all BPF maps (clean shutdown).  Errors are logged, not fatal. */
__attribute__((cold))
void bpf_loader_unpin_maps(struct tcp_syn_stop_bpf *skel);

#endif /* BPF_LOADER_H */
