// SPDX-License-Identifier: GPL-2.0-only
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <grp.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf_version.h>
#include "logging.h"
#include "bpf_loader.h"

#if LIBBPF_MAJOR_VERSION < 1
#error "tcp_syn_stop requires libbpf >= 1.0 (bpf_program__attach_xdp returns NULL on error)"
#endif

int bpf_loader_attach_xdp(struct tcp_syn_stop_bpf *skel, struct iface_state *iface) {
    int ifindex = (int)if_nametoindex(iface->name);
    if (ifindex == 0) {
        log_msg(LEVEL_ERROR, "Invalid interface: %s", iface->name);
        return -1;
    }

    iface->native = true;

    /* First try attaching in Driver (Native) mode.
     * libbpf >= 1.0: bpf_program__attach_xdp returns NULL on error. */
    iface->link = bpf_program__attach_xdp(skel->progs.xdp_drop_spoofed_syns, ifindex);

    if (!iface->link) { /* libbpf >= 1.0: NULL on error */
        /* If native auto-attach fails, fall back to generic (SKB) mode */
        int prog_fd = bpf_program__fd(skel->progs.xdp_drop_spoofed_syns);
        int err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (err) {
            log_msg(LEVEL_ERROR,
                    "Failed to attach XDP to %s (even in generic mode): %d", iface->name, err);
            return -1;
        }
        iface->native = false;
        log_msg(LEVEL_WARN,
                "WARNING: Attached XDP in generic (SKB) mode to %s. CPU overhead will be high.",
                iface->name);
    }

    /* Record program ID for liveness monitoring */
    iface->prog_id = 0;
    struct bpf_prog_info prog_info = {};
    __u32 info_len = sizeof(prog_info);
    int prog_fd = bpf_program__fd(skel->progs.xdp_drop_spoofed_syns);
    if (bpf_obj_get_info_by_fd(prog_fd, &prog_info, &info_len) == 0)
        iface->prog_id = prog_info.id;

    return 0;
}

bool bpf_loader_check_liveness(struct tcp_syn_stop_bpf *skel, struct iface_state *iface) {
    if (iface->prog_id == 0)
        return false;

    int ifindex = (int)if_nametoindex(iface->name);
    if (ifindex == 0)
        return false;

    struct bpf_xdp_query_opts qopts = { .sz = sizeof(qopts) };
    /* Query the same slot we attached to: SKB mode uses XDP_FLAGS_SKB_MODE,
     * native mode uses 0.  Querying the wrong slot always returns
     * prog_id==0, which would trigger a spurious re-attach every tick. */
    __u32 query_flags = iface->native ? 0 : XDP_FLAGS_SKB_MODE;

    if (bpf_xdp_query(ifindex, (int)query_flags, &qopts) != 0 ||
            qopts.prog_id == iface->prog_id)
        return false;

    log_msg(LEVEL_WARN,
            "XDP program detached from %s (expected id=%u, active id=%u). Re-attaching...",
            iface->name, iface->prog_id, qopts.prog_id);

    if (iface->native) {
        /* Native mode: destroy stale link then re-attach */
        bpf_link__destroy(iface->link);
        iface->link = NULL;
        iface->link = bpf_program__attach_xdp(skel->progs.xdp_drop_spoofed_syns, ifindex);
        if (!iface->link)
            log_msg(LEVEL_ERROR, "XDP re-attach (native) failed.");
        else
            log_msg(LEVEL_INFO, "XDP re-attached to %s in native mode.", iface->name);
    } else {
        /* SKB mode: bpf_xdp_attach replaces any existing attachment */
        int prog_fd = bpf_program__fd(skel->progs.xdp_drop_spoofed_syns);
        if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) == 0)
            log_msg(LEVEL_INFO, "XDP re-attached to %s in generic mode.", iface->name);
        else
            log_msg(LEVEL_ERROR, "XDP re-attach (generic) failed.");
    }

    return true;
}

int bpf_loader_pin_maps(struct tcp_syn_stop_bpf *skel) {
    struct {
        struct bpf_map *map;
        const char     *name;
    } maps[] = {
        { skel->maps.drop_ips,      "drop_ips"      },
        { skel->maps.blacklist_cnt, "blacklist_cnt"  },
        { skel->maps.whitelist,     "whitelist"      },
        { skel->maps.blacklist,     "blacklist"      },
        { skel->maps.ignored_ports, "ignored_ports"  },
        { skel->maps.drop_cnt,      "drop_cnt"       },
        { skel->maps.rb_fail_cnt,   "rb_fail_cnt"    },
        { skel->maps.rb,              "rb"               },
        { skel->maps.port_drop_counts, "port_drop_counts" },
    };
    int n = (int)(sizeof(maps) / sizeof(maps[0]));

    if (mkdir(BPF_PIN_BASE_DIR, 0750) != 0 && errno != EEXIST) {
        log_msg(LEVEL_ERROR, "mkdir %s: %s", BPF_PIN_BASE_DIR, strerror(errno));
        return -errno;
    }

    for (int i = 0; i < n; i++) {
        char path[128];
        snprintf(path, sizeof(path), "%s/%s", BPF_PIN_BASE_DIR, maps[i].name);

        if (unlink(path) == 0)
            log_msg(LEVEL_DEBUG, "Removed stale BPF pin %s", path);
        else if (errno != ENOENT) {
            log_msg(LEVEL_ERROR, "unlink %s: %s", path, strerror(errno));
            return -errno;
        }

        int ret = bpf_map__set_pin_path(maps[i].map, path);
        if (ret) {
            log_msg(LEVEL_ERROR, "bpf_map__set_pin_path(%s): %s",
                    maps[i].name, strerror(-ret));
            return ret;
        }
    }

    return 0;
}

int bpf_loader_fix_map_permissions(void) {
    struct group *grp = getgrnam("tcp_syn_stop");
    if (!grp) {
        log_msg(LEVEL_WARN, "group tcp_syn_stop not found — "
                "syn-intel may not be able to read pinned maps");
        return 0; /* non-fatal: single-user setups run as root */
    }
    gid_t gid = grp->gr_gid;

    /* chgrp + chmod the pin directory itself */
    if (chown(BPF_PIN_BASE_DIR, (uid_t)-1, gid) != 0)
        log_msg(LEVEL_WARN, "chown %s: %s", BPF_PIN_BASE_DIR, strerror(errno));
    if (chmod(BPF_PIN_BASE_DIR, 0750) != 0)
        log_msg(LEVEL_WARN, "chmod %s: %s", BPF_PIN_BASE_DIR, strerror(errno));

    /* chgrp + chmod each pinned map file */
    DIR *dir = opendir(BPF_PIN_BASE_DIR);
    if (!dir) {
        log_msg(LEVEL_WARN, "opendir %s: %s", BPF_PIN_BASE_DIR, strerror(errno));
        return 0;
    }
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.')
            continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", BPF_PIN_BASE_DIR, ent->d_name);
        if (chown(path, (uid_t)-1, gid) != 0)
            log_msg(LEVEL_WARN, "chown %s: %s", path, strerror(errno));
        if (chmod(path, 0640) != 0)
            log_msg(LEVEL_WARN, "chmod %s: %s", path, strerror(errno));
    }
    closedir(dir);
    return 0;
}

void bpf_loader_unpin_maps(struct tcp_syn_stop_bpf *skel) {
    int ret = bpf_object__unpin_maps(skel->obj, NULL);
    if (ret)
        log_msg(LEVEL_WARN, "bpf_object__unpin_maps: %s", strerror(-ret));

    if (rmdir(BPF_PIN_BASE_DIR) != 0 && errno != ENOENT && errno != ENOTEMPTY)
        log_msg(LEVEL_WARN, "rmdir %s: %s", BPF_PIN_BASE_DIR, strerror(errno));
}
