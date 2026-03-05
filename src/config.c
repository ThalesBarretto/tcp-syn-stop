// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <nftables/libnftables.h>
#include "logging.h"
#include "utils.h"
#include "config.h"

#define MAX_CONFIG_ENTRIES  131072
#define MAX_MAP_ENTRIES     131072  /* mirror of BPF-side MAX_ENTRIES_BLACKLIST */
/* "255.255.255.255/32" = 18 chars + ", " separator = 20 chars per entry */
#define ELEMENTS_BUF_SIZE  (MAX_CONFIG_ENTRIES * 20 + 1)

static bool is_valid_nft_set_name(const char *name) {
    if (!name || *name == '\0')
        return false;
    for (const char *p = name; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-')
            return false;
    }
    return true;
}

/*
 * clear_bpf_map — two-pass collect-then-delete to clear a BPF LPM trie.
 *
 * BPF map iterators are invalidated by bpf_map_delete_elem(); deleting
 * during iteration causes missed keys or double-visits.  Phase 1 collects
 * all keys into a heap-allocated array; Phase 2 deletes them after iteration ends.
 * Complexity: O(n) where n = map entries.
 * Threading: Main thread only (called during config reload under SIGHUP).
 */
static void clear_bpf_map(int fd) {
    struct lpm_key *keys = malloc(MAX_MAP_ENTRIES * sizeof(*keys));
    if (!keys) {
        log_msg(LEVEL_ERROR, "OOM: could not allocate key buffer for map clear");
        return;
    }
    struct lpm_key cur_key, next_key;
    bool first = true;
    int count = 0;

    /* Phase 1: Collect all keys (whitelist/blacklist ≤ 131072 entries). */
    // cppcheck-suppress uninitvar ; cur_key is guarded by `first ? NULL : &cur_key`
    while (bpf_map_get_next_key(fd, first ? NULL : &cur_key, &next_key) == 0) {
        first = false;
        if (count < MAX_MAP_ENTRIES) {
            keys[count++] = next_key;
        }
        cur_key = next_key;
    }

    /* Phase 2: Delete keys */
    for (int i = 0; i < count; i++) {
        bpf_map_delete_elem(fd, &keys[i]);
    }

    free(keys);
}

void purge_whitelisted_drop_ips(int drop_ips_fd, int whitelist_fd)
{
    __u32 key, next_key;
    int purged = 0;
    bool first = true;

    /* Iterate the LRU hash using get-next-before-delete: read the
     * successor key before deleting the current one.  Safe for hash
     * maps (iteration order is unaffected by deletes of earlier keys). */
    // cppcheck-suppress uninitvar ; key is guarded by `first ? NULL : &key`
    while (bpf_map_get_next_key(drop_ips_fd, first ? NULL : &key, &next_key) == 0) {
        first = false;
        key = next_key;

        struct lpm_key wkey = { .prefixlen = 32, .ip = key };
        __u8 val;
        if (bpf_map_lookup_elem(whitelist_fd, &wkey, &val) == 0) {
            bpf_map_delete_elem(drop_ips_fd, &key);
            purged++;
        }
    }

    if (purged > 0)
        log_msg(LEVEL_INFO, "Purged %d whitelisted IP(s) from drop_ips", purged);
}

void load_config_file(const char *filename, int map_fd, const char *nft_set_name) {
    if (!is_valid_nft_set_name(nft_set_name)) {
        log_msg(LEVEL_ERROR, "Invalid nftables set name rejected: '%s'", nft_set_name);
        return;
    }

    FILE *f = fopen(filename, "r");
    if (!f) {
        if (errno != ENOENT) log_msg(LEVEL_ERROR, "Failed to open %s: %s", filename, strerror(errno));
        return;
    }

    /* Phase 1: Parse the entire file into a validated entries array.
     * No BPF maps or nftables are touched until all entries have been
     * parsed and validated; the subsequent phases operate solely on the
     * lpm_key structs — no raw file content reaches the shell. */
    struct lpm_key *entries = malloc(MAX_CONFIG_ENTRIES * sizeof(*entries));
    if (!entries) {
        log_msg(LEVEL_ERROR, "OOM: could not allocate config entry buffer");
        fclose(f);
        return;
    }
    int count = 0;
    char *line = NULL;
    size_t len = 0;

    while (getline(&line, &len, f) != -1) {
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';

        char *start = line;
        while (isspace(*start)) start++;
        char *end = start + strlen(start) - 1;
        while (end > start && isspace(*end)) { *end = '\0'; end--; }

        if (*start == '\0') continue;

        if (count >= MAX_CONFIG_ENTRIES) {
            log_msg(LEVEL_WARN, "Warning: %s exceeds %d entry limit, ignoring remaining entries",
                    filename, MAX_CONFIG_ENTRIES);
            break;
        }

        if (parse_cidr(start, &entries[count]) == 0) {
            if (entries[count].prefixlen < 8) {
                log_msg(LEVEL_WARN, "Warning: Very broad prefix detected: %s", start);
            }
            count++;
        } else {
            log_msg(LEVEL_ERROR, "Error: Invalid CIDR in %s: %s", filename, start);
        }
    }

    free(line);
    fclose(f);

    /* Phase 2: Load all validated structs into the BPF map.
     * Track failures so Phase 3 (nftables) stays in sync — if BPF updates
     * fail, skip the nftables sync to avoid a split-brain state. */
    clear_bpf_map(map_fd);
    int bpf_errors = 0;
    for (int i = 0; i < count; i++) {
        __u8 val = 1;
        if (bpf_map_update_elem(map_fd, &entries[i], &val, BPF_ANY) != 0) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &entries[i].ip, ip_str, sizeof(ip_str));
            log_msg(LEVEL_ERROR, "Failed to update BPF map with %s/%u",
                    ip_str, entries[i].prefixlen);
            bpf_errors++;
        }
    }
    if (bpf_errors > 0) {
        log_msg(LEVEL_ERROR, "BPF map update had %d errors — skipping nftables sync to prevent split state",
                bpf_errors);
        free(entries);
        return;
    }

    /* Phase 3: Build the nftables element list from validated structs and sync
     * via libnftables — no shell subprocess, errors surface through log_msg.
     * Canonical strings are derived from lpm_key fields (integers), so only
     * decimal digits, dots, and a slash can appear — no injection is possible. */
    char *elements_buf = malloc(ELEMENTS_BUF_SIZE);
    if (!elements_buf) {
        log_msg(LEVEL_ERROR, "OOM: could not allocate nftables element buffer");
        free(entries);
        return;
    }
    int off = 0;

    for (int i = 0; i < count; i++) {
        char ip_str[INET_ADDRSTRLEN], canonical[24];
        inet_ntop(AF_INET, &entries[i].ip, ip_str, sizeof(ip_str));
        snprintf(canonical, sizeof(canonical), "%s/%u", ip_str, entries[i].prefixlen);
        log_msg(LEVEL_INFO, "%s: Loaded %s", nft_set_name, canonical);
        if (i > 0) {
            off += snprintf(elements_buf + off, ELEMENTS_BUF_SIZE - off, ", ");
            if (off >= ELEMENTS_BUF_SIZE) off = ELEMENTS_BUF_SIZE - 1;
        }
        off += snprintf(elements_buf + off, ELEMENTS_BUF_SIZE - off, "%s", canonical);
        if (off >= ELEMENTS_BUF_SIZE) off = ELEMENTS_BUF_SIZE - 1;
    }

    /* nft flush + add; cmd must accommodate the full elements_buf */
    size_t cmd_sz = ELEMENTS_BUF_SIZE + 128;
    char *cmd = malloc(cmd_sz);
    if (!cmd) {
        log_msg(LEVEL_ERROR, "OOM: could not allocate nftables command buffer");
        free(entries);
        free(elements_buf);
        return;
    }

    struct nft_ctx *nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft) {
        log_msg(LEVEL_ERROR, "load_config_file: failed to create libnftables context");
        free(entries);
        free(elements_buf);
        free(cmd);
        return;
    }
    nft_ctx_buffer_error(nft);

    snprintf(cmd, cmd_sz, "flush set inet filter %s", nft_set_name);
    if (nft_run_cmd_from_buffer(nft, cmd) != 0)
        log_msg(LEVEL_DEBUG, "nft flush set '%s': %s",
                nft_set_name, nft_ctx_get_error_buffer(nft));

    if (count > 0) {
        snprintf(cmd, cmd_sz, "add element inet filter %s { %s }",
                 nft_set_name, elements_buf);
        if (nft_run_cmd_from_buffer(nft, cmd) != 0)
            log_msg(LEVEL_WARN, "nft add element to '%s' failed: %s",
                    nft_set_name, nft_ctx_get_error_buffer(nft));
        else
            log_msg(LEVEL_INFO, "Synced %d entries to nftables set '%s'",
                    count, nft_set_name);
    } else {
        log_msg(LEVEL_INFO, "Flushed nftables set '%s' (empty config)", nft_set_name);
    }

    nft_ctx_free(nft);
    free(entries);
    free(elements_buf);
    free(cmd);
}
