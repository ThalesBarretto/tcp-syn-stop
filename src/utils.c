// SPDX-License-Identifier: GPL-2.0-only
/* ---------------------------------------------------------------------------
 * utils.c — CIDR arithmetic and IP parsing utilities.
 *
 * Shared between the daemon (config loading, ASN cache) and tests.
 * All functions are pure (no side effects, no global state).
 * ---------------------------------------------------------------------------*/

#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/*
 * range_to_cidr — find the largest aligned CIDR prefix within [start, end].
 *
 * Algorithm: XOR the endpoints to find the first differing bit; use
 * leading_zeros as the initial prefix length upper bound.  Narrow (plen++)
 * until the block is both aligned to start and fits within the range.
 *
 * Uses 64-bit arithmetic for block_last to prevent overflow when plen is
 * small (block_bits near 32 → block_last ≈ start + 2³² − 1 overflows u32).
 *
 * Correctness: terminates in ≤ 32 iterations; a /32 (single IP) always
 * satisfies both alignment and containment conditions.
 * Complexity: O(32) = O(1).
 */
__u32 range_to_cidr(__u32 start, __u32 end) {
    if (start == end) return 32;
    __u32 diff = start ^ end;
    __u32 plen = __builtin_clz(diff);

    /* Narrow the prefix until the block is aligned to `start` and fits
     * within [start, end].  Use 64-bit arithmetic for the block-end
     * calculation so that large blocks (plen near 0) don't overflow. */
    while (plen < 32) {
        __u32 block_bits = 32 - plen;
        __u32 mask = (block_bits == 32) ? 0 : ~((1U << block_bits) - 1);
        __u64 block_last = (__u64)start + ((1ULL << block_bits) - 1);
        if ((start & mask) == start && block_last <= (__u64)end)
            break;
        plen++;
    }
    return plen;
}

int parse_cidr(const char *cidr_str, struct lpm_key *key) {
    char buf[64];
    char *ip_part, *mask_part;
    struct in_addr addr;

    if (strlen(cidr_str) >= sizeof(buf)) {
        return -EINVAL;
    }
    snprintf(buf, sizeof(buf), "%s", cidr_str);

    ip_part = buf;
    mask_part = strchr(buf, '/');

    if (mask_part) {
        *mask_part = '\0';
        mask_part++;
        char *endptr;
        errno = 0;
        long plen = strtol(mask_part, &endptr, 10);
        if (errno != 0 || endptr == mask_part || *endptr != '\0' || plen < 0 || plen > 32) {
            return -EINVAL;
        }
        key->prefixlen = (__u32)plen;
    } else {
        key->prefixlen = 32;
    }

    if (inet_pton(AF_INET, ip_part, &addr) != 1) {
        return -EINVAL;
    }

    /* Validation logic equivalent to Python strict=True */
    if (key->prefixlen == 0) {
        return -EINVAL;
    }

    /* Reject entries with host bits set (strict=True equivalent).
     * Catches mistakes like "1.2.3.4/24" silently expanding to "1.2.3.0/24". */
    __u32 host_mask = (key->prefixlen < 32) ? (0xFFFFFFFF >> key->prefixlen) : 0;
    if (ntohl(addr.s_addr) & host_mask) {
        return -EINVAL;
    }

    key->ip = addr.s_addr;
    return 0;
}
