// SPDX-License-Identifier: GPL-2.0-only
#ifndef UTILS_H
#define UTILS_H

#include <linux/types.h>
#include <stdbool.h>
#include <arpa/inet.h>

/* Define the LPM Trie Key struct to match the kernel side */
struct lpm_key {
    __u32 prefixlen;
    __u32 ip;
};

/* Find the largest CIDR block that fits the range (start_ip, end_ip)
 * Returns the prefix length (0-32). */
__attribute__((const))
__u32 range_to_cidr(__u32 start, __u32 end);

/* Parse CIDR string (e.g. "1.2.3.0/24") into lpm_key.
 * Returns 0 on success, -EINVAL on error. */
__attribute__((warn_unused_result))
int parse_cidr(const char *cidr_str, struct lpm_key *key);

#endif /* UTILS_H */
