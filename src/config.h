// SPDX-License-Identifier: GPL-2.0-only
#ifndef CONFIG_H
#define CONFIG_H

/* Load a CIDR list from filename into the BPF LPM-trie map at map_fd and
 * sync the same entries into the nftables set named nft_set_name.
 * Three-phase: parse → BPF map → nftables; no raw file content reaches
 * either subsystem. */
void load_config_file(const char *filename, int map_fd, const char *nft_set_name);

/* After a whitelist reload, sweep drop_ips and delete any entries that
 * now match the whitelist LPM trie — otherwise whitelisted IPs stay
 * blocked until TTL expiry. */
void purge_whitelisted_drop_ips(int drop_ips_fd, int whitelist_fd);

#endif /* CONFIG_H */
