// SPDX-License-Identifier: GPL-2.0-only
/*
 * tcp_syn_stop — XDP SYN flood protection daemon (BPF loader)
 *
 * Minimal daemon that loads, pins, and monitors eBPF programs.
 * Policy logic (TTL expiry, autoban, telemetry, persistence) lives in
 * syn-intel; this binary is responsible only for:
 *   - Loading the BPF skeleton and pinning maps to bpffs
 *   - Attaching XDP to interfaces, monitoring liveness
 *   - Reloading whitelist/blacklist on SIGHUP
 *   - sd_notify integration for systemd watchdog
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <syslog.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "logging.h"
#include "config.h"
#include "bpf_loader.h"
#include "tcp_syn_stop.skel.h"

/* Main-loop timing intervals (seconds) */
#define LIVENESS_TICK_SEC    5   /* XDP liveness check              */
#define RELOAD_MIN_INTERVAL 30   /* minimum gap between SIGHUP reloads */

#define PID_PATH "/run/tcp_syn_stop/tcp_syn_stop.pid"

static void drop_capabilities(void) {
    cap_value_t keep[] = { CAP_BPF, CAP_NET_ADMIN };
    cap_t caps = cap_init();
    if (!caps) {
        log_msg(LEVEL_WARN, "cap_init failed");
        return;
    }

    cap_set_flag(caps, CAP_PERMITTED, 2, keep, CAP_SET);
    cap_set_flag(caps, CAP_EFFECTIVE, 2, keep, CAP_SET);

    if (cap_set_proc(caps) != 0)
        log_msg(LEVEL_WARN, "cap_set_proc failed: %m");
    else
        log_msg(LEVEL_INFO, "Dropped to CAP_BPF + CAP_NET_ADMIN");

    cap_free(caps);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        log_msg(LEVEL_WARN, "prctl(NO_NEW_PRIVS) failed: %m");
}

static void install_signal(int signo, void (*handler)(int)) {
    struct sigaction sa = {
        .sa_handler = handler,
        .sa_flags   = SA_RESTART,
    };
    sigemptyset(&sa.sa_mask);
    if (sigaction(signo, &sa, NULL) != 0) {
        perror("sigaction");
        exit(1);
    }
}

int main(int argc, char **argv) {
    struct tcp_syn_stop_bpf *skel;
    int err = 0;
    int opt;
    int whitelist_fd, blacklist_fd, drop_ips_fd;

    /* Configuration defaults */
    char *interfaces[MAX_IFACES];
    int iface_count     = 0;
    char *whitelist_file = "/etc/tcp_syn_stop/whitelist.conf";
    char *blacklist_file = "/etc/tcp_syn_stop/blacklist.conf";
    char *logfile       = NULL;

    static struct option long_options[] = {
        {"interface",  required_argument, 0, 'i'},
        {"whitelist",  required_argument, 0, 'w'},
        {"blacklist",  required_argument, 0, 'b'},
        {"logfile",    required_argument, 0, 'l'},
        {"verbose",    no_argument,       0, 'v'},
        {"version",    no_argument,       0, 'V'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "i:w:b:l:vVh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                if (iface_count < MAX_IFACES) {
                    interfaces[iface_count++] = optarg;
                } else {
                    fprintf(stderr, "Error: Maximum of %d interfaces supported\n", MAX_IFACES);
                    return 1;
                }
                break;
            case 'w': whitelist_file = optarg; break;
            case 'b': blacklist_file = optarg; break;
            case 'l': logfile        = optarg; break;
            case 'v': verbose        = true;   break;
            case 'V':
                printf("tcp_syn_stop %s (%s)\n", APP_VERSION, GIT_HASH);
                return 0;
            case 'h':
                printf(
                    "Usage: %s [OPTIONS]\n\n"
                    "Options:\n"
                    "  -i, --interface <iface>   Network interface to protect (may be repeated, max %d)\n"
                    "  -w, --whitelist <file>    Path to whitelist.conf\n"
                    "  -b, --blacklist <file>    Path to blacklist.conf\n"
                    "  -l, --logfile <file>      Path to log file (default: stdout)\n"
                    "  -v, --verbose             Enable debug logging and libbpf output\n"
                    "  -V, --version             Print version and exit\n"
                    "  -h, --help                Show this help message\n",
                    argv[0], MAX_IFACES);
                return 0;
            default:
                fprintf(stderr, "Error: Unknown option. Run '%s --help' for usage.\n", argv[0]);
                return 1;
        }
    }

    if (iface_count == 0) {
        fprintf(stderr, "Error: At least one interface must be specified with -i\n");
        return 1;
    }

    openlog("tcp_syn_stop", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    /* Set up libbpf logging callback */
    libbpf_set_print(libbpf_print_fn);

    /* Handle signals — sigaction() for portable, well-defined semantics */
    install_signal(SIGINT,  sig_handler);
    install_signal(SIGTERM, sig_handler);
    install_signal(SIGHUP,  sig_handler);
    install_signal(SIGPIPE, SIG_IGN);

    /* Decide syslog routing before any stdout redirect so isatty() is reliable. */
    use_syslog = (logfile == NULL) && !isatty(STDOUT_FILENO);

    /* Redirect output to logfile if requested */
    if (logfile) {
        FILE *f = freopen(logfile, "a", stdout);
        if (!f) {
            perror("Failed to redirect stdout to logfile");
            return 1;
        }
        setvbuf(stdout, NULL, _IOLBF, 0);
    }

    /* Open BPF application */
    skel = tcp_syn_stop_bpf__open();
    if (!skel) {
        log_msg(LEVEL_ERROR, "Failed to open BPF skeleton");
        return 1;
    }

    /* Pin BPF maps to bpffs so external tools can access them */
    err = bpf_loader_pin_maps(skel);
    if (err) {
        log_msg(LEVEL_ERROR, "Failed to configure BPF map pinning");
        goto cleanup;
    }

    /* Load & verify BPF programs */
    err = tcp_syn_stop_bpf__load(skel);
    if (err) {
        log_msg(LEVEL_ERROR, "Failed to load and verify BPF skeleton");
        goto cleanup;
    }

    /* Fix pinned map permissions so syn-intel (tcp_syn_stop group) can read them */
    bpf_loader_fix_map_permissions();

    /* Get map FDs for config reload */
    whitelist_fd = bpf_map__fd(skel->maps.whitelist);
    blacklist_fd = bpf_map__fd(skel->maps.blacklist);
    drop_ips_fd  = bpf_map__fd(skel->maps.drop_ips);

    /* Load configuration files */
    load_config_file(whitelist_file, whitelist_fd, "trusted_sources");
    load_config_file(blacklist_file, blacklist_fd, "blacklisted_sources");

    /* Interface state (replaces engine_ctx.ifaces) */
    struct iface_state ifaces[MAX_IFACES];
    memset(ifaces, 0, sizeof(ifaces));

    /* Attach XDP to all interfaces */
    for (int i = 0; i < iface_count; i++) {
        snprintf(ifaces[i].name, sizeof(ifaces[i].name), "%s", interfaces[i]);
        if (bpf_loader_attach_xdp(skel, &ifaces[i]) != 0) {
            log_msg(LEVEL_ERROR, "Failed to protect interface %s", interfaces[i]);
            err = -1;
            goto cleanup;
        }
    }

    /* Attach tracepoint */
    err = tcp_syn_stop_bpf__attach(skel);
    if (err) {
        log_msg(LEVEL_ERROR, "Failed to attach BPF skeleton (tracepoint)");
        goto cleanup;
    }

    log_msg(LEVEL_INFO, "Successfully loaded and attached BPF programs to %d interfaces.", iface_count);

    sd_notify_ready();

    /* Write PID file so syn-intel can forward SIGHUP to us */
    {
        FILE *pf = fopen(PID_PATH, "w");
        if (pf) { fprintf(pf, "%d\n", getpid()); fclose(pf); }
    }

    drop_capabilities();

    /* -------------------------------------------------------------------
     * Main loop — BPF loader heartbeat
     * ---------------------------------------------------------------- */
    while (!exiting) {
        sd_notify_heartbeat();

        if (reload_requested) {
            static time_t last_reload = 0;
            static bool   rate_warned = false;
            time_t now_reload = time(NULL);
            if (last_reload > 0 && (now_reload - last_reload) < RELOAD_MIN_INTERVAL) {
                if (!rate_warned) {
                    log_msg(LEVEL_WARN, "SIGHUP rate-limited: next reload allowed in %lds",
                            (long)(RELOAD_MIN_INTERVAL - (now_reload - last_reload)));
                    rate_warned = true;
                }
            } else {
                log_msg(LEVEL_INFO, "SIGHUP received, reloading configuration...");
                load_config_file(whitelist_file, whitelist_fd, "trusted_sources");
                purge_whitelisted_drop_ips(drop_ips_fd, whitelist_fd);
                load_config_file(blacklist_file, blacklist_fd, "blacklisted_sources");
                reload_requested = false;
                last_reload  = now_reload;
                rate_warned  = false;
            }
        }

        for (int i = 0; i < iface_count; i++)
            bpf_loader_check_liveness(skel, &ifaces[i]);

        sleep(LIVENESS_TICK_SEC);
    }

cleanup:
    sd_notify_cleanup();
    unlink(PID_PATH);
    bpf_loader_unpin_maps(skel);
    tcp_syn_stop_bpf__destroy(skel);
    closelog();
    return -err;
}
