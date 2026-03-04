// SPDX-License-Identifier: GPL-2.0-only
/* ---------------------------------------------------------------------------
 * logging.c — log output, signal handling, sd_notify, and rate limiting.
 *
 * Provides log_msg() (console or syslog), signal handlers for graceful
 * shutdown (SIGINT/SIGTERM → exiting) and config reload (SIGHUP →
 * reload_requested), lightweight sd_notify (avoids libsystemd dep),
 * and a token-bucket rate limiter for high-frequency log paths.
 *
 * Threading: exiting and reload_requested are _Atomic bool, safe for
 * signal delivery from any context.  All other state is main-thread only.
 * ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bpf/libbpf.h>
#include "compiler.h"
#include "logging.h"

bool verbose = false;
bool use_syslog = false;
_Atomic bool exiting = false;
_Atomic bool reload_requested = false;

void sig_handler(int sig) {
    if (sig == SIGHUP) {
        reload_requested = true;
    } else {
        exiting = true;
    }
}

void log_msg(enum log_level level, const char *fmt, ...) {
    va_list args;

    if (level == LEVEL_DEBUG && !verbose) return;

    if (use_syslog) {
        /* Route to syslog only when running under systemd (no TTY, no -l logfile).
         * use_syslog is set before any stdout redirect so isatty() is reliable. */
        int syslog_level;
        switch (level) {
            case LEVEL_DEBUG: syslog_level = LOG_DEBUG;   break;
            case LEVEL_INFO:  syslog_level = LOG_INFO;    break;
            case LEVEL_WARN:  syslog_level = LOG_WARNING; break;
            case LEVEL_ERROR: syslog_level = LOG_ERR;     break;
            default:          syslog_level = LOG_INFO;    break;
        }
        va_start(args, fmt);
        vsyslog(syslog_level, fmt, args);
        va_end(args);
        return;
    }

    /* Standard console output with timestamps */
    time_t now;
    struct tm tm_info;
    char time_str[24];
    const char *level_str;

    time(&now);
    localtime_r(&now, &tm_info);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_info);

    switch (level) {
        case LEVEL_DEBUG: level_str = "DEBUG"; break;
        case LEVEL_INFO:  level_str = "INFO";  break;
        case LEVEL_WARN:  level_str = "WARN";  break;
        case LEVEL_ERROR: level_str = "ERROR"; break;
        default:          level_str = "UNK";   break;
    }

    printf("[%s] [%s] ", time_str, level_str);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

/* Lightweight manual sd_notify implementation to avoid libsystemd dependency.
 * The socket is lazily opened on first use and cached for the daemon's lifetime.
 * sd_notify_fd states: -1 = uninitialised, -2 = unavailable/failed, ≥0 = open. */
static int sd_notify_fd = -1;

static void sd_notify_send(const char *msg) {
    if (sd_notify_fd == -2) return;    /* known unavailable */

    if (sd_notify_fd == -1) {
        const char *notify_path = getenv("NOTIFY_SOCKET");
        if (!notify_path) { sd_notify_fd = -2; return; }

        sd_notify_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (sd_notify_fd < 0) { sd_notify_fd = -2; return; }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, notify_path, sizeof(addr.sun_path) - 1);
        if (addr.sun_path[0] == '@') addr.sun_path[0] = '\0';

        if (connect(sd_notify_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(sd_notify_fd);
            sd_notify_fd = -2;
            return;
        }
    }

    send(sd_notify_fd, msg, strlen(msg), MSG_NOSIGNAL);
}

/* Called once after full startup: tells systemd the service is ready. */
void sd_notify_ready(void)     { sd_notify_send("READY=1"); }

/* Called every main loop iteration: resets the watchdog timer. */
void sd_notify_heartbeat(void) { sd_notify_send("WATCHDOG=1"); }

/* Close the cached sd_notify socket (called from the cleanup path). */
void sd_notify_cleanup(void) {
    if (sd_notify_fd >= 0) {
        close(sd_notify_fd);
        sd_notify_fd = -1;
    }
}

/*
 * should_ratelimit — token-bucket rate limiter for log output.
 *
 * Parameters: burst capacity = 50 tokens, refill rate = 10 tokens/s.
 * Steady-state: allows 10 log messages per second.  Burst: up to 50
 * messages in rapid succession before throttling.  Returns true if the
 * caller should suppress output; false if a token was consumed.
 *
 * The suppressed counter tracks how many calls were rate-limited since
 * the last successful log, allowing "N messages suppressed" reporting.
 * Complexity: O(1).
 * Threading: Main thread only (rl is not shared).
 */
bool should_ratelimit(struct ratelimit *rl) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    double now = (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;

    if (unlikely(rl->last_ts == 0)) {
        rl->last_ts = now;
        rl->tokens = 50.0;
    }

    /* Refill tokens: 10 per second, max 50 */
    double elapsed = now - rl->last_ts;
    rl->tokens += elapsed * 10.0;
    if (rl->tokens > 50.0) rl->tokens = 50.0;
    rl->last_ts = now;

    if (rl->tokens >= 1.0) {
        rl->tokens -= 1.0;
        return false;
    } else {
        rl->suppressed++;
        return true;
    }
}

__u64 get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int libbpf_print_fn(enum libbpf_print_level blevel, const char *format, va_list args) {
    if (blevel == LIBBPF_DEBUG && !verbose)
        return 0;

    char buf[1024];
    vsnprintf(buf, sizeof(buf), format, args);

    /* Remove trailing newline if it exists; log_msg will add one */
    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';

    if (blevel == LIBBPF_WARN) {
        log_msg(LEVEL_WARN, "%s", buf);
    } else if (blevel == LIBBPF_INFO) {
        log_msg(LEVEL_INFO, "%s", buf);
    } else {
        log_msg(LEVEL_DEBUG, "%s", buf);
    }
    return 0;
}
