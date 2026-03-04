// SPDX-License-Identifier: GPL-2.0-only
#ifndef LOGGING_H
#define LOGGING_H

#include <stdbool.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <linux/types.h>
#include <bpf/libbpf.h>

enum log_level {
    LEVEL_DEBUG,
    LEVEL_INFO,
    LEVEL_WARN,
    LEVEL_ERROR
};

struct ratelimit {
    double tokens;
    double last_ts;
    int suppressed;
};

extern bool verbose;
extern bool use_syslog;
extern _Atomic bool exiting;
extern _Atomic bool reload_requested;

__attribute__((format(printf, 2, 3)))
void log_msg(enum log_level level, const char *fmt, ...);
bool should_ratelimit(struct ratelimit *rl);
__u64 get_time_ns(void);

void sig_handler(int sig);
void sd_notify_ready(void);
void sd_notify_heartbeat(void);
void sd_notify_cleanup(void);

int libbpf_print_fn(enum libbpf_print_level blevel, const char *format, va_list args);

#endif /* LOGGING_H */
