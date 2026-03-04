// SPDX-License-Identifier: GPL-2.0-only
/*
 * bench.c — Micro-benchmark harness for core data structures.
 *
 * Benchmarks:
 *   1. TTL min-heap push throughput (simulated flood of unique IPs)
 *   2. Sched hash upsert throughput (insert + update mixed)
 *   3. Sched hash lookup throughput (hot path: same IPs repeated)
 *   4. Intel hash add throughput (database_add_intel)
 *   5. Top-K selection (database_get_sorted_intel)
 *
 * Usage: make bench
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <linux/types.h>
#include "ttl.h"
#include "database.h"

static __u64 get_time_ns_bench(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static void bench_heap_push(void) {
    printf("=== Heap Push Throughput ===\n");
    ttl_set_expire_ns(60000000000ULL); /* 60s */

    int rounds = 60000; /* HEAP_CAP is 65536 */
    __u64 start = get_time_ns_bench();
    for (int i = 0; i < rounds; i++) {
        __u32 ip = (__u32)(0x0A000000 + i); /* 10.0.0.0 + i */
        __u64 expire = start + ((__u64)i * 1000);
        ttl_heap_push(ip, expire);
    }
    __u64 elapsed = get_time_ns_bench() - start;

    printf("  %d pushes in %llu us = %.1f ops/us (%.0f ns/op)\n",
           rounds,
           (unsigned long long)(elapsed / 1000),
           (double)rounds / ((double)elapsed / 1000.0),
           (double)elapsed / (double)rounds);
    printf("  Heap size: %d\n\n", ttl_heap_size());
}

static void bench_sched_upsert(void) {
    printf("=== Sched Hash Upsert Throughput ===\n");

    int rounds = 50000;
    __u64 start = get_time_ns_bench();
    for (int i = 0; i < rounds; i++) {
        __u32 ip = (__u32)(0xC0A80000 + (i % 65536)); /* 192.168.x.y */
        __u64 expire = start + ((__u64)i * 1000);
        ttl_sched_upsert(ip, expire);
    }
    __u64 elapsed = get_time_ns_bench() - start;

    printf("  %d upserts in %llu us = %.1f ops/us (%.0f ns/op)\n",
           rounds,
           (unsigned long long)(elapsed / 1000),
           (double)rounds / ((double)elapsed / 1000.0),
           (double)elapsed / (double)rounds);
    printf("  Live: %u, Tombstones: %u\n\n",
           ttl_sched_live_count(), ttl_sched_tombstone_count());
}

static void bench_sched_lookup(void) {
    printf("=== Sched Hash Lookup Throughput ===\n");

    /* Pre-populate */
    for (int i = 0; i < 30000; i++) {
        __u32 ip = (__u32)(0xAC100000 + i); /* 172.16.x.y */
        ttl_sched_upsert(ip, 999999999ULL);
    }

    int rounds = 200000;
    int hits = 0;
    __u64 start = get_time_ns_bench();
    for (int i = 0; i < rounds; i++) {
        __u32 ip = (__u32)(0xAC100000 + (i % 30000));
        if (ttl_sched_get(ip) > 0)
            hits++;
    }
    __u64 elapsed = get_time_ns_bench() - start;

    printf("  %d lookups in %llu us = %.1f ops/us (%.0f ns/op)\n",
           rounds,
           (unsigned long long)(elapsed / 1000),
           (double)rounds / ((double)elapsed / 1000.0),
           (double)elapsed / (double)rounds);
    printf("  Hits: %d/%d\n\n", hits, rounds);
}

static void bench_intel_add(void) {
    printf("=== Intel Hash Add Throughput ===\n");

    /* Simulate attack: many IPs hitting few ports */
    int rounds = MAX_INTEL_ENTRIES;
    __u64 start = get_time_ns_bench();
    for (int i = 0; i < rounds; i++) {
        __u32 ip = (__u32)(0x0B000000 + i); /* 11.0.x.y */
        __u16 port = (__u16)(80 + (i % 4)); /* 4 target ports */
        database_add_intel(ip, port);
    }
    __u64 elapsed = get_time_ns_bench() - start;

    printf("  %d inserts in %llu us = %.1f ops/us (%.0f ns/op)\n",
           rounds,
           (unsigned long long)(elapsed / 1000),
           (double)rounds / ((double)elapsed / 1000.0),
           (double)elapsed / (double)rounds);

    /* Benchmark repeated hits on existing entries */
    int repeat_rounds = 100000;
    start = get_time_ns_bench();
    for (int i = 0; i < repeat_rounds; i++) {
        __u32 ip = (__u32)(0x0B000000 + (i % rounds));
        database_add_intel(ip, 80);
    }
    elapsed = get_time_ns_bench() - start;

    printf("  %d updates in %llu us = %.1f ops/us (%.0f ns/op)\n\n",
           repeat_rounds,
           (unsigned long long)(elapsed / 1000),
           (double)repeat_rounds / ((double)elapsed / 1000.0),
           (double)elapsed / (double)repeat_rounds);
}

static void bench_topk_sort(void) {
    printf("=== Top-K Sort Throughput ===\n");

    /* Ensure intel_hash is populated (from bench_intel_add) */
    struct intel_entry *buf[MAX_INTEL_ENTRIES];

    int rounds = 1000;
    __u64 start = get_time_ns_bench();
    int n = 0;
    for (int i = 0; i < rounds; i++) {
        n = database_get_sorted_intel(buf, MAX_INTEL_ENTRIES);
    }
    __u64 elapsed = get_time_ns_bench() - start;

    printf("  %d sorts (%d entries) in %llu us = %.1f sorts/ms\n\n",
           rounds, n,
           (unsigned long long)(elapsed / 1000),
           (double)rounds / ((double)elapsed / 1000000.0));

    /* Clean up */
    database_free_intel();
}

int main(void) {
    printf("tcp_syn_stop micro-benchmarks\n");
    printf("=============================\n\n");

    bench_heap_push();
    bench_sched_upsert();
    bench_sched_lookup();
    bench_intel_add();
    bench_topk_sort();

    printf("All benchmarks complete.\n");
    return 0;
}
