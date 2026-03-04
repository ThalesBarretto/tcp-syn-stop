#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include "../src/utils.h"

void test_parse_cidr() {
    struct lpm_key key;

    printf("Testing parse_cidr...\n");

    // Valid CIDR
    assert(parse_cidr("1.2.3.0/24", &key) == 0);
    assert(key.prefixlen == 24);
    assert(key.ip == inet_addr("1.2.3.0"));

    // Valid Host
    assert(parse_cidr("192.168.1.1", &key) == 0);
    assert(key.prefixlen == 32);
    assert(key.ip == inet_addr("192.168.1.1"));

    // Invalid: /0 rejected
    assert(parse_cidr("0.0.0.0/0", &key) != 0);

    // Invalid: Host bits set (strict mode)
    assert(parse_cidr("1.2.3.4/24", &key) != 0);

    // Invalid: Bad IP
    assert(parse_cidr("999.999.999.999/24", &key) != 0);

    // Invalid: Bad prefix
    assert(parse_cidr("1.2.3.0/33", &key) != 0);

    printf("parse_cidr tests passed!\n");
}

void test_range_to_cidr() {
    printf("Testing range_to_cidr...\n");

    // Exact /24
    assert(range_to_cidr(0x01020300, 0x010203FF) == 24);

    // Single IP
    assert(range_to_cidr(0x01020304, 0x01020304) == 32);

    // Non-aligned range (1.2.3.1 to 1.2.3.14) -> /32
    assert(range_to_cidr(0x01020301, 0x0102030E) == 32);

    // 1.2.3.0 to 1.2.3.14. Tightest aligned starting at .0 is /29 (8 IPs)
    // Actually, 1.2.3.0/28 is 0-15. 1.2.3.0/29 is 0-7.
    // 14 < 15, but alignment check: (start + mask_size - 1) <= end.
    // 0 + 16 - 1 = 15. 15 > 14. So /28 doesn't fit.
    // 0 + 8 - 1 = 7. 7 <= 14. So /29 fits.
    assert(range_to_cidr(0x01020300, 0x0102030E) == 29);

    printf("range_to_cidr tests passed!\n");
}

/* ===========================================================================
 * Engine data-structure tests — standalone copies of the heap/sched algorithms
 * with reduced sizes for unit testing.
 * ========================================================================= */

#include <stdint.h>
#include <limits.h>

#define TEST_HEAP_CAP   8
#define TEST_SCHED_SLOTS 16           /* must be power-of-2 */
#define TEST_SCHED_SHIFT 4u           /* log2(TEST_SCHED_SLOTS) */
#define TEST_SCHED_TOMBSTONE UINT64_MAX

struct test_heap_entry {
    uint64_t expire_at;
    uint32_t ip;
};

static struct test_heap_entry t_heap[TEST_HEAP_CAP];
static int t_heap_sz = 0;

static void t_heap_sift_up(int i) {
    while (i > 0) {
        int p = (i - 1) / 2;
        if (t_heap[p].expire_at <= t_heap[i].expire_at) break;
        struct test_heap_entry tmp = t_heap[p];
        t_heap[p] = t_heap[i];
        t_heap[i] = tmp;
        i = p;
    }
}

static void t_heap_sift_down(int i) {
    while (1) {
        int s = i, l = 2 * i + 1, r = 2 * i + 2;
        if (l < t_heap_sz && t_heap[l].expire_at < t_heap[s].expire_at) s = l;
        if (r < t_heap_sz && t_heap[r].expire_at < t_heap[s].expire_at) s = r;
        if (s == i) break;
        struct test_heap_entry tmp = t_heap[s];
        t_heap[s] = t_heap[i];
        t_heap[i] = tmp;
        i = s;
    }
}

/* Returns 0 on success, -1 on overflow */
static int t_heap_push(uint32_t ip, uint64_t expire_at) {
    if (t_heap_sz >= TEST_HEAP_CAP)
        return -1;
    t_heap[t_heap_sz] = (struct test_heap_entry){ .expire_at = expire_at, .ip = ip };
    t_heap_sift_up(t_heap_sz++);
    return 0;
}

static struct test_heap_entry t_heap_pop(void) {
    struct test_heap_entry top = t_heap[0];
    t_heap[0] = t_heap[--t_heap_sz];
    t_heap_sift_down(0);
    return top;
}

static void t_heap_reset(void) { t_heap_sz = 0; }

/* --- Sched hash table (identical algorithm to engine.c) --- */

struct test_sched_entry {
    uint64_t expire_at;
    uint32_t ip;
};

static struct test_sched_entry t_sched[TEST_SCHED_SLOTS];
static int t_sched_tomb_count = 0;

static inline uint32_t t_sched_hash(uint32_t ip) {
    return (ip * 2654435761u) >> (32u - TEST_SCHED_SHIFT);
}

static void t_sched_reset(void) {
    memset(t_sched, 0, sizeof(t_sched));
    t_sched_tomb_count = 0;
}

static void t_sched_compact(void);

static void t_sched_upsert(uint32_t ip, uint64_t expire_at) {
    uint32_t slot = t_sched_hash(ip);
    int first_tomb = -1;
    for (uint32_t i = 0; i < TEST_SCHED_SLOTS; i++) {
        uint32_t idx = (slot + i) & (TEST_SCHED_SLOTS - 1);
        uint64_t ea = t_sched[idx].expire_at;
        if (ea == 0) {
            uint32_t ins = (first_tomb >= 0) ? (uint32_t)first_tomb : idx;
            t_sched[ins].ip = ip;
            t_sched[ins].expire_at = expire_at;
            return;
        }
        if (ea == TEST_SCHED_TOMBSTONE) {
            if (first_tomb < 0) first_tomb = (int)idx;
            continue;
        }
        if (t_sched[idx].ip == ip) {
            t_sched[idx].expire_at = expire_at;
            return;
        }
    }
}

static uint64_t t_sched_get(uint32_t ip) {
    uint32_t slot = t_sched_hash(ip);
    for (uint32_t i = 0; i < TEST_SCHED_SLOTS; i++) {
        uint32_t idx = (slot + i) & (TEST_SCHED_SLOTS - 1);
        uint64_t ea = t_sched[idx].expire_at;
        if (ea == 0) return 0;
        if (ea == TEST_SCHED_TOMBSTONE) continue;
        if (t_sched[idx].ip == ip) return ea;
    }
    return 0;
}

static void t_sched_remove(uint32_t ip) {
    uint32_t slot = t_sched_hash(ip);
    for (uint32_t i = 0; i < TEST_SCHED_SLOTS; i++) {
        uint32_t idx = (slot + i) & (TEST_SCHED_SLOTS - 1);
        uint64_t ea = t_sched[idx].expire_at;
        if (ea == 0) return;
        if (ea == TEST_SCHED_TOMBSTONE) continue;
        if (t_sched[idx].ip == ip) {
            t_sched[idx].expire_at = TEST_SCHED_TOMBSTONE;
            if (++t_sched_tomb_count > (int)(TEST_SCHED_SLOTS / 4))
                t_sched_compact();
            return;
        }
    }
}

static void t_sched_compact(void) {
    struct test_sched_entry tmp[TEST_SCHED_SLOTS];
    memcpy(tmp, t_sched, sizeof(t_sched));
    memset(t_sched, 0, sizeof(t_sched));
    t_sched_tomb_count = 0;
    for (uint32_t i = 0; i < TEST_SCHED_SLOTS; i++) {
        if (tmp[i].expire_at != 0 && tmp[i].expire_at != TEST_SCHED_TOMBSTONE)
            t_sched_upsert(tmp[i].ip, tmp[i].expire_at);
    }
}

void test_heap_push_pop_order() {
    printf("Testing heap push/pop min-ordering...\n");
    t_heap_reset();

    /* Push in non-sorted order */
    t_heap_push(0x0A000001, 500);
    t_heap_push(0x0A000002, 100);
    t_heap_push(0x0A000003, 300);
    t_heap_push(0x0A000004, 200);
    t_heap_push(0x0A000005, 400);

    assert(t_heap_sz == 5);

    /* Pop should return in ascending expire_at order (min-heap) */
    struct test_heap_entry e;
    e = t_heap_pop(); assert(e.expire_at == 100 && e.ip == 0x0A000002);
    e = t_heap_pop(); assert(e.expire_at == 200 && e.ip == 0x0A000004);
    e = t_heap_pop(); assert(e.expire_at == 300 && e.ip == 0x0A000003);
    e = t_heap_pop(); assert(e.expire_at == 400 && e.ip == 0x0A000005);
    e = t_heap_pop(); assert(e.expire_at == 500 && e.ip == 0x0A000001);
    assert(t_heap_sz == 0);

    printf("test_heap_push_pop_order passed!\n");
}

void test_heap_overflow() {
    printf("Testing heap overflow at capacity...\n");
    t_heap_reset();

    /* Fill to capacity */
    for (int i = 0; i < TEST_HEAP_CAP; i++)
        assert(t_heap_push((uint32_t)(i + 1), (uint64_t)(i * 10)) == 0);

    assert(t_heap_sz == TEST_HEAP_CAP);

    /* One more push should fail (return -1) */
    assert(t_heap_push(0xFFFFFFFF, 999) == -1);
    assert(t_heap_sz == TEST_HEAP_CAP);  /* size unchanged */

    /* Existing entries still valid — pop the minimum */
    struct test_heap_entry e = t_heap_pop();
    assert(e.expire_at == 0);  /* first pushed had expire_at=0 */
    assert(t_heap_sz == TEST_HEAP_CAP - 1);

    printf("test_heap_overflow passed!\n");
}

void test_sched_upsert_get_roundtrip() {
    printf("Testing sched upsert/get roundtrip...\n");
    t_sched_reset();

    /* Insert several IPs */
    t_sched_upsert(0x0A000001, 1000);
    t_sched_upsert(0x0A000002, 2000);
    t_sched_upsert(0x0A000003, 3000);

    /* Lookup should return correct values */
    assert(t_sched_get(0x0A000001) == 1000);
    assert(t_sched_get(0x0A000002) == 2000);
    assert(t_sched_get(0x0A000003) == 3000);

    /* Update existing IP */
    t_sched_upsert(0x0A000002, 5000);
    assert(t_sched_get(0x0A000002) == 5000);

    /* Miss returns 0 */
    assert(t_sched_get(0xDEADBEEF) == 0);

    printf("test_sched_upsert_get_roundtrip passed!\n");
}

void test_sched_compact() {
    printf("Testing sched compact (tombstone elimination)...\n");
    t_sched_reset();

    /* Insert 6 entries */
    t_sched_upsert(0x00000001, 100);
    t_sched_upsert(0x00000002, 200);
    t_sched_upsert(0x00000003, 300);
    t_sched_upsert(0x00000004, 400);
    t_sched_upsert(0x00000005, 500);
    t_sched_upsert(0x00000006, 600);

    /* Remove 5 to exceed threshold (compact triggers when count > SLOTS/4 = 4,
     * i.e. on the 5th removal) */
    t_sched_remove(0x00000001);
    assert(t_sched_tomb_count == 1);
    t_sched_remove(0x00000002);
    assert(t_sched_tomb_count == 2);
    t_sched_remove(0x00000003);
    assert(t_sched_tomb_count == 3);
    t_sched_remove(0x00000004);
    assert(t_sched_tomb_count == 4); /* not yet triggered (4 == 4, need > 4) */
    t_sched_remove(0x00000005);
    /* 5th removal triggers compact, which resets tomb_count to 0 */
    assert(t_sched_tomb_count == 0);

    /* Surviving entry should still be accessible after compaction */
    assert(t_sched_get(0x00000006) == 600);

    /* Removed entries should be gone */
    assert(t_sched_get(0x00000001) == 0);
    assert(t_sched_get(0x00000002) == 0);
    assert(t_sched_get(0x00000003) == 0);
    assert(t_sched_get(0x00000004) == 0);
    assert(t_sched_get(0x00000005) == 0);

    printf("test_sched_compact passed!\n");
}

void test_sched_hash_distribution() {
    printf("Testing sched_hash distribution for same-/16 IPs...\n");
    t_sched_reset();

    /* Insert 16 IPs from 192.168.0.0/16 in network byte order.
     * With the old mask hash, these would all collide on x86 (LE).
     * With Knuth multiplicative hash, they should scatter. */
    uint32_t ips[16];
    for (int i = 0; i < 16; i++) {
        /* 192.168.i.0 in NBO on LE = 0x00(i)A8C0 */
        ips[i] = htonl(0xC0A80000u | ((uint32_t)i << 8));
        t_sched_upsert(ips[i], (uint64_t)(1000 + i));
    }

    /* Verify all 16 IPs are retrievable */
    for (int i = 0; i < 16; i++)
        assert(t_sched_get(ips[i]) == (uint64_t)(1000 + i));

    /* Count occupied slots — with good distribution, expect > 12 of 16 */
    int occupied = 0;
    for (int s = 0; s < TEST_SCHED_SLOTS; s++) {
        if (t_sched[s].expire_at != 0 && t_sched[s].expire_at != TEST_SCHED_TOMBSTONE)
            occupied++;
    }
    assert(occupied == 16);  /* all 16 must be present */

    /* Count unique initial hash slots to verify distribution */
    int slots_hit[TEST_SCHED_SLOTS] = {0};
    for (int i = 0; i < 16; i++)
        slots_hit[t_sched_hash(ips[i])]++;
    int unique_slots = 0;
    for (int s = 0; s < TEST_SCHED_SLOTS; s++)
        if (slots_hit[s] > 0) unique_slots++;

    /* With 16 IPs into 16 slots, Knuth hash should hit > 12 unique slots
     * (the old bit-mask hash would hit only 1 slot for same-/16 IPs) */
    assert(unique_slots > 12);

    printf("test_sched_hash_distribution passed! (%d/16 unique slots)\n", unique_slots);
}

void test_topk_heap() {
    printf("Testing topk min-heap streaming selection...\n");

    /* Replicate the topk_heap at test scale */
    struct { uint32_t ip; uint64_t count; } tk_entries[5];
    int tk_sz = 0;

    /* sift_down for the test min-heap */
    #define TK_SIFT_DOWN() do { \
        int _i = 0; \
        while (1) { \
            int _s = _i, _l = 2*_i+1, _r = 2*_i+2; \
            if (_l < tk_sz && tk_entries[_l].count < tk_entries[_s].count) _s = _l; \
            if (_r < tk_sz && tk_entries[_r].count < tk_entries[_s].count) _s = _r; \
            if (_s == _i) break; \
            typeof(tk_entries[0]) _tmp = tk_entries[_s]; \
            tk_entries[_s] = tk_entries[_i]; \
            tk_entries[_i] = _tmp; \
            _i = _s; \
        } \
    } while(0)

    /* Push 20 entries with known counts through the K=5 heap */
    for (int i = 0; i < 20; i++) {
        uint32_t ip = (uint32_t)(i + 1);
        uint64_t count = (uint64_t)((i * 37 + 13) % 100);  /* pseudo-random counts */

        /* Dedup check (not needed here but matches production) */
        int dup = 0;
        for (int j = 0; j < tk_sz; j++)
            if (tk_entries[j].ip == ip) { dup = 1; break; }
        if (dup) continue;

        if (tk_sz < 5) {
            tk_entries[tk_sz].ip = ip;
            tk_entries[tk_sz].count = count;
            /* sift up */
            int k = tk_sz++;
            while (k > 0) {
                int p = (k - 1) / 2;
                if (tk_entries[p].count <= tk_entries[k].count) break;
                typeof(tk_entries[0]) tmp = tk_entries[p];
                tk_entries[p] = tk_entries[k];
                tk_entries[k] = tmp;
                k = p;
            }
        } else if (count > tk_entries[0].count) {
            tk_entries[0].ip = ip;
            tk_entries[0].count = count;
            TK_SIFT_DOWN();
        }
    }
    #undef TK_SIFT_DOWN

    assert(tk_sz == 5);

    /* Compute what the actual top 5 counts should be */
    uint64_t all_counts[20];
    for (int i = 0; i < 20; i++)
        all_counts[i] = (uint64_t)((i * 37 + 13) % 100);
    /* Simple selection sort to find top 5 */
    for (int i = 0; i < 5; i++) {
        for (int j = i + 1; j < 20; j++) {
            if (all_counts[j] > all_counts[i]) {
                uint64_t tmp = all_counts[i];
                all_counts[i] = all_counts[j];
                all_counts[j] = tmp;
            }
        }
    }

    /* Every entry in the heap must be one of the top 5 counts */
    for (int i = 0; i < 5; i++) {
        int found = 0;
        for (int j = 0; j < 5; j++) {
            if (tk_entries[i].count == all_counts[j]) {
                found = 1;
                break;
            }
        }
        assert(found);
    }

    /* The heap root must be the minimum of the top 5 */
    uint64_t min_top5 = all_counts[0];
    for (int i = 1; i < 5; i++)
        if (all_counts[i] < min_top5) min_top5 = all_counts[i];
    assert(tk_entries[0].count == min_top5);

    printf("test_topk_heap passed!\n");
}

/* ===========================================================================
 * Autoban decay tests — standalone escalation math
 * ========================================================================= */

/* Replicate autoban_compute_duration for standalone testing */
static int test_autoban_compute_duration(int base, int cap, int offense_count) {
    int duration = base;
    for (int i = 1; i < offense_count; i++) {
        if (duration > cap / 2) { duration = cap; break; }
        duration *= 2;
    }
    return duration < cap ? duration : cap;
}

void test_autoban_escalation_curve() {
    printf("Testing autoban escalation curve (base=300, cap=86400)...\n");

    int base = 300, cap = 86400;

    /* Offense 1: 300s (5 min) */
    assert(test_autoban_compute_duration(base, cap, 1) == 300);
    /* Offense 2: 600s (10 min) */
    assert(test_autoban_compute_duration(base, cap, 2) == 600);
    /* Offense 3: 1200s (20 min) */
    assert(test_autoban_compute_duration(base, cap, 3) == 1200);
    /* Offense 4: 2400s (40 min) */
    assert(test_autoban_compute_duration(base, cap, 4) == 2400);
    /* Offense 5: 4800s (80 min) */
    assert(test_autoban_compute_duration(base, cap, 5) == 4800);
    /* Offense 6: 9600s (160 min) */
    assert(test_autoban_compute_duration(base, cap, 6) == 9600);
    /* Offense 7: 19200s (320 min) */
    assert(test_autoban_compute_duration(base, cap, 7) == 19200);
    /* Offense 8: 38400s */
    assert(test_autoban_compute_duration(base, cap, 8) == 38400);
    /* Offense 9: 76800s (300 * 2^8, still under 86400 cap) */
    assert(test_autoban_compute_duration(base, cap, 9) == 76800);
    /* Offense 10: 153600 > cap -> 86400s (24h) */
    assert(test_autoban_compute_duration(base, cap, 10) == 86400);
    /* Offense 11+: still capped */
    assert(test_autoban_compute_duration(base, cap, 11) == 86400);
    assert(test_autoban_compute_duration(base, cap, 20) == 86400);

    /* Edge case: base == cap -> always cap */
    assert(test_autoban_compute_duration(300, 300, 1) == 300);
    assert(test_autoban_compute_duration(300, 300, 5) == 300);

    /* Edge case: offense_count == 0 (should not happen, but be safe) */
    assert(test_autoban_compute_duration(base, cap, 0) == 300);

    printf("test_autoban_escalation_curve passed!\n");
}

int main() {
    test_parse_cidr();
    test_range_to_cidr();
    test_heap_push_pop_order();
    test_heap_overflow();
    test_sched_upsert_get_roundtrip();
    test_sched_compact();
    test_sched_hash_distribution();
    test_topk_heap();
    test_autoban_escalation_curve();
    printf("\nAll unit tests passed successfully!\n");
    return 0;
}
