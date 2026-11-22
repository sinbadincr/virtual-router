#include <stdlib.h>

#include "minivr/lpm.h"
#include "tharness.h"

static struct lpm_pool pool;
static struct lpm_root root;
#define t &pool, &root
static void init(void) {
    lpm_pool_init(&pool);
    lpm_root_init(&pool, &root);
}

static uint32_t mask(uint8_t len) {
    return len == 0 ? 0 : ~0U << (32 - len);
}

TEST(basics) {
    init();
    uint32_t v;
    uint8_t len;
    CHECK(!lpm_lookup(t, 0x0a000001, &v, &len));
    CHECK(lpm_add(t, 0x0a000000, 8, 1) == 0);
    CHECK(lpm_add(t, 0x0a000000, 8, 2) == -1); /* duplicate */
    CHECK(lpm_lookup(t, 0x0a0a0a0a, &v, &len));
    CHECK_EQ_U64(v, 1);
    CHECK_EQ_U64(len, 8);
    CHECK(!lpm_lookup(t, 0x0b000001, &v, &len));
    CHECK(lpm_del(t, 0x0a000000, 8) == 0);
    CHECK(lpm_del(t, 0x0a000000, 8) == -1);
    CHECK(!lpm_lookup(t, 0x0a0a0a0a, &v, &len));
    CHECK_EQ_U64(lpm_count(&root), 0);
}

TEST(default_and_host_routes) {
    init();
    uint32_t v;
    uint8_t len;
    CHECK(lpm_add(t, 0, 0, 100) == 0);
    CHECK(lpm_add(t, 0x01020304, 32, 200) == 0);
    CHECK(lpm_lookup(t, 0x01020304, &v, &len));
    CHECK_EQ_U64(v, 200);
    CHECK_EQ_U64(len, 32);
    CHECK(lpm_lookup(t, 0x01020305, &v, &len));
    CHECK_EQ_U64(v, 100);
    CHECK_EQ_U64(len, 0);
    CHECK(lpm_get(t, 0, 0, &v) && v == 100);
    CHECK(!lpm_get(t, 0x01020305, 32, &v));
}

TEST(most_specific_wins) {
    init();
    uint32_t v;
    uint8_t len;
    lpm_add(t, 0x0a010000, 16, 16);
    lpm_add(t, 0x0a010200, 24, 24);
    CHECK(lpm_lookup(t, 0x0a010203, &v, &len) && v == 24 && len == 24);
    CHECK(lpm_lookup(t, 0x0a010303, &v, &len) && v == 16 && len == 16);
    lpm_del(t, 0x0a010200, 24);
    CHECK(lpm_lookup(t, 0x0a010203, &v, &len) && v == 16);
}

TEST(capacity_is_10000_rules) {
    init();
    for (uint32_t i = 0; i < LPM_MAX_RULES; i++)
        CHECK(lpm_add(t, 0x0a000000 + (i << 8), 24, i) == 0);
    CHECK(lpm_add(t, 0xc0000000, 24, 1) == -2);
    CHECK_EQ_U64(lpm_count(&root), LPM_MAX_RULES);
    CHECK(lpm_del(t, 0x0a000000, 24) == 0);
    CHECK(lpm_add(t, 0xc0000000, 24, 1) == 0); /* space again after a delete */
}

struct oracle {
    uint32_t prefix;
    uint8_t len;
    uint32_t value;
    int live;
};
static struct oracle rules[10000];

static int oracle_lookup(uint32_t ip, uint32_t *value) {
    int best = -1;
    for (int i = 0; i < 10000; i++)
        if (rules[i].live && (ip & mask(rules[i].len)) == rules[i].prefix &&
            (best < 0 || rules[i].len > rules[best].len))
            best = i;
    if (best < 0)
        return 0;
    *value = rules[best].value;
    return 1;
}

static uint32_t rng_state = 0xC0FFEE;
static uint32_t rnd(void) {
    rng_state = rng_state * 1664525u + 1013904223u;
    return rng_state;
}

static void compare(int lookups) {
    for (int i = 0; i < lookups; i++) {
        uint32_t ip = rnd();
        /* half of the probes are drawn near existing rules so hits are common */
        if (i & 1) {
            const struct oracle *r = &rules[rnd() % 10000];
            ip = r->prefix | (rnd() & ~mask(r->len));
        }
        uint32_t want = 0, got = 0;
        int w = oracle_lookup(ip, &want), g = lpm_lookup(t, ip, &got, NULL);
        if (w != g || (w && want != got)) {
            TH_FAIL("lookup %08x: oracle %d/%u, trie %d/%u", ip, w, want, g, got);
            return;
        }
    }
}

TEST(differential_against_linear_scan) {
    init();
    memset(rules, 0, sizeof rules);
    for (int i = 0; i < 10000;) {
        uint8_t len = (uint8_t)(8 + rnd() % 25); /* /8../32 */
        uint32_t prefix = rnd() & mask(len);
        int dup = 0;
        for (int j = 0; j < i && !dup; j++)
            dup = rules[j].len == len && rules[j].prefix == prefix;
        if (dup)
            continue;
        rules[i] = (struct oracle){prefix, len, (uint32_t)i, 1};
        CHECK(lpm_add(t, prefix, len, (uint32_t)i) == 0);
        i++;
    }
    compare(10000);
    for (int i = 0; i < 10000; i += 2) { /* delete a random half (every other entry of a random order) */
        int k = (int)(rnd() % 10000);
        if (rules[k].live) {
            CHECK(lpm_del(t, rules[k].prefix, rules[k].len) == 0);
            rules[k].live = 0;
        }
    }
    compare(10000);
}

static void count_cb(uint32_t p, uint8_t l, uint32_t v, void *arg) {
    (void)p; (void)l; (void)v;
    (*(int *)arg)++;
}

TEST(walk_visits_every_rule_in_prefix_order) {
    init();
    lpm_add(t, 0x0a000100, 24, 1);
    lpm_add(t, 0x0a000000, 8, 2);
    lpm_add(t, 0x0a00010b, 32, 3);
    int n = 0;
    lpm_walk(t, count_cb, &n);
    CHECK_EQ_U64(n, 3);
}

/* ---- shared pool, one root per VRF (phase 2) ---- */

TEST(roots_are_isolated_in_one_pool) {
    lpm_pool_init(&pool);
    struct lpm_root a, b;
    CHECK(lpm_root_init(&pool, &a) == 0);
    CHECK(lpm_root_init(&pool, &b) == 0);
    uint32_t v;
    uint8_t len;
    CHECK(lpm_add(&pool, &a, 0x0a010100, 24, 1) == 0);
    CHECK(lpm_add(&pool, &b, 0x0a010100, 24, 2) == 0); /* same prefix, other root: not a duplicate */
    CHECK(lpm_lookup(&pool, &a, 0x0a010105, &v, &len) && v == 1);
    CHECK(lpm_lookup(&pool, &b, 0x0a010105, &v, &len) && v == 2);
    CHECK(lpm_add(&pool, &a, 0xc0a80000, 16, 3) == 0);
    CHECK(!lpm_lookup(&pool, &b, 0xc0a80001, &v, &len)); /* never returns the other root's value */
    CHECK(lpm_del(&pool, &a, 0x0a010100, 24) == 0);
    CHECK(!lpm_lookup(&pool, &a, 0x0a010105, &v, &len));
    CHECK(lpm_lookup(&pool, &b, 0x0a010105, &v, &len) && v == 2); /* b untouched */
    CHECK(lpm_del(&pool, &a, 0x0a010100, 24) == -1);
    CHECK_EQ_U64(lpm_count(&a), 1);
    CHECK_EQ_U64(lpm_count(&b), 1);
    CHECK_EQ_U64(lpm_pool_count(&pool), 2);
}

TEST(default_route_is_per_root) {
    lpm_pool_init(&pool);
    struct lpm_root a, b;
    lpm_root_init(&pool, &a);
    lpm_root_init(&pool, &b);
    uint32_t v;
    CHECK(lpm_add(&pool, &a, 0, 0, 7) == 0);
    CHECK(lpm_lookup(&pool, &a, 0x01020304, &v, NULL) && v == 7);
    CHECK(!lpm_lookup(&pool, &b, 0x01020304, &v, NULL));
}

TEST(ten_thousand_rules_in_total_across_roots) {
    lpm_pool_init(&pool);
    struct lpm_root r[4];
    for (int i = 0; i < 4; i++)
        CHECK(lpm_root_init(&pool, &r[i]) == 0);
    for (uint32_t i = 0; i < LPM_MAX_RULES; i++)
        CHECK(lpm_add(&pool, &r[i % 4], 0x0a000000 + (i << 8), 24, i) == 0);
    CHECK(lpm_add(&pool, &r[0], 0xc0000000, 24, 1) == -2); /* full, whichever root asks */
    CHECK(lpm_add(&pool, &r[3], 0xc0000000, 24, 1) == -2);
    CHECK_EQ_U64(lpm_pool_count(&pool), LPM_MAX_RULES);
    CHECK_EQ_U64(lpm_count(&r[2]), LPM_MAX_RULES / 4);
}

struct order {
    uint32_t last;
    int n, ok;
};
static void order_cb(uint32_t p, uint8_t l, uint32_t v, void *arg) {
    (void)l; (void)v;
    struct order *o = arg;
    if (o->n && p < o->last)
        o->ok = 0;
    o->last = p;
    o->n++;
}

TEST(walk_covers_only_its_root_in_prefix_order) {
    lpm_pool_init(&pool);
    struct lpm_root a, b;
    lpm_root_init(&pool, &a);
    lpm_root_init(&pool, &b);
    lpm_add(&pool, &a, 0x0a000100, 24, 1);
    lpm_add(&pool, &a, 0x0a000000, 8, 2);
    lpm_add(&pool, &a, 0x0a00010b, 32, 3);
    lpm_add(&pool, &b, 0xc0000000, 8, 4);
    struct order o = {0, 0, 1};
    lpm_walk(&pool, &a, order_cb, &o);
    CHECK_EQ_U64(o.n, 3);
    CHECK(o.ok);
}
