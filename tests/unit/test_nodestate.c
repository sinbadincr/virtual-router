#include <stdlib.h>
#include <string.h>

#include "minivr/nodestate.h"
#include "tharness.h"

static struct nentry mk_vrf(const char *name, unsigned id) {
    struct nentry e;
    memset(&e, 0, sizeof e);
    e.kind = NE_VRF;
    strcpy(e.name, name);
    e.id = (uint8_t)id;
    return e;
}

static struct nentry mk_route(const char *vrf, uint32_t pfx, unsigned tag) {
    struct nentry e;
    memset(&e, 0, sizeof e);
    e.kind = NE_ROUTE;
    strcpy(e.vrf, vrf);
    e.prefix = pfx;
    e.plen = 32;
    strcpy(e.node, "cn2");
    e.encap = NE_ENCAP_MPLSOUDP;
    e.tag = tag;
    return e;
}

static struct nentry mk_label(uint32_t l, const char *port) {
    struct nentry e;
    memset(&e, 0, sizeof e);
    e.kind = NE_LABEL;
    e.label = l;
    strcpy(e.port, port);
    return e;
}

TEST(put_replace_remove_and_sorted_iteration) {
    struct nentry store[8];
    struct nstate s;
    ns_init(&s, store, 8);
    struct nentry b = mk_vrf("blue", 2), r = mk_vrf("red", 1), l = mk_label(1001, "red1");
    struct nentry rt = mk_route("red", 0x0a010101, 5);
    CHECK(ns_put(&s, &rt) == 0);
    CHECK(ns_put(&s, &r) == 0);
    CHECK(ns_put(&s, &l) == 0);
    CHECK(ns_put(&s, &b) == 0);
    CHECK_EQ_U64(ns_count(&s), 4);
    /* sorted by kind, then key */
    CHECK_STR_EQ(ns_at(&s, 0)->name, "blue");
    CHECK_STR_EQ(ns_at(&s, 1)->name, "red");
    CHECK_EQ_U64(ns_at(&s, 2)->kind, NE_LABEL);
    CHECK_EQ_U64(ns_at(&s, 3)->kind, NE_ROUTE);
    CHECK(ns_at(&s, 4) == NULL);
    /* replace by key */
    struct nentry r2 = mk_vrf("red", 9);
    CHECK(ns_put(&s, &r2) == 0);
    CHECK_EQ_U64(ns_count(&s), 4);
    CHECK_EQ_U64(ns_get(&s, &r)->id, 9);
    CHECK(ns_del(&s, &r) == 0);
    CHECK(ns_del(&s, &r) == -1);
    CHECK(ns_get(&s, &r) == NULL);
    CHECK_EQ_U64(ns_count(&s), 3);
}

TEST(capacity_is_enforced) {
    struct nentry store[3];
    struct nstate s;
    ns_init(&s, store, 3);
    for (unsigned i = 0; i < 3; i++) {
        struct nentry e = mk_label(1000 + i, "p");
        CHECK(ns_put(&s, &e) == 0);
    }
    struct nentry e = mk_label(2000, "p");
    CHECK(ns_put(&s, &e) == -1);
    e = mk_label(1001, "q"); /* replacing at capacity is fine */
    CHECK(ns_put(&s, &e) == 0);
    CHECK_EQ_U64(ns_count(&s), 3);
}

static unsigned rnd_state = 42;
static unsigned rnd(void) {
    rnd_state = rnd_state * 1103515245u + 12345u;
    return (rnd_state >> 16) & 0x7fff;
}

static void random_set(struct nstate *s) {
    ns_clear(s);
    unsigned n = rnd() % 40;
    for (unsigned i = 0; i < n; i++) {
        struct nentry e;
        switch (rnd() % 3) {
        case 0: e = mk_label(1000 + rnd() % 30, rnd() % 2 ? "a" : "b"); break;
        case 1: e = mk_route(rnd() % 2 ? "red" : "blue", 0x0a000000u + rnd() % 20, rnd() % 4); break;
        default: e = mk_vrf(rnd() % 2 ? "red" : "blue", 1 + rnd() % 3); break;
        }
        ns_put(s, &e);
    }
}

TEST(diff_applied_to_have_equals_want_10000_cases) {
    static struct nentry hs[256], ws[256], dels[256], adds[256];
    struct nstate have, want;
    ns_init(&have, hs, 256);
    ns_init(&want, ws, 256);
    rnd_state = 42;
    for (int i = 0; i < 10000; i++) {
        random_set(&have);
        random_set(&want);
        struct ndiff d = {dels, adds, 0, 0, 256, 256};
        CHECK(ns_diff(&have, &want, &d) == 0);
        /* dels are in have and not in want; adds are new or changed */
        for (unsigned k = 0; k < d.ndels; k++)
            CHECK(ns_get(&want, &d.dels[k]) == NULL && ns_get(&have, &d.dels[k]) != NULL);
        for (unsigned k = 0; k < d.nadds; k++) {
            const struct nentry *h = ns_get(&have, &d.adds[k]);
            CHECK(h == NULL || !ne_val_eq(h, &d.adds[k]));
        }
        CHECK(ns_apply(&have, &d) == 0);
        CHECK(ns_equal(&have, &want));
        if (th_cur_failed)
            return;
    }
}

TEST(identical_sets_have_an_empty_diff_and_overflow_is_reported) {
    struct nentry hs[4], ws[4], dels[1], adds[1];
    struct nstate have, want;
    ns_init(&have, hs, 4);
    ns_init(&want, ws, 4);
    struct nentry a = mk_label(1000, "x"), b = mk_label(1001, "y");
    ns_put(&have, &a);
    ns_put(&want, &a);
    struct ndiff d = {dels, adds, 0, 0, 1, 1};
    CHECK(ns_diff(&have, &want, &d) == 0 && d.ndels == 0 && d.nadds == 0);
    ns_put(&want, &b);
    struct nentry c = mk_label(1002, "z");
    ns_put(&want, &c);
    CHECK(ns_diff(&have, &want, &d) == -1);
}

TEST(names) {
    CHECK(ne_name_ok("red-1_a"));
    CHECK(!ne_name_ok(""));
    CHECK(!ne_name_ok("Red"));
    CHECK(!ne_name_ok("0123456789abcdef")); /* 16 chars */
    CHECK_STR_EQ(ne_kind_name(NE_ROUTE), "route");
}
