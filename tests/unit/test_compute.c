#include "ctl_fixture.h"
#include "tharness.h"

static struct nentry store[4096];

static const struct nentry *find(const struct nstate *s, unsigned kind, const char *name, uint32_t ip) {
    for (unsigned i = 0; i < s->n; i++) {
        const struct nentry *e = &s->e[i];
        if (e->kind != kind)
            continue;
        switch (kind) {
        case NE_VRF: case NE_NODE: case NE_PORT:
            if (strcmp(e->name, name) == 0) return e;
            break;
        case NE_NEIGH:
            if (strcmp(e->vrf, name) == 0 && e->ip == ip) return e;
            break;
        case NE_ROUTE:
            if (strcmp(e->vrf, name) == 0 && e->prefix == ip) return e;
            break;
        }
    }
    return NULL;
}

TEST(cn1_state_of_the_phase2_lab) {
    CHECK_EQ_U64(cf_load_intent(), 15);
    cf_phase2_bindings();
    struct nstate s;
    ns_init(&s, store, 4096);
    CHECK(cm_compute(&cf_m, 0, &s) == 0);
    /* 2 VRF + 2 VNI + NODE cn2 + 2 PORT + 2 NEIGH + 2 LABEL + 3 ROUTE */
    CHECK_EQ_U64(s.n, 14);
    CHECK_EQ_U64(find(&s, NE_VRF, "red", 0)->id, 1);
    CHECK_EQ_U64(find(&s, NE_VRF, "blue", 0)->id, 2);
    const struct nentry *cn2 = find(&s, NE_NODE, "cn2", 0);
    CHECK(cn2 && cn2->ip == 0xac100002u && cn2->rmac[5] == 2);
    const struct nentry *p = find(&s, NE_PORT, "red1", 0);
    CHECK(p && strcmp(p->vrf, "red") == 0 && p->prefix == 0x0a010101u && p->plen == 24);
    p = find(&s, NE_PORT, "blue1", 0);
    CHECK(p && strcmp(p->vrf, "blue") == 0 && p->prefix == 0x0a010101u);
    const struct nentry *n = find(&s, NE_NEIGH, "red", 0x0a01010bu);
    CHECK(n && n->mac[4] == 1 && strcmp(n->port, "red1") == 0);
    n = find(&s, NE_NEIGH, "blue", 0x0a01010bu);
    CHECK(n && n->mac[3] == 2);
    const struct nentry *r = find(&s, NE_ROUTE, "red", 0x0a01010cu);
    CHECK(r && r->encap == NE_ENCAP_MPLSOUDP && r->tag == 1000 && strcmp(r->node, "cn2") == 0);
    r = find(&s, NE_ROUTE, "red", 0x0a01020du);
    CHECK(r && r->tag == 1001);
    r = find(&s, NE_ROUTE, "blue", 0x0a01010cu);
    CHECK(r && r->encap == NE_ENCAP_VXLAN && r->tag == 200);
}

TEST(isolation_locality_and_determinism) {
    CHECK_EQ_U64(cf_load_intent(), 15);
    cf_phase2_bindings();
    for (unsigned node = 0; node < 2; node++) {
        struct nstate s;
        ns_init(&s, store, 4096);
        CHECK(cm_compute(&cf_m, node, &s) == 0);
        for (unsigned i = 0; i < s.n; i++) {
            const struct nentry *e = &s.e[i];
            /* locality: no route to an address bound on this very node */
            if (e->kind == NE_ROUTE)
                for (int v = 0; v < CM_MAX_VMIS; v++)
                    if (cf_m.vmis[v].used && cf_m.vmis[v].node == (int8_t)node)
                        CHECK(!(cf_m.vmis[v].ip == e->prefix &&
                                strcmp(cf_m.tenants[cf_m.vmis[v].tenant].name, e->vrf) == 0));
        }
    }
    /* isolation: cn3 hosts nothing and gets nothing; a tenant only appears where it is present */
    struct nstate s;
    ns_init(&s, store, 4096);
    CHECK(cm_compute(&cf_m, 2, &s) == 0);
    CHECK_EQ_U64(s.n, 0);
    unsigned l;
    int from;
    cm_node_learn(&cf_m, 2, 0xac100004u, (const uint8_t[]){2, 0, 0, 0xff, 0, 4});
    CHECK(cm_bind(&cf_m, 2, "red4", "red4", &l, &from) == CM_BIND_OK);
    CHECK(cm_compute(&cf_m, 2, &s) == 0);
    CHECK(find(&s, NE_VRF, "red", 0) && !find(&s, NE_VRF, "blue", 0));
    for (unsigned i = 0; i < s.n; i++) {
        CHECK(s.e[i].kind != NE_ROUTE || strcmp(s.e[i].vrf, "red") == 0);
    }
    /* determinism: same bindings bound in another order give the same state */
    struct nstate a, b;
    static struct nentry sa[4096], sb[4096];
    ns_init(&a, sa, 4096);
    ns_init(&b, sb, 4096);
    CHECK(cm_compute(&cf_m, 0, &a) == 0);
    CHECK(cm_compute(&cf_m, 0, &b) == 0);
    CHECK(ns_equal(&a, &b));
}

TEST(unreported_node_is_not_a_node_and_vxlan_needs_the_rmac) {
    CHECK_EQ_U64(cf_load_intent(), 15);
    unsigned l;
    int from;
    cm_bind(&cf_m, 0, "red1", "red1", &l, &from);
    cm_bind(&cf_m, 1, "red2", "red2", &l, &from);
    struct nstate s;
    ns_init(&s, store, 4096);
    CHECK(cm_compute(&cf_m, 0, &s) == 0);
    CHECK(!find(&s, NE_NODE, "cn2", 0) && !find(&s, NE_ROUTE, "red", 0x0a01010cu));
    cm_node_learn(&cf_m, 1, 0xac100002u, (const uint8_t[]){2, 0, 0, 0xff, 0, 2});
    CHECK(cm_compute(&cf_m, 0, &s) == 0);
    CHECK(find(&s, NE_NODE, "cn2", 0) && find(&s, NE_ROUTE, "red", 0x0a01010cu));
    /* switching the tenant to vxlan: tag becomes the vni */
    CHECK(cli("tenant set red encap vxlan") == 0);
    CHECK(cm_compute(&cf_m, 0, &s) == 0);
    const struct nentry *r = find(&s, NE_ROUTE, "red", 0x0a01010cu);
    CHECK(r && r->encap == NE_ENCAP_VXLAN && r->tag == 100);
}

TEST(state_too_big_for_the_buffer_is_reported) {
    CHECK_EQ_U64(cf_load_intent(), 15);
    cf_phase2_bindings();
    static struct nentry tiny[4];
    struct nstate s;
    ns_init(&s, tiny, 4);
    CHECK(cm_compute(&cf_m, 0, &s) == -1);
}
