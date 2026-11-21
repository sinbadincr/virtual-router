#include "fixture.h"
#include "overlay_fixture.h"
#include "tharness.h"

static int run(enum cmd_where where, const char *line, struct cmd_err *e) {
    char buf[512];
    struct jw w;
    jw_init(&w, buf, sizeof buf);
    return cmd_exec(line, where, &w, e);
}

struct collect {
    int n;
    uint32_t prefix[32];
    uint8_t len[32];
    enum route_origin origin[32];
    int port[32];
};
static void collect_cb(const struct route *r, void *arg) {
    struct collect *c = arg;
    c->prefix[c->n] = r->prefix;
    c->len[c->n] = r->len;
    c->origin[c->n] = r->origin;
    c->port[c->n] = r->port;
    c->n++;
}

TEST(connected_routes_and_shared_subnet) {
    fx_setup(1);
    const struct route *r = route_find(0, IP4(10, 0, 2, 0), 24);
    CHECK(r != NULL);
    CHECK(r->origin == ROUTE_CONNECTED);
    CHECK_EQ_U64(r->port, port_find("p3")->id);
    /* p1 and p2 share 10.0.1.0/24: egress none */
    r = route_find(0, IP4(10, 0, 1, 0), 24);
    CHECK(r != NULL);
    CHECK_EQ_U64(r->port, ROUTE_NO_PORT);
    fx_teardown();
}

TEST(static_neighbour_installs_and_removes_host_route) {
    fx_setup(1);
    const struct route *r = route_find(0, VM1_IP, 32);
    CHECK(r != NULL);
    CHECK(r->origin == ROUTE_HOST);
    CHECK_EQ_U64(r->port, port_find("p1")->id);
    struct cmd_err e;
    CHECK(neigh_del(0, VM1_IP, &e) == 0);
    CHECK(route_find(0, VM1_IP, 32) == NULL);
    fx_teardown();
}

TEST(host_routes_count_toward_capacity) {
    fx_setup(1);
    unsigned before = route_count(); /* 2 connected subnets + 3 host routes */
    CHECK_EQ_U64(before, 5);
    fx_teardown();
}

TEST(route_add_validation) {
    fx_setup(1);
    struct cmd_err e;
    CHECK(run(CMD_CLI, "route add 10.0.9.0/24 dev p3 via 10.0.2.13", &e) == 0);
    const struct route *r = route_lookup(0, IP4(10, 0, 9, 1));
    CHECK(r && r->origin == ROUTE_STATIC && r->gateway == VM3_IP);
    CHECK(run(CMD_CLI, "route add 10.0.9.0/24 dev p3 via 10.0.2.13", &e) == -1);
    CHECK_STR_EQ(e.code, "exists");
    CHECK(run(CMD_CLI, "route add 10.0.8.0/24 dev p3 via 10.0.7.1", &e) == -1); /* outside p3 subnet */
    CHECK_STR_EQ(e.code, "gw-not-connected");
    CHECK(run(CMD_CLI, "route add 10.0.8.1/24 dev p3", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-prefix");
    CHECK(run(CMD_CLI, "route add 10.0.8.0/24 dev p9", &e) == -1);
    CHECK_STR_EQ(e.code, "unknown-port");
    fx_teardown();
}

TEST(route_del_rules) {
    fx_setup(1);
    struct cmd_err e;
    CHECK(route_del(0, IP4(10, 0, 2, 0), 24, &e) == -1); /* connected */
    CHECK_STR_EQ(e.code, "immutable");
    CHECK(route_del(0, VM3_IP, 32, &e) == -1); /* host */
    CHECK_STR_EQ(e.code, "immutable");
    CHECK(route_del(0, IP4(10, 9, 0, 0), 16, &e) == -1);
    CHECK_STR_EQ(e.code, "not-found");
    CHECK(run(CMD_CLI, "route add 10.0.9.0/24 dev p3 via 10.0.2.13", &e) == 0);
    CHECK(route_del(0, IP4(10, 0, 9, 0), 24, &e) == 0);
    CHECK(route_find(0, IP4(10, 0, 9, 0), 24) == NULL);
    fx_teardown();
}

TEST(table_full_at_10000) {
    fx_setup(1);
    struct cmd_err e;
    unsigned n = route_count();
    for (uint32_t i = 0; n < LPM_MAX_RULES; i++, n++)
        CHECK(route_add_static(0, IP4(100, 0, 0, 0) + (i << 8), 24, 0, 0, &e) == 0);
    CHECK(route_add_static(0, IP4(200, 0, 0, 0), 24, 0, 0, &e) == -1);
    CHECK_STR_EQ(e.code, "table-full");
    CHECK_EQ_U64(route_count(), LPM_MAX_RULES);
    fx_teardown();
}

TEST(walk_is_in_prefix_order) {
    fx_setup(1);
    struct collect c = {0};
    route_walk(0, collect_cb, &c);
    CHECK_EQ_U64(c.n, 5);
    for (int i = 1; i < c.n; i++)
        CHECK(c.prefix[i - 1] < c.prefix[i] || (c.prefix[i - 1] == c.prefix[i] && c.len[i - 1] < c.len[i]));
    CHECK_EQ_U64(c.prefix[0], IP4(10, 0, 1, 0)); /* connected before its /32s */
    fx_teardown();
}

/* ---- VRFs and remote routes (phase 2) ---- */

TEST(same_routes_in_two_vrfs_do_not_clash) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    unsigned red = vrf_by_name("red")->id, blue = vrf_by_name("blue")->id;
    /* both tenants have 10.1.1.0/24 connected and 10.1.1.11/32 host */
    const struct route *r = route_find(red, IP4(10, 1, 1, 0), 24);
    const struct route *b = route_find(blue, IP4(10, 1, 1, 0), 24);
    CHECK(r && b && r != b);
    CHECK_EQ_U64(r->port, port_find("red1")->id);
    CHECK_EQ_U64(b->port, port_find("blue1")->id);
    CHECK_EQ_U64(route_lookup(red, IP4(10, 1, 1, 11))->port, port_find("red1")->id);
    CHECK_EQ_U64(route_lookup(blue, IP4(10, 1, 1, 11))->port, port_find("blue1")->id);
    CHECK(route_lookup(0, IP4(10, 1, 1, 11)) == NULL); /* default sees neither */
    /* a static route added in red is invisible in blue */
    struct cmd_err e;
    CHECK(ov_cmd(CMD_CLI, "route add 10.9.0.0/24 vrf red dev red1 via 10.1.1.50", &e) == 0);
    CHECK(route_lookup(red, IP4(10, 9, 0, 1)) != NULL);
    CHECK(route_lookup(blue, IP4(10, 9, 0, 1)) == NULL);
    CHECK_EQ_U64(route_count_vrf(red), 5); /* connected, host, 2 remote, 1 static */
    CHECK_EQ_U64(route_count_vrf(blue), 3); /* connected, host, 1 remote */
    ov_teardown();
}

TEST(dev_must_be_in_the_routes_vrf) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    struct cmd_err e;
    CHECK(ov_cmd(CMD_CLI, "route add 10.9.0.0/24 vrf blue dev red1", &e) == -1);
    CHECK_STR_EQ(e.code, "unknown-port");
    CHECK(ov_cmd(CMD_CLI, "route add 10.9.0.0/24 dev red1", &e) == -1); /* default VRF */
    CHECK_STR_EQ(e.code, "unknown-port");
    CHECK(ov_cmd(CMD_CLI, "route add 10.9.0.0/24 vrf nosuch dev red1", &e) == -1);
    CHECK_STR_EQ(e.code, "unknown-vrf");
    ov_teardown();
}

TEST(remote_route_validation) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    struct cmd_err e;
    enum cmd_where w = CMD_CLI;
    CHECK(ov_cmd(w, "route add 10.7.0.1/32 vrf red node nosuch encap mplsoudp label 100", &e) == -1);
    CHECK_STR_EQ(e.code, "unknown-node");
    CHECK(ov_cmd(w, "route add 10.7.0.1/32 vrf nosuch node cn2 encap mplsoudp label 100", &e) == -1);
    CHECK_STR_EQ(e.code, "unknown-vrf");
    CHECK(ov_cmd(w, "route add 10.7.0.1/32 vrf red node cn2 encap mplsoudp label 15", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(ov_cmd(w, "route add 10.7.0.1/32 vrf red node cn2 encap mplsoudp label 1048576", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(ov_cmd(w, "route add 10.7.0.1/32 vrf red node cn2 encap vxlan vni 0", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(ov_cmd(w, "route add 10.7.0.1/32 vrf red node cn2 encap vxlan vni 16777216", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(ov_cmd(w, "route add 10.7.0.1/32 vrf red node cn2 encap mplsoudp label 16", &e) == 0);
    CHECK(ov_cmd(w, "route add 10.7.0.2/32 vrf red node cn2 encap vxlan vni 16777215", &e) == 0);
    const struct route *r = route_find(vrf_by_name("red")->id, IP4(10, 7, 0, 2), 32);
    CHECK(r && r->kind == NH_REMOTE && r->origin == ROUTE_REMOTE && r->encap == ENCAP_VXLAN);
    CHECK_EQ_U64(r->tag, 16777215);
    /* VXLAN needs the node's router MAC */
    CHECK(ov_cmd(CMD_CONFIG, "node add nomac ip 172.16.0.77", &e) == 0);
    CHECK(ov_cmd(w, "route add 10.7.0.3/32 vrf red node nomac encap vxlan vni 5", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(ov_cmd(w, "route add 10.7.0.3/32 vrf red node nomac encap mplsoudp label 500", &e) == 0);
    ov_teardown();
}

TEST(remote_route_needs_an_underlay) {
    ov_reset();
    port_set_backend(&pio_fake_ops);
    struct cmd_err e;
    CHECK(ov_cmd(CMD_CONFIG, "vrf add red id 1", &e) == 0);
    CHECK(ov_cmd(CMD_CONFIG, "route add 10.7.0.1/32 vrf red node n1 encap mplsoudp label 100", &e) == -1);
    CHECK_STR_EQ(e.code, "no-underlay");
    ov_teardown();
}

TEST(route_replace_is_atomic_and_validated) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    unsigned red = vrf_by_name("red")->id;
    struct cmd_err e;
    const struct route *r = route_lookup(red, IP4(10, 1, 1, 12));
    CHECK(r && r->kind == NH_REMOTE && r->encap == ENCAP_MPLSOUDP && r->tag == 1012);
    const struct route *slot = r;
    CHECK(ov_cmd(CMD_CLI, "route replace 10.1.1.12/32 vrf red node cn2 encap vxlan vni 300", &e) == 0);
    r = route_lookup(red, IP4(10, 1, 1, 12));
    CHECK(r == slot); /* same entry rewritten in place: no window without a route */
    CHECK(r->encap == ENCAP_VXLAN && r->tag == 300);
    CHECK_EQ_U64(route_count_vrf(red), 4); /* connected, host, two remote */
    CHECK(ov_cmd(CMD_CLI, "route replace 10.1.1.12/32 vrf red node cn2 encap vxlan vni 0", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    r = route_lookup(red, IP4(10, 1, 1, 12));
    CHECK(r->tag == 300); /* a failed replace changes nothing */
    CHECK(ov_cmd(CMD_CLI, "route replace 10.8.8.8/32 vrf red node cn2 encap vxlan vni 9", &e) == -1);
    CHECK_STR_EQ(e.code, "not-found");
    CHECK(ov_cmd(CMD_CLI, "route replace 10.1.1.11/32 vrf red dev red1", &e) == -1); /* host route */
    CHECK_STR_EQ(e.code, "immutable");
    /* a remote route can become a local static route and back */
    CHECK(ov_cmd(CMD_CLI, "route replace 10.1.1.12/32 vrf red dev red1 via 10.1.1.40", &e) == 0);
    r = route_lookup(red, IP4(10, 1, 1, 12));
    CHECK(r->kind == NH_LOCAL && r->origin == ROUTE_STATIC && r->gateway == IP4(10, 1, 1, 40));
    ov_teardown();
}

TEST(ten_thousand_routes_in_total_across_vrfs) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    struct cmd_err e;
    unsigned red = vrf_by_name("red")->id, blue = vrf_by_name("blue")->id;
    unsigned n = route_count();
    uint32_t i = 0;
    for (; n < LPM_MAX_RULES; i++, n++)
        CHECK(route_add_remote(i & 1 ? red : blue, IP4(100, 0, 0, 0) + (i << 8), 24,
                               node_find("cn2")->id, ENCAP_MPLSOUDP, 100, &e) == 0);
    CHECK(route_add_remote(red, IP4(200, 0, 0, 0), 24, node_find("cn2")->id, ENCAP_MPLSOUDP, 100,
                           &e) == -1);
    CHECK_STR_EQ(e.code, "table-full");
    CHECK(route_add_remote(blue, IP4(200, 0, 0, 0), 24, node_find("cn2")->id, ENCAP_MPLSOUDP, 100,
                           &e) == -1);
    CHECK_EQ_U64(route_count(), LPM_MAX_RULES);
    ov_teardown();
}
