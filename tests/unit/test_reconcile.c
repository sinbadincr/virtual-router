#include <string.h>

#include "minivr/reconcile.h"
#include "tharness.h"

static struct reconciler rc;
static struct nentry have_s[RC_CAP];
static struct nstate have;
static struct rc_cmd cmds[512];
static struct rc_conflict conf[16];

static struct nentry vrf(const char *n, unsigned id) {
    struct nentry e; memset(&e, 0, sizeof e);
    e.kind = NE_VRF; strcpy(e.name, n); e.id = (uint8_t)id; return e;
}
static struct nentry vni(uint32_t v, const char *r) {
    struct nentry e; memset(&e, 0, sizeof e);
    e.kind = NE_VNI; e.vni = v; strcpy(e.vrf, r); return e;
}
static struct nentry node(const char *n, uint32_t ip, uint8_t rm) {
    struct nentry e; memset(&e, 0, sizeof e);
    e.kind = NE_NODE; strcpy(e.name, n); e.ip = ip; e.rmac[0] = 2; e.rmac[5] = rm; return e;
}
static struct nentry port(const char *n, const char *r, uint32_t gw, unsigned plen) {
    struct nentry e; memset(&e, 0, sizeof e);
    e.kind = NE_PORT; strcpy(e.name, n); strcpy(e.vrf, r); e.prefix = gw; e.plen = (uint8_t)plen; return e;
}
static struct nentry neigh(const char *r, uint32_t ip, const char *p) {
    struct nentry e; memset(&e, 0, sizeof e);
    e.kind = NE_NEIGH; strcpy(e.vrf, r); e.ip = ip; e.mac[0] = 2; e.mac[5] = 0x11; strcpy(e.port, p); return e;
}
static struct nentry label(uint32_t l, const char *p) {
    struct nentry e; memset(&e, 0, sizeof e);
    e.kind = NE_LABEL; e.label = l; strcpy(e.port, p); return e;
}
static struct nentry route(const char *r, uint32_t pfx, const char *n, uint32_t tag) {
    struct nentry e; memset(&e, 0, sizeof e);
    e.kind = NE_ROUTE; strcpy(e.vrf, r); e.prefix = pfx; e.plen = 32; strcpy(e.node, n);
    e.encap = NE_ENCAP_MPLSOUDP; e.tag = tag; return e;
}

static void reset(void) {
    rc_init(&rc);
    ns_init(&have, have_s, RC_CAP);
}

/* a complete sync of `n` entries */
static void sync_want(const struct nentry *e, unsigned n) {
    rc_sync_begin(&rc, 1);
    CHECK(rc_update(&rc, NULL, 0, e, n) == 0);
    CHECK(rc_sync_end(&rc, 1) == 0);
}

static int plan(unsigned *nconf) {
    return rc_plan(&rc, &have, cmds, 512, conf, 16, nconf);
}

static void expect(int idx, const char *text) {
    if (strcmp(cmds[idx].text, text) != 0)
        TH_FAIL("cmd %d: \"%s\" != \"%s\"", idx, cmds[idx].text, text);
}

static const uint32_t IP11 = 0x0a01010bu, IP12 = 0x0a01010cu, GW = 0x0a010101u;

TEST(adds_go_in_dependency_order_with_the_contract_command_text) {
    reset();
    struct nentry want[] = {route("red", IP12, "cn2", 1012), label(1000, "red1"), neigh("red", IP11, "red1"),
                            port("red1", "red", GW, 24), node("cn2", 0xac100002u, 2), vni(100, "red"), vrf("red", 1)};
    sync_want(want, 7);
    unsigned nc;
    CHECK_EQ_U64(plan(&nc), 7);
    expect(0, "vrf add red id 1");
    expect(1, "node add cn2 ip 172.16.0.2 rmac 02:00:00:00:00:02");
    expect(2, "port add red1 ifname red1 ip 10.1.1.1/24 vrf red fd");
    CHECK(cmds[2].is_port_add);
    expect(3, "neigh add 10.1.1.11 lladdr 02:00:00:00:00:11 dev red1");
    CHECK(cmds[4].entry.kind == NE_LABEL || cmds[4].entry.kind == NE_VNI);
    CHECK(cmds[5].entry.kind == NE_LABEL || cmds[5].entry.kind == NE_VNI);
    expect(6, "route add 10.1.1.12/32 vrf red node cn2 encap mplsoudp label 1012");
    CHECK_EQ_U64(nc, 0);
}

TEST(deletes_precede_adds_in_reverse_dependency_order) {
    reset();
    struct nentry h[] = {vrf("blue", 2), vni(200, "blue"), port("blue1", "blue", GW, 24), neigh("blue", IP11, "blue1"),
                         label(1001, "blue1"), node("cn2", 0xac100002u, 2), route("blue", IP12, "cn2", 200)};
    for (int i = 0; i < 7; i++) ns_put(&have, &h[i]);
    struct nentry w = vrf("red", 1);
    sync_want(&w, 1);
    unsigned nc;
    CHECK_EQ_U64(plan(&nc), 8);
    expect(0, "route del 10.1.1.12/32 vrf blue");
    CHECK(cmds[1].entry.kind == NE_LABEL || cmds[1].entry.kind == NE_VNI);
    CHECK(cmds[2].entry.kind == NE_LABEL || cmds[2].entry.kind == NE_VNI);
    expect(3, "neigh del 10.1.1.11 vrf blue");
    expect(4, "port del blue1");
    expect(5, "node del cn2");
    expect(6, "vrf del blue");
    expect(7, "vrf add red id 1");
    CHECK(cmds[0].is_del && !cmds[7].is_del);
}

TEST(a_port_whose_vrf_or_gateway_changes_is_cycled_with_its_dependents) {
    reset();
    struct nentry h[] = {vrf("red", 1), port("red1", "red", GW, 24), neigh("red", IP11, "red1"), label(1000, "red1")};
    for (int i = 0; i < 4; i++) ns_put(&have, &h[i]);
    struct nentry w[] = {vrf("red", 1), port("red1", "red", 0x0a010201u, 24), neigh("red", IP11, "red1"), label(1000, "red1")};
    sync_want(w, 4);
    unsigned nc;
    int n = plan(&nc);
    CHECK_EQ_U64(n, 6); /* del neigh, del label, del port, add port, add neigh, add label */
    int dels = 0;
    for (int i = 0; i < n; i++) dels += cmds[i].is_del;
    CHECK_EQ_U64(dels, 3);
    CHECK(cmds[2].is_del && cmds[2].entry.kind == NE_PORT);
    expect(3, "port add red1 ifname red1 ip 10.1.2.1/24 vrf red fd");
    CHECK(cmds[4].entry.kind == NE_NEIGH && !cmds[4].is_del);
    CHECK(cmds[5].entry.kind == NE_LABEL && !cmds[5].is_del);
}

TEST(a_changed_route_is_replaced_in_place_and_a_changed_rmac_uses_node_set) {
    reset();
    struct nentry h[] = {vrf("red", 1), node("cn2", 0xac100002u, 2), route("red", IP12, "cn2", 1012)};
    for (int i = 0; i < 3; i++) ns_put(&have, &h[i]);
    struct nentry w[] = {vrf("red", 1), node("cn2", 0xac100002u, 9), route("red", IP12, "cn2", 1500)};
    sync_want(w, 3);
    unsigned nc;
    CHECK_EQ_U64(plan(&nc), 2);
    expect(0, "node set cn2 rmac 02:00:00:00:00:09");
    expect(1, "route replace 10.1.1.12/32 vrf red node cn2 encap mplsoudp label 1500");
}

TEST(keys_owned_by_config_or_cli_are_conflicts_never_commands) {
    reset();
    struct nentry f = route("red", IP12, "cn2", 7);
    f.node[0] = 0;
    ns_put(&rc.foreign, &f);
    struct nentry w[] = {vrf("red", 1), route("red", IP12, "cn2", 1012), route("red", 0x0a01020du, "cn2", 1013)};
    sync_want(w, 3);
    unsigned nc;
    CHECK_EQ_U64(plan(&nc), 2); /* vrf add + the other route */
    CHECK_EQ_U64(nc, 1);
    CHECK_EQ_U64(conf[0].entry.prefix, IP12);
    for (int i = 0; i < 2; i++) CHECK(strstr(cmds[i].text, "10.1.1.12") == NULL);
}

TEST(full_sync_goes_to_pending_and_nothing_is_deleted_before_sync_end) {
    reset();
    struct nentry h = vrf("old", 3);
    ns_put(&have, &h);
    unsigned nc;
    CHECK_EQ_U64(plan(&nc), 0); /* a fresh agent has no want: no deletes */
    rc_sync_begin(&rc, 7);
    struct nentry a = vrf("red", 1);
    CHECK(rc_update(&rc, NULL, 0, &a, 1) == 0);
    CHECK_EQ_U64(plan(&nc), 0); /* still syncing: want is empty and invalid */
    CHECK(rc_sync_end(&rc, 8) == -1); /* wrong GEN */
    CHECK(rc.syncing);
    CHECK(rc_sync_end(&rc, 7) == 0);
    CHECK_EQ_U64(plan(&nc), 2); /* now: del old, add red */
    expect(0, "vrf del old");
    expect(1, "vrf add red id 1");
}

TEST(session_lost_while_syncing_discards_pending_and_keeps_want) {
    reset();
    struct nentry a = vrf("red", 1);
    sync_want(&a, 1);
    rc_sync_begin(&rc, 2);
    struct nentry b = vrf("blue", 2);
    rc_update(&rc, NULL, 0, &b, 1);
    rc_session_lost(&rc);
    CHECK(!rc.syncing);
    CHECK_EQ_U64(rc.pending.n, 0);
    CHECK_EQ_U64(rc.want.n, 1);
    CHECK_STR_EQ(rc.want.e[0].name, "red");
}

TEST(a_new_boot_id_means_empty_have_and_the_full_add_list_an_adopted_state_means_no_commands) {
    reset();
    struct nentry w[] = {vrf("red", 1), vni(100, "red"), port("red1", "red", GW, 24)};
    sync_want(w, 3);
    unsigned nc;
    CHECK_EQ_U64(plan(&nc), 3); /* forwarder restarted: everything again, in order */
    expect(0, "vrf add red id 1");
    for (int i = 0; i < 3; i++) ns_put(&have, &w[i]);
    CHECK_EQ_U64(plan(&nc), 0); /* agent restart with have == want: adopt, no flush */
}

TEST(incremental_updates_apply_to_want_after_sync_end) {
    reset();
    struct nentry a = vrf("red", 1);
    sync_want(&a, 1);
    struct nentry b = vrf("blue", 2);
    CHECK(rc_update(&rc, &a, 1, &b, 1) == 0);
    CHECK_EQ_U64(rc.want.n, 1);
    CHECK_STR_EQ(rc.want.e[0].name, "blue");
}

TEST(backoff_sequence_and_reset) {
    struct backoff b;
    backoff_reset(&b);
    unsigned want[] = {500, 1000, 2000, 4000, 5000, 5000, 5000};
    for (int i = 0; i < 7; i++)
        CHECK_EQ_U64(backoff_next(&b), want[i]);
    backoff_reset(&b);
    CHECK_EQ_U64(backoff_next(&b), 500);
}
