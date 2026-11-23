#include "ctl_fixture.h"
#include "minivr/ctl_store.h"
#include "minivr/proto.h"
#include "tharness.h"

TEST(shipped_intent_parses) {
    CHECK_EQ_U64(cf_load_intent(), 15);
    CHECK_EQ_U64(cf_m.gen > 0, 1);
}

TEST(names_ids_and_vnis) {
    cm_init(&cf_m);
    CHECK(cli("tenant add red id 1 vni 100 encap mplsoudp") == 0);
    CHECK(cli("tenant add red id 2 vni 200 encap vxlan") == -1);
    CHECK_STR_EQ(cf_err.code, "exists");
    CHECK(cli("tenant add blue id 1 vni 200 encap vxlan") == -1);
    CHECK_STR_EQ(cf_err.code, "exists"); /* id */
    CHECK(cli("tenant add blue id 2 vni 100 encap vxlan") == -1);
    CHECK_STR_EQ(cf_err.code, "exists"); /* vni */
    const char *bad[] = {"tenant add default id 2 vni 2 encap vxlan", "tenant add 1x id 2 vni 2 encap vxlan",
                         "tenant add Red id 2 vni 2 encap vxlan", "tenant add a_very_long_name_x id 2 vni 2 encap vxlan",
                         "tenant add b id 0 vni 2 encap vxlan", "tenant add b id 64 vni 2 encap vxlan",
                         "tenant add b id 2 vni 0 encap vxlan", "tenant add b id 2 vni 16777216 encap vxlan",
                         "tenant add b id 2 vni 2 encap gre", "tenant add b id 2 vni 2"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        CHECK(cli(bad[i]) == -1);
        CHECK_STR_EQ(cf_err.code, "bad-syntax");
    }
    CHECK(cli("tenant add b id 2 vni 16777215 encap vxlan") == 0);
}

TEST(subnets_gateways_and_overlap) {
    cm_init(&cf_m);
    CHECK(cli("tenant add red id 1 vni 100 encap mplsoudp") == 0);
    CHECK(cli("tenant add blue id 2 vni 200 encap vxlan") == 0);
    CHECK(cli("subnet add red 10.1.1.0/24 gw 10.1.1.1") == 0);
    CHECK(cli("subnet add red 10.1.1.128/25 gw 10.1.1.129") == -1);
    CHECK_STR_EQ(cf_err.code, "overlap");
    CHECK(cli("subnet add red 10.0.0.0/8 gw 10.0.0.1") == -1);
    CHECK_STR_EQ(cf_err.code, "overlap");
    CHECK(cli("subnet add blue 10.1.1.0/24 gw 10.1.1.1") == 0); /* other tenants may overlap */
    CHECK(cli("subnet add red 10.1.2.0/7 gw 10.1.2.1") == -1);
    CHECK_STR_EQ(cf_err.code, "bad-prefix");
    CHECK(cli("subnet add red 10.2.0.0/31 gw 10.2.0.1") == -1);
    CHECK_STR_EQ(cf_err.code, "bad-prefix");
    CHECK(cli("subnet add red 10.2.0.1/24 gw 10.2.0.2") == -1);
    CHECK_STR_EQ(cf_err.code, "bad-prefix"); /* host bits */
    CHECK(cli("subnet add red 10.2.0.0/24 gw 10.2.0.0") == -1);
    CHECK_STR_EQ(cf_err.code, "bad-address");
    CHECK(cli("subnet add red 10.2.0.0/24 gw 10.2.0.255") == -1);
    CHECK_STR_EQ(cf_err.code, "bad-address");
    CHECK(cli("subnet add red 10.2.0.0/24 gw 10.9.0.1") == -1);
    CHECK_STR_EQ(cf_err.code, "bad-address");
    CHECK(cli("subnet add nosuch 10.2.0.0/24 gw 10.2.0.1") == -1);
    CHECK_STR_EQ(cf_err.code, "unknown-tenant");
}

TEST(vmi_rules) {
    CHECK_EQ_U64(cf_load_intent(), 15);
    CHECK(cli("vmi add x tenant red ip 10.9.9.9 mac 02:00:00:00:00:01") == -1);
    CHECK_STR_EQ(cf_err.code, "no-subnet");
    CHECK(cli("vmi add x tenant red ip 10.1.1.1 mac 02:00:00:00:00:01") == -1);
    CHECK_STR_EQ(cf_err.code, "bad-address"); /* = gw */
    CHECK(cli("vmi add x tenant red ip 10.1.1.11 mac 02:00:00:00:00:01") == -1);
    CHECK_STR_EQ(cf_err.code, "exists"); /* ip used by red1 in red */
    CHECK(cli("vmi add x tenant blue ip 10.1.1.11 mac 02:00:00:00:00:01") == -1);
    CHECK_STR_EQ(cf_err.code, "exists"); /* blue1 holds it in blue */
    CHECK(cli("vmi add x tenant red ip 10.1.1.99 mac 02:00:00:01:01:11") == -1);
    CHECK_STR_EQ(cf_err.code, "exists"); /* mac used in red */
    CHECK(cli("vmi add x tenant red ip 10.1.1.99 mac 03:00:00:00:00:01") == -1);
    CHECK_STR_EQ(cf_err.code, "bad-mac"); /* multicast */
    CHECK(cli("vmi add red1 tenant red ip 10.1.1.99 mac 02:00:00:00:00:99") == -1);
    CHECK_STR_EQ(cf_err.code, "exists"); /* name */
    CHECK(cli("vmi add x tenant nosuch ip 10.1.1.99 mac 02:00:00:00:00:99") == -1);
    CHECK_STR_EQ(cf_err.code, "unknown-tenant");
    /* the same mac in another tenant is fine */
    CHECK(cli("vmi add x tenant blue ip 10.1.1.77 mac 02:00:00:01:01:11") == 0);
    CHECK(cli("vmi del x") == 0);
    CHECK(cli("vmi del x") == -1);
    CHECK_STR_EQ(cf_err.code, "not-found");
}

TEST(busy_rules_name_what_blocks) {
    CHECK_EQ_U64(cf_load_intent(), 15);
    cf_phase2_bindings();
    CHECK(cli("tenant del red") == -1);
    CHECK_STR_EQ(cf_err.code, "busy");
    CHECK(cli("subnet del red 10.1.1.0/24") == -1);
    CHECK_STR_EQ(cf_err.code, "busy");
    CHECK(cli("vmi del red1") == -1);
    CHECK_STR_EQ(cf_err.code, "busy");
    CHECK(strstr(cf_err.message, "cn1") != NULL); /* names the node */
    CHECK(cli("node del cn1") == -1);
    CHECK_STR_EQ(cf_err.code, "busy");
    cf_m.nodes[2].connected = true;
    CHECK(cli("node del cn3") == -1);
    CHECK_STR_EQ(cf_err.code, "busy"); /* live session */
    CHECK(cli("node forget cn3") == -1);
    CHECK_STR_EQ(cf_err.code, "busy");
    cf_m.nodes[2].connected = false;
    CHECK(cli("node del cn3") == 0);
    CHECK(cli("node forget nosuch") == -1);
    CHECK_STR_EQ(cf_err.code, "unknown-node");
    /* forget drops every binding of the node and its quarantine */
    CHECK(cli("node forget cn1") == 0);
    CHECK_EQ_U64(cm_bound_count(&cf_m, 0), 0);
    CHECK(cli("vmi del red1") == 0);
}

TEST(placement_of_commands) {
    cm_init(&cf_m);
    CHECK(cf_run("tenant set red encap vxlan", CG_FILE) == -1);
    CHECK(cf_run("tenant del red", CG_FILE) == -1);
    CHECK(cf_run("bind v node n port p label 1000", CG_CLI) == -1);
    CHECK(cf_run("bind v node n port p label 1000", CG_FILE) == -1);
    CHECK(cf_run("quarantine node n label 1000", CG_CLI) == -1);
    CHECK(cf_run("tenant show", CG_FILE) == -1);
    CHECK(cf_run("tenant add t id 1 vni 1 encap vxlan", CG_STATE | CG_FILE) == 0);
    CHECK(cf_run("nonsense", CG_CLI) == -1);
    CHECK(cf_run("", CG_CLI) == -1);
}

TEST(capacities) {
    cm_init(&cf_m);
    for (unsigned i = 0; i < 16; i++) {
        char l[64];
        snprintf(l, sizeof l, "node add n%u", i);
        CHECK(cli(l) == 0);
    }
    CHECK(cli("node add n16") == -1);
    CHECK_STR_EQ(cf_err.code, "table-full");
    for (unsigned i = 0; i < 63; i++) {
        char l[96];
        snprintf(l, sizeof l, "tenant add t%u id %u vni %u encap vxlan", i, i + 1, i + 1);
        CHECK(cli(l) == 0);
    }
    CHECK(cli("tenant add tx id 64 vni 99 encap vxlan") == -1); /* id 64 is out of range first */
}

TEST(a_failed_command_leaves_state_unchanged) {
    CHECK_EQ_U64(cf_load_intent(), 15);
    char before[8192], after[8192];
    CHECK(cm_serialize(&cf_m, before, sizeof before) > 0);
    uint64_t gen = cf_m.gen;
    CHECK(cli("vmi add x tenant red ip 10.9.9.9 mac 02:00:00:00:00:01") == -1);
    CHECK(cli("tenant add red id 9 vni 9 encap vxlan") == -1);
    CHECK(cli("subnet add red 10.1.1.0/24 gw 10.1.1.1") == -1);
    CHECK(cm_serialize(&cf_m, after, sizeof after) > 0);
    CHECK_STR_EQ(before, after);
    CHECK_EQ_U64(cf_m.gen, gen);
}

static void fake_node_info(void *arg, unsigned node, struct cg_node_info *out) {
    (void)arg;
    out->state = node == 0 ? "in-sync" : "none";
    if (node == 0) {
        strcpy(out->peer, "10.98.0.1:40000");
        out->in_sync = true;
        out->entries = 12;
        out->msgs_in = 5;
        out->last_seq = 9;
        out->acked_seq = 9;
        out->nerr = 1;
        strcpy(out->errs[0].kind, "route");
        strcpy(out->errs[0].key, "red 10.1.1.12/32");
        strcpy(out->errs[0].code, "entry-rejected");
        strcpy(out->errs[0].text, "exists: key held by cli");
        out->proto_err[PE_ATTR_VALUE] = 2;
    }
}
static void fake_stats(void *arg, struct cg_stats *s) {
    (void)arg;
    s->sessions_accepted = 3;
    s->reject[PC_UNKNOWN_NODE] = 1;
    s->proto_err[PE_TRUNCATED] = 4;
}
static uint64_t fake_uptime(void *arg) { (void)arg; return 77; }
static const struct cg_ops OPS = {fake_node_info, fake_stats, fake_uptime, NULL};

TEST(json_shapes) {
    CHECK_EQ_U64(cf_load_intent(), 15);
    cf_phase2_bindings();
    CHECK(cli("tenant show") == 0);
    CHECK(strstr(cf_out, "{\"name\":\"red\",\"id\":1,\"vni\":100,\"encap\":\"mplsoudp\",\"subnets\":"
                         "[{\"prefix\":\"10.1.1.0/24\",\"gw\":\"10.1.1.1\"},{\"prefix\":\"10.1.2.0/24\","
                         "\"gw\":\"10.1.2.1\"}],\"vmis\":5,\"nodes\":[\"cn1\",\"cn2\"]}"));
    CHECK(cli("vmi show") == 0);
    CHECK(strstr(cf_out, "\"total\":7,\"offset\":0,"));
    CHECK(strstr(cf_out, "{\"name\":\"red1\",\"tenant\":\"red\",\"ip\":\"10.1.1.11\",\"mac\":"
                         "\"02:00:00:01:01:11\",\"state\":\"bound\",\"node\":\"cn1\",\"port\":\"red1\","
                         "\"label\":1000,\"since\":0}"));
    CHECK(strstr(cf_out, "\"name\":\"red5\",\"tenant\":\"red\",\"ip\":\"10.1.2.15\",\"mac\":"
                         "\"02:00:00:01:02:15\",\"state\":\"unbound\",\"node\":null,\"port\":null,"
                         "\"label\":null,\"since\":null}"));
    CHECK(strstr(cf_out, "\"next_offset\":null"));
    CHECK(cli("vmi show tenant blue limit 1") == 0);
    CHECK(strstr(cf_out, "\"total\":2,") && strstr(cf_out, "\"next_offset\":1"));
    CHECK(cli("vmi show tenant nosuch") == -1);
    CHECK_STR_EQ(cf_err.code, "unknown-tenant");

    struct jw w;
    jw_init(&w, cf_out, sizeof cf_out);
    CHECK(cg_exec(&cf_m, "node show", CG_CLI, &OPS, &w, &cf_err) == 0);
    CHECK(strstr(cf_out, "{\"name\":\"cn1\",\"underlay_ip\":\"172.16.0.1\",\"rmac\":\"02:00:00:ff:00:01\","
                         "\"session\":{\"state\":\"in-sync\",\"peer\":\"10.98.0.1:40000\",\"since\":0,"
                         "\"last_error\":null,\"msgs_in\":5,\"msgs_out\":0,\"bytes_in\":0,\"bytes_out\":0,"
                         "\"last_seq\":9,\"acked_seq\":9},\"in_sync\":true,\"entries\":12,"
                         "\"entry_errors\":[{\"kind\":\"route\",\"key\":\"red 10.1.1.12/32\","
                         "\"code\":\"entry-rejected\",\"text\":\"exists: key held by cli\"}],"
                         "\"proto_errors\":{\"truncated\":0,"));
    CHECK(strstr(cf_out, "\"attr-value\":2"));
    CHECK(strstr(cf_out, "{\"name\":\"cn3\",\"underlay_ip\":null,\"rmac\":null,\"session\":{\"state\":\"none\""));

    CHECK(cli("node state cn1") == 0);
    CHECK(strstr(cf_out, "\"node\":\"cn1\",\"total\":"));
    CHECK(strstr(cf_out, "{\"kind\":\"vrf\",\"name\":\"blue\",\"id\":2}"));
    CHECK(strstr(cf_out, "{\"kind\":\"route\",\"vrf\":\"red\",\"prefix\":\"10.1.1.12/32\",\"node\":\"cn2\","
                         "\"encap\":\"mplsoudp\",\"tag\":1000}"));
    CHECK(cli("node state cn1 limit 3") == 0);
    CHECK(strstr(cf_out, "\"next_offset\":3"));
    CHECK(cli("node state nosuch") == -1);
    CHECK_STR_EQ(cf_err.code, "unknown-node");

    jw_init(&w, cf_out, sizeof cf_out);
    CHECK(cg_exec(&cf_m, "stats show", CG_CLI, &OPS, &w, &cf_err) == 0);
    CHECK(strstr(cf_out, "\"sessions\":{\"accepted\":3,\"rejected\":0,\"rejected_by_reason\":{"));
    CHECK(strstr(cf_out, "\"unknown-node\":1"));
    CHECK(strstr(cf_out, "\"state_write_errors\":0"));
    CHECK(strstr(cf_out, "\"updates_sent\":0") && strstr(cf_out, "\"truncated\":4"));
    jw_init(&w, cf_out, sizeof cf_out);
    CHECK(cg_exec(&cf_m, "version", CG_CLI, &OPS, &w, &cf_err) == 0);
    CHECK(strstr(cf_out, "\"daemon\":\"minivr-ctld\",\"protocol\":1,\"wire\":1,\"version\":\"0.1.0\","
                         "\"uptime_s\":77"));
}
