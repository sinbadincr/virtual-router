#include "overlay_fixture.h"
#include "tharness.h"

static int cfg(const char *line, struct cmd_err *e) {
    return ov_cmd(CMD_CONFIG, line, e);
}
static int cli(const char *line, struct cmd_err *e) {
    return ov_cmd(CMD_CLI, line, e);
}

/* cn1 with nothing else but the underlay and two VM ports in red: a blank tunnel state. */
static void bare(void) {
    ov_reset();
    uint8_t mac[6];
    for (int i = 0; i < 3; i++) {
        char n[24];
        snprintf(n, sizeof n, "v%d", i);
        ov_port_mac(mac, 1, i + 1);
        pio_fake_add_if(n, mac, 1500);
    }
    pio_fake_add_if("u0", OV_UL_MAC1, 1600);
    port_set_backend(&pio_fake_ops);
    struct cmd_err e;
    CHECK(cfg("vrf add red id 1", &e) == 0);
    CHECK(cfg("underlay add u0 ifname u0 ip 172.16.0.1/24", &e) == 0);
    CHECK(cfg("port add v0 ifname v0 ip 10.1.1.1/24 vrf red", &e) == 0);
    CHECK(cfg("port add v1 ifname v1 ip 10.1.2.1/24 vrf red", &e) == 0);
}

TEST(node_validation) {
    bare();
    struct cmd_err e;
    CHECK(cfg("node add n1 ip 172.16.0.2", &e) == 0);
    CHECK(node_find("n1") != NULL && !node_find("n1")->has_rmac);
    CHECK(cfg("node add n1 ip 172.16.0.3", &e) == -1);
    CHECK_STR_EQ(e.code, "exists");
    CHECK(cfg("node add n9 ip 192.168.0.2", &e) == -1); /* outside the underlay subnet */
    CHECK_STR_EQ(e.code, "bad-prefix");
    CHECK(cfg("node add averyveryverylongnodename ip 172.16.0.5", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(cli("node set n1 rmac 02:00:00:ff:00:02", &e) == 0);
    CHECK(node_find("n1")->has_rmac);
    CHECK(cli("node set nosuch rmac 02:00:00:ff:00:02", &e) == -1);
    CHECK_STR_EQ(e.code, "unknown-node");
    CHECK_EQ_U64(node_id_by_ip(IP4(172, 16, 0, 2)), node_find("n1")->id);
    CHECK_EQ_U64(node_id_by_ip(IP4(172, 16, 0, 77)), NODE_UNKNOWN);
    ov_teardown();
}

TEST(node_needs_underlay) {
    ov_reset();
    port_set_backend(&pio_fake_ops);
    struct cmd_err e;
    CHECK(cfg("node add n1 ip 172.16.0.2", &e) == -1);
    CHECK_STR_EQ(e.code, "no-underlay");
    ov_teardown();
}

TEST(at_most_64_nodes) {
    bare();
    struct cmd_err e;
    char line[64];
    for (int i = 0; i < TUNNEL_MAX_NODES; i++) {
        snprintf(line, sizeof line, "node add n%d ip 172.16.0.%d", i, 100 + i);
        CHECK(cfg(line, &e) == 0);
    }
    CHECK(cfg("node add extra ip 172.16.0.250", &e) == -1);
    CHECK_STR_EQ(e.code, "table-full");
    ov_teardown();
}

TEST(node_del_is_busy_while_a_route_uses_it) {
    bare();
    struct cmd_err e;
    CHECK(cfg("node add n1 ip 172.16.0.2 rmac 02:00:00:ff:00:02", &e) == 0);
    CHECK(cfg("route add 10.1.1.12/32 vrf red node n1 encap mplsoudp label 1012", &e) == 0);
    CHECK(cli("node del n1", &e) == -1);
    CHECK_STR_EQ(e.code, "busy");
    CHECK(cli("route del 10.1.1.12/32 vrf red", &e) == 0);
    CHECK(cli("node del n1", &e) == 0);
    CHECK(node_find("n1") == NULL);
    ov_teardown();
}

TEST(label_validation) {
    bare();
    struct cmd_err e;
    CHECK(cfg("label add 1011 port v0", &e) == 0);
    CHECK_EQ_U64(label_lookup(1011), port_find("v0")->id);
    CHECK(label_lookup(1012) == -1);
    CHECK(cfg("label add 1011 port v1", &e) == -1);
    CHECK_STR_EQ(e.code, "exists");
    CHECK(cfg("label add 15 port v0", &e) == -1); /* 0..15 reserved */
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(cfg("label add 1048576 port v0", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(cfg("label add 16 port v0", &e) == 0);
    CHECK(cfg("label add 1048575 port v0", &e) == 0);
    CHECK(cfg("label add 2000 port u0", &e) == -1); /* the underlay is not a VM port */
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(cfg("label add 2000 port nosuch", &e) == -1);
    CHECK_STR_EQ(e.code, "unknown-port");
    CHECK(cli("label del 1011", &e) == 0);
    CHECK(label_lookup(1011) == -1);
    CHECK(cli("label del 1011", &e) == -1);
    CHECK_STR_EQ(e.code, "not-found");
    ov_teardown();
}

TEST(a_port_may_have_several_labels_and_deleting_it_removes_them) {
    bare();
    struct cmd_err e;
    CHECK(cfg("label add 100 port v0", &e) == 0);
    CHECK(cfg("label add 101 port v0", &e) == 0);
    CHECK(cfg("label add 200 port v1", &e) == 0);
    CHECK_EQ_U64(label_count(), 3);
    label_del_port(port_find("v0")->id);
    CHECK_EQ_U64(label_count(), 1);
    CHECK(label_lookup(100) == -1 && label_lookup(101) == -1);
    CHECK(label_lookup(200) >= 0);
    ov_teardown();
}

TEST(label_table_holds_1024_and_survives_churn_with_tombstones) {
    bare();
    struct cmd_err e;
    uint8_t p0 = port_find("v0")->id;
    for (uint32_t i = 0; i < LABEL_MAX_MAPPINGS; i++)
        CHECK(label_add(16 + i, p0, &e) == 0);
    CHECK(label_add(5000, p0, &e) == -1);
    CHECK_STR_EQ(e.code, "table-full");
    /* delete and re-add many times: tombstones must not break lookups or fill the table */
    for (int round = 0; round < 5; round++) {
        for (uint32_t i = 0; i < LABEL_MAX_MAPPINGS; i += 2)
            CHECK(label_del(16 + i, &e) == 0);
        for (uint32_t i = 0; i < LABEL_MAX_MAPPINGS; i += 2)
            CHECK(label_add(16 + i, p0, &e) == 0);
    }
    for (uint32_t i = 0; i < LABEL_MAX_MAPPINGS; i++)
        CHECK(label_lookup(16 + i) == p0);
    CHECK(label_lookup(5000) == -1);
    CHECK_EQ_U64(label_count(), LABEL_MAX_MAPPINGS);
    ov_teardown();
}

TEST(vni_validation) {
    bare();
    struct cmd_err e;
    CHECK(cfg("vni add 200 vrf red", &e) == 0);
    CHECK_EQ_U64(vni_lookup(200), vrf_by_name("red")->id);
    CHECK(vni_lookup(201) == -1);
    CHECK(cfg("vni add 200 vrf default", &e) == -1);
    CHECK_STR_EQ(e.code, "exists");
    CHECK(cfg("vni add 0 vrf red", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(cfg("vni add 16777216 vrf red", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(cfg("vni add 16777215 vrf red", &e) == 0);
    CHECK(cfg("vni add 5 vrf nosuch", &e) == -1);
    CHECK_STR_EQ(e.code, "unknown-vrf");
    CHECK(cli("vni del 200", &e) == 0);
    CHECK(vni_lookup(200) == -1);
    CHECK(cli("vni del 200", &e) == -1);
    CHECK_STR_EQ(e.code, "not-found");
    ov_teardown();
}

TEST(at_most_64_vnis) {
    bare();
    struct cmd_err e;
    for (uint32_t i = 1; i <= VNI_MAX_MAPPINGS; i++)
        CHECK(vni_add(i, 1, &e) == 0);
    CHECK(vni_add(1000, 1, &e) == -1);
    CHECK_STR_EQ(e.code, "table-full");
    ov_teardown();
}

TEST(shipped_configs_load) {
    struct cmd_err e;
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    CHECK(port_underlay() != NULL);
    CHECK_EQ_U64(label_lookup(1011), port_find("red1")->id);
    CHECK_EQ_U64(vni_lookup(200), vrf_by_name("blue")->id);
    CHECK(cli("node del cn2", &e) == -1); /* its routes use it */
    ov_teardown();
    CHECK_EQ_U64(ov_setup(2, 1600), 0);
    CHECK_EQ_U64(label_lookup(1013), port_find("red3")->id);
    ov_teardown();
}
