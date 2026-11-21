#include "fixture.h"
#include "overlay_fixture.h"
#include "tharness.h"

static int run(const char *line, struct cmd_err *e) {
    char buf[256];
    struct jw w;
    jw_init(&w, buf, sizeof buf);
    return cmd_exec(line, CMD_CONFIG, &w, e);
}

TEST(sixteen_vm_ports_then_table_full) {
    fx_setup(1);
    port_reset();
    pio_fake_reset();
    struct cmd_err e;
    for (int i = 0; i < MAX_VM_PORTS; i++) {
        char name[16], line[128];
        uint8_t mac[6] = {2, 0, 0, 0, 9, (uint8_t)i};
        snprintf(name, sizeof name, "q%d", i);
        pio_fake_add_if(name, mac, 1500);
        snprintf(line, sizeof line, "port add %s ifname %s ip 10.%d.0.1/24", name, name, 100 + i);
        if (run(line, &e) != 0)
            TH_FAIL("port %d refused: %s", i, e.message);
    }
    CHECK_EQ_U64(port_count(), MAX_VM_PORTS);
    uint8_t mac[6] = {2, 0, 0, 0, 9, 99};
    pio_fake_add_if("q16", mac, 1500);
    CHECK(run("port add q16 ifname q16 ip 10.200.0.1/24", &e) == -1);
    CHECK_STR_EQ(e.code, "table-full");
    fx_teardown();
}

TEST(port_add_validation) {
    fx_setup(1);
    struct cmd_err e;
    CHECK(run("port add p1 ifname p9 ip 10.9.9.1/24", &e) == -1); /* name taken */
    CHECK_STR_EQ(e.code, "exists");
    CHECK(run("port add px ifname p1 ip 10.9.9.1/24", &e) == -1); /* interface already used */
    CHECK_STR_EQ(e.code, "exists");
    CHECK(run("port add px ifname nosuch ip 10.9.9.1/24", &e) == -1);
    CHECK_STR_EQ(e.code, "not-found");
    uint8_t mac[6] = {2, 0, 0, 0, 7, 7};
    pio_fake_add_if("x1", mac, 1500);
    /* the anycast address may be shared only with an identical prefix */
    CHECK(run("port add px ifname x1 ip 10.0.1.1/16", &e) == -1);
    CHECK_STR_EQ(e.code, "exists");
    CHECK(run("port add px ifname x1 ip 10.0.1.1/24", &e) == 0);
    CHECK(run("port add averyveryverylongportname ifname x1 ip 10.9.9.1/24", &e) == -1);
    fx_teardown();
}

TEST(port_reads_mac_and_mtu_from_the_interface) {
    fx_setup(1);
    const struct port *p = port_find("p2");
    CHECK_MEM_EQ(p->mac, MAC_P2, 6);
    CHECK_EQ_U64(p->mtu, 1500);
    CHECK(p->admin_up && p->oper_up);
    CHECK_EQ_U64(port_netmask(p), 0xffffff00);
    fx_teardown();
}

/* ---- roles and VRFs (phase 2) ---- */

static void mk_if(const char *n, int idx) {
    uint8_t mac[6] = {2, 0, 0, 0, 0x33, (uint8_t)idx};
    pio_fake_add_if(n, mac, 1500);
}

TEST(at_most_one_underlay) {
    ov_reset();
    port_set_backend(&pio_fake_ops);
    mk_if("u0", 1);
    mk_if("u1", 2);
    struct cmd_err e;
    CHECK(run("underlay add u0 ifname u0 ip 172.16.0.1/24", &e) == 0);
    CHECK(port_underlay() != NULL && port_underlay()->role == PORT_UNDERLAY);
    CHECK(run("underlay add u1 ifname u1 ip 172.17.0.1/24", &e) == -1);
    CHECK_STR_EQ(e.code, "exists");
    CHECK_EQ_U64(route_count(), 0); /* the underlay is in no VRF: no connected route */
    ov_teardown();
}

TEST(sixteen_vm_ports_plus_the_underlay) {
    ov_reset();
    port_set_backend(&pio_fake_ops);
    struct cmd_err e;
    char name[16], line[128];
    for (int i = 0; i < MAX_VM_PORTS; i++) {
        snprintf(name, sizeof name, "q%d", i);
        mk_if(name, i);
        snprintf(line, sizeof line, "port add %s ifname %s ip 10.%d.0.1/24", name, name, 100 + i);
        CHECK(run(line, &e) == 0);
    }
    mk_if("u0", 90);
    CHECK(run("underlay add u0 ifname u0 ip 172.16.0.1/24", &e) == 0); /* the 17th */
    CHECK_EQ_U64(port_count(), MAX_PORTS);
    mk_if("q16", 91);
    CHECK(run("port add q16 ifname q16 ip 10.200.0.1/24", &e) == -1);
    CHECK_STR_EQ(e.code, "table-full");
    ov_teardown();
}

TEST(gateway_may_repeat_across_vrfs_but_not_with_another_prefix_in_one) {
    ov_reset();
    port_set_backend(&pio_fake_ops);
    for (int i = 0; i < 4; i++) {
        char n[24];
        snprintf(n, sizeof n, "a%d", i);
        mk_if(n, i);
    }
    struct cmd_err e;
    CHECK(run("vrf add red id 1", &e) == 0);
    CHECK(run("vrf add blue id 2", &e) == 0);
    CHECK(run("port add a0 ifname a0 ip 10.1.1.1/24 vrf red", &e) == 0);
    CHECK(run("port add a1 ifname a1 ip 10.1.1.1/24 vrf blue", &e) == 0);
    CHECK(run("port add a2 ifname a2 ip 10.1.1.1/16 vrf red", &e) == -1); /* phase 1 rule in a VRF */
    CHECK_STR_EQ(e.code, "exists");
    CHECK(run("port add a2 ifname a2 ip 10.1.1.1/16 vrf blue", &e) == -1);
    CHECK_STR_EQ(e.code, "exists");
    CHECK(run("port add a2 ifname a2 ip 10.1.1.1/16 vrf default", &e) == 0); /* a third VRF is free */
    CHECK(run("port add a3 ifname a3 ip 10.2.2.1/24 vrf nosuch", &e) == -1);
    CHECK_STR_EQ(e.code, "unknown-vrf");
    CHECK(port_by_ip(1, IP4(10, 1, 1, 1)) == port_find("a0"));
    CHECK(port_by_ip(2, IP4(10, 1, 1, 1)) == port_find("a1"));
    CHECK(port_by_ip(3, IP4(10, 1, 1, 1)) == NULL);
    ov_teardown();
}

TEST(port_set_vrf_moves_static_neighbour_and_routes_and_flushes_learned) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    struct cmd_err e;
    unsigned red = vrf_by_name("red")->id, blue = vrf_by_name("blue")->id;
    CHECK(ov_cmd(CMD_CLI, "vrf add green id 3", &e) == 0);
    unsigned green = vrf_by_name("green")->id;
    struct port *p = port_find("red1");
    neigh_learn(IP4(10, 1, 1, 50), OV_RED2, p->id); /* learned: must go */
    CHECK(neigh_lookup(red, IP4(10, 1, 1, 50)) != NULL);
    /* red1 holds 10.1.1.0/24 with the static 10.1.1.11 */
    CHECK(ov_cmd(CMD_CLI, "route add 10.9.0.0/24 vrf red dev red1", &e) == 0);
    CHECK(ov_cmd(CMD_CLI, "port set red1 vrf green", &e) == -1); /* a static route still names it */
    CHECK_STR_EQ(e.code, "busy");
    CHECK(ov_cmd(CMD_CLI, "route del 10.9.0.0/24 vrf red", &e) == 0);
    CHECK(ov_cmd(CMD_CLI, "port set red1 vrf green", &e) == 0);
    CHECK_EQ_U64(p->vrf, green);
    CHECK(neigh_lookup(red, IP4(10, 1, 1, 50)) == NULL);   /* flushed */
    CHECK(neigh_lookup(red, IP4(10, 1, 1, 11)) == NULL);   /* the static one left red ... */
    const struct neigh *n = neigh_lookup(green, IP4(10, 1, 1, 11));
    CHECK(n && n->kind == NEIGH_STATIC);                    /* ... and arrived in green */
    CHECK_MEM_EQ(n->mac, OV_RED1, 6);
    CHECK(route_find(green, IP4(10, 1, 1, 11), 32) != NULL);
    CHECK(route_find(red, IP4(10, 1, 1, 11), 32) == NULL);
    CHECK(route_find(green, IP4(10, 1, 1, 0), 24) != NULL);
    CHECK(route_find(red, IP4(10, 1, 1, 0), 24) == NULL);  /* the only port on it left red */
    uint32_t bip;
    uint8_t bmac[6];
    CHECK(neigh_binding(p->id, &bip, bmac) && bip == IP4(10, 1, 1, 11)); /* anti-spoof binding kept */
    (void)blue;
    CHECK(ov_cmd(CMD_CLI, "port set red1 vrf nosuch", &e) == -1);
    CHECK_STR_EQ(e.code, "unknown-vrf");
    CHECK(ov_cmd(CMD_CLI, "port set u0 vrf red", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    ov_teardown();
}

TEST(port_set_vrf_refuses_a_clash_and_changes_nothing) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    struct cmd_err e;
    /* blue already has 10.1.1.11 static (from blue1): moving red1 there clashes */
    CHECK(ov_cmd(CMD_CLI, "port set red1 vrf blue", &e) == -1);
    CHECK_STR_EQ(e.code, "exists");
    CHECK_EQ_U64(port_find("red1")->vrf, vrf_by_name("red")->id);
    CHECK(neigh_lookup(vrf_by_name("red")->id, IP4(10, 1, 1, 11)) != NULL);
    CHECK(route_find(vrf_by_name("red")->id, IP4(10, 1, 1, 11), 32) != NULL);
    ov_teardown();
}
