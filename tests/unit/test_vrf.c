#include "fixture.h"
#include "tharness.h"
#include "minivr/tunnel.h"
#include "minivr/vrf.h"

static int run(const char *line, struct cmd_err *e) {
    char buf[512];
    struct jw w;
    jw_init(&w, buf, sizeof buf);
    return cmd_exec(line, CMD_BOTH, &w, e);
}
static int cli(const char *line, struct cmd_err *e) {
    char buf[512];
    struct jw w;
    jw_init(&w, buf, sizeof buf);
    return cmd_exec(line, CMD_CLI, &w, e);
}

TEST(default_exists_and_is_immutable) {
    fx_setup(1);
    struct cmd_err e;
    const struct vrf *d = vrf_by_id(0);
    CHECK(d != NULL);
    CHECK_STR_EQ(d->name, "default");
    CHECK(vrf_by_name("default") == d);
    CHECK(cli("vrf del default", &e) == -1);
    CHECK_STR_EQ(e.code, "immutable");
    fx_teardown();
}

TEST(add_validates_name_and_id) {
    fx_setup(1);
    struct cmd_err e;
    CHECK(run("vrf add red id 1", &e) == 0);
    CHECK(vrf_by_id(1) == vrf_by_name("red"));
    CHECK(vrf_by_id(1)->id == 1);
    CHECK(run("vrf add Red id 2", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(run("vrf add has.dot id 2", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(run("vrf add averyveryverylongvrfname id 2", &e) == -1); /* 16 chars */
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(run("vrf add ok-name_1 id 2", &e) == 0);
    CHECK(run("vrf add x id 0", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(run("vrf add x id 64", &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(run("vrf add red id 3", &e) == -1); /* duplicate name */
    CHECK_STR_EQ(e.code, "exists");
    CHECK(run("vrf add other id 1", &e) == -1); /* duplicate id */
    CHECK_STR_EQ(e.code, "exists");
    fx_teardown();
}

TEST(sixty_fourth_ok_sixty_fifth_table_full) {
    fx_setup(1);
    struct cmd_err e;
    char line[64];
    for (int i = 1; i < VRF_MAX; i++) {
        snprintf(line, sizeof line, "vrf add v%d id %d", i, i);
        CHECK(run(line, &e) == 0);
    }
    CHECK_EQ_U64(vrf_count(), VRF_MAX);
    CHECK(run("vrf add extra id 5", &e) == -1);
    CHECK_STR_EQ(e.code, "table-full");
    CHECK(vrf_del("v5", &e) == 0);
    CHECK(run("vrf add extra id 5", &e) == 0);
    CHECK(run("vrf add extra2 id 63", &e) == -1);
    CHECK_STR_EQ(e.code, "table-full");
    fx_teardown();
}

TEST(del_is_busy_while_referenced) {
    fx_setup(1);
    struct cmd_err e;
    uint8_t mac[6] = {2, 0, 0, 0, 5, 5};
    pio_fake_add_if("r1", mac, 1500);
    CHECK(run("vrf add red id 1", &e) == 0);
    CHECK(run("port add r1 ifname r1 ip 10.5.0.1/24 vrf red", &e) == 0);
    CHECK(cli("vrf del red", &e) == -1); /* a port */
    CHECK_STR_EQ(e.code, "busy");
    CHECK(run("route add 10.6.0.0/24 vrf red dev r1", &e) == 0);
    CHECK(run("vni add 100 vrf red", &e) == 0);
    CHECK(cli("vrf del red", &e) == -1);
    CHECK(cli("vni del 100", &e) == 0);
    CHECK(cli("route del 10.6.0.0/24 vrf red", &e) == 0);
    CHECK(cli("vrf del red", &e) == -1); /* still the port */
    CHECK_STR_EQ(e.code, "busy");
    CHECK(cli("vrf del nosuch", &e) == -1);
    CHECK_STR_EQ(e.code, "not-found");
    fx_teardown();
}

TEST(del_after_port_moved_away_works_and_frees_the_root) {
    fx_setup(1);
    struct cmd_err e;
    uint8_t mac[6] = {2, 0, 0, 0, 5, 6};
    pio_fake_add_if("r1", mac, 1500);
    CHECK(run("vrf add red id 1", &e) == 0);
    CHECK(run("port add r1 ifname r1 ip 10.5.0.1/24 vrf red", &e) == 0);
    CHECK(cli("port set r1 vrf default", &e) == 0);
    CHECK(cli("vrf del red", &e) == 0);
    CHECK(vrf_by_name("red") == NULL);
    CHECK(run("vrf add red id 1", &e) == 0); /* the id is reusable */
    fx_teardown();
}
