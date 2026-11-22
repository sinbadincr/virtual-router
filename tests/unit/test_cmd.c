#include <string.h>

#include "minivr/cmd.h"
#include "tharness.h"

TEST(tokenize_splits_on_spaces) {
    char line[] = "route  add 10.0.9.0/24\tdev p3";
    char *argv[CMD_MAX_ARGS];
    int n = cmd_tokenize(line, argv, CMD_MAX_ARGS);
    CHECK_EQ_U64(n, 5);
    CHECK_STR_EQ(argv[0], "route");
    CHECK_STR_EQ(argv[1], "add");
    CHECK_STR_EQ(argv[2], "10.0.9.0/24");
    CHECK_STR_EQ(argv[4], "p3");
    char empty[] = "   ";
    CHECK_EQ_U64(cmd_tokenize(empty, argv, CMD_MAX_ARGS), 0);
    char many[] = "a b c d";
    CHECK(cmd_tokenize(many, argv, 3) == -1);
}

TEST(parse_ipv4) {
    uint32_t ip = 0;
    CHECK(cmd_parse_ipv4("10.0.1.12", &ip) == NULL);
    CHECK_EQ_U64(ip, 0x0a00010cU);
    CHECK(cmd_parse_ipv4("255.255.255.255", &ip) == NULL);
    const char *bad[] = {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.-4", "a.b.c.d",
                         "1..2.3", "1.2.3.4 ", "01234.1.1.1", " 1.2.3.4", "1.2.3.4/24"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
        CHECK_STR_EQ(cmd_parse_ipv4(bad[i], &ip), "bad-address");
}

TEST(parse_prefix) {
    uint32_t ip;
    uint8_t len;
    CHECK(cmd_parse_prefix("10.0.9.0/24", &ip, &len) == NULL);
    CHECK_EQ_U64(ip, 0x0a000900U);
    CHECK_EQ_U64(len, 24);
    CHECK(cmd_parse_prefix("0.0.0.0/0", &ip, &len) == NULL);
    CHECK(cmd_parse_prefix("1.2.3.4/32", &ip, &len) == NULL);
    CHECK_STR_EQ(cmd_parse_prefix("10.0.9.1/24", &ip, &len), "bad-prefix"); /* host bits */
    CHECK_STR_EQ(cmd_parse_prefix("10.0.9.0/33", &ip, &len), "bad-prefix");
    CHECK_STR_EQ(cmd_parse_prefix("10.0.9.0", &ip, &len), "bad-prefix");
    CHECK_STR_EQ(cmd_parse_prefix("10.0.9.0/", &ip, &len), "bad-prefix");
    CHECK_STR_EQ(cmd_parse_prefix("10.0.9.0/x", &ip, &len), "bad-prefix");
    CHECK_STR_EQ(cmd_parse_prefix("bogus/24", &ip, &len), "bad-prefix");
}

TEST(parse_mac) {
    uint8_t mac[6];
    CHECK(cmd_parse_mac("02:00:00:00:01:0a", mac) == NULL);
    const uint8_t want[6] = {2, 0, 0, 0, 1, 0x0a};
    CHECK_MEM_EQ(mac, want, 6);
    CHECK(cmd_parse_mac("FF:ff:Ff:fF:ff:ff", mac) == NULL);
    const char *bad[] = {"", "02:00:00:00:01", "02:00:00:00:01:0a:0b", "02-00-00-00-01-0a",
                         "02:00:00:00:01:0g", "2:0:0:0:1:a", "02:00:00:00:01:0a "};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
        CHECK_STR_EQ(cmd_parse_mac(bad[i], mac), "bad-mac");
}

TEST(parse_uint_range) {
    uint64_t v;
    CHECK(cmd_parse_uint("100", 1, 100000, &v) == NULL);
    CHECK_EQ_U64(v, 100);
    CHECK_STR_EQ(cmd_parse_uint("0", 1, 100000, &v), "bad-syntax");
    CHECK_STR_EQ(cmd_parse_uint("100001", 1, 100000, &v), "bad-syntax");
    CHECK_STR_EQ(cmd_parse_uint("-1", 0, 10, &v), "bad-syntax");
    CHECK_STR_EQ(cmd_parse_uint("", 0, 10, &v), "bad-syntax");
    CHECK_STR_EQ(cmd_parse_uint("12x", 0, 100, &v), "bad-syntax");
    CHECK_STR_EQ(cmd_parse_uint("99999999999999999999999", 0, 100, &v), "bad-syntax");
}

static int run(const char *line, enum cmd_where where, char *buf, size_t cap, struct cmd_err *e) {
    struct jw w;
    jw_init(&w, buf, cap);
    memset(e, 0, sizeof *e);
    int rc = cmd_exec(line, where, &w, e);
    CHECK(jw_finish(&w) == 0);
    return rc;
}

TEST(unknown_command_is_bad_syntax) {
    char b[512];
    struct cmd_err e;
    CHECK(run("frobnicate now", CMD_CLI, b, sizeof b, &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(strstr(b, "\"ok\":false") != NULL);
    CHECK(strstr(b, "\"code\":\"bad-syntax\"") != NULL);
    CHECK(run("", CMD_CLI, b, sizeof b, &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
}

TEST(version_command) {
    char b[512];
    struct cmd_err e;
    cmd_init();
    CHECK(run("version", CMD_CLI, b, sizeof b, &e) == 0);
    CHECK(strstr(b, "\"ok\":true") != NULL);
    CHECK(strstr(b, "\"protocol\":1") != NULL);
    CHECK(strstr(b, "\"version\":\"") != NULL);
    CHECK(strstr(b, "\"build\":\"") != NULL);
    CHECK(strstr(b, "\"uptime_s\":") != NULL);
}

TEST(where_is_enforced) {
    char b[512];
    struct cmd_err e;
    CHECK(run("port add p1 ifname eth0 ip 10.0.1.1/24", CMD_CLI, b, sizeof b, &e) == -1);
    CHECK_STR_EQ(e.code, "config-only");
    CHECK(run("version", CMD_CONFIG, b, sizeof b, &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
}

TEST(port_add_argument_validation) {
    char b[512];
    struct cmd_err e;
    CHECK(run("port add p1 ifname eth0 ip 10.0.1.1/33", CMD_CONFIG, b, sizeof b, &e) == -1);
    CHECK_STR_EQ(e.code, "bad-prefix");
    CHECK(run("port add p1 ifname eth0", CMD_CONFIG, b, sizeof b, &e) == -1);
    CHECK_STR_EQ(e.code, "bad-syntax");
    CHECK(run("port add p1 ifname eth0 ip 10.0.1.1", CMD_CONFIG, b, sizeof b, &e) == -1);
    CHECK_STR_EQ(e.code, "bad-prefix");
}

/* ---- full command set against the lab fixture (T061) ---- */
#include "fixture.h"
#include "overlay_fixture.h"

static char out[65536];
static struct cmd_err cerr;

static int cli(const char *line) {
    struct jw w;
    jw_init(&w, out, sizeof out);
    memset(&cerr, 0, sizeof cerr);
    int rc = cmd_exec(line, CMD_CLI, &w, &cerr);
    CHECK(jw_finish(&w) == 0);
    return rc;
}

static void state_digest(char *dst, size_t cap) {
    dst[0] = 0;
    static const char *const cmds[] = {"route show", "neigh show", "port show"};
    for (size_t i = 0; i < 3; i++) {
        cli(cmds[i]);
        strncat(dst, out, cap - strlen(dst) - 1);
    }
}

TEST(show_commands_json_shapes) {
    fx_setup(1);
    CHECK(cli("route show") == 0);
    CHECK(strstr(out, "{\"vrf\":\"default\",\"prefix\":\"10.0.1.0/24\",\"port\":null,\"gateway\":null,\"origin\":\"connected\",\"owner\":\"config\"}"));
    CHECK(strstr(out, "{\"vrf\":\"default\",\"prefix\":\"10.0.1.11/32\",\"port\":\"p1\",\"gateway\":null,\"origin\":\"host\",\"owner\":\"config\"}"));
    CHECK(cli("neigh show") == 0);
    CHECK(strstr(out, "{\"vrf\":\"default\",\"ip\":\"10.0.2.13\",\"mac\":\"02:00:00:00:01:03\",\"port\":\"p3\","
                      "\"kind\":\"static\",\"state\":\"REACHABLE\",\"held\":0,\"owner\":\"config\"}"));
    CHECK(cli("port show") == 0);
    CHECK(strstr(out, "\"name\":\"p1\",\"ifname\":\"p1\",\"role\":\"vm\",\"vrf\":\"default\",\"mac\":\"02:00:00:00:00:01\","
                      "\"ip\":\"10.0.1.1/24\",\"mtu\":1500,\"admin\":\"up\",\"oper\":\"up\""));
    CHECK(cli("stats show") == 0);
    CHECK(strstr(out, "\"mbuf\":{\"total\":4096,\"in_use\":0}"));
    CHECK(strstr(out, "\"drops\":{\"total\":0,\"reasons\":{\"truncated\":0"));
    CHECK(strstr(out, "\"events\":{\"icmp_ratelimited\":0"));
    CHECK(cli("route lookup 10.0.2.13") == 0);
    CHECK(strstr(out, "\"route\":{\"vrf\":\"default\",\"prefix\":\"10.0.2.13/32\""));
    CHECK(cli("version") == 0);
    fx_teardown();
}

TEST(mutating_commands_work) {
    fx_setup(0);
    CHECK(cli("route add 10.0.9.0/24 dev p3 via 10.0.2.13") == 0);
    CHECK(strstr(out, "{\"ok\":true,\"data\":{}}"));
    CHECK(cli("route lookup 10.0.9.1") == 0);
    CHECK(strstr(out, "\"gateway\":\"10.0.2.13\""));
    CHECK(cli("route del 10.0.9.0/24") == 0);
    CHECK(cli("route lookup 10.0.9.1") == -1);
    CHECK_STR_EQ(cerr.code, "not-found");
    CHECK(cli("neigh add 10.0.2.13 lladdr 02:00:00:00:01:03 dev p3") == 0);
    CHECK(cli("neigh del 10.0.2.13") == 0);
    CHECK(cli("port set p3 admin down") == 0);
    CHECK(!port_find("p3")->admin_up);
    CHECK(cli("port set p3 admin up") == 0);
    CHECK(port_find("p3")->admin_up);
    stats_drop(DROP_NO_ROUTE);
    CHECK(cli("stats clear") == 0);
    CHECK_EQ_U64(g_stats.drop_total, 0);
    fx_teardown();
}

TEST(every_error_code_is_reachable_and_leaves_state_unchanged) {
    fx_setup(1);
    char before[2 * 65536], after[2 * 65536];
    struct {
        const char *line;
        const char *code;
    } bad[] = {
        {"route add 10.0.9.1/24 dev p3", "bad-prefix"},
        {"route add nonsense dev p3", "bad-prefix"},
        {"route add 10.0.9.0/24 dev p3 via 999.1.1.1", "bad-address"},
        {"route add 10.0.9.0/24 dev p3 via 10.7.7.7", "gw-not-connected"},
        {"route add 10.0.9.0/24 dev nope", "unknown-port"},
        {"route add 10.0.9.0/24", "bad-syntax"},
        {"route add 10.0.1.0/24 dev p1", "exists"},
        {"route del 10.0.2.0/24", "immutable"},
        {"route del 10.0.2.13/32", "immutable"},
        {"route del 10.5.0.0/16", "not-found"},
        {"route del 10.5.0.1/16", "bad-prefix"},
        {"route lookup 1.2.3", "bad-address"},
        {"neigh add 10.0.1.99 lladdr zz:00:00:00:00:00 dev p1", "bad-mac"},
        {"neigh add 10.0.1.99.9 lladdr 02:00:00:00:00:09 dev p1", "bad-address"},
        {"neigh add 10.0.1.99 lladdr 02:00:00:00:00:09 dev nope", "unknown-port"},
        {"neigh add 10.0.1.99 lladdr 02:00:00:00:00:09 dev p1", "exists"}, /* p1 already bound */
        {"neigh add 10.0.1.11 lladdr 02:00:00:00:00:09 dev p2", "exists"},
        {"neigh del 10.1.1.1", "not-found"},
        {"port set nope admin up", "unknown-port"},
        {"port set p1 admin sideways", "bad-syntax"},
        {"port add p9 ifname p9 ip 10.9.9.1/24", "config-only"},
        {"icmp-ratelimit rate 0 burst 5", "bad-syntax"},
        {"icmp-ratelimit rate 5", "bad-syntax"},
        {"stats show extra", "bad-syntax"},
        {"bogus", "bad-syntax"},
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        state_digest(before, sizeof before);
        CHECK(cli(bad[i].line) == -1);
        if (cerr.code == NULL || strcmp(cerr.code, bad[i].code) != 0)
            TH_FAIL("'%s': got %s, want %s", bad[i].line, cerr.code ? cerr.code : "(none)", bad[i].code);
        CHECK(strstr(out, "\"ok\":false") != NULL);
        state_digest(after, sizeof after);
        if (strcmp(before, after) != 0)
            TH_FAIL("'%s' changed state", bad[i].line);
    }
    fx_teardown();
}

TEST(table_full_error) {
    fx_setup(1);
    for (uint32_t i = 0; route_count() < LPM_MAX_RULES; i++) {
        char line[96];
        snprintf(line, sizeof line, "route add %u.%u.%u.0/24 dev p3", 100 + (i >> 16), (i >> 8) & 255, i & 255);
        CHECK(cli(line) == 0);
    }
    CHECK(cli("route add 200.0.0.0/24 dev p3") == -1);
    CHECK_STR_EQ(cerr.code, "table-full");
    CHECK(strstr(out, "route table full (10000)"));
    fx_teardown();
}

TEST(oversized_response_is_an_error_not_truncation) {
    fx_setup(1);
    for (uint32_t i = 0; i < 2000; i++) {
        char line[96];
        snprintf(line, sizeof line, "route add 100.%u.%u.0/24 dev p3", i >> 8, i & 255);
        CHECK(cli(line) == 0);
    }
    struct jw w;
    char small[4096];
    jw_init(&w, small, sizeof small);
    struct cmd_err e;
    cmd_exec("route show", CMD_CLI, &w, &e);
    CHECK(w.overflow); /* the server maps this to an error response (ctl_server.c) */
    fx_teardown();
}

TEST(show_commands_are_paged) {
    fx_setup(1);
    for (uint32_t i = 0; i < 1200; i++) {
        char line[96];
        snprintf(line, sizeof line, "route add 100.%u.%u.0/24 dev p3", i >> 8, i & 255);
        CHECK(cli(line) == 0);
    }
    /* default page: fits one response, says where the next page starts */
    CHECK(cli("route show") == 0);
    CHECK(strstr(out, "\"total\":1205,\"offset\":0,"));
    CHECK(strstr(out, "\"next_offset\":400}"));
    CHECK(cli("route show offset 500 limit 600") == 0);
    CHECK(strstr(out, "\"offset\":500,"));
    CHECK(strstr(out, "\"next_offset\":1100}"));
    CHECK(cli("route show offset 1200") == 0); /* last page: 5 routes, next_offset null */
    CHECK(strstr(out, "\"next_offset\":null}"));
    CHECK(cli("route show limit 0") == -1);
    CHECK_STR_EQ(cerr.code, "bad-syntax");
    CHECK(cli("route show offset") == -1);
    CHECK(cli("neigh show limit 2") == 0);
    CHECK(strstr(out, "\"total\":3,\"offset\":0,"));
    CHECK(strstr(out, "\"next_offset\":2}"));
    CHECK(cli("neigh show offset 2 limit 2") == 0);
    CHECK(strstr(out, "\"next_offset\":null}"));
    fx_teardown();
}

/* ---- phase 2 grammar (contracts/cli.md) ---- */

static int cfg(const char *line) {
    char buf[1024];
    struct jw w;
    struct cmd_err e;
    jw_init(&w, buf, sizeof buf);
    return cmd_exec(line, CMD_CONFIG, &w, &e);
}

static const char *ecode(const char *line, enum cmd_where where) {
    struct jw w;
    struct cmd_err e;
    static char buf[2048];
    jw_init(&w, buf, sizeof buf);
    return cmd_exec(line, where, &w, &e) == 0 ? "ok" : e.code;
}

TEST(placement_config_vs_cli) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    /* config-only */
    CHECK_STR_EQ(ecode("underlay add u9 ifname u9 ip 172.16.0.9/24", CMD_CLI), "config-only");
    /* CLI-only */
    const char *cli_only[] = {"vrf del blue", "vrf show", "port set red1 vrf blue", "node set cn2 rmac 02:00:00:ff:00:02",
                              "node del cn2", "node show", "route replace 10.1.1.12/32 vrf red dev red1",
                              "label del 1011", "vni del 200", "tunnel show", "route show vrf red",
                              "neigh show underlay", "route lookup 10.1.1.11 vrf red"};
    for (size_t i = 0; i < sizeof cli_only / sizeof *cli_only; i++)
        CHECK_STR_EQ(ecode(cli_only[i], CMD_CONFIG), "bad-syntax");
    /* both */
    CHECK_STR_EQ(ecode("vrf add green id 3", CMD_CLI), "ok");
    CHECK_STR_EQ(ecode("node add n9 ip 172.16.0.9", CMD_CLI), "ok");
    CHECK_STR_EQ(ecode("label add 4000 port red1", CMD_CLI), "ok");
    CHECK_STR_EQ(ecode("vni add 4000 vrf green", CMD_CLI), "ok");
    CHECK_STR_EQ(ecode("route add 10.8.0.0/24 vrf red dev red1", CMD_CLI), "ok");
    ov_teardown();
}

TEST(every_new_error_code_is_reachable) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    struct { const char *line; enum cmd_where w; const char *code; } t[] = {
        {"vrf add red id 9", CMD_CLI, "exists"},
        {"vrf add x id 2", CMD_CLI, "exists"},
        {"vrf add X id 9", CMD_CLI, "bad-syntax"},
        {"vrf add x id", CMD_CLI, "bad-syntax"},
        {"vrf add x id abc", CMD_CLI, "bad-syntax"},
        {"vrf del default", CMD_CLI, "immutable"},
        {"vrf del red", CMD_CLI, "busy"},
        {"vrf del nosuch", CMD_CLI, "not-found"},
        {"port set red1 vrf nosuch", CMD_CLI, "unknown-vrf"},
        {"route lookup 10.1.1.11 vrf nosuch", CMD_CLI, "unknown-vrf"},
        {"route show vrf nosuch", CMD_CLI, "unknown-vrf"},
        {"neigh show vrf nosuch", CMD_CLI, "unknown-vrf"},
        {"neigh del 10.1.1.11 vrf nosuch", CMD_CLI, "unknown-vrf"},
        {"node add cn2 ip 172.16.0.9", CMD_CLI, "exists"},
        {"node add far ip 192.168.9.9", CMD_CLI, "bad-prefix"},
        {"node del nosuch", CMD_CLI, "unknown-node"},
        {"node del cn2", CMD_CLI, "busy"},
        {"node set cn2 rmac zz", CMD_CLI, "bad-mac"},
        {"route add 10.5.0.1/32 vrf red node nosuch encap mplsoudp label 100", CMD_CLI, "unknown-node"},
        {"route add 10.5.0.1/32 vrf red node cn2 encap mplsoudp label 3", CMD_CLI, "bad-syntax"},
        {"route add 10.5.0.1/32 vrf red node cn2 encap vxlan vni 99999999", CMD_CLI, "bad-syntax"},
        {"route add 10.5.0.1/32 vrf red node cn2 encap gre label 3", CMD_CLI, "bad-syntax"},
        {"route add 10.5.0.1/32 vrf red node cn2 encap mplsoudp vni 3", CMD_CLI, "bad-syntax"},
        {"route add 10.5.0.1/32 vrf red node cn2 dev red1", CMD_CLI, "bad-syntax"},
        {"route add 10.5.0.1/32 vrf red", CMD_CLI, "bad-syntax"},
        {"route replace 10.5.0.1/32 vrf red dev red1", CMD_CLI, "not-found"},
        {"route del 10.5.0.1/32 vrf red", CMD_CLI, "not-found"},
        {"label add 1011 port red1", CMD_CLI, "exists"},
        {"label add 5 port red1", CMD_CLI, "bad-syntax"},
        {"label add 4000 port nosuch", CMD_CLI, "unknown-port"},
        {"label add 4000 port u0", CMD_CLI, "bad-syntax"},
        {"label del 4001", CMD_CLI, "not-found"},
        {"vni add 200 vrf red", CMD_CLI, "exists"},
        {"vni add 300 vrf nosuch", CMD_CLI, "unknown-vrf"},
        {"vni add 0 vrf red", CMD_CLI, "bad-syntax"},
        {"vni del 4001", CMD_CLI, "not-found"},
        {"port add rx ifname rx ip 10.7.7.1/24 vrf nosuch", CMD_CONFIG, "unknown-vrf"},
        {"underlay add u1 ifname u1 ip 172.16.9.1/24", CMD_CONFIG, "exists"},
    };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        const char *got = ecode(t[i].line, t[i].w);
        if (strcmp(got, t[i].code) != 0)
            TH_FAIL("'%s': want %s, got %s", t[i].line, t[i].code, got);
    }
    ov_teardown();
}

TEST(no_underlay_error) {
    ov_reset();
    port_set_backend(&pio_fake_ops);
    CHECK(cfg("vrf add red id 1") == 0);
    CHECK_STR_EQ(ecode("node add n1 ip 172.16.0.2", CMD_CLI), "no-underlay");
    CHECK_STR_EQ(ecode("route add 10.5.0.1/32 vrf red node n1 encap mplsoudp label 100", CMD_CLI), "no-underlay");
    ov_teardown();
}

TEST(vrf_show_node_show_tunnel_show_shapes) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    CHECK(cli("vrf show") == 0);
    CHECK(strstr(out, "{\"name\":\"default\",\"id\":0,\"ports\":[],\"routes\":0,\"neighbours\":0,\"labels\":0,\"vnis\":0,\"owner\":\"config\"}"));
    CHECK(strstr(out, "{\"name\":\"red\",\"id\":1,\"ports\":[\"red1\"],\"routes\":4,\"neighbours\":1,\"labels\":1,\"vnis\":0,\"owner\":\"config\"}"));
    CHECK(strstr(out, "{\"name\":\"blue\",\"id\":2,\"ports\":[\"blue1\"],\"routes\":4,\"neighbours\":1,\"labels\":0,\"vnis\":1,\"owner\":\"config\"}"));
    CHECK(cli("node show") == 0);
    CHECK(strstr(out, "\"name\":\"cn2\",\"ip\":\"172.16.0.2\",\"rmac\":\"02:00:00:ff:00:02\",\"underlay_mac\":null,\"state\":\"unresolved\""));
    CHECK(strstr(out, "\"encap\":{\"mplsoudp\":{\"pkts\":0,\"bytes\":0},\"vxlan\":{\"pkts\":0,\"bytes\":0}},\"decap\":{"));
    CHECK(cli("tunnel show") == 0);
    CHECK(strstr(out, "\"labels\":[{\"label\":1011,\"port\":\"red1\",\"vrf\":\"red\",\"owner\":\"config\"}]"));
    CHECK(strstr(out, "\"vnis\":[{\"vni\":200,\"vrf\":\"blue\",\"owner\":\"config\"}]"));
    CHECK(strstr(out, "\"underlay\":{\"port\":\"u0\",\"ip\":\"172.16.0.1/24\",\"mac\":\"02:00:00:ff:00:01\",\"mtu\":1600}"));
    CHECK(cli("route show vrf red") == 0);
    CHECK(strstr(out, "{\"vrf\":\"red\",\"prefix\":\"10.1.1.12/32\",\"port\":null,\"gateway\":null,\"origin\":\"remote\",\"node\":\"cn2\",\"encap\":\"mplsoudp\",\"tag\":1012,\"owner\":\"config\"}"));
    CHECK(strstr(out, "\"total\":4"));
    CHECK(cli("route show vrf blue") == 0);
    CHECK(strstr(out, "\"encap\":\"vxlan\",\"tag\":200"));
    CHECK(cli("route lookup 10.1.2.13 vrf red") == 0);
    CHECK(strstr(out, "\"tag\":1013"));
    CHECK(cli("neigh show vrf blue") == 0);
    CHECK(strstr(out, "\"vrf\":\"blue\",\"ip\":\"10.1.1.11\",\"mac\":\"02:00:00:02:01:11\""));
    CHECK(strstr(out, "\"vrf\":\"red\"") == NULL);
    CHECK(cli("neigh show underlay") == 0);
    CHECK(strstr(out, "\"total\":0"));
    CHECK(cli("stats show") == 0);
    CHECK(strstr(out, "\"tunnel_mtu_exceeded\":0"));
    CHECK(strstr(out, "\"nodes\":[{\"name\":\"cn2\""));
    CHECK(strstr(out, "{\"name\":\"unknown\",\"encap\":"));
    CHECK(cli("port show") == 0);
    CHECK(strstr(out, "\"role\":\"underlay\",\"vrf\":null"));
    ov_teardown();
}

TEST(node_counters_in_node_show_follow_the_stats) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    stats_node_encap(node_find("cn2")->id, ENCAP_VXLAN, 150);
    stats_node_decap(node_find("cn2")->id, ENCAP_MPLSOUDP, 90);
    CHECK(cli("node show") == 0);
    CHECK(strstr(out, "\"vxlan\":{\"pkts\":1,\"bytes\":150}"));
    CHECK(strstr(out, "\"decap\":{\"mplsoudp\":{\"pkts\":1,\"bytes\":90}"));
    ov_teardown();
}

TEST(a_failed_new_command_leaves_state_unchanged) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    unsigned routes = route_count(), labels = label_count(), vnis = vni_count(), nodes = node_count();
    CHECK(cli("route add 10.5.0.1/32 vrf red node cn2 encap mplsoudp label 3") == -1);
    CHECK(cli("label add 1011 port red1") == -1);
    CHECK(cli("vni add 200 vrf red") == -1);
    CHECK(cli("node add cn2 ip 172.16.0.2") == -1);
    CHECK_EQ_U64(route_count(), routes);
    CHECK_EQ_U64(label_count(), labels);
    CHECK_EQ_U64(vni_count(), vnis);
    CHECK_EQ_U64(node_count(), nodes);
    ov_teardown();
}

TEST(vrf_and_tunnel_show_follow_live_changes) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    CHECK(cli("vrf add green id 3") == 0);
    CHECK(cli("vrf show") == 0);
    CHECK(strstr(out, "{\"name\":\"green\",\"id\":3,\"ports\":[],\"routes\":0,\"neighbours\":0,\"labels\":0,\"vnis\":0,\"owner\":\"cli\"}"));
    CHECK(cli("vni add 500 vrf green") == 0);
    CHECK(cli("label add 3000 port red1") == 0);
    CHECK(cli("vrf show") == 0);
    CHECK(strstr(out, "\"name\":\"green\",\"id\":3,\"ports\":[],\"routes\":0,\"neighbours\":0,\"labels\":0,\"vnis\":1,\"owner\":\"cli\"}"));
    CHECK(strstr(out, "\"name\":\"red\",\"id\":1,\"ports\":[\"red1\"],\"routes\":4,\"neighbours\":1,\"labels\":2,"));
    CHECK(cli("vrf del green") == -1);
    CHECK_STR_EQ(cerr.code, "busy"); /* a VNI maps to it */
    CHECK(cli("vni add 500 vrf green") == -1);
    CHECK_STR_EQ(cerr.code, "exists");
    CHECK(cli("label add 3000 port red1") == -1);
    CHECK_STR_EQ(cerr.code, "exists");
    CHECK(cli("vni del 500") == 0);
    CHECK(cli("vrf del green") == 0);
    CHECK(cli("tunnel show") == 0);
    CHECK(strstr(out, "{\"label\":3000,\"port\":\"red1\",\"vrf\":\"red\",\"owner\":\"cli\"}"));
    CHECK(cli("label del 3000") == 0);
    CHECK(cli("tunnel show") == 0);
    CHECK(strstr(out, "{\"label\":3000") == NULL);
    ov_teardown();
}
