#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fixture.h"
#include "overlay_fixture.h"
#include "minivr/config.h"
#include "tharness.h"

static char path[] = "/tmp/minivr-test-config-XXXXXX";

static void write_file(const char *text) {
    FILE *f = fopen(path, "w");
    fputs(text, f);
    fclose(f);
}

/* config_load plus whatever it printed on stderr. */
static int load(char *err, size_t cap) {
    fflush(stderr);
    int saved = dup(2), p[2];
    if (pipe(p) != 0)
        return -99;
    dup2(p[1], 2);
    int rc = config_load(path);
    fflush(stderr);
    dup2(saved, 2);
    close(p[1]);
    close(saved);
    ssize_t n = read(p[0], err, cap - 1);
    close(p[0]);
    err[n > 0 ? n : 0] = 0;
    return rc;
}

static void setup(void) {
    int fd = mkstemp(path);
    close(fd);
    clock_set_fake(1000 * NS_PER_SEC);
    mbuf_pool_init(64);
    stats_clear();
    port_reset();
    route_reset();
    neigh_reset();
    pio_fake_reset();
    ratelimit_configure(RL_DEFAULT_RATE, RL_DEFAULT_BURST);
    pio_fake_add_if("p1", MAC_P1, 1500);
    pio_fake_add_if("p3", MAC_P3, 1500);
    port_set_backend(&pio_fake_ops);
}

static void teardown(void) {
    unlink(path);
    strcpy(path, "/tmp/minivr-test-config-XXXXXX");
    fx_teardown();
}

TEST(comments_blank_lines_and_crlf_are_ignored) {
    setup();
    char err[512];
    write_file("# lab\n\n   \n\t# indented comment\n"
               "port add p1 ifname p1 ip 10.0.1.1/24   # trailing comment\r\n"
               "neigh add 10.0.1.11 lladdr 02:00:00:00:01:01 dev p1\r\n"
               "icmp-ratelimit rate 50 burst 7");
    CHECK_EQ_U64(load(err, sizeof err), 0);
    CHECK_EQ_U64(err[0], 0);
    CHECK(port_find("p1") != NULL);
    CHECK(neigh_lookup(0, VM1_IP) != NULL);
    CHECK_EQ_U64(ratelimit_rate(), 50); /* the last line had no newline */
    teardown();
}

TEST(first_error_is_reported_with_file_and_line_and_stops_loading) {
    setup();
    char err[512], want[256];
    write_file("port add p1 ifname p1 ip 10.0.1.1/24\n"
               "# comment lines count too\n"
               "route add 10.0.9.1/24 dev p1\n"
               "port add p3 ifname p3 ip 10.0.2.1/24\n");
    CHECK_EQ_U64(load(err, sizeof err), -1);
    snprintf(want, sizeof want, "%s:3: bad-prefix:", path);
    CHECK(strstr(err, want) != NULL);
    CHECK(port_find("p1") != NULL);  /* lines before the error were applied */
    CHECK(port_find("p3") == NULL);  /* nothing after it was */
    teardown();
}

TEST(cli_only_commands_are_refused_in_a_config_file) {
    setup();
    char err[512], want[256];
    write_file("version\n");
    CHECK_EQ_U64(load(err, sizeof err), -1);
    snprintf(want, sizeof want, "%s:1: bad-syntax:", path);
    CHECK(strstr(err, want) != NULL);
    write_file("route show\n");
    CHECK_EQ_U64(load(err, sizeof err), -1);
    teardown();
}

TEST(over_long_lines_are_rejected) {
    setup();
    char err[512], want[256];
    static char big[3000];
    memset(big, 'x', sizeof big - 2);
    big[sizeof big - 2] = '\n';
    big[sizeof big - 1] = 0;
    write_file(big);
    CHECK_EQ_U64(load(err, sizeof err), -1);
    snprintf(want, sizeof want, "%s:1: bad-syntax: line too long", path);
    CHECK(strstr(err, want) != NULL);
    teardown();
}

TEST(missing_file_and_unknown_interface_fail_cleanly) {
    setup();
    char err[512];
    unlink(path);
    CHECK_EQ_U64(load(err, sizeof err), -1);
    CHECK(strstr(err, path) != NULL);
    write_file("port add p1 ifname nosuch0 ip 10.0.1.1/24\n");
    CHECK_EQ_U64(load(err, sizeof err), -1);
    CHECK(strstr(err, ":1: not-found: cannot open interface nosuch0") != NULL);
    teardown();
}

/* ---- shipped configs (phase 2) ---- */

TEST(overlay_configs_parse_with_no_error) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    CHECK_EQ_U64(port_count(), 3); /* red1 blue1 u0 */
    CHECK_EQ_U64(vrf_count(), 3);
    CHECK_EQ_U64(node_count(), 2); /* cn2 and the interop endpoint `ix` */
    CHECK(node_find("ix") != NULL && node_find("ix")->has_rmac);
    CHECK(route_find(vrf_by_name("blue")->id, IP4(10, 1, 3, 33), 32) != NULL);
    CHECK_EQ_U64(label_count(), 1);
    CHECK_EQ_U64(vni_count(), 1);
    CHECK_EQ_U64(ratelimit_rate(), 100);
    ov_teardown();
    CHECK_EQ_U64(ov_setup(2, 1600), 0);
    CHECK_EQ_U64(port_count(), 4);
    CHECK_EQ_U64(label_count(), 2);
    CHECK(node_find("cn1") != NULL && node_find("cn1")->has_rmac);
    ov_teardown();
}

/* FR-023: the phase 1 lab config still means exactly what it meant: everything in `default`,
 * no underlay, no tunnels. */
TEST(phase1_config_parses_to_the_phase1_state) {
    ov_reset();
    pio_fake_add_if("p1", MAC_P1, 1500);
    pio_fake_add_if("p2", MAC_P2, 1500);
    pio_fake_add_if("p3", MAC_P3, 1500);
    port_set_backend(&pio_fake_ops);
    CHECK_EQ_U64(config_load(MINIVR_SOURCE_DIR "/lab/cn1.conf"), 0);
    CHECK_EQ_U64(vrf_count(), 1);
    CHECK(port_underlay() == NULL);
    CHECK_EQ_U64(node_count() + label_count() + vni_count(), 0);
    CHECK_EQ_U64(port_count(), 3);
    for (unsigned i = 0; i < 3; i++)
        CHECK_EQ_U64(port_get((uint8_t)i)->vrf, 0);
    CHECK_EQ_U64(route_count(), 5); /* 2 connected + 3 host, all in default */
    CHECK_EQ_U64(route_count_vrf(0), 5);
    CHECK_EQ_U64(neigh_count(), 3);
    CHECK(neigh_lookup(0, VM1_IP) != NULL);
    ov_teardown();
}

/* ---- phase 3 bootstrap configs (FR-002) and owner (FR-030) ---- */

TEST(ctl_bootstrap_configs_parse_and_only_declare_the_underlay) {
    static const char *const files[] = {"cn1", "cn2", "cn3"};
    static const uint32_t ips[] = {0xac100001u, 0xac100002u, 0xac100004u};
    for (int i = 0; i < 3; i++) {
        char name[64], cfg[160];
        ov_reset();
        snprintf(name, sizeof name, "u%d", i);
        uint8_t mac[6] = {2, 0, 0, 0xff, 0, (uint8_t)(i == 2 ? 4 : i + 1)};
        pio_fake_add_if("u0", mac, 1500);
        port_set_backend(&pio_fake_ops);
        snprintf(cfg, sizeof cfg, MINIVR_SOURCE_DIR "/lab/ctl/%s.conf", files[i]);
        CHECK(config_load(cfg) == 0);
        CHECK_EQ_U64(port_count(), 1);
        CHECK(port_underlay() != NULL);
        CHECK_EQ_U64(port_underlay()->ip, ips[i]);
        CHECK_EQ_U64(port_underlay()->owner, OWNER_CONFIG);
        CHECK_EQ_U64(vrf_count(), 1);
        CHECK_EQ_U64(node_count(), 0);
        CHECK_EQ_U64(label_count(), 0);
        fx_teardown();
    }
}

TEST(earlier_phase_configs_still_parse_with_config_owner) {
    CHECK(ov_setup(1, 1500) == 0);
    CHECK(vrf_by_name("red") && vrf_by_name("red")->owner == OWNER_CONFIG);
    CHECK(node_find("cn2") && node_find("cn2")->owner == OWNER_CONFIG);
    CHECK(port_find("red1") && port_find("red1")->owner == OWNER_CONFIG);
    CHECK_EQ_U64(label_owner(1011), OWNER_CONFIG);
    CHECK_EQ_U64(vni_owner(200), OWNER_CONFIG);
    const struct route *r = route_find(vrf_by_name("red")->id, 0x0a01010cu, 32);
    CHECK(r && r->owner == OWNER_CONFIG);
    const struct neigh *n = neigh_lookup(vrf_by_name("red")->id, 0x0a01010bu);
    CHECK(n && n->owner == OWNER_CONFIG);
    ov_teardown();
}
