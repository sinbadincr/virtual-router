#include "fixture.h"
#include "minivr/antispoof.h"
#include "tharness.h"

static uint8_t f[256];

TEST(bound_port_accepts_the_bound_sender) {
    fx_setup(1);
    struct port *p1 = port_find("p1");
    size_t n = make_echo(f, MAC_P1, MAC_VM1, VM1_IP, VM3_IP, 64, ICMP_ECHO_REQUEST, 1, 1);
    CHECK(antispoof_ok(p1, ETH_C_IPV4, f, n));
    n = make_arp_request(f, MAC_VM1, VM1_IP, GW1_IP);
    CHECK(antispoof_ok(p1, ETH_C_ARP, f, n));
    fx_teardown();
}

TEST(bound_port_rejects_mismatches) {
    fx_setup(1);
    struct port *p1 = port_find("p1");
    size_t n = make_echo(f, MAC_P1, MAC_VM2, VM1_IP, VM3_IP, 64, ICMP_ECHO_REQUEST, 1, 1);
    CHECK(!antispoof_ok(p1, ETH_C_IPV4, f, n)); /* wrong Ethernet src */
    n = make_echo(f, MAC_P1, MAC_VM1, VM2_IP, VM3_IP, 64, ICMP_ECHO_REQUEST, 1, 1);
    CHECK(!antispoof_ok(p1, ETH_C_IPV4, f, n)); /* wrong IPv4 src */
    n = make_echo(f, MAC_P1, MAC_VM1, GW1_IP, VM3_IP, 64, ICMP_ECHO_REQUEST, 1, 1);
    CHECK(!antispoof_ok(p1, ETH_C_IPV4, f, n)); /* the gateway address as source */
    n = make_arp_request(f, MAC_VM1, VM2_IP, GW1_IP);
    CHECK(!antispoof_ok(p1, ETH_C_ARP, f, n)); /* ARP sender IP */
    n = make_arp_request(f, MAC_VM1, VM1_IP, GW1_IP);
    memcpy(f + ETH_HDR_LEN + 8, MAC_VM2, 6);
    CHECK(!antispoof_ok(p1, ETH_C_ARP, f, n)); /* ARP sender MAC */
    fx_teardown();
}

TEST(unbound_port_passes_everything) {
    fx_setup(0);
    struct port *p3 = port_find("p3");
    size_t n = make_echo(f, MAC_P3, MAC_VM2, VM1_IP, VM1_IP, 64, ICMP_ECHO_REQUEST, 1, 1);
    CHECK(antispoof_ok(p3, ETH_C_IPV4, f, n));
    fx_teardown();
}

TEST(second_static_neighbour_on_a_port_is_refused) {
    fx_setup(1);
    struct cmd_err e;
    CHECK(neigh_add_static(IP4(10, 0, 2, 14), MAC_VM2, port_find("p3")->id, &e) == -1);
    CHECK_STR_EQ(e.code, "exists");
    fx_teardown();
}

TEST(binding_follows_neighbour_delete) {
    fx_setup(1);
    struct port *p3 = port_find("p3");
    size_t n = make_echo(f, MAC_P3, MAC_VM2, VM3_IP, VM1_IP, 64, ICMP_ECHO_REQUEST, 1, 1);
    CHECK(!antispoof_ok(p3, ETH_C_IPV4, f, n));
    struct cmd_err e;
    CHECK(neigh_del(0, VM3_IP, &e) == 0);
    CHECK(antispoof_ok(p3, ETH_C_IPV4, f, n));
    fx_teardown();
}
