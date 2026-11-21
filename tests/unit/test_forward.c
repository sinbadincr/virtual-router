#include "fixture.h"
#include "overlay_fixture.h"
#include "tharness.h"

static uint8_t f[2048];

static size_t echo_from_vm1(uint32_t dst, uint8_t ttl) {
    return make_echo(f, MAC_P1, MAC_VM1, VM1_IP, dst, ttl, ICMP_ECHO_REQUEST, 7, 1);
}

static void check_invariants(void) {
    CHECK_EQ_U64(stats_reason_sum(), g_stats.drop_total);
}

static const uint8_t *tx1(int pn, size_t idx, size_t *len) {
    return fx_tx(pn, idx, len);
}

TEST(forward_vm1_to_vm3_rewrites_l2_and_ttl) {
    fx_setup(1);
    size_t n = echo_from_vm1(VM3_IP, 64);
    fx_rx(1, f, n);
    CHECK_EQ_U64(fx_tx_count(3), 1);
    size_t len;
    const uint8_t *o = tx1(3, 0, &len);
    CHECK_EQ_U64(len, n);
    CHECK_MEM_EQ(o, MAC_VM3, 6);
    CHECK_MEM_EQ(o + 6, MAC_P3, 6);
    CHECK_EQ_U64(o[ETH_HDR_LEN + 8], 63);
    CHECK_EQ_U64(pkt_csum16(o + ETH_HDR_LEN, IPV4_HDR_LEN), 0);
    CHECK_EQ_U64(g_stats.port[0].rx_pkts, 1);
    CHECK_EQ_U64(g_stats.port[2].tx_pkts, 1);
    CHECK_EQ_U64(g_stats.drop_total, 0);
    CHECK_EQ_U64(mbuf_in_use(), 0);
    fx_teardown();
}

TEST(forward_vm1_to_vm2_across_ports_of_one_subnet) {
    fx_setup(1);
    size_t n = echo_from_vm1(VM2_IP, 64);
    fx_rx(1, f, n);
    CHECK_EQ_U64(fx_tx_count(2), 1);
    size_t len;
    const uint8_t *o = tx1(2, 0, &len);
    CHECK_MEM_EQ(o, MAC_VM2, 6);
    CHECK_MEM_EQ(o + 6, MAC_P2, 6);
    CHECK_EQ_U64(fx_tx_count(1), 0);
    fx_teardown();
}

TEST(ethernet_padding_is_stripped) {
    fx_setup(1);
    size_t n = echo_from_vm1(VM3_IP, 64);
    memset(f + n, 0, 20);
    fx_rx(1, f, n + 20);
    size_t len;
    tx1(3, 0, &len);
    CHECK_EQ_U64(len, n);
    fx_teardown();
}

TEST(arp_for_gateway_known_vm_and_unknown) {
    fx_setup(1);
    size_t len;
    size_t n = make_arp_request(f, MAC_VM1, VM1_IP, GW1_IP);
    fx_rx(1, f, n);
    CHECK_EQ_U64(fx_tx_count(1), 1);
    const uint8_t *o = tx1(1, 0, &len);
    CHECK_MEM_EQ(o, MAC_VM1, 6);
    CHECK_MEM_EQ(o + 6, MAC_P1, 6);
    CHECK_EQ_U64(rd16(o + ETH_HDR_LEN + 6), ARP_OP_REPLY);
    CHECK_MEM_EQ(o + ETH_HDR_LEN + 8, MAC_P1, 6);

    fx_clear_tx();
    n = make_arp_request(f, MAC_VM1, VM1_IP, VM2_IP); /* proxy for vm2 */
    fx_rx(1, f, n);
    o = tx1(1, 0, &len);
    CHECK(o != NULL);
    CHECK_EQ_U64(rd32(o + ETH_HDR_LEN + 14), VM2_IP);
    CHECK_MEM_EQ(o + ETH_HDR_LEN + 8, MAC_P1, 6);
    CHECK_EQ_U64(fx_tx_count(2), 0); /* nothing leaks to vm2's port */

    fx_clear_tx();
    n = make_arp_request(f, MAC_VM1, VM1_IP, IP4(10, 0, 1, 99));
    fx_rx(1, f, n);
    CHECK_EQ_U64(fx_tx_count(1), 0);
    CHECK_EQ_U64(g_stats.reasons[DROP_ARP_UNKNOWN_TARGET], 1);
    CHECK_EQ_U64(g_stats.arp_replies_sent, 2);
    check_invariants();
    fx_teardown();
}

TEST(echo_to_the_gateway_is_answered_locally) {
    fx_setup(1);
    size_t n = echo_from_vm1(GW1_IP, 64);
    fx_rx(1, f, n);
    CHECK_EQ_U64(fx_tx_count(1), 1);
    size_t len;
    const uint8_t *o = tx1(1, 0, &len);
    CHECK_MEM_EQ(o, MAC_VM1, 6);
    CHECK_MEM_EQ(o + 6, MAC_P1, 6);
    CHECK_EQ_U64(rd32(o + ETH_HDR_LEN + 12), GW1_IP);
    CHECK_EQ_U64(o[ETH_HDR_LEN + IPV4_HDR_LEN], ICMP_ECHO_REPLY);
    CHECK_EQ_U64(g_stats.drop_total, 0);
    fx_teardown();
}

static void check_icmp_on_p1(uint8_t type, uint8_t code) {
    CHECK_EQ_U64(fx_tx_count(1), 1);
    size_t len;
    const uint8_t *o = tx1(1, 0, &len);
    if (!o)
        return;
    CHECK_MEM_EQ(o, MAC_VM1, 6);
    CHECK_EQ_U64(rd32(o + ETH_HDR_LEN + 12), GW1_IP);
    CHECK_EQ_U64(rd32(o + ETH_HDR_LEN + 16), VM1_IP);
    CHECK_EQ_U64(o[ETH_HDR_LEN + IPV4_HDR_LEN], type);
    CHECK_EQ_U64(o[ETH_HDR_LEN + IPV4_HDR_LEN + 1], code);
}

TEST(no_route_gives_net_unreachable) {
    fx_setup(1);
    fx_rx(1, f, echo_from_vm1(IP4(10, 9, 9, 9), 64));
    check_icmp_on_p1(ICMP_UNREACH, ICMP_UNREACH_NET);
    CHECK_EQ_U64(g_stats.reasons[DROP_NO_ROUTE], 1);
    check_invariants();
    fx_teardown();
}

TEST(shared_subnet_without_host_route_gives_host_unreachable) {
    fx_setup(1);
    fx_rx(1, f, echo_from_vm1(IP4(10, 0, 1, 99), 64));
    check_icmp_on_p1(ICMP_UNREACH, ICMP_UNREACH_HOST);
    CHECK_EQ_U64(g_stats.reasons[DROP_NO_ROUTE], 1);
    fx_teardown();
}

TEST(ttl_one_gives_time_exceeded) {
    fx_setup(1);
    fx_rx(1, f, echo_from_vm1(VM3_IP, 1));
    check_icmp_on_p1(ICMP_TIME_EXCEEDED, 0);
    CHECK_EQ_U64(g_stats.reasons[DROP_TTL_EXCEEDED], 1);
    CHECK_EQ_U64(fx_tx_count(3), 0);
    fx_teardown();
}

TEST(oversize_with_df_gives_frag_needed) {
    fx_setup(1);
    static uint8_t big[1700];
    size_t n = make_ipv4(f, MAC_P1, MAC_VM1, VM1_IP, VM3_IP, 64, 17, big, 1580); /* total 1600 */
    wr16(f + ETH_HDR_LEN + 6, IP_DF);
    pkt_ipv4_set_csum(f + ETH_HDR_LEN);
    fx_rx(1, f, n);
    check_icmp_on_p1(ICMP_UNREACH, ICMP_UNREACH_FRAG_NEEDED);
    size_t len;
    const uint8_t *o = tx1(1, 0, &len);
    CHECK_EQ_U64(rd16(o + ETH_HDR_LEN + IPV4_HDR_LEN + 6), 1500);
    CHECK_EQ_U64(g_stats.reasons[DROP_MTU_EXCEEDED], 1);

    fx_clear_tx(); /* without DF: dropped, no ICMP */
    n = make_ipv4(f, MAC_P1, MAC_VM1, VM1_IP, VM3_IP, 64, 17, big, 1580);
    fx_rx(1, f, n);
    CHECK_EQ_U64(fx_tx_count(1), 0);
    CHECK_EQ_U64(g_stats.reasons[DROP_MTU_EXCEEDED], 2);
    check_invariants();
    fx_teardown();
}

TEST(non_echo_to_own_ip_is_unsupported) {
    fx_setup(1);
    size_t n = make_ipv4(f, MAC_P1, MAC_VM1, VM1_IP, GW1_IP, 64, 17, "abcdefgh", 8);
    fx_rx(1, f, n);
    CHECK_EQ_U64(g_stats.reasons[DROP_LOCAL_UNSUPPORTED], 1);
    CHECK_EQ_U64(fx_tx_count(1), 0);
    fx_teardown();
}

TEST(egress_down_is_dropped) {
    fx_setup(1);
    port_find("p3")->oper_up = false;
    fx_rx(1, f, echo_from_vm1(VM3_IP, 64));
    CHECK_EQ_U64(g_stats.reasons[DROP_PORT_DOWN], 1);
    CHECK_EQ_U64(fx_tx_count(3), 0);
    port_find("p3")->oper_up = true;
    port_find("p3")->admin_up = false;
    fx_rx(1, f, echo_from_vm1(VM3_IP, 64));
    CHECK_EQ_U64(g_stats.reasons[DROP_PORT_DOWN], 2);
    fx_teardown();
}

TEST(hairpin_is_forwarded) {
    fx_setup(1);
    struct cmd_err e;
    CHECK(route_add_static(0, IP4(10, 0, 9, 0), 24, port_find("p1")->id, VM1_IP, &e) == 0);
    fx_rx(1, f, echo_from_vm1(IP4(10, 0, 9, 5), 64));
    CHECK_EQ_U64(fx_tx_count(1), 1);
    size_t len;
    const uint8_t *o = tx1(1, 0, &len);
    CHECK_MEM_EQ(o, MAC_VM1, 6);
    CHECK_EQ_U64(o[ETH_HDR_LEN + 8], 63);
    fx_teardown();
}

TEST(spoofed_sources_are_dropped_before_anything_else) {
    fx_setup(1);
    size_t n = make_echo(f, MAC_P1, MAC_VM1, VM2_IP, VM3_IP, 64, ICMP_ECHO_REQUEST, 1, 1);
    fx_rx(1, f, n);
    n = make_echo(f, MAC_P1, MAC_VM1, GW1_IP, VM3_IP, 64, ICMP_ECHO_REQUEST, 1, 1);
    fx_rx(1, f, n);
    n = make_arp_request(f, MAC_VM1, VM2_IP, GW1_IP);
    fx_rx(1, f, n);
    CHECK_EQ_U64(g_stats.reasons[DROP_SOURCE_SPOOFED], 3);
    CHECK_EQ_U64(g_stats.drop_total, 3);
    CHECK_EQ_U64(fx_tx_count(3) + fx_tx_count(1) + fx_tx_count(2), 0);
    fx_teardown();
}

TEST(malformed_frames_are_counted_once_each) {
    fx_setup(1);
    size_t n = echo_from_vm1(VM3_IP, 64);
    fx_rx(1, f, 10);                    /* truncated */
    f[ETH_HDR_LEN] = 0x65;              /* version 6 */
    fx_rx(1, f, n);
    n = make_ipv4(f, MAC_BCAST, MAC_VM1, VM1_IP, VM3_IP, 64, 17, "x", 1);
    fx_rx(1, f, n);                     /* broadcast non-ARP */
    n = make_ipv4(f, MAC_P2, MAC_VM1, VM1_IP, VM3_IP, 64, 17, "x", 1);
    fx_rx(1, f, n);                     /* not for us */
    n = echo_from_vm1(VM3_IP, 64);
    wr16(f + 12, 0x86dd);
    fx_rx(1, f, n);                     /* IPv6 ethertype */
    CHECK_EQ_U64(g_stats.reasons[DROP_TRUNCATED], 1);
    CHECK_EQ_U64(g_stats.reasons[DROP_BAD_IP_VERSION], 1);
    CHECK_EQ_U64(g_stats.reasons[DROP_NON_ARP_BCAST_MCAST], 1);
    CHECK_EQ_U64(g_stats.reasons[DROP_NOT_FOR_US_L2], 1);
    CHECK_EQ_U64(g_stats.reasons[DROP_UNSUPPORTED_ETHERTYPE], 1);
    CHECK_EQ_U64(g_stats.drop_total, 5);
    CHECK_EQ_U64(g_stats.port[0].drops, 5);
    check_invariants();
    CHECK_EQ_U64(mbuf_in_use(), 0);
    fx_teardown();
}

TEST(icmp_errors_are_rate_limited_but_drops_are_still_counted) {
    fx_setup(1);
    for (int i = 0; i < 25; i++)
        fx_rx(1, f, echo_from_vm1(IP4(10, 9, 9, 9), 64));
    CHECK_EQ_U64(g_stats.reasons[DROP_NO_ROUTE], 25);
    CHECK_EQ_U64(g_stats.icmp_sent, 20); /* burst */
    CHECK_EQ_U64(g_stats.icmp_ratelimited, 5);
    CHECK_EQ_U64(fx_tx_count(1), 20);
    check_invariants();
    fx_teardown();
}

TEST(unbound_port_learns_and_releases_the_held_packet) {
    fx_setup(0); /* vm3 unbound */
    size_t n = echo_from_vm1(VM3_IP, 64);
    fx_rx(1, f, n);
    /* the packet is held; the forwarder asked who has 10.0.2.13 on p3 */
    CHECK_EQ_U64(mbuf_in_use(), 1);
    CHECK_EQ_U64(fx_tx_count(3), 1);
    size_t len;
    const uint8_t *arp = tx1(3, 0, &len);
    CHECK_EQ_U64(rd16(arp + ETH_HDR_LEN + 6), ARP_OP_REQUEST);
    CHECK_EQ_U64(rd32(arp + ETH_HDR_LEN + 24), VM3_IP);

    fx_clear_tx();
    n = make_arp_reply(f, MAC_P3, MAC_VM3, VM3_IP, GW3_IP);
    fx_rx(3, f, n);
    CHECK_EQ_U64(fx_tx_count(3), 1); /* the held echo request, now with vm3's MAC */
    const uint8_t *o = tx1(3, 0, &len);
    CHECK_MEM_EQ(o, MAC_VM3, 6);
    CHECK_EQ_U64(o[ETH_HDR_LEN + 8], 63);
    const struct neigh *ne = neigh_lookup(0, VM3_IP);
    CHECK(ne && ne->kind == NEIGH_LEARNED && ne->state == NEIGH_REACHABLE);
    CHECK_EQ_U64(mbuf_in_use(), 0);
    CHECK_EQ_U64(g_stats.drop_total, 0);
    fx_teardown();
}

TEST(unbound_port_learns_from_arp_requests_too) {
    fx_setup(0);
    size_t n = make_arp_request(f, MAC_VM3, VM3_IP, GW3_IP);
    fx_rx(3, f, n);
    CHECK_EQ_U64(fx_tx_count(3), 1); /* reply for the gateway */
    CHECK(neigh_lookup(0, VM3_IP) != NULL);
    fx_teardown();
}

TEST(gratuitous_arp_is_consumed_silently) {
    fx_setup(0);
    size_t n = make_arp_request(f, MAC_VM3, VM3_IP, VM3_IP);
    fx_rx(3, f, n);
    CHECK_EQ_U64(fx_tx_count(3), 0);
    CHECK_EQ_U64(g_stats.drop_total, 0);
    CHECK(neigh_lookup(0, VM3_IP) != NULL);
    fx_teardown();
}

TEST(burst_of_many_frames_is_batched_without_leaks) {
    fx_setup(1);
    struct port *p1 = port_find("p1");
    for (int i = 0; i < 32; i++) {
        size_t n = echo_from_vm1(VM3_IP, 64);
        pio_fake_inject(p1->pio, f, n);
    }
    struct mbuf *burst[PIO_BURST];
    int n = port_backend()->rx_burst(p1->pio, burst, PIO_BURST);
    CHECK_EQ_U64(n, 32);
    forward_burst(p1, burst, n);
    CHECK_EQ_U64(fx_tx_count(3), 32);
    CHECK_EQ_U64(mbuf_in_use(), 0);
    CHECK_EQ_U64(g_stats.port[0].rx_pkts, 32);
    CHECK_EQ_U64(g_stats.port[2].tx_pkts, 32);
    fx_teardown();
}

TEST(kernel_stripped_vlan_tag_is_unsupported_ethertype) {
    fx_setup(1);
    struct port *p1 = port_find("p1");
    size_t n = echo_from_vm1(VM3_IP, 64); /* looks like plain IPv4 because the tag is gone */
    pio_fake_inject_vlan(p1->pio, f, n);
    struct mbuf *burst[PIO_BURST];
    int k = port_backend()->rx_burst(p1->pio, burst, PIO_BURST);
    forward_burst(p1, burst, k);
    CHECK_EQ_U64(g_stats.reasons[DROP_UNSUPPORTED_ETHERTYPE], 1);
    CHECK_EQ_U64(fx_tx_count(3), 0);
    CHECK_EQ_U64(mbuf_in_use(), 0);
    fx_teardown();
}

/* ---- phase 1 inside VRFs (phase 2) ----
 * red: r1 10.1.1.11, r2 10.1.1.12 (gateway 10.1.1.1/24)
 * blue: b1 10.1.1.11, b2 10.1.1.13 (gateway 10.1.1.254/24, the same subnet as red's) */

static const uint8_t M_R1[6] = {2, 0, 0, 0x0a, 1, 1}, M_R2[6] = {2, 0, 0, 0x0a, 1, 2};
static const uint8_t M_B1[6] = {2, 0, 0, 0x0a, 1, 3}, M_B2[6] = {2, 0, 0, 0x0a, 1, 4};
static const uint8_t V_R1[6] = {2, 0, 0, 1, 1, 0x11}, V_R2[6] = {2, 0, 0, 1, 1, 0x12};
static const uint8_t V_B1[6] = {2, 0, 0, 2, 1, 0x11}, V_B2[6] = {2, 0, 0, 2, 1, 0x13};

static void vrf_setup(void) {
    ov_reset();
    const char *names[] = {"r1", "r2", "b1", "b2"};
    const uint8_t *macs[] = {M_R1, M_R2, M_B1, M_B2};
    for (int i = 0; i < 4; i++)
        pio_fake_add_if(names[i], macs[i], 1500);
    pio_fake_add_if("u0", OV_UL_MAC1, 1600);
    port_set_backend(&pio_fake_ops);
    CHECK(fx_cmd("vrf add red id 1") == 0);
    CHECK(fx_cmd("vrf add blue id 2") == 0);
    CHECK(fx_cmd("underlay add u0 ifname u0 ip 172.16.0.1/24") == 0);
    CHECK(fx_cmd("port add r1 ifname r1 ip 10.1.1.1/24 vrf red") == 0);
    CHECK(fx_cmd("port add r2 ifname r2 ip 10.1.1.1/24 vrf red") == 0);
    CHECK(fx_cmd("port add b1 ifname b1 ip 10.1.1.254/24 vrf blue") == 0);
    CHECK(fx_cmd("port add b2 ifname b2 ip 10.1.1.254/24 vrf blue") == 0);
    CHECK(fx_cmd("neigh add 10.1.1.11 lladdr 02:00:00:01:01:11 dev r1") == 0);
    CHECK(fx_cmd("neigh add 10.1.1.12 lladdr 02:00:00:01:01:12 dev r2") == 0);
    CHECK(fx_cmd("neigh add 10.1.1.11 lladdr 02:00:00:02:01:11 dev b1") == 0);
    CHECK(fx_cmd("neigh add 10.1.1.13 lladdr 02:00:00:02:01:13 dev b2") == 0);
}

TEST(vrf_forward_goes_to_the_ports_of_the_ingress_vrf_only) {
    vrf_setup();
    uint8_t fr[256];
    size_t n = make_echo(fr, M_R1, V_R1, IP4(10, 1, 1, 11), IP4(10, 1, 1, 12), 64, ICMP_ECHO_REQUEST, 1, 1);
    ov_rx("r1", fr, n);
    CHECK_EQ_U64(ov_tx_count("r2"), 1);
    CHECK_EQ_U64(ov_tx_count("b1") + ov_tx_count("b2") + ov_tx_count("r1"), 0);
    size_t len;
    const uint8_t *o = ov_tx("r2", 0, &len);
    CHECK_MEM_EQ(o, V_R2, 6);
    CHECK_MEM_EQ(o + 6, M_R2, 6);
    CHECK_EQ_U64(o[ETH_HDR_LEN + 8], 63);
    ov_clear_tx();
    /* blue: same source IP, destination 10.1.1.13 lives in blue only */
    n = make_echo(fr, M_B1, V_B1, IP4(10, 1, 1, 11), IP4(10, 1, 1, 13), 64, ICMP_ECHO_REQUEST, 1, 1);
    ov_rx("b1", fr, n);
    CHECK_EQ_U64(ov_tx_count("b2"), 1);
    CHECK_MEM_EQ(ov_tx("b2", 0, &len), V_B2, 6);
    CHECK_EQ_U64(ov_tx_count("r1") + ov_tx_count("r2"), 0);
    CHECK_EQ_U64(g_stats.drop_total, 0);
    check_invariants();
    ov_teardown();
}

TEST(a_destination_that_exists_only_in_the_other_vrf_is_not_reachable) {
    vrf_setup();
    uint8_t fr[256];
    /* red1 -> 10.1.1.13 exists only in blue: red has the subnet but no host route for it */
    size_t n = make_echo(fr, M_R1, V_R1, IP4(10, 1, 1, 11), IP4(10, 1, 1, 13), 64, ICMP_ECHO_REQUEST, 1, 1);
    ov_rx("r1", fr, n);
    CHECK_EQ_U64(ov_tx_count("b2"), 0);
    CHECK_EQ_U64(g_stats.reasons[DROP_NO_ROUTE], 1);
    /* and the ICMP host unreachable comes from red's gateway, out of the ingress port */
    CHECK_EQ_U64(ov_tx_count("r1"), 1);
    size_t len;
    const uint8_t *o = ov_tx("r1", 0, &len);
    CHECK_EQ_U64(o[ETH_HDR_LEN + 12], 10);
    CHECK_EQ_U64(rd32(o + ETH_HDR_LEN + 12), IP4(10, 1, 1, 1));
    check_invariants();
    ov_teardown();
}

TEST(icmp_errors_are_sourced_from_the_ingress_vrfs_gateway) {
    vrf_setup();
    uint8_t fr[256];
    size_t n = make_echo(fr, M_B1, V_B1, IP4(10, 1, 1, 11), IP4(10, 1, 1, 13), 1, ICMP_ECHO_REQUEST, 1, 1);
    ov_rx("b1", fr, n); /* TTL 1 */
    CHECK_EQ_U64(ov_tx_count("b1"), 1);
    size_t len;
    const uint8_t *o = ov_tx("b1", 0, &len);
    CHECK_EQ_U64(rd32(o + ETH_HDR_LEN + 12), IP4(10, 1, 1, 254)); /* blue's gateway, not red's */
    CHECK_EQ_U64(o[ETH_HDR_LEN + IPV4_HDR_LEN], ICMP_TIME_EXCEEDED);
    ov_teardown();
}

TEST(arp_is_answered_from_the_ingress_vrf_only) {
    vrf_setup();
    uint8_t fr[64];
    size_t len;
    /* gateway of each VRF */
    ov_rx("r1", fr, make_arp_request(fr, V_R1, IP4(10, 1, 1, 11), IP4(10, 1, 1, 1)));
    CHECK_EQ_U64(ov_tx_count("r1"), 1);
    CHECK_MEM_EQ(ov_tx("r1", 0, &len) + 22, M_R1, 6); /* sender hardware address of the reply */
    ov_clear_tx();
    ov_rx("b1", fr, make_arp_request(fr, V_B1, IP4(10, 1, 1, 11), IP4(10, 1, 1, 1)));
    CHECK_EQ_U64(ov_tx_count("b1"), 0); /* 10.1.1.1 is red's gateway, not blue's */
    ov_rx("b1", fr, make_arp_request(fr, V_B1, IP4(10, 1, 1, 11), IP4(10, 1, 1, 254)));
    CHECK_EQ_U64(ov_tx_count("b1"), 1);
    ov_clear_tx();
    /* a neighbour: known in red, unknown in blue */
    ov_rx("r1", fr, make_arp_request(fr, V_R1, IP4(10, 1, 1, 11), IP4(10, 1, 1, 12)));
    CHECK_EQ_U64(ov_tx_count("r1"), 1);
    ov_clear_tx();
    ov_rx("b1", fr, make_arp_request(fr, V_B1, IP4(10, 1, 1, 11), IP4(10, 1, 1, 12)));
    CHECK_EQ_U64(ov_tx_count("b1"), 0);
    ov_rx("r1", fr, make_arp_request(fr, V_R1, IP4(10, 1, 1, 11), IP4(10, 1, 1, 13)));
    CHECK_EQ_U64(ov_tx_count("r1"), 0);
    CHECK_EQ_U64(g_stats.reasons[DROP_ARP_UNKNOWN_TARGET], 3);
    check_invariants();
    ov_teardown();
}

TEST(echo_to_a_gateway_is_answered_in_its_own_vrf) {
    vrf_setup();
    uint8_t fr[256];
    size_t n = make_echo(fr, M_R1, V_R1, IP4(10, 1, 1, 11), IP4(10, 1, 1, 1), 64, ICMP_ECHO_REQUEST, 1, 1);
    ov_rx("r1", fr, n);
    CHECK_EQ_U64(ov_tx_count("r1"), 1);
    ov_clear_tx();
    /* 10.1.1.1 is not an address of the forwarder inside blue: not answered, routed as transit */
    n = make_echo(fr, M_B1, V_B1, IP4(10, 1, 1, 11), IP4(10, 1, 1, 1), 64, ICMP_ECHO_REQUEST, 1, 1);
    ov_rx("b1", fr, n);
    CHECK_EQ_U64(g_stats.reasons[DROP_LOCAL_UNSUPPORTED], 0);
    CHECK_EQ_U64(ov_tx_count("b1") + 0, 1); /* an ICMP host unreachable, not an echo reply */
    size_t len;
    CHECK(ov_tx("b1", 0, &len)[ETH_HDR_LEN + IPV4_HDR_LEN] != ICMP_ECHO_REPLY);
    ov_teardown();
}

TEST(a_frame_on_the_underlay_port_is_dropped_until_decap_exists) {
    vrf_setup();
    uint8_t fr[256];
    size_t n = make_echo(fr, OV_UL_MAC1, OV_UL_MAC2, IP4(172, 16, 0, 2), IP4(172, 16, 0, 1), 64, ICMP_ECHO_REQUEST, 1, 1);
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(g_stats.reasons[DROP_UNDERLAY_UNEXPECTED], 1);
    check_invariants();
    CHECK_EQ_U64(mbuf_in_use(), 0);
    ov_teardown();
}
