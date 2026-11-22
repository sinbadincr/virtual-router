#include "overlay_fixture.h"
#include "tharness.h"

static uint8_t fr[2048];

/* An inner IPv4 packet (no Ethernet) from 10.1.1.11 to `dst`, 28 bytes of UDP payload. */
static size_t inner_ip(uint8_t *out, uint32_t dst, uint8_t ttl) {
    uint8_t body[28];
    memset(body, 0x42, sizeof body);
    uint8_t tmp[128];
    size_t n = make_ipv4(tmp, OV_UL_MAC1, OV_UL_MAC1, IP4(10, 1, 1, 11), dst, ttl, 17, body, sizeof body);
    memcpy(out, tmp + ETH_HDR_LEN, n - ETH_HDR_LEN);
    return n - ETH_HDR_LEN;
}

/* Outer Ethernet + IPv4 + UDP around `payload`; addressed to cn2's underlay by default. */
static size_t outer(uint8_t *out, uint16_t dport, const uint8_t *payload, size_t plen, uint32_t src_ip,
                    uint32_t dst_ip) {
    memcpy(out, OV_UL_MAC2, 6);
    memcpy(out + 6, OV_UL_MAC1, 6);
    wr16(out + 12, ETHERTYPE_IPV4);
    uint8_t *ip = out + ETH_HDR_LEN;
    ip[0] = 0x45; ip[1] = 0;
    wr16(ip + 2, (uint16_t)(IPV4_HDR_LEN + UDP_HDR_LEN + plen));
    wr16(ip + 4, 0); wr16(ip + 6, 0x4000);
    ip[8] = 64; ip[9] = 17;
    wr32(ip + 12, src_ip); wr32(ip + 16, dst_ip);
    pkt_ipv4_set_csum(ip);
    pkt_udp_build(ip + IPV4_HDR_LEN, 51234, dport, (uint16_t)plen);
    memcpy(ip + IPV4_HDR_LEN + UDP_HDR_LEN, payload, plen);
    return ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + plen;
}

#define CN1_IP IP4(172, 16, 0, 1)
#define CN2_IP IP4(172, 16, 0, 2)

static size_t mpls_frame(uint32_t label, uint32_t inner_dst, uint8_t ttl) {
    uint8_t pl[256];
    pkt_mpls_build(pl, label, ttl);
    size_t n = inner_ip(pl + 4, inner_dst, ttl);
    return outer(fr, UDP_PORT_MPLS, pl, 4 + n, CN1_IP, CN2_IP);
}

static size_t vxlan_frame(uint32_t vni, uint32_t inner_dst, uint8_t ttl) {
    uint8_t pl[256];
    pkt_vxlan_build(pl, vni);
    memcpy(pl + 8, OV_UL_MAC2, 6); /* inner dst = our router MAC */
    memcpy(pl + 14, OV_UL_MAC1, 6);
    wr16(pl + 20, ETHERTYPE_IPV4);
    size_t n = inner_ip(pl + 22, inner_dst, ttl);
    return outer(fr, UDP_PORT_VXLAN, pl, 22 + n, CN1_IP, CN2_IP);
}

static void cn2(void) {
    CHECK_EQ_U64(ov_setup(2, 1600), 0);
    struct cmd_err e;
    CHECK(ov_cmd(CMD_CLI, "vni add 300 vrf red", &e) == 0); /* red VNI: for the no-transit cases */
}

static void check_invariant(void) {
    CHECK_EQ_U64(stats_reason_sum(), g_stats.drop_total);
    CHECK_EQ_U64(mbuf_in_use(), 0);
}

/* ---- delivery ---- */

TEST(vxlan_vni_to_vrf_to_local_vm_rebuilds_the_inner_ethernet) {
    cn2();
    size_t n = vxlan_frame(200, IP4(10, 1, 1, 12), 63);
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(ov_tx_count("blue2"), 1);
    CHECK_EQ_U64(ov_tx_count("red2") + ov_tx_count("red3"), 0); /* tenant isolation */
    size_t len;
    const uint8_t *o = ov_tx("blue2", 0, &len);
    uint8_t pm[6];
    ov_port_mac(pm, 2, 3);
    CHECK_MEM_EQ(o, OV_BLUE2, 6);   /* dst = the VM */
    CHECK_MEM_EQ(o + 6, pm, 6);     /* src = the VM port's MAC */
    CHECK_EQ_U64(rd16(o + 12), 0x0800);
    CHECK_EQ_U64(o[ETH_HDR_LEN + 8], 63); /* TTL not decremented */
    CHECK_EQ_U64(pkt_csum16(o + ETH_HDR_LEN, IPV4_HDR_LEN), 0);
    CHECK_EQ_U64(len, ETH_HDR_LEN + 20 + 8 + 20); /* inner 48 bytes + Ethernet, nothing else */
    CHECK_EQ_U64(g_stats.drop_total, 0);
    check_invariant();
    ov_teardown();
}

TEST(inner_ttl_1_and_0_are_delivered_untouched) {
    cn2();
    for (uint8_t ttl = 0; ttl <= 1; ttl++) {
        ov_clear_tx();
        size_t n = vxlan_frame(200, IP4(10, 1, 1, 12), ttl);
        ov_rx("u0", fr, n);
        size_t len;
        CHECK_EQ_U64(ov_tx_count("blue2"), 1);
        CHECK_EQ_U64(ov_tx("blue2", 0, &len)[ETH_HDR_LEN + 8], ttl);
    }
    ov_teardown();
}

TEST(mpls_label_to_port_when_the_inner_destination_is_its_bound_address) {
    cn2();
    size_t n = mpls_frame(1012, IP4(10, 1, 1, 12), 63);
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(ov_tx_count("red2"), 1);
    size_t len;
    const uint8_t *o = ov_tx("red2", 0, &len);
    uint8_t pm[6];
    ov_port_mac(pm, 2, 1);
    CHECK_MEM_EQ(o, OV_RED2, 6);
    CHECK_MEM_EQ(o + 6, pm, 6);
    CHECK_EQ_U64(o[ETH_HDR_LEN + 8], 63);
    CHECK_EQ_U64(g_stats.drop_total, 0);
    ov_clear_tx();
    n = mpls_frame(1013, IP4(10, 1, 2, 13), 5); /* the other red VM on this node */
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(ov_tx_count("red3"), 1);
    check_invariant();
    ov_teardown();
}

TEST(mpls_with_another_inner_destination_is_decap_no_local_dest) {
    cn2();
    { size_t k = mpls_frame(1012, IP4(10, 1, 1, 99), 63); ov_rx("u0", fr, k); } /* no such VM */
    { size_t k = mpls_frame(1012, IP4(10, 1, 2, 13), 63); ov_rx("u0", fr, k); } /* red3's address on red2's label */
    { size_t k = mpls_frame(1012, IP4(10, 9, 9, 9), 63); ov_rx("u0", fr, k); } /* nowhere near our subnets */
    CHECK_EQ_U64(g_stats.reasons[DROP_DECAP_NO_LOCAL_DEST], 3);
    CHECK_EQ_U64(ov_tx_count("red2") + ov_tx_count("red3") + ov_tx_count("blue2"), 0);
    check_invariant();
    ov_teardown();
}

TEST(vxlan_never_transits_to_a_remote_or_absent_destination) {
    cn2();
    /* red VNI 300, destination 10.1.1.11 is a REMOTE route on this node: no hairpin */
    { size_t k = vxlan_frame(300, IP4(10, 1, 1, 11), 63); ov_rx("u0", fr, k); }
    /* blue VNI, destination inside the connected subnet but not a known VM */
    { size_t k = vxlan_frame(200, IP4(10, 1, 1, 200), 63); ov_rx("u0", fr, k); }
    /* blue VNI, destination in no route at all */
    { size_t k = vxlan_frame(200, IP4(192, 168, 7, 7), 63); ov_rx("u0", fr, k); }
    CHECK_EQ_U64(g_stats.reasons[DROP_DECAP_NO_LOCAL_DEST], 3);
    CHECK_EQ_U64(ov_tx_count("u0"), 0); /* nothing sent back out: the underlay never forwards */
    check_invariant();
    ov_teardown();
}

TEST(a_static_route_through_a_gateway_is_not_a_local_destination) {
    cn2();
    struct cmd_err e;
    CHECK(ov_cmd(CMD_CLI, "route add 10.8.0.0/24 vrf blue dev blue2 via 10.1.1.12", &e) == 0);
    { size_t k = vxlan_frame(200, IP4(10, 8, 0, 5), 63); ov_rx("u0", fr, k); }
    CHECK_EQ_U64(g_stats.reasons[DROP_DECAP_NO_LOCAL_DEST], 1);
    CHECK_EQ_U64(ov_tx_count("blue2"), 0);
    ov_teardown();
}

/* ---- outer-header problems ---- */

TEST(outer_destination_other_than_our_underlay_ip_is_not_for_us) {
    cn2();
    uint8_t pl[64];
    pkt_mpls_build(pl, 1012, 63);
    size_t n = inner_ip(pl + 4, IP4(10, 1, 1, 12), 63);
    n = outer(fr, UDP_PORT_MPLS, pl, 4 + n, CN1_IP, CN1_IP); /* addressed to cn1's IP, sent to cn2's MAC */
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(g_stats.reasons[DROP_TUNNEL_NOT_FOR_US], 1);
    check_invariant();
    ov_teardown();
}

TEST(unexpected_underlay_traffic_is_counted_not_delivered) {
    cn2();
    uint8_t pl[16] = {1, 2, 3, 4};
    size_t n = outer(fr, 9999, pl, 4, CN1_IP, CN2_IP); /* UDP to another port */
    ov_rx("u0", fr, n);
    n = outer(fr, UDP_PORT_VXLAN, pl, 4, CN1_IP, CN2_IP);
    fr[ETH_HDR_LEN + 9] = 6; /* TCP */
    pkt_ipv4_set_csum(fr + ETH_HDR_LEN);
    ov_rx("u0", fr, n);
    n = outer(fr, UDP_PORT_VXLAN, pl, 4, CN1_IP, CN2_IP);
    wr16(fr + 12, 0x86dd); /* IPv6 EtherType */
    ov_rx("u0", fr, n);
    n = outer(fr, UDP_PORT_VXLAN, pl, 4, CN1_IP, CN2_IP);
    fr[ETH_HDR_LEN + 9] = 47; /* GRE */
    pkt_ipv4_set_csum(fr + ETH_HDR_LEN);
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(g_stats.reasons[DROP_UNDERLAY_UNEXPECTED], 4);
    CHECK_EQ_U64(g_stats.drop_total, 4);
    check_invariant();
    ov_teardown();
}

TEST(malformed_udp_and_tunnel_headers_have_their_own_reasons) {
    cn2();
    uint8_t pl[64];
    memset(pl, 0, sizeof pl);
    size_t n;
    /* UDP length larger than the IP payload */
    pkt_mpls_build(pl, 1012, 63);
    n = outer(fr, UDP_PORT_MPLS, pl, 4 + 20, CN1_IP, CN2_IP);
    wr16(fr + ETH_HDR_LEN + IPV4_HDR_LEN + 4, 200);
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(g_stats.reasons[DROP_BAD_UDP], 1);
    /* VXLAN without the I flag */
    pkt_vxlan_build(pl, 200);
    pl[0] = 0;
    n = outer(fr, UDP_PORT_VXLAN, pl, 8 + 14 + 20, CN1_IP, CN2_IP);
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(g_stats.reasons[DROP_BAD_VXLAN], 1);
    /* VXLAN header cut short */
    n = outer(fr, UDP_PORT_VXLAN, pl, 5, CN1_IP, CN2_IP);
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(g_stats.reasons[DROP_BAD_VXLAN], 2);
    /* MPLS with S = 0, and a stack entry cut short */
    pkt_mpls_build(pl, 1012, 63);
    pl[2] &= (uint8_t)~1;
    n = outer(fr, UDP_PORT_MPLS, pl, 4 + 20, CN1_IP, CN2_IP);
    ov_rx("u0", fr, n);
    n = outer(fr, UDP_PORT_MPLS, pl, 3, CN1_IP, CN2_IP);
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(g_stats.reasons[DROP_BAD_MPLS], 2);
    check_invariant();
    ov_teardown();
}

TEST(unmapped_label_and_vni_are_unknown_tag) {
    cn2();
    { size_t k = mpls_frame(4000, IP4(10, 1, 1, 12), 63); ov_rx("u0", fr, k); }
    { size_t k = vxlan_frame(777, IP4(10, 1, 1, 12), 63); ov_rx("u0", fr, k); }
    CHECK_EQ_U64(g_stats.reasons[DROP_UNKNOWN_TAG], 2);
    check_invariant();
    ov_teardown();
}

TEST(bad_inner_ethernet_in_vxlan) {
    cn2();
    size_t n = vxlan_frame(200, IP4(10, 1, 1, 12), 63);
    uint8_t *inner = fr + ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN;
    inner[5] ^= 0xff; /* destination is not our router MAC */
    ov_rx("u0", fr, n);
    n = vxlan_frame(200, IP4(10, 1, 1, 12), 63);
    inner = fr + ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN;
    wr16(inner + 12, ETHERTYPE_ARP); /* not IPv4 */
    ov_rx("u0", fr, n);
    uint8_t pl[32];
    memset(pl, 0, sizeof pl);
    pkt_vxlan_build(pl, 200);
    n = outer(fr, UDP_PORT_VXLAN, pl, 8 + 10, CN1_IP, CN2_IP); /* inner Ethernet < 14 bytes */
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(g_stats.reasons[DROP_BAD_INNER_L2], 3);
    check_invariant();
    ov_teardown();
}

TEST(a_malformed_inner_ipv4_uses_the_phase1_reasons) {
    cn2();
    size_t n = mpls_frame(1012, IP4(10, 1, 1, 12), 63);
    fr[ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + 4 + 10] ^= 0xff; /* inner checksum */
    ov_rx("u0", fr, n);
    n = vxlan_frame(200, IP4(10, 1, 1, 12), 63);
    fr[ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN + ETH_HDR_LEN] = 0x65; /* version 6 */
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(g_stats.reasons[DROP_BAD_IP_CHECKSUM], 1);
    CHECK_EQ_U64(g_stats.reasons[DROP_BAD_IP_VERSION], 1);
    /* an inner packet shorter than an IPv4 header */
    uint8_t pl[16];
    pkt_mpls_build(pl, 1012, 63);
    n = outer(fr, UDP_PORT_MPLS, pl, 4 + 6, CN1_IP, CN2_IP);
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(g_stats.reasons[DROP_TRUNCATED], 1);
    check_invariant();
    ov_teardown();
}

/* ---- the underlay's own services ---- */

TEST(icmp_echo_to_the_underlay_address_is_answered) {
    cn2();
    size_t n = make_echo(fr, OV_UL_MAC2, OV_UL_MAC1, CN1_IP, CN2_IP, 64, ICMP_ECHO_REQUEST, 9, 1);
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(ov_tx_count("u0"), 1);
    size_t len;
    const uint8_t *o = ov_tx("u0", 0, &len);
    CHECK_MEM_EQ(o, OV_UL_MAC1, 6);
    CHECK_MEM_EQ(o + 6, OV_UL_MAC2, 6);
    CHECK_EQ_U64(o[ETH_HDR_LEN + IPV4_HDR_LEN], ICMP_ECHO_REPLY);
    CHECK_EQ_U64(rd32(o + ETH_HDR_LEN + 12), CN2_IP);
    ov_teardown();
}

TEST(arp_on_the_underlay_is_answered_and_learned_only_in_the_underlay_table) {
    cn2();
    uint8_t a[64];
    size_t n = make_arp_request(a, OV_UL_MAC1, CN1_IP, CN2_IP);
    ov_rx("u0", a, n);
    CHECK_EQ_U64(ov_tx_count("u0"), 1);
    size_t len;
    const uint8_t *r = ov_tx("u0", 0, &len);
    CHECK_EQ_U64(rd16(r + 20), ARP_OP_REPLY);
    CHECK_MEM_EQ(r + 22, OV_UL_MAC2, 6); /* we claim our underlay address */
    const struct neigh *nb = neigh_lookup(NEIGH_UNDERLAY, CN1_IP);
    CHECK(nb && nb->state == NEIGH_REACHABLE);
    CHECK_MEM_EQ(nb->mac, OV_UL_MAC1, 6);
    for (unsigned v = 0; v < 3; v++)
        CHECK(neigh_lookup(v, CN1_IP) == NULL);
    /* an address we do not own, and a sender that is no node: not answered, not learned */
    ov_clear_tx();
    n = make_arp_request(a, OV_UL_MAC1, CN1_IP, IP4(172, 16, 0, 55));
    ov_rx("u0", a, n);
    n = make_arp_request(a, OV_UL_MAC1, IP4(172, 16, 0, 66), CN2_IP);
    ov_rx("u0", a, n);
    CHECK_EQ_U64(ov_tx_count("u0"), 1);
    CHECK(neigh_lookup(NEIGH_UNDERLAY, IP4(172, 16, 0, 66)) == NULL);
    CHECK_EQ_U64(g_stats.reasons[DROP_ARP_UNKNOWN_TARGET], 1);
    check_invariant();
    ov_teardown();
}

TEST(a_frame_for_another_mac_is_dropped_by_the_phase1_classifier) {
    cn2();
    size_t n = mpls_frame(1012, IP4(10, 1, 1, 12), 63);
    memcpy(fr, OV_UL_MAC1, 6);
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(g_stats.reasons[DROP_NOT_FOR_US_L2], 1);
    ov_teardown();
}

/* ---- counters ---- */

TEST(decap_counters_per_source_node_and_unknown) {
    cn2();
    uint8_t cn1 = node_find("cn1")->id;
    size_t n = mpls_frame(1012, IP4(10, 1, 1, 12), 63);
    ov_rx("u0", fr, n);
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(g_stats.node[cn1].decap[ENCAP_MPLSOUDP].pkts, 2);
    CHECK_EQ_U64(g_stats.node[cn1].decap[ENCAP_MPLSOUDP].bytes, 2 * n);
    n = vxlan_frame(200, IP4(10, 1, 1, 12), 63);
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(g_stats.node[cn1].decap[ENCAP_VXLAN].pkts, 1);
    /* a tunnel from an address that is no configured node */
    n = mpls_frame(1012, IP4(10, 1, 1, 12), 63);
    wr32(fr + ETH_HDR_LEN + 12, IP4(172, 16, 0, 77));
    pkt_ipv4_set_csum(fr + ETH_HDR_LEN);
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(g_stats.node[NODE_UNKNOWN].decap[ENCAP_MPLSOUDP].pkts, 1);
    CHECK_EQ_U64(g_stats.node[cn1].decap[ENCAP_MPLSOUDP].pkts, 2);
    /* dropped packets are not counted as decapsulated */
    { size_t k = mpls_frame(4000, IP4(10, 1, 1, 12), 63); ov_rx("u0", fr, k); }
    CHECK_EQ_U64(g_stats.node[cn1].decap[ENCAP_MPLSOUDP].pkts, 2);
    check_invariant();
    ov_teardown();
}

TEST(egress_port_down_is_port_down) {
    cn2();
    struct cmd_err e;
    CHECK(ov_cmd(CMD_CLI, "port set blue2 admin down", &e) == 0);
    size_t n = vxlan_frame(200, IP4(10, 1, 1, 12), 63);
    ov_rx("u0", fr, n);
    CHECK_EQ_U64(g_stats.reasons[DROP_PORT_DOWN], 1);
    ov_teardown();
}

/* ---- US3: no tenant crosses over (extra ports give each tenant addresses the other lacks) ---- */

static void cn2_with_private_vms(void) {
    cn2();
    uint8_t m1[6] = {2, 0, 0, 0x0a, 2, 0x10}, m2[6] = {2, 0, 0, 0x0a, 2, 0x11};
    pio_fake_add_if("blue3", m1, 1500);
    pio_fake_add_if("red4", m2, 1500);
    struct cmd_err e;
    CHECK(ov_cmd(CMD_CONFIG, "port add blue3 ifname blue3 ip 10.1.5.1/24 vrf blue", &e) == 0);
    CHECK(ov_cmd(CMD_CONFIG, "neigh add 10.1.5.50 lladdr 02:00:00:02:02:50 dev blue3", &e) == 0); /* blue only */
    CHECK(ov_cmd(CMD_CONFIG, "port add red4 ifname red4 ip 10.1.6.1/24 vrf red", &e) == 0);
    CHECK(ov_cmd(CMD_CONFIG, "neigh add 10.1.6.60 lladdr 02:00:00:01:02:60 dev red4", &e) == 0);   /* red only */
    CHECK(ov_cmd(CMD_CONFIG, "label add 1600 port red4", &e) == 0);
}

TEST(a_red_label_carrying_a_blue_only_destination_reaches_no_blue_port) {
    cn2_with_private_vms();
    { size_t k = mpls_frame(1012, IP4(10, 1, 5, 50), 63); ov_rx("u0", fr, k); } /* red2's label */
    { size_t k = mpls_frame(1600, IP4(10, 1, 5, 50), 63); ov_rx("u0", fr, k); } /* red4's label */
    CHECK_EQ_U64(g_stats.reasons[DROP_DECAP_NO_LOCAL_DEST], 2);
    CHECK_EQ_U64(ov_tx_count("blue3") + ov_tx_count("blue2") + ov_tx_count("red2") + ov_tx_count("red4"), 0);
    check_invariant();
    ov_teardown();
}

TEST(a_blue_vni_carrying_a_red_only_destination_reaches_no_red_port) {
    cn2_with_private_vms();
    { size_t k = vxlan_frame(200, IP4(10, 1, 6, 60), 63); ov_rx("u0", fr, k); } /* blue VNI, red-only host */
    { size_t k = vxlan_frame(200, IP4(10, 1, 2, 13), 63); ov_rx("u0", fr, k); } /* blue VNI, red3's address */
    CHECK_EQ_U64(g_stats.reasons[DROP_DECAP_NO_LOCAL_DEST], 2);
    CHECK_EQ_U64(ov_tx_count("red4") + ov_tx_count("red3") + ov_tx_count("red2"), 0);
    /* the legitimate case still works: a red VNI to the red-only host */
    { size_t k = vxlan_frame(300, IP4(10, 1, 6, 60), 63); ov_rx("u0", fr, k); }
    CHECK_EQ_U64(ov_tx_count("red4"), 1);
    check_invariant();
    ov_teardown();
}

TEST(a_route_added_in_red_is_absent_from_blue) {
    cn2_with_private_vms();
    struct cmd_err e;
    CHECK(ov_cmd(CMD_CLI, "route add 10.9.0.0/24 vrf red dev red4 via 10.1.6.60", &e) == 0);
    CHECK(route_lookup(vrf_by_name("red")->id, IP4(10, 9, 0, 1)) != NULL);
    CHECK(route_lookup(vrf_by_name("blue")->id, IP4(10, 9, 0, 1)) == NULL);
    char buf[4096];
    struct jw w;
    jw_init(&w, buf, sizeof buf);
    CHECK(cmd_exec("route show vrf blue", CMD_CLI, &w, &e) == 0);
    CHECK(strstr(buf, "10.9.0.0/24") == NULL);
    jw_init(&w, buf, sizeof buf);
    CHECK(cmd_exec("route show vrf red", CMD_CLI, &w, &e) == 0);
    CHECK(strstr(buf, "10.9.0.0/24") != NULL);
    ov_teardown();
}

/* ---- US5: truncation and corruption sweeps (run under ASan in the gate) ---- */

static size_t mpls_good(void) {
    return mpls_frame(1012, IP4(10, 1, 1, 12), 63);
}
static size_t vxlan_good(void) {
    return vxlan_frame(200, IP4(10, 1, 1, 12), 63);
}

static uint64_t vm_tx_total(void) {
    return ov_tx_count("red2") + ov_tx_count("red3") + ov_tx_count("blue2");
}

/* Every prefix of a valid tunnel frame is dropped under a named reason, never delivered, and the
 * bytes past the end of the frame (a stale copy of the full valid frame from the previous
 * iteration is still in the pooled buffer) are never read: a read past the end would deliver. */
static void truncation_sweep(size_t (*good)(void), const char *what) {
    cn2();
    size_t full = good();
    uint8_t keep[2048];
    memcpy(keep, fr, full);
    { /* the full frame is delivered once, leaving its bytes in the pooled buffer */
        ov_rx("u0", keep, full);
        CHECK_EQ_U64(vm_tx_total(), 1);
        ov_clear_tx();
    }
    for (size_t n = 1; n < full; n++) {
        uint64_t drops = g_stats.drop_total;
        ov_rx("u0", keep, n);
        if (vm_tx_total() != 0 || g_stats.drop_total != drops + 1 || mbuf_in_use() != 0) {
            TH_FAIL("%s truncated to %zu of %zu: tx=%llu drops +%llu", what, n, full,
                    (unsigned long long)vm_tx_total(), (unsigned long long)(g_stats.drop_total - drops));
            break;
        }
    }
    CHECK_EQ_U64(stats_reason_sum(), g_stats.drop_total);
    ov_teardown();
}

TEST(every_truncation_of_a_valid_mplsoudp_frame_is_dropped) {
    truncation_sweep(mpls_good, "mplsoudp");
}

TEST(every_truncation_of_a_valid_vxlan_frame_is_dropped) {
    truncation_sweep(vxlan_good, "vxlan");
}

/* Flip every byte of the headers (outer Ethernet, IPv4, UDP and the tunnel header and, for VXLAN,
 * the inner Ethernet): the result is either exactly one drop, or a packet that is still valid
 * (a field the receiver ignores) and delivered once; never a crash, a leak or both. */
static void corruption_sweep(size_t (*good)(void), size_t hdr_bytes, const char *what) {
    cn2();
    uint8_t keep[2048];
    size_t full = good();
    memcpy(keep, fr, full);
    unsigned delivered = 0, dropped = 0;
    for (size_t i = 0; i < hdr_bytes; i++) {
        uint8_t bad[2048];
        memcpy(bad, keep, full);
        bad[i] ^= 0xff;
        uint64_t drops = g_stats.drop_total;
        ov_clear_tx();
        ov_rx("u0", bad, full);
        uint64_t d = g_stats.drop_total - drops, tx = vm_tx_total();
        if (!((d == 1 && tx == 0) || (d == 0 && tx == 1) || (d == 0 && ov_tx_count("u0") == 1))) {
            TH_FAIL("%s byte %zu flipped: drops +%llu, vm tx %llu", what, i, (unsigned long long)d,
                    (unsigned long long)tx);
        }
        delivered += (unsigned)tx;
        dropped += (unsigned)d;
        if (mbuf_in_use() != 0)
            TH_FAIL("%s byte %zu: mbuf leak", what, i);
    }
    CHECK(dropped > 0 && delivered > 0); /* both outcomes occur: the sweep is not vacuous */
    CHECK_EQ_U64(stats_reason_sum(), g_stats.drop_total);
    ov_teardown();
}

TEST(flipping_any_header_byte_of_mplsoudp_never_crashes_or_leaks) {
    corruption_sweep(mpls_good, ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + MPLS_LSE_LEN + IPV4_HDR_LEN,
                     "mplsoudp");
}

TEST(flipping_any_header_byte_of_vxlan_never_crashes_or_leaks) {
    corruption_sweep(vxlan_good,
                     ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN + ETH_HDR_LEN + IPV4_HDR_LEN,
                     "vxlan");
}
