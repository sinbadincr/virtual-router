#include "overlay_fixture.h"
#include "tharness.h"

static uint8_t f[2048];

static size_t from_red1(uint32_t dst, uint8_t ttl, size_t payload, int df) {
    uint8_t body[1600];
    memset(body, 0x5a, sizeof body);
    uint8_t pm[6];
    ov_port_mac(pm, 1, 1);
    size_t n = make_ipv4(f, pm, OV_RED1, IP4(10, 1, 1, 11), dst, ttl, 17, body, payload);
    if (df) {
        wr16(f + ETH_HDR_LEN + 6, IP_DF);
        pkt_ipv4_set_csum(f + ETH_HDR_LEN);
    }
    return n;
}

static size_t from_blue1(uint32_t dst, uint8_t ttl, size_t payload, int df) {
    uint8_t body[1600];
    memset(body, 0x5a, sizeof body);
    uint8_t pm[6];
    ov_port_mac(pm, 1, 2);
    size_t n = make_ipv4(f, pm, OV_BLUE1, IP4(10, 1, 1, 11), dst, ttl, 17, body, payload);
    if (df) {
        wr16(f + ETH_HDR_LEN + 6, IP_DF);
        pkt_ipv4_set_csum(f + ETH_HDR_LEN);
    }
    return n;
}

/* cn1 with the neighbour cn2 already resolved on the underlay */
static void setup_cn1(int ul_mtu) {
    CHECK_EQ_U64(ov_setup(1, ul_mtu), 0);
    neigh_learn(IP4(172, 16, 0, 2), OV_UL_MAC2, port_underlay()->id);
}

/* expected outer headers, written out field by field from contracts/wire-formats.md */
static void expect_outer(const uint8_t *o, size_t len, uint16_t dport, size_t udp_payload) {
    const uint8_t *ip = o + ETH_HDR_LEN;
    CHECK_MEM_EQ(o, OV_UL_MAC2, 6);
    CHECK_MEM_EQ(o + 6, OV_UL_MAC1, 6);
    CHECK_EQ_U64(rd16(o + 12), 0x0800);
    CHECK_EQ_U64(ip[0], 0x45);
    CHECK_EQ_U64(ip[1], 0);
    CHECK_EQ_U64(rd16(ip + 2), IPV4_HDR_LEN + UDP_HDR_LEN + udp_payload);
    CHECK_EQ_U64(rd16(ip + 4), 0); /* ID 0 */
    CHECK_EQ_U64(rd16(ip + 6), 0x4000); /* DF, no fragment */
    CHECK_EQ_U64(ip[8], 64);
    CHECK_EQ_U64(ip[9], 17);
    CHECK_EQ_U64(pkt_csum16(ip, IPV4_HDR_LEN), 0);
    CHECK_EQ_U64(rd32(ip + 12), IP4(172, 16, 0, 1));
    CHECK_EQ_U64(rd32(ip + 16), IP4(172, 16, 0, 2));
    const uint8_t *udp = ip + IPV4_HDR_LEN;
    CHECK(rd16(udp) >= 49152);
    CHECK_EQ_U64(rd16(udp + 2), dport);
    CHECK_EQ_U64(rd16(udp + 4), UDP_HDR_LEN + udp_payload);
    CHECK_EQ_U64(rd16(udp + 6), 0); /* checksum 0 */
    CHECK_EQ_U64(len, ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + udp_payload);
}

TEST(mplsoudp_frame_is_byte_exact) {
    setup_cn1(1600);
    size_t n = from_red1(IP4(10, 1, 1, 12), 64, 100, 0);
    uint8_t inner_before[256];
    size_t inner_len = n - ETH_HDR_LEN;
    memcpy(inner_before, f + ETH_HDR_LEN, inner_len);
    ov_rx("red1", f, n);
    CHECK_EQ_U64(ov_tx_count("u0"), 1);
    CHECK_EQ_U64(ov_tx_count("red1") + ov_tx_count("blue1"), 0);
    size_t len;
    const uint8_t *o = ov_tx("u0", 0, &len);
    expect_outer(o, len, UDP_PORT_MPLS, MPLS_LSE_LEN + inner_len);
    /* label 1012, TC 0, S 1, TTL = inner TTL after the one decrement */
    const uint8_t want_lse[4] = {0x00, 0x3f, 0x41, 63};
    CHECK_MEM_EQ(o + 42, want_lse, 4);
    /* inner IPv4 packet: unchanged except TTL 63 and its checksum */
    const uint8_t *in = o + 46;
    CHECK_EQ_U64(in[8], 63);
    CHECK_EQ_U64(pkt_csum16(in, IPV4_HDR_LEN), 0);
    CHECK_MEM_EQ(in, inner_before, 8);          /* version .. flags */
    CHECK_MEM_EQ(in + 12, inner_before + 12, inner_len - 12); /* addresses and payload */
    CHECK_EQ_U64(g_stats.drop_total, 0);
    /* counters per node */
    uint8_t cn2 = node_find("cn2")->id;
    CHECK_EQ_U64(g_stats.node[cn2].encap[ENCAP_MPLSOUDP].pkts, 1);
    CHECK_EQ_U64(g_stats.node[cn2].encap[ENCAP_MPLSOUDP].bytes, len);
    CHECK_EQ_U64(g_stats.node[cn2].encap[ENCAP_VXLAN].pkts, 0);
    CHECK_EQ_U64(mbuf_in_use(), 0);
    ov_teardown();
}

TEST(vxlan_frame_is_byte_exact_with_router_macs_inside) {
    setup_cn1(1600);
    size_t n = from_blue1(IP4(10, 1, 1, 12), 64, 100, 0);
    size_t inner_len = n - ETH_HDR_LEN;
    ov_rx("blue1", f, n);
    CHECK_EQ_U64(ov_tx_count("u0"), 1);
    size_t len;
    const uint8_t *o = ov_tx("u0", 0, &len);
    expect_outer(o, len, UDP_PORT_VXLAN, VXLAN_HDR_LEN + ETH_HDR_LEN + inner_len);
    const uint8_t want_vx[8] = {0x08, 0, 0, 0, 0x00, 0x00, 0xc8, 0x00}; /* I flag, VNI 200 */
    CHECK_MEM_EQ(o + 42, want_vx, 8);
    CHECK_MEM_EQ(o + 50, OV_UL_MAC2, 6);     /* inner dst = remote router MAC */
    CHECK_MEM_EQ(o + 56, OV_UL_MAC1, 6);     /* inner src = own router MAC */
    CHECK_EQ_U64(rd16(o + 62), 0x0800);
    CHECK_EQ_U64(o[64 + 8], 63);
    CHECK_EQ_U64(pkt_csum16(o + 64, IPV4_HDR_LEN), 0);
    CHECK_EQ_U64(g_stats.node[node_find("cn2")->id].encap[ENCAP_VXLAN].pkts, 1);
    ov_teardown();
}

TEST(inner_ttl_is_decremented_exactly_once_and_ttl_1_is_not_tunnelled) {
    setup_cn1(1600);
    size_t n = from_red1(IP4(10, 1, 1, 12), 2, 20, 0);
    ov_rx("red1", f, n);
    size_t len;
    CHECK_EQ_U64(ov_tx("u0", 0, &len)[46 + 8], 1);
    ov_clear_tx();
    n = from_red1(IP4(10, 1, 1, 12), 1, 20, 0);
    ov_rx("red1", f, n);
    CHECK_EQ_U64(ov_tx_count("u0"), 0);
    CHECK_EQ_U64(g_stats.reasons[DROP_TTL_EXCEEDED], 1);
    CHECK_EQ_U64(ov_tx_count("red1"), 1); /* ICMP time exceeded back to the VM */
    ov_teardown();
}

TEST(source_port_is_stable_per_flow_and_differs_between_flows) {
    setup_cn1(1600);
    uint16_t sp[3];
    uint32_t dsts[3] = {IP4(10, 1, 1, 12), IP4(10, 1, 1, 12), IP4(10, 1, 2, 13)};
    for (int i = 0; i < 3; i++) {
        ov_clear_tx();
        size_t n = from_red1(dsts[i], 64, 40 + (size_t)i * 0, 0);
        if (i == 1) /* the same flow again: identical addresses, protocol and ports */
            n = from_red1(dsts[i], 64, 40, 0);
        ov_rx("red1", f, n);
        size_t len;
        sp[i] = rd16(ov_tx("u0", 0, &len) + 34);
        CHECK(sp[i] >= 49152);
    }
    CHECK_EQ_U64(sp[0], sp[1]);
    CHECK(sp[0] != sp[2]);
    ov_teardown();
}

TEST(size_rule_df_gets_frag_needed_with_the_remaining_mtu) {
    CHECK_EQ_U64(ov_setup(1, 1500), 0);
    neigh_learn(IP4(172, 16, 0, 2), OV_UL_MAC2, port_underlay()->id);
    /* 1500-byte inner packet (DF) + 32 > 1500 */
    size_t n = from_red1(IP4(10, 1, 1, 12), 64, 1480, 1);
    ov_rx("red1", f, n);
    CHECK_EQ_U64(ov_tx_count("u0"), 0);
    CHECK_EQ_U64(g_stats.reasons[DROP_TUNNEL_MTU_EXCEEDED], 1);
    CHECK_EQ_U64(ov_tx_count("red1"), 1);
    size_t len;
    const uint8_t *e = ov_tx("red1", 0, &len);
    CHECK_EQ_U64(rd32(e + ETH_HDR_LEN + 12), IP4(10, 1, 1, 1)); /* from the VM's gateway */
    const uint8_t *icmp = e + ETH_HDR_LEN + IPV4_HDR_LEN;
    CHECK_EQ_U64(icmp[0], ICMP_UNREACH);
    CHECK_EQ_U64(icmp[1], ICMP_UNREACH_FRAG_NEEDED);
    CHECK_EQ_U64(rd16(icmp + 6), 1500 - OVERHEAD_MPLSOUDP); /* 1468 */
    ov_clear_tx();
    n = from_blue1(IP4(10, 1, 1, 12), 64, 1480, 1);
    ov_rx("blue1", f, n);
    icmp = ov_tx("blue1", 0, &len) + ETH_HDR_LEN + IPV4_HDR_LEN;
    CHECK_EQ_U64(rd16(icmp + 6), 1500 - OVERHEAD_VXLAN); /* 1450 */
    CHECK_EQ_U64(g_stats.reasons[DROP_TUNNEL_MTU_EXCEEDED], 2);
    ov_teardown();
}

TEST(size_rule_without_df_is_dropped_silently_and_counted) {
    CHECK_EQ_U64(ov_setup(1, 1500), 0);
    neigh_learn(IP4(172, 16, 0, 2), OV_UL_MAC2, port_underlay()->id);
    size_t n = from_red1(IP4(10, 1, 1, 12), 64, 1480, 0);
    ov_rx("red1", f, n);
    CHECK_EQ_U64(ov_tx_count("u0") + ov_tx_count("red1"), 0);
    CHECK_EQ_U64(g_stats.reasons[DROP_TUNNEL_MTU_EXCEEDED], 1);
    ov_teardown();
}

TEST(a_packet_that_just_fits_is_sent_at_mtu_1600_and_at_the_exact_limit) {
    setup_cn1(1600);
    size_t n = from_red1(IP4(10, 1, 1, 12), 64, 1480, 1); /* 1500 + 32 = 1532 <= 1600 */
    ov_rx("red1", f, n);
    CHECK_EQ_U64(ov_tx_count("u0"), 1);
    ov_teardown();
    CHECK_EQ_U64(ov_setup(1, 1532), 0); /* exactly inner + overhead */
    neigh_learn(IP4(172, 16, 0, 2), OV_UL_MAC2, port_underlay()->id);
    n = from_red1(IP4(10, 1, 1, 12), 64, 1480, 1);
    ov_rx("red1", f, n);
    CHECK_EQ_U64(ov_tx_count("u0"), 1);
    ov_teardown();
}

TEST(underlay_down_drops_as_port_down) {
    setup_cn1(1600);
    struct cmd_err e;
    CHECK(ov_cmd(CMD_CLI, "port set u0 admin down", &e) == 0);
    size_t n = from_red1(IP4(10, 1, 1, 12), 64, 40, 0);
    ov_rx("red1", f, n);
    CHECK_EQ_U64(ov_tx_count("u0"), 0);
    CHECK_EQ_U64(g_stats.reasons[DROP_PORT_DOWN], 1);
    /* a local flow in the same VRF is unaffected: red1 -> red1's own host route is not remote */
    CHECK(ov_cmd(CMD_CLI, "port set u0 admin up", &e) == 0);
    neigh_learn(IP4(172, 16, 0, 2), OV_UL_MAC2, port_underlay()->id);
    ov_rx("red1", f, n);
    CHECK_EQ_U64(ov_tx_count("u0"), 1); /* and it recovers without a restart */
    ov_teardown();
}

TEST(an_unresolved_node_is_held_then_sent_when_arp_resolves) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    uint8_t ul = port_underlay()->id;
    size_t n = from_red1(IP4(10, 1, 1, 12), 64, 40, 0);
    ov_rx("red1", f, n);
    /* nothing tunnelled yet: an ARP request for cn2 went out on the underlay */
    CHECK_EQ_U64(ov_tx_count("u0"), 1);
    size_t len;
    const uint8_t *arp = ov_tx("u0", 0, &len);
    CHECK_EQ_U64(len, ARP_FRAME_LEN);
    CHECK_EQ_U64(rd16(arp + 20), ARP_OP_REQUEST);
    CHECK_EQ_U64(rd32(arp + 38), IP4(172, 16, 0, 2));
    CHECK_EQ_U64(neigh_lookup(NEIGH_UNDERLAY, IP4(172, 16, 0, 2))->nhold, 1);
    ov_clear_tx();
    uint8_t rep[64];
    make_arp_reply(rep, OV_UL_MAC1, OV_UL_MAC2, IP4(172, 16, 0, 2), IP4(172, 16, 0, 1));
    ov_rx("u0", rep, ARP_FRAME_LEN);
    CHECK_EQ_U64(ov_tx_count("u0"), 1); /* the held packet */
    const uint8_t *o = ov_tx("u0", 0, &len);
    expect_outer(o, len, UDP_PORT_MPLS, MPLS_LSE_LEN + (n - ETH_HDR_LEN));
    const uint8_t lse[4] = {0x00, 0x3f, 0x41, 63};
    CHECK_MEM_EQ(o + 42, lse, 4);
    (void)ul;
    CHECK_EQ_U64(mbuf_in_use(), 0);
    ov_teardown();
}

TEST(a_node_that_never_answers_gets_the_phase1_failure_path) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    size_t n = from_red1(IP4(10, 1, 1, 12), 64, 40, 0);
    uint8_t orig_ip[28];
    memcpy(orig_ip, f + ETH_HDR_LEN, 28);
    ov_rx("red1", f, n);
    ov_clear_tx();
    clock_advance(2 * NS_PER_SEC);
    neigh_tick(clock_now_ns());
    CHECK_EQ_U64(g_stats.reasons[DROP_NEIGHBOUR_UNRESOLVED], 1);
    CHECK_EQ_U64(ov_tx_count("u0"), 0);
    /* the source VM gets host unreachable from its gateway, quoting its own packet */
    size_t len;
    CHECK_EQ_U64(ov_tx_count("red1"), 1);
    const uint8_t *e = ov_tx("red1", 0, &len);
    CHECK_MEM_EQ(e, OV_RED1, 6);
    CHECK_EQ_U64(rd32(e + ETH_HDR_LEN + 12), IP4(10, 1, 1, 1));
    CHECK_EQ_U64(rd32(e + ETH_HDR_LEN + 16), IP4(10, 1, 1, 11));
    const uint8_t *icmp = e + ETH_HDR_LEN + IPV4_HDR_LEN;
    CHECK_EQ_U64(icmp[0], ICMP_UNREACH);
    CHECK_EQ_U64(icmp[1], ICMP_UNREACH_HOST);
    CHECK_EQ_U64(rd32(icmp + ICMP_HDR_LEN + 16), IP4(10, 1, 1, 12)); /* quoted original header */
    CHECK_EQ_U64(rd32(icmp + ICMP_HDR_LEN + 12), IP4(10, 1, 1, 11));
    CHECK_EQ_U64(mbuf_in_use(), 0);
    CHECK_EQ_U64(stats_reason_sum(), g_stats.drop_total);
    (void)orig_ip;
    ov_teardown();
}

TEST(per_node_counters_follow_the_encapsulation_used) {
    setup_cn1(1600);
    for (int i = 0; i < 3; i++) {
        size_t n = from_red1(IP4(10, 1, 1, 12), 64, 40, 0);
        ov_rx("red1", f, n);
    }
    size_t n = from_blue1(IP4(10, 1, 1, 12), 64, 40, 0);
    ov_rx("blue1", f, n);
    uint8_t cn2 = node_find("cn2")->id;
    CHECK_EQ_U64(g_stats.node[cn2].encap[ENCAP_MPLSOUDP].pkts, 3);
    CHECK_EQ_U64(g_stats.node[cn2].encap[ENCAP_VXLAN].pkts, 1);
    CHECK_EQ_U64(g_stats.port[port_underlay()->id].tx_pkts, 4);
    ov_teardown();
}
