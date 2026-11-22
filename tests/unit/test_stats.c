#include <string.h>

#include "minivr/mbuf.h"
#include "minivr/stats.h"
#include "tharness.h"

static const char *expected[] = {
    "truncated",        "bad_ip_version",       "bad_ip_hdr_len",       "ip_options",
    "bad_ip_total_len", "bad_ip_checksum",      "ip_fragment",          "unsupported_ethertype",
    "non_arp_bcast_mcast", "not_for_us_l2",     "bad_arp",              "arp_unknown_target",
    "source_spoofed",   "no_route",             "ttl_exceeded",         "mtu_exceeded",
    "neighbour_unresolved", "port_down",        "local_unsupported",    "nobuf",
    "tx_error",
    "tunnel_not_for_us", "underlay_unexpected", "bad_udp", "bad_vxlan", "bad_mpls",
    "bad_inner_l2",     "unknown_tag",          "decap_no_local_dest", "tunnel_mtu_exceeded",
    "port_deleted",
};

TEST(all_reasons_have_stable_names) {
    CHECK_EQ_U64(DROP_COUNT, 31);
    for (int i = 0; i < DROP_COUNT; i++)
        CHECK_STR_EQ(stats_reason_name((enum drop_reason)i), expected[i]);
}

TEST(drop_counts_reason_and_total) {
    stats_clear();
    stats_drop(DROP_NO_ROUTE);
    stats_drop(DROP_NO_ROUTE);
    stats_drop_port(2, DROP_SOURCE_SPOOFED);
    CHECK_EQ_U64(g_stats.reasons[DROP_NO_ROUTE], 2);
    CHECK_EQ_U64(g_stats.reasons[DROP_SOURCE_SPOOFED], 1);
    CHECK_EQ_U64(g_stats.drop_total, 3);
    CHECK_EQ_U64(g_stats.port[2].drops, 1);
    CHECK_EQ_U64(stats_reason_sum(), g_stats.drop_total);
    for (int i = 0; i < DROP_COUNT; i++)
        stats_drop((enum drop_reason)i);
    CHECK_EQ_U64(stats_reason_sum(), g_stats.drop_total);
}

TEST(clear_zeroes_counters_not_gauges) {
    CHECK(mbuf_pool_init(8) == 0);
    struct mbuf *m = mbuf_alloc();
    stats_drop(DROP_NOBUF);
    g_stats.icmp_sent = 5;
    g_stats.port[0].rx_pkts = 9;
    stats_clear();
    CHECK_EQ_U64(g_stats.drop_total, 0);
    CHECK_EQ_U64(g_stats.icmp_sent, 0);
    CHECK_EQ_U64(g_stats.port[0].rx_pkts, 0);
    CHECK_EQ_U64(mbuf_in_use(), 1);
    mbuf_free(m);
    mbuf_pool_fini();
}

TEST(json_has_every_reason) {
    stats_clear();
    stats_drop(DROP_TTL_EXCEEDED);
    char b[2048];
    struct jw w;
    jw_init(&w, b, sizeof b);
    jw_obj_begin(&w, NULL);
    stats_json_drops(&w);
    stats_json_events(&w);
    jw_obj_end(&w);
    CHECK(jw_finish(&w) == 0);
    for (int i = 0; i < DROP_COUNT; i++) {
        char key[64];
        snprintf(key, sizeof key, "\"%s\":", expected[i]);
        CHECK(strstr(b, key) != NULL);
    }
    CHECK(strstr(b, "\"total\":1") != NULL);
    CHECK(strstr(b, "\"icmp_ratelimited\":0") != NULL);
}

TEST(node_counters_per_encap_and_the_unknown_pseudo_node) {
    stats_clear();
    stats_node_encap(3, ENCAP_MPLSOUDP, 100);
    stats_node_encap(3, ENCAP_MPLSOUDP, 50);
    stats_node_encap(3, ENCAP_VXLAN, 70);
    stats_node_decap(3, ENCAP_VXLAN, 10);
    stats_node_decap(NODE_UNKNOWN, ENCAP_MPLSOUDP, 5);
    CHECK_EQ_U64(g_stats.node[3].encap[ENCAP_MPLSOUDP].pkts, 2);
    CHECK_EQ_U64(g_stats.node[3].encap[ENCAP_MPLSOUDP].bytes, 150);
    CHECK_EQ_U64(g_stats.node[3].encap[ENCAP_VXLAN].pkts, 1);
    CHECK_EQ_U64(g_stats.node[3].decap[ENCAP_VXLAN].bytes, 10);
    CHECK_EQ_U64(g_stats.node[3].decap[ENCAP_MPLSOUDP].pkts, 0);
    CHECK_EQ_U64(g_stats.node[NODE_UNKNOWN].decap[ENCAP_MPLSOUDP].pkts, 1);
    stats_node_encap(200, ENCAP_VXLAN, 1); /* out of range: ignored, no overflow */
    CHECK_STR_EQ(stats_encap_name(ENCAP_MPLSOUDP), "mplsoudp");
    CHECK_STR_EQ(stats_encap_name(ENCAP_VXLAN), "vxlan");
    stats_clear();
    CHECK_EQ_U64(g_stats.node[3].encap[ENCAP_MPLSOUDP].pkts, 0);
}

TEST(nine_new_reasons_keep_total_equal_to_the_sum) {
    stats_clear();
    for (int i = DROP_TUNNEL_NOT_FOR_US; i <= DROP_TUNNEL_MTU_EXCEEDED; i++)
        stats_drop((enum drop_reason)i);
    CHECK_EQ_U64(DROP_TUNNEL_MTU_EXCEEDED - DROP_TUNNEL_NOT_FOR_US + 1, 9);
    CHECK_EQ_U64(g_stats.drop_total, 9);
    CHECK_EQ_U64(stats_reason_sum(), 9);
}

TEST(port_deleted_is_a_named_reason_inside_the_total) {
    stats_clear();
    stats_drop(DROP_PORT_DELETED);
    CHECK_STR_EQ(stats_reason_name(DROP_PORT_DELETED), "port_deleted");
    CHECK_EQ_U64(g_stats.drop_total, 1);
    CHECK_EQ_U64(stats_reason_sum(), 1);
}
