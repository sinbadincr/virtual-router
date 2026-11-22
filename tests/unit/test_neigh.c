#include "fixture.h"
#include "overlay_fixture.h"
#include "tharness.h"

static struct mbuf *pkt_to(uint32_t dst) {
    struct mbuf *m = mbuf_alloc();
    m->len = (uint16_t)make_ipv4(mbuf_data(m), MAC_P3, MAC_VM1, VM1_IP, dst, 63, 17, "x", 1);
    m->in_port = port_find("p1")->id;
    return m;
}

#define UNKNOWN_IP IP4(10, 0, 2, 50)

TEST(static_entry_is_reachable_immediately) {
    fx_setup(1);
    uint8_t mac[6];
    struct mbuf *m = pkt_to(VM3_IP);
    CHECK(neigh_resolve(VM3_IP, port_find("p3")->id, m, mac) == NEIGH_OK);
    CHECK_MEM_EQ(mac, MAC_VM3, 6);
    mbuf_free(m);
    const struct neigh *n = neigh_lookup(0, VM3_IP);
    CHECK(n && n->kind == NEIGH_STATIC && n->state == NEIGH_REACHABLE);
    fx_teardown();
}

TEST(incomplete_then_reachable_on_arp_releases_held_in_order) {
    fx_setup(0);
    size_t base = mbuf_in_use();
    uint8_t mac[6];
    uint8_t p3 = port_find("p3")->id;
    struct mbuf *m1 = pkt_to(UNKNOWN_IP), *m2 = pkt_to(UNKNOWN_IP), *m3 = pkt_to(UNKNOWN_IP);
    m1->buf[m1->off + 34] = 1;
    m2->buf[m2->off + 34] = 2;
    m3->buf[m3->off + 34] = 3;
    CHECK(neigh_resolve(UNKNOWN_IP, p3, m1, mac) == NEIGH_HELD);
    CHECK_EQ_U64(fx_tx_count(3), 1); /* the first ARP request went out */
    CHECK(neigh_resolve(UNKNOWN_IP, p3, m2, mac) == NEIGH_HELD);
    CHECK(neigh_resolve(UNKNOWN_IP, p3, m3, mac) == NEIGH_HELD);
    CHECK(neigh_lookup(0, UNKNOWN_IP)->state == NEIGH_INCOMPLETE);
    CHECK_EQ_U64(neigh_lookup(0, UNKNOWN_IP)->nhold, 3);

    fx_clear_tx();
    neigh_learn(UNKNOWN_IP, MAC_VM3, p3);
    const struct neigh *n = neigh_lookup(0, UNKNOWN_IP);
    CHECK(n->state == NEIGH_REACHABLE && n->kind == NEIGH_LEARNED);
    CHECK_EQ_U64(fx_tx_count(3), 3);
    for (size_t i = 0; i < 3; i++) {
        size_t len;
        const uint8_t *f = fx_tx(3, i, &len);
        CHECK(f != NULL);
        CHECK_MEM_EQ(f, MAC_VM3, 6);
        CHECK_MEM_EQ(f + 6, MAC_P3, 6);
        CHECK_EQ_U64(f[34], i + 1); /* sent in order */
    }
    CHECK_EQ_U64(mbuf_in_use(), base);
    fx_teardown();
}

TEST(fourth_packet_is_dropped_as_unresolved) {
    fx_setup(0);
    size_t base = mbuf_in_use();
    uint8_t mac[6];
    uint8_t p3 = port_find("p3")->id;
    for (int i = 0; i < 3; i++)
        CHECK(neigh_resolve(UNKNOWN_IP, p3, pkt_to(UNKNOWN_IP), mac) == NEIGH_HELD);
    struct mbuf *m4 = pkt_to(UNKNOWN_IP);
    CHECK(neigh_resolve(UNKNOWN_IP, p3, m4, mac) == NEIGH_DROP);
    mbuf_free(m4);
    neigh_port_down(p3);
    CHECK_EQ_U64(mbuf_in_use(), base);
    fx_teardown();
}

TEST(arp_retries_then_fails_at_the_deadline) {
    fx_setup(0);
    size_t base = mbuf_in_use();
    uint8_t mac[6];
    uint8_t p3 = port_find("p3")->id;
    CHECK(neigh_resolve(UNKNOWN_IP, p3, pkt_to(UNKNOWN_IP), mac) == NEIGH_HELD);
    CHECK_EQ_U64(fx_tx_count(3), 1);
    for (int ms = 10; ms <= 1000; ms += 10) {
        clock_advance(10 * NS_PER_MS);
        neigh_tick(clock_now_ns());
    }
    /* 3 ARP requests in total within the 1 s window, then ICMP host unreachable to vm1 */
    int arps = 0;
    for (size_t i = 0; i < fx_tx_count(3); i++) {
        size_t len;
        const uint8_t *f = fx_tx(3, i, &len);
        arps += rd16(f + 12) == ETHERTYPE_ARP;
    }
    CHECK_EQ_U64(arps, 3);
    CHECK_EQ_U64(g_stats.reasons[DROP_NEIGHBOUR_UNRESOLVED], 1);
    CHECK(neigh_lookup(0, UNKNOWN_IP)->state == NEIGH_FAILED);
    CHECK_EQ_U64(fx_tx_count(1), 1);
    size_t len;
    const uint8_t *icmp = fx_tx(1, 0, &len);
    CHECK_EQ_U64(icmp[ETH_HDR_LEN + IPV4_HDR_LEN], ICMP_UNREACH);
    CHECK_EQ_U64(icmp[ETH_HDR_LEN + IPV4_HDR_LEN + 1], ICMP_UNREACH_HOST);
    CHECK_EQ_U64(mbuf_in_use(), base);
    /* the failed entry is negative-cached for 1 s, then removed */
    struct mbuf *m = pkt_to(UNKNOWN_IP);
    CHECK(neigh_resolve(UNKNOWN_IP, p3, m, mac) == NEIGH_DROP_UNREACH);
    mbuf_free(m);
    clock_advance(NS_PER_SEC + NS_PER_MS);
    neigh_tick(clock_now_ns());
    CHECK(neigh_lookup(0, UNKNOWN_IP) == NULL);
    fx_teardown();
}

TEST(learned_never_overwrites_static) {
    fx_setup(1);
    uint8_t other[6] = {2, 9, 9, 9, 9, 9};
    neigh_learn(VM3_IP, other, port_find("p3")->id);
    const struct neigh *n = neigh_lookup(0, VM3_IP);
    CHECK(n->kind == NEIGH_STATIC);
    CHECK_MEM_EQ(n->mac, MAC_VM3, 6);
    fx_teardown();
}

TEST(learned_entry_updates_its_mac) {
    fx_setup(0);
    uint8_t p3 = port_find("p3")->id, other[6] = {2, 9, 9, 9, 9, 9};
    neigh_learn(UNKNOWN_IP, MAC_VM3, p3);
    neigh_learn(UNKNOWN_IP, other, p3);
    CHECK_MEM_EQ(neigh_lookup(0, UNKNOWN_IP)->mac, other, 6);
    CHECK_EQ_U64(neigh_count(), 3); /* vm1, vm2 and the learned one */
    fx_teardown();
}

TEST(capacity_1024) {
    fx_setup(0);
    struct cmd_err e;
    uint8_t p3 = port_find("p3")->id;
    unsigned have = neigh_count(); /* 2 static */
    /* learned fill the table; the next learned is refused and counted, a static add errors */
    for (uint32_t i = 0; have < NEIGH_CAPACITY; i++, have++)
        neigh_learn(IP4(10, 0, 2, 0) + 100 + i, MAC_VM3, p3);
    CHECK_EQ_U64(neigh_count(), NEIGH_CAPACITY);
    neigh_learn(IP4(10, 7, 7, 7), MAC_VM3, p3);
    CHECK(neigh_lookup(0, IP4(10, 7, 7, 7)) == NULL);
    CHECK_EQ_U64(g_stats.neighbour_table_full, 1);
    CHECK(neigh_add_static(VM3_IP, MAC_VM3, p3, &e) == -1);
    CHECK_STR_EQ(e.code, "table-full");
    fx_teardown();
}

TEST(port_down_and_gateway_removal_release_held_packets) {
    fx_setup(0);
    size_t base = mbuf_in_use();
    uint8_t mac[6];
    uint8_t p3 = port_find("p3")->id;
    CHECK(neigh_resolve(UNKNOWN_IP, p3, pkt_to(UNKNOWN_IP), mac) == NEIGH_HELD);
    CHECK(mbuf_in_use() == base + 1);
    neigh_port_down(p3);
    CHECK_EQ_U64(mbuf_in_use(), base);
    CHECK(neigh_lookup(0, UNKNOWN_IP) == NULL); /* learned entries go with the port */
    CHECK_EQ_U64(g_stats.reasons[DROP_PORT_DOWN], 1);

    /* deleting the static route whose next hop is still resolving releases that too */
    struct cmd_err e;
    CHECK(route_add_static(0, IP4(10, 0, 9, 0), 24, p3, IP4(10, 0, 2, 77), &e) == 0);
    CHECK(neigh_resolve(IP4(10, 0, 2, 77), p3, pkt_to(IP4(10, 0, 9, 1)), mac) == NEIGH_HELD);
    CHECK(route_del(0, IP4(10, 0, 9, 0), 24, &e) == 0);
    CHECK_EQ_U64(mbuf_in_use(), base);
    fx_teardown();
}

TEST(neigh_del_releases_held_packets) {
    fx_setup(0);
    size_t base = mbuf_in_use();
    uint8_t mac[6];
    struct cmd_err e;
    CHECK(neigh_resolve(UNKNOWN_IP, port_find("p3")->id, pkt_to(UNKNOWN_IP), mac) == NEIGH_HELD);
    CHECK(neigh_del(0, UNKNOWN_IP, &e) == 0);
    CHECK_EQ_U64(mbuf_in_use(), base);
    CHECK(neigh_del(0, UNKNOWN_IP, &e) == -1);
    CHECK_STR_EQ(e.code, "not-found");
    fx_teardown();
}

/* ---- per-VRF and underlay tables (phase 2) ---- */

static struct mbuf *ov_pkt(uint32_t dst) {
    struct mbuf *m = mbuf_alloc();
    m->len = (uint16_t)make_ipv4(mbuf_data(m), MAC_P3, MAC_VM1, IP4(10, 1, 1, 11), dst, 63, 17, "x", 1);
    return m;
}

TEST(same_ip_static_in_two_vrfs_with_different_macs) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    unsigned red = vrf_by_name("red")->id, blue = vrf_by_name("blue")->id;
    const struct neigh *r = neigh_lookup(red, IP4(10, 1, 1, 11));
    const struct neigh *b = neigh_lookup(blue, IP4(10, 1, 1, 11));
    CHECK(r && b && r != b);
    CHECK_MEM_EQ(r->mac, OV_RED1, 6);
    CHECK_MEM_EQ(b->mac, OV_BLUE1, 6);
    CHECK(neigh_lookup(0, IP4(10, 1, 1, 11)) == NULL);
    uint8_t mac[6];
    struct mbuf *m = ov_pkt(IP4(10, 1, 1, 11));
    CHECK(neigh_resolve(IP4(10, 1, 1, 11), port_find("blue1")->id, m, mac) == NEIGH_OK);
    CHECK_MEM_EQ(mac, OV_BLUE1, 6);
    mbuf_free(m);
    ov_teardown();
}

TEST(underlay_entries_are_invisible_to_vrfs_and_vice_versa) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    uint8_t mac[6], ul = port_underlay()->id;
    struct mbuf *m = ov_pkt(IP4(172, 16, 0, 2));
    /* resolving on the underlay creates an underlay-table entry only */
    CHECK(neigh_resolve(IP4(172, 16, 0, 2), ul, m, mac) == NEIGH_HELD);
    CHECK(neigh_lookup(NEIGH_UNDERLAY, IP4(172, 16, 0, 2)) != NULL);
    for (unsigned v = 0; v < 3; v++)
        CHECK(neigh_lookup(v, IP4(172, 16, 0, 2)) == NULL);
    /* learning on a VM port never lands in the underlay table */
    neigh_learn(IP4(10, 1, 1, 77), OV_RED2, port_find("red1")->id);
    CHECK(neigh_lookup(vrf_by_name("red")->id, IP4(10, 1, 1, 77)) != NULL);
    CHECK(neigh_lookup(NEIGH_UNDERLAY, IP4(10, 1, 1, 77)) == NULL);
    ov_teardown();
}

TEST(underlay_fsm_is_the_phase1_fsm) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    uint8_t mac[6], ul = port_underlay()->id;
    uint32_t ip = IP4(172, 16, 0, 2);
    for (int i = 0; i < NEIGH_HOLD_MAX; i++)
        CHECK(neigh_resolve(ip, ul, ov_pkt(ip), mac) == NEIGH_HELD);
    CHECK(neigh_resolve(ip, ul, ov_pkt(ip), mac) == NEIGH_DROP); /* the 4th is dropped */
    CHECK_EQ_U64(neigh_lookup(NEIGH_UNDERLAY, ip)->nhold, NEIGH_HOLD_MAX);
    clock_advance(2 * NS_PER_SEC);
    neigh_tick(clock_now_ns());
    CHECK(neigh_lookup(NEIGH_UNDERLAY, ip)->state == NEIGH_FAILED);
    ov_teardown();
}

TEST(a_held_underlay_frame_only_gets_its_outer_destination_mac) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    uint8_t mac[6], ul = port_underlay()->id;
    uint32_t ip = IP4(172, 16, 0, 2);
    struct mbuf *m = ov_pkt(ip);
    memset(mbuf_data(m) + 6, 0x77, 6); /* the already-built outer source MAC */
    CHECK(neigh_resolve(ip, ul, m, mac) == NEIGH_HELD);
    ov_clear_tx();
    neigh_learn(ip, OV_UL_MAC2, ul);
    CHECK_EQ_U64(ov_tx_count("u0"), 1);
    size_t len;
    const uint8_t *f = ov_tx("u0", 0, &len);
    CHECK_MEM_EQ(f, OV_UL_MAC2, 6);
    CHECK_EQ_U64(f[6], 0x77); /* source MAC untouched */
    ov_teardown();
}

TEST(capacity_1024_is_shared_by_all_tables) {
    CHECK_EQ_U64(ov_setup(1, 1600), 0);
    unsigned red = vrf_by_name("red")->id;
    uint8_t red1 = port_find("red1")->id;
    unsigned have = neigh_count();
    for (unsigned i = 0; have < NEIGH_CAPACITY; i++, have++)
        neigh_learn(IP4(10, 1, 1, 100) + i, OV_RED2, red1);
    CHECK_EQ_U64(neigh_count(), NEIGH_CAPACITY);
    neigh_learn(IP4(10, 1, 1, 99), OV_RED2, red1);
    CHECK(neigh_lookup(red, IP4(10, 1, 1, 99)) == NULL);
    neigh_learn(IP4(172, 16, 0, 9), OV_UL_MAC2, port_underlay()->id); /* the underlay is full too */
    CHECK(neigh_lookup(NEIGH_UNDERLAY, IP4(172, 16, 0, 9)) == NULL);
    ov_teardown();
}
