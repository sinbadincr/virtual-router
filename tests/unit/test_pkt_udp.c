#include <stdlib.h>
#include "minivr/pkt.h"
#include "tharness.h"

TEST(parse_a_known_good_header) {
    /* sport 49153, dport 6635, length 12 (4 payload bytes), checksum 0 */
    const uint8_t v[12] = {0xc0, 0x01, 0x19, 0xeb, 0x00, 0x0c, 0x00, 0x00, 1, 2, 3, 4};
    struct udp_hdr h;
    CHECK(pkt_udp_parse(v, sizeof v, &h) == 0);
    CHECK_EQ_U64(h.sport, 49153);
    CHECK_EQ_U64(h.dport, UDP_PORT_MPLS);
    CHECK_EQ_U64(h.len, 12);
}

TEST(length_field_may_be_smaller_than_the_buffer_but_never_larger) {
    uint8_t v[20] = {0, 1, 0, 2, 0, 12, 0, 0};
    struct udp_hdr h;
    CHECK(pkt_udp_parse(v, 20, &h) == 0); /* trailing padding is fine */
    CHECK(pkt_udp_parse(v, 11, &h) == -1); /* length 12 > 11 available */
    wr16(v + 4, 7);
    CHECK(pkt_udp_parse(v, 20, &h) == -1); /* length < header */
    wr16(v + 4, 0);
    CHECK(pkt_udp_parse(v, 20, &h) == -1);
    wr16(v + 4, 8);
    CHECK(pkt_udp_parse(v, 20, &h) == 0); /* an empty datagram is valid */
    wr16(v + 4, 0xffff);
    CHECK(pkt_udp_parse(v, 20, &h) == -1);
}

TEST(every_truncation_is_rejected_without_reading_past_the_buffer) {
    uint8_t v[8];
    pkt_udp_build(v, 1000, 4789, 0);
    struct udp_hdr h;
    for (size_t n = 0; n < 8; n++) {
        uint8_t *copy = malloc(n ? n : 1); /* exact size: ASan flags any read beyond n */
        memcpy(copy, v, n);
        CHECK(pkt_udp_parse(copy, n, &h) == -1);
        free(copy);
    }
    CHECK(pkt_udp_parse(v, 8, &h) == 0);
}

TEST(build_writes_length_and_zero_checksum) {
    uint8_t v[8];
    memset(v, 0xaa, sizeof v);
    pkt_udp_build(v, 50000, UDP_PORT_VXLAN, 100);
    const uint8_t want[8] = {0xc3, 0x50, 0x12, 0xb5, 0x00, 0x6c, 0x00, 0x00};
    CHECK_MEM_EQ(v, want, 8);
}

TEST(flow_hash_is_stable_per_flow_and_differs_between_flows) {
    uint8_t ip[28] = {0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 1, 1, 11, 10, 1, 1, 12, 0x30, 0x39, 0x00, 0x50, 0, 8, 0, 0};
    uint32_t a = pkt_flow_hash(ip, sizeof ip);
    CHECK_EQ_U64(pkt_flow_hash(ip, sizeof ip), a);
    ip[23] = 0x51; /* another destination port */
    CHECK(pkt_flow_hash(ip, sizeof ip) != a);
    ip[23] = 0x50;
    ip[15] = 12; /* another source address */
    CHECK(pkt_flow_hash(ip, sizeof ip) != a);
    /* ICMP: ports are not part of the hash, and a short buffer is safe */
    ip[15] = 11;
    ip[9] = 1;
    uint32_t i1 = pkt_flow_hash(ip, sizeof ip);
    ip[20] ^= 0xff;
    CHECK_EQ_U64(pkt_flow_hash(ip, sizeof ip), i1);
    (void)pkt_flow_hash(ip, 3);
}
