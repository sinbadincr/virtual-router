#include <stdlib.h>

#include "minivr/pkt.h"
#include "tharness.h"
#include "vectors/vxlan.h"

TEST(parse_the_header_of_a_frame_captured_from_the_linux_kernel) {
    uint32_t vni = 0;
    CHECK(pkt_vxlan_parse(VEC_LINUX_VXLAN + VXLAN_VEC_VXLAN, sizeof VEC_LINUX_VXLAN - VXLAN_VEC_VXLAN, &vni) == 0);
    CHECK_EQ_U64(vni, 100);
    /* the surrounding headers the decoder relies on, as the kernel wrote them */
    const uint8_t *ip = VEC_LINUX_VXLAN + VXLAN_VEC_OUTER_IP;
    CHECK_EQ_U64(ip[9], IPPROTO_UDP_);
    struct udp_hdr u;
    CHECK(pkt_udp_parse(VEC_LINUX_VXLAN + VXLAN_VEC_UDP, sizeof VEC_LINUX_VXLAN - VXLAN_VEC_UDP, &u) == 0);
    CHECK_EQ_U64(u.dport, UDP_PORT_VXLAN);
    CHECK_EQ_U64(u.len, sizeof VEC_LINUX_VXLAN - VXLAN_VEC_UDP);
    CHECK_EQ_U64(rd16(VEC_LINUX_VXLAN + VXLAN_VEC_INNER_ETH + 12), ETHERTYPE_IPV4);
}

TEST(build_emits_exactly_what_the_kernel_emitted) {
    uint8_t v[VXLAN_HDR_LEN];
    pkt_vxlan_build(v, 100);
    CHECK_MEM_EQ(v, VEC_LINUX_VXLAN + VXLAN_VEC_VXLAN, VXLAN_HDR_LEN);
}

TEST(i_flag_clear_is_rejected) {
    uint8_t v[8];
    pkt_vxlan_build(v, 5);
    v[0] = 0;
    uint32_t vni;
    CHECK(pkt_vxlan_parse(v, 8, &vni) == -1);
    v[0] = 0x80; /* some other flag, still no I */
    CHECK(pkt_vxlan_parse(v, 8, &vni) == -1);
}

TEST(reserved_bits_set_are_still_accepted) {
    uint8_t v[8];
    pkt_vxlan_build(v, 0xabcdef);
    v[0] |= 0x77; /* reserved flag bits (RFC 7348: ignored on receive) */
    v[1] = v[2] = v[3] = 0xff;
    v[7] = 0xff;
    uint32_t vni;
    CHECK(pkt_vxlan_parse(v, 8, &vni) == 0);
    CHECK_EQ_U64(vni, 0xabcdef);
}

TEST(every_truncation_is_rejected_without_reading_past_the_buffer) {
    uint8_t v[8];
    pkt_vxlan_build(v, 77);
    uint32_t vni;
    for (size_t n = 0; n < 8; n++) {
        uint8_t *copy = malloc(n ? n : 1);
        memcpy(copy, v, n);
        CHECK(pkt_vxlan_parse(copy, n, &vni) == -1);
        free(copy);
    }
}

TEST(vni_range_round_trips) {
    uint8_t v[8];
    uint32_t vni;
    for (uint32_t x = 1; x <= 16777215; x += 99991) {
        pkt_vxlan_build(v, x);
        CHECK(pkt_vxlan_parse(v, 8, &vni) == 0 && vni == x);
    }
    pkt_vxlan_build(v, 16777215);
    CHECK(pkt_vxlan_parse(v, 8, &vni) == 0 && vni == 16777215);
}
