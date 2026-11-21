#include <stdlib.h>

#include "minivr/pkt.h"
#include "tharness.h"

TEST(build_matches_a_hand_checked_vector) {
    /* label 1012 = 0x003f4, TC 0, S 1, TTL 63:
     * 0x003f4 << 12 = 0x003f4000 | S<<8 = 0x100 | TTL 0x3f  ->  00 3f 41 3f */
    uint8_t v[4];
    pkt_mpls_build(v, 1012, 63);
    const uint8_t want[4] = {0x00, 0x3f, 0x41, 0x3f};
    CHECK_MEM_EQ(v, want, 4);
    /* the largest label and the smallest usable one */
    pkt_mpls_build(v, 1048575, 255);
    const uint8_t w2[4] = {0xff, 0xff, 0xf1, 0xff};
    CHECK_MEM_EQ(v, w2, 4);
    pkt_mpls_build(v, 16, 1);
    const uint8_t w3[4] = {0x00, 0x01, 0x01, 0x01};
    CHECK_MEM_EQ(v, w3, 4);
}

TEST(parse_reads_the_fields_back) {
    const uint8_t v[4] = {0x00, 0x3f, 0x41, 0x3f};
    struct mpls_lse e;
    CHECK(pkt_mpls_parse(v, 4, &e) == 0);
    CHECK_EQ_U64(e.label, 1012);
    CHECK_EQ_U64(e.tc, 0);
    CHECK_EQ_U64(e.s, 1);
    CHECK_EQ_U64(e.ttl, 63);
    const uint8_t tc[4] = {0x00, 0x3f, 0x4b, 0x01}; /* TC 5 */
    CHECK(pkt_mpls_parse(tc, 4, &e) == 0 && e.tc == 5 && e.label == 1012);
}

TEST(bottom_of_stack_clear_is_rejected) {
    const uint8_t v[4] = {0x00, 0x3f, 0x40, 0x3f}; /* S = 0: a second label would follow */
    struct mpls_lse e;
    CHECK(pkt_mpls_parse(v, 4, &e) == -1);
}

TEST(every_truncation_is_rejected_without_reading_past_the_buffer) {
    const uint8_t v[4] = {0x00, 0x3f, 0x41, 0x3f};
    struct mpls_lse e;
    for (size_t n = 0; n < 4; n++) {
        uint8_t *copy = malloc(n ? n : 1);
        memcpy(copy, v, n);
        CHECK(pkt_mpls_parse(copy, n, &e) == -1);
        free(copy);
    }
}

TEST(round_trip_over_label_and_ttl_ranges) {
    struct mpls_lse e;
    uint8_t v[4];
    for (uint32_t label = 16; label <= 1048575; label += 4097)
        for (unsigned ttl = 0; ttl < 256; ttl += 51) {
            pkt_mpls_build(v, label, (uint8_t)ttl);
            CHECK(pkt_mpls_parse(v, 4, &e) == 0);
            CHECK(e.label == label && e.ttl == ttl && e.s == 1 && e.tc == 0);
        }
}
