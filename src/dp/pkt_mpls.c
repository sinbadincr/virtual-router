#include "minivr/pkt.h"

int pkt_mpls_parse(const uint8_t *p, size_t avail, struct mpls_lse *out) {
    if (avail < MPLS_LSE_LEN)
        return -1;
    uint32_t w = rd32(p);
    out->s = (w >> 8) & 1;
    if (!out->s) /* a label stack deeper than one entry is not supported (RFC 7510 as used here) */
        return -1;
    out->label = w >> 12;
    out->tc = (w >> 9) & 7;
    out->ttl = (uint8_t)w;
    return 0;
}

void pkt_mpls_build(uint8_t *out, uint32_t label, uint8_t ttl) {
    wr32(out, (label << 12) | (1u << 8) | ttl); /* TC 0, S 1 */
}
