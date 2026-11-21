#include "minivr/pkt.h"

int pkt_udp_parse(const uint8_t *udp, size_t avail, struct udp_hdr *out) {
    if (avail < UDP_HDR_LEN)
        return -1;
    uint16_t len = rd16(udp + 4);
    if (len < UDP_HDR_LEN || len > avail)
        return -1;
    out->sport = rd16(udp);
    out->dport = rd16(udp + 2);
    out->len = len;
    return 0;
}

void pkt_udp_build(uint8_t *out, uint16_t sport, uint16_t dport, uint16_t payload_len) {
    wr16(out, sport);
    wr16(out + 2, dport);
    wr16(out + 4, (uint16_t)(UDP_HDR_LEN + payload_len));
    wr16(out + 6, 0); /* no checksum: allowed over IPv4, and what the kernel does for VXLAN by default */
}

uint32_t pkt_flow_hash(const uint8_t *ip, size_t avail) {
    /* FNV-1a over the 5-tuple */
    uint32_t h = 2166136261u;
    if (avail < IPV4_HDR_LEN)
        return h;
    uint8_t proto = ip[9];
    for (int i = 12; i < 20; i++)
        h = (h ^ ip[i]) * 16777619u;
    h = (h ^ proto) * 16777619u;
    if ((proto == 6 || proto == IPPROTO_UDP_) && avail >= IPV4_HDR_LEN + 4)
        for (int i = IPV4_HDR_LEN; i < IPV4_HDR_LEN + 4; i++)
            h = (h ^ ip[i]) * 16777619u;
    return h;
}
