/* Tunnel transmit path (research R5): a validated, TTL-checked IPv4 frame from a VM port that
 * matched a REMOTE route is wrapped in MPLSoUDP or L3 VXLAN, in place in the mbuf headroom, and
 * sent on the underlay. No copies of the inner packet, no allocation, no syscalls. */
#include <string.h>

#include "minivr/forward.h"
#include "minivr/neigh.h"
#include "minivr/pkt.h"
#include "minivr/tunnel.h"

void encap_tx(struct port *in, struct mbuf *m, const struct route *r) {
    struct port *u = port_underlay();
    if (!u || !u->admin_up || !u->oper_up) {
        fwd_drop(in, m, DROP_PORT_DOWN);
        return;
    }
    const struct node *node = node_get(r->node);
    if (!node) { /* cannot happen: `node del` is refused while a route uses the node */
        fwd_drop(in, m, DROP_NO_ROUTE);
        return;
    }
    const int vxlan = r->encap == ENCAP_VXLAN;
    const unsigned overhead = vxlan ? OVERHEAD_VXLAN : OVERHEAD_MPLSOUDP;

    uint8_t *f = mbuf_data(m);
    uint8_t *ip = f + ETH_HDR_LEN;
    unsigned inner_len = rd16(ip + 2);

    /* FR-016: the tunnel never fragments; the sender learns the size that fits */
    if (inner_len + overhead > u->mtu) {
        if (rd16(ip + 6) & IP_DF)
            fwd_send_icmp_error(in, m, ICMP_UNREACH, ICMP_UNREACH_FRAG_NEEDED,
                                (uint16_t)(u->mtu - overhead));
        fwd_drop(in, m, DROP_TUNNEL_MTU_EXCEEDED);
        return;
    }
    /* the whole outer header set must fit in front of the inner packet */
    unsigned need = overhead; /* bytes added in front of the frame start */
    if (m->off < need) {
        fwd_drop(in, m, DROP_NOBUF);
        return;
    }

    uint32_t hash = pkt_flow_hash(ip, inner_len);
    memcpy(m->src_mac, f + 6, ETH_ALEN); /* for an ICMP error if the frame is held and times out */
    pkt_ipv4_dec_ttl(ip);                /* exactly once (FR-011) */
    uint8_t ttl = ip[8];
    uint16_t sport = (uint16_t)(49152 + hash % 16384);

    uint8_t *start;
    unsigned udp_payload;
    if (vxlan) {
        /* the inner Ethernet header stays where it is and becomes the VXLAN inner header */
        memcpy(f, node->rmac, ETH_ALEN);
        memcpy(f + 6, u->mac, ETH_ALEN);
        udp_payload = VXLAN_HDR_LEN + ETH_HDR_LEN + inner_len;
        start = f - (ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN);
        pkt_vxlan_build(start + ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN, r->tag);
        m->inner_off = (uint16_t)(ETH_HDR_LEN + overhead);
    } else {
        /* the inner Ethernet header is replaced by the outer one: the inner IPv4 packet stays in
         * place, 46 bytes behind the new start of frame */
        udp_payload = MPLS_LSE_LEN + inner_len;
        start = ip - (ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + MPLS_LSE_LEN);
        pkt_mpls_build(start + ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN, r->tag, ttl);
        m->inner_off = (uint16_t)(ETH_HDR_LEN + overhead);
    }
    uint8_t *oip = start + ETH_HDR_LEN;
    pkt_udp_build(oip + IPV4_HDR_LEN, sport, vxlan ? UDP_PORT_VXLAN : UDP_PORT_MPLS,
                  (uint16_t)udp_payload);
    oip[0] = 0x45;
    oip[1] = 0;
    wr16(oip + 2, (uint16_t)(IPV4_HDR_LEN + UDP_HDR_LEN + udp_payload));
    wr16(oip + 4, 0);
    wr16(oip + 6, IP_DF);
    oip[8] = 64;
    oip[9] = IPPROTO_UDP_;
    wr32(oip + 12, u->ip);
    wr32(oip + 16, node->ip);
    pkt_ipv4_set_csum(oip);
    memcpy(start + 6, u->mac, ETH_ALEN); /* the destination is filled in once the node resolves */
    wr16(start + 12, ETHERTYPE_IPV4);

    m->off = (uint16_t)(start - m->buf);
    m->len = (uint16_t)(ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + udp_payload);

    uint8_t mac[6];
    switch (neigh_resolve(node->ip, u->id, m, mac)) {
    case NEIGH_OK:
        memcpy(start, mac, ETH_ALEN);
        stats_node_encap(node->id, r->encap, m->len);
        m->inner_off = 0;
        fwd_tx_enqueue(u->id, m);
        return;
    case NEIGH_HELD:
        stats_node_encap(node->id, r->encap, m->len);
        return;
    case NEIGH_DROP_UNREACH: {
        /* the node did not answer ARP: the source VM hears host unreachable from its gateway */
        fwd_icmp_host_unreach(m);
        fwd_drop(in, m, DROP_NEIGHBOUR_UNRESOLVED);
        return;
    }
    default:
        fwd_drop(in, m, DROP_NEIGHBOUR_UNRESOLVED);
    }
}
