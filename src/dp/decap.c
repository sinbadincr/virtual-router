/* Underlay receive path (research R6). Every outer header is validated, the tag is mapped, and
 * the inner packet is delivered only to a local VM of the right tenant: no transit (FR-015), no
 * TTL decrement (FR-011). Each failure lands in one named drop reason. */
#include <string.h>

#include "minivr/forward.h"
#include "minivr/neigh.h"
#include "minivr/pkt.h"
#include "minivr/tunnel.h"
#include "minivr/vrf.h"

/* ARP on the underlay touches only the underlay table (FR-010). */
static void underlay_arp(struct port *u, struct mbuf *m) {
    uint8_t *f = mbuf_data(m);
    struct arp_pkt a;
    if (pkt_arp_parse(f, m->len, &a) != 0) {
        fwd_drop(u, m, DROP_BAD_ARP);
        return;
    }
    /* only the configured nodes are worth a neighbour entry */
    if (a.spa != 0 && node_id_by_ip(a.spa) != NODE_UNKNOWN)
        neigh_learn(a.spa, a.sha, u->id);
    if (a.op == ARP_OP_REPLY || a.spa == a.tpa) {
        mbuf_free(m);
        return;
    }
    if (a.tpa == u->ip) {
        pkt_arp_make_reply(f, u->mac);
        m->len = ARP_FRAME_LEN;
        g_stats.arp_replies_sent++;
        fwd_tx_enqueue(u->id, m);
        return;
    }
    fwd_drop(u, m, DROP_ARP_UNKNOWN_TARGET);
}

/* Deliver the validated inner frame (Ethernet header already in place at f, inner IPv4 behind it)
 * to the VM port `eg` with the next-hop MAC `mac`. */
static void deliver(struct port *u, struct mbuf *m, struct port *eg, const uint8_t mac[6],
                    uint8_t node, enum encap_kind kind, uint16_t outer_len) {
    uint8_t *f = mbuf_data(m);
    if (!eg->admin_up || !eg->oper_up) {
        fwd_drop(u, m, DROP_PORT_DOWN);
        return;
    }
    if (rd16(f + ETH_HDR_LEN + 2) > eg->mtu) {
        fwd_drop(u, m, DROP_MTU_EXCEEDED);
        return;
    }
    memcpy(f, mac, ETH_ALEN);
    memcpy(f + 6, eg->mac, ETH_ALEN);
    stats_node_decap(node, kind, outer_len);
    fwd_tx_enqueue(eg->id, m);
}

void decap_rx(struct port *u, struct mbuf *m, enum eth_class cls) {
    if (cls == ETH_C_ARP) {
        underlay_arp(u, m);
        return;
    }
    uint8_t *f = mbuf_data(m);
    enum drop_reason why;
    if (pkt_ipv4_validate(f, m->len, &why) != 0) {
        fwd_drop(u, m, why);
        return;
    }
    uint8_t *ip = f + ETH_HDR_LEN;
    uint16_t outer_total = rd16(ip + 2);
    m->len = (uint16_t)(ETH_HDR_LEN + outer_total); /* strip Ethernet padding */
    const uint16_t outer_len = m->len;
    if (rd32(ip + 16) != u->ip) {
        fwd_drop(u, m, DROP_TUNNEL_NOT_FOR_US);
        return;
    }
    if (ip[9] == IPPROTO_ICMP_) {
        if (outer_total >= IPV4_HDR_LEN + ICMP_HDR_LEN && ip[IPV4_HDR_LEN] == ICMP_ECHO_REQUEST &&
            pkt_icmp_echo_reply(f, m->len) == 0) {
            memcpy(f + 6, u->mac, ETH_ALEN);
            fwd_tx_enqueue(u->id, m);
            return;
        }
        fwd_drop(u, m, DROP_UNDERLAY_UNEXPECTED);
        return;
    }
    if (ip[9] != IPPROTO_UDP_) {
        fwd_drop(u, m, DROP_UNDERLAY_UNEXPECTED);
        return;
    }
    uint8_t *udp = ip + IPV4_HDR_LEN;
    struct udp_hdr uh;
    if (pkt_udp_parse(udp, (size_t)outer_total - IPV4_HDR_LEN, &uh) != 0) {
        fwd_drop(u, m, DROP_BAD_UDP);
        return;
    }
    if (uh.dport != UDP_PORT_VXLAN && uh.dport != UDP_PORT_MPLS) {
        fwd_drop(u, m, DROP_UNDERLAY_UNEXPECTED);
        return;
    }
    const uint8_t src_node = node_id_by_ip(rd32(ip + 12)); /* NODE_UNKNOWN for an unconfigured sender */
    uint8_t *payload = udp + UDP_HDR_LEN;
    size_t plen = uh.len - UDP_HDR_LEN;

    if (uh.dport == UDP_PORT_VXLAN) {
        uint32_t vni;
        if (pkt_vxlan_parse(payload, plen, &vni) != 0) {
            fwd_drop(u, m, DROP_BAD_VXLAN);
            return;
        }
        int vrf = vni_lookup(vni);
        if (vrf < 0) {
            fwd_drop(u, m, DROP_UNKNOWN_TAG);
            return;
        }
        uint8_t *ie = payload + VXLAN_HDR_LEN; /* inner Ethernet */
        size_t ilen = plen - VXLAN_HDR_LEN;
        if (ilen < ETH_HDR_LEN || memcmp(ie, u->mac, ETH_ALEN) != 0 ||
            rd16(ie + 12) != ETHERTYPE_IPV4) {
            fwd_drop(u, m, DROP_BAD_INNER_L2);
            return;
        }
        if (pkt_ipv4_validate(ie, ilen, &why) != 0) {
            fwd_drop(u, m, why);
            return;
        }
        uint32_t dst = rd32(ie + ETH_HDR_LEN + 16);
        /* no transit: the destination must be a VM of this tenant on this node */
        const struct route *r = route_lookup((unsigned)vrf, dst);
        if (!r || r->kind != NH_LOCAL || r->port == ROUTE_NO_PORT || r->gateway != 0 ||
            (r->origin != ROUTE_HOST && r->origin != ROUTE_CONNECTED)) {
            fwd_drop(u, m, DROP_DECAP_NO_LOCAL_DEST);
            return;
        }
        struct port *eg = port_get((uint8_t)r->port);
        const struct neigh *n = neigh_lookup((unsigned)vrf, dst);
        if (!eg || eg->role != PORT_VM || eg->vrf != vrf || !n || n->state != NEIGH_REACHABLE) {
            fwd_drop(u, m, DROP_DECAP_NO_LOCAL_DEST);
            return;
        }
        m->off = (uint16_t)(ie - m->buf);
        m->len = (uint16_t)(ETH_HDR_LEN + rd16(ie + ETH_HDR_LEN + 2));
        deliver(u, m, eg, n->mac, src_node, ENCAP_VXLAN, outer_len);
        return;
    }

    /* MPLSoUDP: label -> VM port, no Ethernet header on the wire */
    struct mpls_lse lse;
    if (pkt_mpls_parse(payload, plen, &lse) != 0) {
        fwd_drop(u, m, DROP_BAD_MPLS);
        return;
    }
    int port = label_lookup(lse.label);
    if (port < 0) {
        fwd_drop(u, m, DROP_UNKNOWN_TAG);
        return;
    }
    /* write an Ethernet header in front of the inner IPv4 packet (the label and UDP bytes before
     * it are consumed) so the phase 1 validation can run on it unchanged */
    uint8_t *iip = payload + MPLS_LSE_LEN;
    uint8_t *ie = iip - ETH_HDR_LEN;
    wr16(ie + 12, ETHERTYPE_IPV4);
    if (pkt_ipv4_validate(ie, ETH_HDR_LEN + plen - MPLS_LSE_LEN, &why) != 0) {
        fwd_drop(u, m, why);
        return;
    }
    struct port *eg = port_get((uint8_t)port);
    uint32_t bip;
    uint8_t bmac[6];
    /* a per-interface label only carries traffic for the address bound to that interface */
    if (!eg || eg->role != PORT_VM || !neigh_binding(eg->id, &bip, bmac) ||
        rd32(iip + 16) != bip) {
        fwd_drop(u, m, DROP_DECAP_NO_LOCAL_DEST);
        return;
    }
    m->off = (uint16_t)(ie - m->buf);
    m->len = (uint16_t)(ETH_HDR_LEN + rd16(iip + 2));
    deliver(u, m, eg, bmac, src_node, ENCAP_MPLSOUDP, outer_len);
}
