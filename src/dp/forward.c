/* Per-burst pipeline (plan.md "Packet path"). No syscalls: all I/O through port->pio ops. */
#include "minivr/forward.h"

#include <string.h>

#include "minivr/antispoof.h"
#include "minivr/clock.h"
#include "minivr/neigh.h"
#include "minivr/pkt.h"
#include "minivr/ratelimit.h"
#include "minivr/route.h"
#include "minivr/stats.h"
#include "pio.h"

struct txq {
    struct mbuf *m[PIO_BURST];
    int n;
};
static struct txq txq[MAX_PORTS];

static void tx_flush(uint8_t id) {
    struct txq *q = &txq[id];
    struct port *p = port_get(id);
    if (q->n == 0)
        return;
    int n = q->n;
    q->n = 0;
    uint16_t lens[PIO_BURST];
    for (int i = 0; i < n; i++)
        lens[i] = q->m[i]->len;
    int sent = port_backend()->tx_burst(p->pio, q->m, n);
    if (sent < 0)
        sent = 0;
    g_stats.port[id].tx_pkts += (uint64_t)sent;
    for (int i = 0; i < sent && i < n; i++)
        g_stats.port[id].tx_bytes += lens[i];
}

static void tx_enqueue(uint8_t id, struct mbuf *m) {
    struct txq *q = &txq[id];
    if (q->n == PIO_BURST)
        tx_flush(id);
    q->m[q->n++] = m;
}

static void flush_all(void) {
    for (unsigned i = 0; i < MAX_PORTS; i++)
        if (txq[i].n)
            tx_flush((uint8_t)i);
}

static void drop(const struct port *in, struct mbuf *m, enum drop_reason r) {
    stats_drop_port(in->id, r);
    mbuf_free(m);
}

/* ICMP error back to the sender, gated by the ingress port's token bucket. */
static void send_icmp_error(struct port *in, const struct mbuf *orig, uint8_t type, uint8_t code,
                            uint16_t mtu) {
    const uint8_t *f = mbuf_data((struct mbuf *)orig);
    if (!pkt_icmp_error_allowed(f, orig->len))
        return;
    if (!tb_take(&in->icmp_bucket, clock_now_ns())) {
        g_stats.icmp_ratelimited++;
        return;
    }
    struct mbuf *e = mbuf_alloc();
    if (!e)
        return;
    e->len = (uint16_t)pkt_icmp_build_error(mbuf_data(e), f, orig->len, in->mac, in->ip, type, code,
                                            mtu);
    g_stats.icmp_sent++;
    tx_enqueue(in->id, e);
}

void fwd_tx_now(uint8_t port, struct mbuf *m) {
    if (!port_get(port)) {
        mbuf_free(m);
        return;
    }
    tx_enqueue(port, m);
    tx_flush(port);
}

void fwd_send_arp_request(uint8_t port, uint32_t target_ip) {
    struct port *p = port_get(port);
    if (!p || !p->admin_up || !p->oper_up)
        return;
    struct mbuf *m = mbuf_alloc();
    if (!m)
        return;
    pkt_arp_build_request(mbuf_data(m), p->mac, p->ip, target_ip);
    m->len = ARP_FRAME_LEN;
    fwd_tx_now(port, m);
}

void fwd_icmp_host_unreach(const struct mbuf *held) {
    struct port *in = port_get(held->in_port);
    if (!in)
        return;
    send_icmp_error(in, held, ICMP_UNREACH, ICMP_UNREACH_HOST, 0);
    tx_flush(in->id);
}

static int in_subnet(const struct port *p, uint32_t ip) {
    return (ip & port_netmask(p)) == (p->ip & port_netmask(p));
}

static void handle_arp(struct port *in, struct mbuf *m) {
    uint8_t *f = mbuf_data(m);
    struct arp_pkt a;
    if (pkt_arp_parse(f, m->len, &a) != 0) {
        drop(in, m, DROP_BAD_ARP);
        return;
    }
    uint32_t bip;
    uint8_t bmac[6];
    int bound = neigh_binding(in->id, &bip, bmac);
    /* learn only on unbound ports, only for senders inside the port's subnet */
    if (!bound && a.spa != 0 && a.spa != in->ip && in_subnet(in, a.spa))
        neigh_learn(a.spa, a.sha, in->id);
    if (a.op == ARP_OP_REPLY || a.spa == a.tpa) { /* reply or gratuitous: consumed */
        mbuf_free(m);
        return;
    }
    const struct neigh *n = neigh_lookup(in->vrf, a.tpa);
    if (a.tpa == in->ip || (n && n->state == NEIGH_REACHABLE)) {
        pkt_arp_make_reply(f, in->mac);
        m->len = ARP_FRAME_LEN;
        g_stats.arp_replies_sent++;
        tx_enqueue(in->id, m);
        return;
    }
    drop(in, m, DROP_ARP_UNKNOWN_TARGET);
}

static void handle_ipv4(struct port *in, struct mbuf *m) {
    uint8_t *f = mbuf_data(m);
    enum drop_reason why;
    if (pkt_ipv4_validate(f, m->len, &why) != 0) {
        drop(in, m, why);
        return;
    }
    uint8_t *ip = f + ETH_HDR_LEN;
    m->len = (uint16_t)(ETH_HDR_LEN + rd16(ip + 2)); /* strip Ethernet padding */
    uint32_t dst = rd32(ip + 16);

    if (port_by_ip(in->vrf, dst)) { /* addressed to the forwarder itself */
        if (ip[9] == IPPROTO_ICMP_ && m->len >= ETH_HDR_LEN + IPV4_HDR_LEN + 1 &&
            ip[IPV4_HDR_LEN] == ICMP_ECHO_REQUEST) {
            if (pkt_icmp_echo_reply(f, m->len) != 0) {
                drop(in, m, DROP_TRUNCATED);
                return;
            }
            memcpy(f + 6, in->mac, ETH_ALEN);
            tx_enqueue(in->id, m);
            return;
        }
        drop(in, m, DROP_LOCAL_UNSUPPORTED);
        return;
    }
    if (ip[8] <= 1) {
        send_icmp_error(in, m, ICMP_TIME_EXCEEDED, 0, 0);
        drop(in, m, DROP_TTL_EXCEEDED);
        return;
    }
    const struct route *r = route_lookup(in->vrf, dst);
    if (!r) {
        send_icmp_error(in, m, ICMP_UNREACH, ICMP_UNREACH_NET, 0);
        drop(in, m, DROP_NO_ROUTE);
        return;
    }
    if (r->kind == NH_REMOTE) { /* tunnel transmit path: encap.c (US2) */
        drop(in, m, DROP_NO_ROUTE);
        return;
    }
    if (r->port == ROUTE_NO_PORT) { /* multi-port subnet without a /32 for this host */
        send_icmp_error(in, m, ICMP_UNREACH, ICMP_UNREACH_HOST, 0);
        drop(in, m, DROP_NO_ROUTE);
        return;
    }
    struct port *eg = port_get((uint8_t)r->port);
    if (!eg || !eg->admin_up || !eg->oper_up) {
        drop(in, m, DROP_PORT_DOWN);
        return;
    }
    if (rd16(ip + 2) > eg->mtu) {
        if (rd16(ip + 6) & IP_DF)
            send_icmp_error(in, m, ICMP_UNREACH, ICMP_UNREACH_FRAG_NEEDED, eg->mtu);
        drop(in, m, DROP_MTU_EXCEEDED);
        return;
    }
    pkt_ipv4_dec_ttl(ip);
    uint32_t nexthop = r->gateway ? r->gateway : dst;
    uint8_t mac[6];
    switch (neigh_resolve(nexthop, eg->id, m, mac)) {
    case NEIGH_OK:
        memcpy(f, mac, ETH_ALEN);
        memcpy(f + 6, eg->mac, ETH_ALEN);
        tx_enqueue(eg->id, m);
        return;
    case NEIGH_HELD:
        return;
    case NEIGH_DROP_UNREACH:
        send_icmp_error(in, m, ICMP_UNREACH, ICMP_UNREACH_HOST, 0);
        drop(in, m, DROP_NEIGHBOUR_UNRESOLVED);
        return;
    default:
        drop(in, m, DROP_NEIGHBOUR_UNRESOLVED);
    }
}

void forward_burst(struct port *in, struct mbuf **m, int n) {
    for (int i = 0; i < n; i++) {
        struct mbuf *b = m[i];
        g_stats.port[in->id].rx_pkts++;
        g_stats.port[in->id].rx_bytes += b->len;
        b->in_port = in->id;
        const uint8_t *f = mbuf_data(b);
        enum drop_reason why;
        enum eth_class c = pkt_eth_classify(f, b->len, in->mac, &why);
        if (c == ETH_C_DROP) {
            drop(in, b, why);
            continue;
        }
        if (b->vlan_tagged) { /* tag already stripped by the kernel: VLAN is unsupported */
            drop(in, b, DROP_UNSUPPORTED_ETHERTYPE);
            continue;
        }
        if (in->role == PORT_UNDERLAY) { /* decap.c (US2) takes over; until then nothing is tunnelled */
            drop(in, b, DROP_UNDERLAY_UNEXPECTED);
            continue;
        }
        if (!antispoof_ok(in, c, f, b->len)) {
            drop(in, b, DROP_SOURCE_SPOOFED);
            continue;
        }
        if (c == ETH_C_ARP)
            handle_arp(in, b);
        else
            handle_ipv4(in, b);
    }
    flush_all();
}
