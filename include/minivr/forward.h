#ifndef MINIVR_FORWARD_H
#define MINIVR_FORWARD_H
#include <stdint.h>

#include "mbuf.h"
#include "pkt.h"
#include "port.h"
#include "route.h"
#include "stats.h"

/* Process one received burst: classify, forward, drop. Takes ownership of every mbuf. */
void forward_burst(struct port *in, struct mbuf **m, int n);

/* Helpers used by the neighbour table (also usable outside a burst); each transmits at once. */
void fwd_tx_now(uint8_t port, struct mbuf *m);              /* takes ownership */
void fwd_send_arp_request(uint8_t port, uint32_t target_ip);
void fwd_icmp_host_unreach(const struct mbuf *held);        /* rate-limited; does not free */

/* Building blocks shared by forward.c, encap.c and decap.c (all in the per-burst pipeline). */
void fwd_tx_enqueue(uint8_t port, struct mbuf *m); /* batched; takes ownership */
void fwd_drop(const struct port *in, struct mbuf *m, enum drop_reason r); /* count + free */
/* ICMP error to the sender of `orig` (an Ethernet frame holding a validated IPv4 packet), through
 * the ingress port's token bucket; does not free `orig`. */
void fwd_send_icmp_error(struct port *in, const struct mbuf *orig, uint8_t type, uint8_t code,
                         uint16_t mtu);

/* Tunnel transmit: encapsulate a validated, TTL-checked IPv4 frame received on VM port `in` for
 * REMOTE route `r` and send it on the underlay (encap.c). Takes ownership of `m`. */
void encap_tx(struct port *in, struct mbuf *m, const struct route *r);
/* Underlay receive: ARP, outer IPv4, UDP 4789/6635, VXLAN/MPLS, local delivery (decap.c). Takes
 * ownership of `m`; the Ethernet classification (destination MAC) was already done. */
void decap_rx(struct port *u, struct mbuf *m, enum eth_class cls);
#endif
