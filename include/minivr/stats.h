#ifndef MINIVR_STATS_H
#define MINIVR_STATS_H
#include <stdint.h>

#include "json_out.h"

#define MAX_PORTS 17 /* 16 VM ports + 1 underlay */
#define MAX_VM_PORTS 16
#define TUNNEL_MAX_NODES 64
#define NODE_UNKNOWN TUNNEL_MAX_NODES /* pseudo-node for tunnels from unconfigured sources */

#define DROP_REASONS(X)                                                                            \
    X(TRUNCATED, "truncated")                                                                      \
    X(BAD_IP_VERSION, "bad_ip_version")                                                            \
    X(BAD_IP_HDR_LEN, "bad_ip_hdr_len")                                                            \
    X(IP_OPTIONS, "ip_options")                                                                    \
    X(BAD_IP_TOTAL_LEN, "bad_ip_total_len")                                                        \
    X(BAD_IP_CHECKSUM, "bad_ip_checksum")                                                          \
    X(IP_FRAGMENT, "ip_fragment")                                                                  \
    X(UNSUPPORTED_ETHERTYPE, "unsupported_ethertype")                                              \
    X(NON_ARP_BCAST_MCAST, "non_arp_bcast_mcast")                                                  \
    X(NOT_FOR_US_L2, "not_for_us_l2")                                                              \
    X(BAD_ARP, "bad_arp")                                                                          \
    X(ARP_UNKNOWN_TARGET, "arp_unknown_target")                                                    \
    X(SOURCE_SPOOFED, "source_spoofed")                                                            \
    X(NO_ROUTE, "no_route")                                                                        \
    X(TTL_EXCEEDED, "ttl_exceeded")                                                                \
    X(MTU_EXCEEDED, "mtu_exceeded")                                                                \
    X(NEIGHBOUR_UNRESOLVED, "neighbour_unresolved")                                                \
    X(PORT_DOWN, "port_down")                                                                      \
    X(LOCAL_UNSUPPORTED, "local_unsupported")                                                      \
    X(NOBUF, "nobuf")                                                                              \
    X(TX_ERROR, "tx_error")                                                                        \
    X(TUNNEL_NOT_FOR_US, "tunnel_not_for_us")                                                      \
    X(UNDERLAY_UNEXPECTED, "underlay_unexpected")                                                  \
    X(BAD_UDP, "bad_udp")                                                                          \
    X(BAD_VXLAN, "bad_vxlan")                                                                      \
    X(BAD_MPLS, "bad_mpls")                                                                        \
    X(BAD_INNER_L2, "bad_inner_l2")                                                                \
    X(UNKNOWN_TAG, "unknown_tag")                                                                  \
    X(DECAP_NO_LOCAL_DEST, "decap_no_local_dest")                                                  \
    X(TUNNEL_MTU_EXCEEDED, "tunnel_mtu_exceeded")

enum drop_reason {
#define X(id, name) DROP_##id,
    DROP_REASONS(X)
#undef X
        DROP_COUNT
};

struct port_stats {
    uint64_t rx_pkts, rx_bytes, tx_pkts, tx_bytes, drops;
};

enum encap_kind { ENCAP_MPLSOUDP, ENCAP_VXLAN, ENCAP_COUNT };

struct dir_stats {
    uint64_t pkts, bytes;
};

/* Per remote node (index = node id; NODE_UNKNOWN collects decap from unconfigured sources). */
struct node_stats {
    struct dir_stats encap[ENCAP_COUNT], decap[ENCAP_COUNT];
};

struct stats {
    uint64_t drop_total;
    uint64_t reasons[DROP_COUNT];
    struct port_stats port[MAX_PORTS];
    struct node_stats node[TUNNEL_MAX_NODES + 1];
    uint64_t icmp_ratelimited, neighbour_table_full, arp_replies_sent, icmp_sent;
};

/* One global instance owned by the forwarding thread. In phase 1 a single writer means plain
 * increments and no padding are needed; the per-port blocks are separate 40-byte structs so phase 4
 * can turn them into per-core copies, padded to cache lines, summed on read. */
extern struct stats g_stats;

const char *stats_reason_name(enum drop_reason r);
void stats_drop(enum drop_reason r);                      /* counts total + reason */
void stats_drop_port(uint8_t port, enum drop_reason r);   /* also the ingress port's drops */
void stats_node_encap(uint8_t node, enum encap_kind k, uint64_t bytes);
void stats_node_decap(uint8_t node, enum encap_kind k, uint64_t bytes);
const char *stats_encap_name(enum encap_kind k); /* "mplsoudp" / "vxlan" */
void stats_clear(void);                                   /* counters only, not gauges */
uint64_t stats_reason_sum(void);
void stats_json_drops(struct jw *w);  /* "drops":{total,reasons:{all 30}} */
void stats_json_events(struct jw *w); /* "events":{...} */
#endif
