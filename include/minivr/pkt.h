#ifndef MINIVR_PKT_H
#define MINIVR_PKT_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "stats.h"

/* Wire-format helpers and packet codecs. Every parser is bounds-checked against the
 * actual buffer length (FR-013). Addresses passed around are host byte order. */

#define ETH_ALEN 6
#define ETH_HDR_LEN 14
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define IPV4_HDR_LEN 20
#define IPPROTO_ICMP_ 1
#define ICMP_HDR_LEN 8
#define ARP_PKT_LEN 28
#define ARP_FRAME_LEN (ETH_HDR_LEN + ARP_PKT_LEN)
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff

#define IPPROTO_UDP_ 17
#define UDP_HDR_LEN 8
#define UDP_PORT_VXLAN 4789 /* RFC 7348 */
#define UDP_PORT_MPLS 6635  /* RFC 7510 */
#define MPLS_LSE_LEN 4
#define VXLAN_HDR_LEN 8
#define VXLAN_FLAG_I 0x08
/* bytes added around the inner IPv4 packet (data-model, contracts/wire-formats.md) */
#define OVERHEAD_MPLSOUDP (IPV4_HDR_LEN + UDP_HDR_LEN + MPLS_LSE_LEN)                       /* 32 */
#define OVERHEAD_VXLAN (IPV4_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN + ETH_HDR_LEN)           /* 50 */

#define ICMP_ECHO_REPLY 0
#define ICMP_UNREACH 3
#define ICMP_ECHO_REQUEST 8
#define ICMP_TIME_EXCEEDED 11
#define ICMP_UNREACH_NET 0
#define ICMP_UNREACH_HOST 1
#define ICMP_UNREACH_FRAG_NEEDED 4

static inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}
static inline uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
static inline void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* ---- Ethernet (pkt_eth.c) ---- */
enum eth_class { ETH_C_IPV4, ETH_C_ARP, ETH_C_DROP };
/* Order: truncated -> destination MAC (ingress MAC, or broadcast only for ARP) -> ethertype.
 * On ETH_C_DROP, *reason says why. */
enum eth_class pkt_eth_classify(const uint8_t *frame, size_t len, const uint8_t port_mac[ETH_ALEN],
                                enum drop_reason *reason);

/* ---- IPv4 (pkt_ipv4.c); `frame` is the whole Ethernet frame ---- */
uint16_t pkt_csum16(const void *data, size_t len); /* folded one's-complement checksum (to store) */
/* Order: truncated, version, IHL<5 or beyond frame, options, total length, checksum, fragment. */
int pkt_ipv4_validate(const uint8_t *frame, size_t len, enum drop_reason *reason);
/* TTL-- with RFC 1624 incremental checksum update; ip points at the IPv4 header. */
void pkt_ipv4_dec_ttl(uint8_t *ip);
void pkt_ipv4_set_csum(uint8_t *ip); /* recompute header checksum (IHL 5) */

/* ---- ARP (pkt_arp.c) ---- */
struct arp_pkt {
    uint16_t op;
    uint8_t sha[ETH_ALEN];
    uint32_t spa;
    uint8_t tha[ETH_ALEN];
    uint32_t tpa;
};
int pkt_arp_parse(const uint8_t *frame, size_t len, struct arp_pkt *out); /* 0, or -1 = bad_arp */
/* Turn a received ARP request into the reply, in place: sender = `mac` claiming the asked IP. */
void pkt_arp_make_reply(uint8_t *frame, const uint8_t mac[ETH_ALEN]);
/* Broadcast request "who has target_ip, tell src_ip" into out[ARP_FRAME_LEN]. */
void pkt_arp_build_request(uint8_t *out, const uint8_t src_mac[ETH_ALEN], uint32_t src_ip,
                           uint32_t target_ip);

/* ---- ICMP (pkt_icmp.c) ---- */
/* In place: Ethernet/IP swapped, type 0, TTL 64, checksums recomputed. frame is a validated
 * IPv4 echo request addressed to us; returns -1 if the ICMP part is shorter than 8 bytes. */
int pkt_icmp_echo_reply(uint8_t *frame, size_t len);
/* Whether an ICMP error may be generated for this (validated) IPv4 frame (RFC 1812 4.3.2.7). */
int pkt_icmp_error_allowed(const uint8_t *frame, size_t len);
/* Build an error into out (cap >= ICMP_ERR_MAX): Ethernet back to the sender, IP from src_ip,
 * quoting the original IP header + 8 bytes. mtu only used for type 3 code 4. Returns frame length. */
#define ICMP_ERR_MAX (ETH_HDR_LEN + IPV4_HDR_LEN + ICMP_HDR_LEN + IPV4_HDR_LEN + 8)
size_t pkt_icmp_build_error(uint8_t *out, const uint8_t *orig, size_t orig_len,
                            const uint8_t eth_src[ETH_ALEN], uint32_t src_ip, uint8_t type,
                            uint8_t code, uint16_t mtu);

/* ---- UDP (pkt_udp.c) ---- `udp` points at the UDP header, `avail` = bytes the IP payload holds ---- */
struct udp_hdr {
    uint16_t sport, dport, len; /* len = header + payload as stated by the sender */
};
/* 0, or -1 = bad_udp: fewer than 8 bytes, length < 8 or length > avail. Checksum is not checked
 * (it is 0 on everything we emit, RFC 7348 / 7510 allow that for IPv4). */
int pkt_udp_parse(const uint8_t *udp, size_t avail, struct udp_hdr *out);
/* Writes sport/dport, length = 8 + payload_len and checksum 0. */
void pkt_udp_build(uint8_t *out, uint16_t sport, uint16_t dport, uint16_t payload_len);

/* ---- MPLS label stack entry (pkt_mpls.c), RFC 7510 (one label, S = 1) ---- */
struct mpls_lse {
    uint32_t label;
    uint8_t tc, s, ttl;
};
int pkt_mpls_parse(const uint8_t *p, size_t avail, struct mpls_lse *out); /* 0, or -1 = bad_mpls */
void pkt_mpls_build(uint8_t *out, uint32_t label, uint8_t ttl);           /* TC 0, S 1 */

/* ---- VXLAN header (pkt_vxlan.c), RFC 7348 ---- */
/* 0, or -1 = bad_vxlan: fewer than 8 bytes or I flag clear. Reserved bits are ignored. */
int pkt_vxlan_parse(const uint8_t *p, size_t avail, uint32_t *vni);
void pkt_vxlan_build(uint8_t *out, uint32_t vni);

/* Flow hash of an IPv4 packet (src, dst, protocol and, for TCP/UDP, both ports): the same flow
 * always hashes the same, which keeps one flow on one underlay path (FR-012). `ip` points at the
 * IPv4 header of `avail` bytes. */
uint32_t pkt_flow_hash(const uint8_t *ip, size_t avail);
#endif
