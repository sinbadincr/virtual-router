#ifndef MINIVR_NEIGH_H
#define MINIVR_NEIGH_H
#include <stdbool.h>
#include <stdint.h>

#include "cmd.h"
#include "owner.h"
#include "mbuf.h"

#define NEIGH_CAPACITY 1024
#define NEIGH_SLOTS 2048
#define NEIGH_UNDERLAY 255 /* table id of the underlay; 0..63 are VRFs */
#define NEIGH_HOLD_MAX 3
#define NEIGH_MAX_TRIES 3

enum neigh_kind { NEIGH_STATIC, NEIGH_LEARNED };
enum neigh_state { NEIGH_INCOMPLETE, NEIGH_REACHABLE, NEIGH_FAILED };

struct neigh {
    uint8_t slot; /* 0 empty, 1 used, 2 tombstone */
    uint8_t table; /* VRF id, or NEIGH_UNDERLAY */
    uint32_t ip;
    uint8_t mac[6];
    uint8_t port;
    uint8_t owner; /* enum owner; learned entries are never agent-owned */
    enum neigh_kind kind;
    enum neigh_state state;
    uint8_t nhold;
    struct mbuf *hold_head, *hold_tail; /* only while INCOMPLETE */
    uint64_t deadline;                  /* INCOMPLETE start + 1 s; FAILED: removal time */
    uint64_t next_arp;
    uint8_t arp_tries;
};

enum neigh_res {
    NEIGH_OK,          /* mac filled in */
    NEIGH_HELD,        /* mbuf now owned by the hold queue */
    NEIGH_DROP,        /* caller drops: neighbour_unresolved */
    NEIGH_DROP_UNREACH /* caller drops and sends ICMP host unreachable (entry FAILED) */
};

/* The table of a port is its VRF (VM ports) or NEIGH_UNDERLAY (the underlay port).
 * Errors: unknown-port, bad-syntax (underlay port), exists (ip is static in that VRF, or the port
 * already has a static neighbour), table-full, plus whatever installing the /32 host route reports. */
int neigh_add_static(uint32_t ip, const uint8_t mac[6], uint8_t port, struct cmd_err *err);
int neigh_del(unsigned table, uint32_t ip, struct cmd_err *err); /* not-found */

const struct neigh *neigh_lookup(unsigned table, uint32_t ip);
enum neigh_res neigh_resolve(uint32_t ip, uint8_t port, struct mbuf *m, uint8_t mac[6]);
void neigh_learn(uint32_t ip, const uint8_t mac[6], uint8_t port); /* unbound ports only */
void neigh_tick(uint64_t now_ns);                                  /* ARP retry, expiry */
void neigh_port_down(uint8_t port);
/* drops a pending resolution for a deleted route's hop */
void neigh_gateway_removed(unsigned table, uint32_t gw);
/* A VM port moved to another VRF: learned entries are flushed, the static one is re-keyed. */
void neigh_port_set_vrf(uint8_t port, uint8_t new_vrf);
/* A port is being deleted: every neighbour on it goes (static ones take their host route and the
 * source binding), held packets are freed and counted as port_deleted. */
void neigh_port_removed(uint8_t port);

/* Source binding of a port = its single static neighbour (FR-014a). */
bool neigh_binding(uint8_t port, uint32_t *ip, uint8_t mac[6]);

unsigned neigh_count(void);
typedef void (*neigh_walk_fn)(const struct neigh *n, void *arg);
void neigh_walk(neigh_walk_fn fn, void *arg);
void neigh_reset(void); /* tests: forget everything (held mbufs are freed) */
#endif
