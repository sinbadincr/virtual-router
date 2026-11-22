#ifndef MINIVR_ROUTE_H
#define MINIVR_ROUTE_H
#include <stdbool.h>
#include <stdint.h>

#include "cmd.h"
#include "owner.h"
#include "lpm.h"
#include "port.h"
#include "stats.h"

#define ROUTE_NO_PORT (-1)

enum route_origin { ROUTE_CONNECTED, ROUTE_HOST, ROUTE_STATIC, ROUTE_REMOTE };
enum route_kind { NH_LOCAL, NH_REMOTE };

/* Key: (vrf, prefix, len). Next hop: LOCAL {port, gateway} or REMOTE {node, encap, tag}. */
struct route {
    uint32_t prefix; /* host bits zero */
    uint8_t len;
    uint8_t vrf;
    enum route_kind kind;
    int8_t port;      /* LOCAL: egress port id, or ROUTE_NO_PORT for a multi-port connected subnet */
    uint32_t gateway; /* LOCAL: 0 = none */
    uint8_t node;     /* REMOTE: node id */
    enum encap_kind encap;
    uint32_t tag;     /* REMOTE: MPLS label or VNI */
    enum route_origin origin;
    uint8_t owner; /* enum owner; connected/host routes take their port's owner */
    uint8_t used;
    uint32_t next_free;
};

typedef void (*route_walk_fn)(const struct route *r, void *arg);

const char *route_origin_name(enum route_origin o);

#define MPLS_LABEL_MIN 16
#define MPLS_LABEL_MAX 1048575
#define VNI_MIN 1
#define VNI_MAX 16777215

/* Connected route for a VM port's subnet in its VRF; a second port on the same prefix makes it
 * egress-less. */
int route_add_connected(const struct port *p, struct cmd_err *err);
int route_add_host(unsigned vrf, uint32_t ip, uint8_t port, struct cmd_err *err);
int route_del_host(unsigned vrf, uint32_t ip);
/* Errors: unknown-vrf, unknown-port (also when the port is in another VRF), bad-prefix,
 * gw-not-connected, exists, table-full. */
int route_add_static(unsigned vrf, uint32_t prefix, uint8_t len, uint8_t port, uint32_t gw,
                     struct cmd_err *err);
/* Errors: unknown-vrf, no-underlay, unknown-node, bad-prefix, bad-syntax (tag range, VXLAN node
 * without rmac), exists, table-full. */
int route_add_remote(unsigned vrf, uint32_t prefix, uint8_t len, uint8_t node, enum encap_kind encap,
                     uint32_t tag, struct cmd_err *err);
/* Atomically replace a static or remote route (same validation as add; not-found, immutable). The
 * next lookup sees either the old or the new next hop, never a gap. */
int route_replace_static(unsigned vrf, uint32_t prefix, uint8_t len, uint8_t port, uint32_t gw,
                         struct cmd_err *err);
int route_replace_remote(unsigned vrf, uint32_t prefix, uint8_t len, uint8_t node,
                         enum encap_kind encap, uint32_t tag, struct cmd_err *err);
/* Errors: unknown-vrf, not-found, immutable (connected/host). */
int route_del(unsigned vrf, uint32_t prefix, uint8_t len, struct cmd_err *err);

const struct route *route_lookup(unsigned vrf, uint32_t ip); /* LPM; NULL on miss */
const struct route *route_find(unsigned vrf, uint32_t prefix, uint8_t len);
unsigned route_count(void);               /* all VRFs */
unsigned route_count_vrf(unsigned vrf);
void route_walk(unsigned vrf, route_walk_fn fn, void *arg); /* prefix order */
bool route_port_has_static(unsigned vrf, uint8_t port);
bool route_node_in_use(uint8_t node);
/* Remove the connected route of a VM port being deleted (the other ports on the prefix keep it). */
void route_port_removed(const struct port *p);
/* Move a VM port's connected and host routes between VRFs, all or nothing. */
int route_move_port(const struct port *p, uint8_t from, uint8_t to, struct cmd_err *err);
void route_reset(void); /* tests: all routes, VRFs and tunnel tables back to the empty state */
#endif
