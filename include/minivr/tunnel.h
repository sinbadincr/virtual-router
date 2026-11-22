#ifndef MINIVR_TUNNEL_H
#define MINIVR_TUNNEL_H
#include <stdbool.h>
#include <stdint.h>

#include "cmd.h"
#include "owner.h"
#include "stats.h"

#define LABEL_MAX_MAPPINGS 1024
#define LABEL_SLOTS 2048
#define VNI_MAX_MAPPINGS 64
#define NODE_NAME_MAX 15

/* A remote compute node reachable over the underlay (data-model "Remote node"). Counters live in
 * g_stats.node[id] so `stats show` and `node show` read the same numbers. */
struct node {
    uint8_t id;
    bool in_use;
    uint8_t owner;
    char name[NODE_NAME_MAX + 1];
    uint32_t ip;
    uint8_t rmac[6];
    bool has_rmac;
};

/* Errors: no-underlay, bad-syntax (name), exists (name or ip), table-full, bad-prefix (ip outside
 * the underlay subnet). rmac may be NULL. */
int node_add(const char *name, uint32_t ip, const uint8_t *rmac, struct cmd_err *err);
int node_set_rmac(const char *name, const uint8_t rmac[6], struct cmd_err *err); /* unknown-node */
int node_del(const char *name, struct cmd_err *err); /* unknown-node, busy (a route uses it) */
struct node *node_find(const char *name);
const struct node *node_get(uint8_t id);
uint8_t node_id_by_ip(uint32_t ip); /* NODE_UNKNOWN when no node has this address */
unsigned node_count(void);

/* MPLS receive mappings: label -> one local VM port (per-interface labels).
 * Errors: bad-syntax (label range, port is not a VM port), unknown-port, exists, table-full. */
int label_add(uint32_t label, uint8_t port, struct cmd_err *err);
int label_del(uint32_t label, struct cmd_err *err); /* not-found */
int label_lookup(uint32_t label);                    /* port id, or -1 */
int label_owner(uint32_t label);                     /* enum owner, or -1 */
void label_del_port(uint8_t port);                   /* a deleted port takes its labels with it */
unsigned label_count(void);
unsigned label_count_vrf(unsigned vrf);
typedef void (*label_walk_fn)(uint32_t label, uint8_t port, void *arg);
void label_walk(label_walk_fn fn, void *arg); /* ascending label order */

/* VXLAN receive mappings: VNI -> one VRF. Errors: bad-syntax (range), unknown-vrf, exists,
 * table-full. */
int vni_add(uint32_t vni, unsigned vrf, struct cmd_err *err);
int vni_del(uint32_t vni, struct cmd_err *err); /* not-found */
int vni_lookup(uint32_t vni);                    /* VRF id, or -1 */
int vni_owner(uint32_t vni);                     /* enum owner, or -1 */
unsigned vni_count(void);
unsigned tunnel_vni_count_vrf(unsigned vrf);
typedef void (*vni_walk_fn)(uint32_t vni, unsigned vrf, void *arg);
void vni_walk(vni_walk_fn fn, void *arg); /* ascending VNI order */

void tunnel_reset(void); /* tests */
#endif
