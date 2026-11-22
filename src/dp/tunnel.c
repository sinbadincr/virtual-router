#include "minivr/tunnel.h"

#include <string.h>

#include "minivr/port.h"
#include "minivr/route.h"
#include "minivr/vrf.h"

static struct node nodes[TUNNEL_MAX_NODES];

/* ---- remote nodes ---- */

struct node *node_find(const char *name) {
    for (unsigned i = 0; i < TUNNEL_MAX_NODES; i++)
        if (nodes[i].in_use && strcmp(nodes[i].name, name) == 0)
            return &nodes[i];
    return NULL;
}

const struct node *node_get(uint8_t id) {
    return (id < TUNNEL_MAX_NODES && nodes[id].in_use) ? &nodes[id] : NULL;
}

uint8_t node_id_by_ip(uint32_t ip) {
    for (unsigned i = 0; i < TUNNEL_MAX_NODES; i++)
        if (nodes[i].in_use && nodes[i].ip == ip)
            return (uint8_t)i;
    return NODE_UNKNOWN;
}

unsigned node_count(void) {
    unsigned n = 0;
    for (unsigned i = 0; i < TUNNEL_MAX_NODES; i++)
        n += nodes[i].in_use;
    return n;
}

int node_add(const char *name, uint32_t ip, const uint8_t *rmac, struct cmd_err *err) {
    const struct port *u = port_underlay();
    if (!u)
        return cmd_fail(err, "no-underlay", "no underlay port is configured");
    size_t n = strlen(name);
    if (n < 1 || n > NODE_NAME_MAX)
        return cmd_fail(err, "bad-syntax", "node name must be 1..%d characters", NODE_NAME_MAX);
    if (node_find(name))
        return cmd_fail(err, "exists", "node %s already exists", name);
    if ((ip & port_netmask(u)) != (u->ip & port_netmask(u)))
        return cmd_fail(err, "bad-prefix", "node address is outside the underlay subnet");
    if (node_id_by_ip(ip) != NODE_UNKNOWN)
        return cmd_fail(err, "exists", "a node with this address already exists");
    for (unsigned i = 0; i < TUNNEL_MAX_NODES; i++) {
        if (nodes[i].in_use)
            continue;
        memset(&nodes[i], 0, sizeof nodes[i]);
        nodes[i].id = (uint8_t)i;
        nodes[i].in_use = true;
        nodes[i].owner = (uint8_t)g_owner_ctx;
        memcpy(nodes[i].name, name, n + 1);
        nodes[i].ip = ip;
        if (rmac) {
            memcpy(nodes[i].rmac, rmac, 6);
            nodes[i].has_rmac = true;
        }
        memset(&g_stats.node[i], 0, sizeof g_stats.node[i]);
        return 0;
    }
    return cmd_fail(err, "table-full", "at most %d nodes", TUNNEL_MAX_NODES);
}

int node_set_rmac(const char *name, const uint8_t rmac[6], struct cmd_err *err) {
    struct node *n = node_find(name);
    if (!n)
        return cmd_fail(err, "unknown-node", "no such node '%s'", name);
    memcpy(n->rmac, rmac, 6);
    n->has_rmac = true;
    return 0;
}

int node_del(const char *name, struct cmd_err *err) {
    struct node *n = node_find(name);
    if (!n)
        return cmd_fail(err, "unknown-node", "no such node '%s'", name);
    if (route_node_in_use(n->id))
        return cmd_fail(err, "busy", "node %s is used by a route", name);
    memset(n, 0, sizeof *n);
    return 0;
}

/* ---- labels: 2,048-slot open-addressing hash, linear probing, tombstones ---- */

enum { SLOT_EMPTY, SLOT_USED, SLOT_TOMB };
static struct {
    uint8_t state;
    uint8_t port;
    uint8_t owner;
    uint32_t label;
} lab[LABEL_SLOTS];
static unsigned lab_used, lab_tombs;

static unsigned lab_hash(uint32_t label) {
    return (label * 2654435761u) >> (32 - 11);
}

static int lab_find(uint32_t label) {
    unsigned i = lab_hash(label);
    for (unsigned n = 0; n < LABEL_SLOTS; n++, i = (i + 1) & (LABEL_SLOTS - 1)) {
        if (lab[i].state == SLOT_EMPTY)
            return -1;
        if (lab[i].state == SLOT_USED && lab[i].label == label)
            return (int)i;
    }
    return -1;
}

static void lab_rehash(void) {
    static struct {
        uint32_t label;
        uint8_t port;
        uint8_t owner;
    } tmp[LABEL_MAX_MAPPINGS];
    unsigned n = 0;
    for (unsigned i = 0; i < LABEL_SLOTS; i++)
        if (lab[i].state == SLOT_USED) {
            tmp[n].label = lab[i].label;
            tmp[n].owner = lab[i].owner;
            tmp[n++].port = lab[i].port;
        }
    memset(lab, 0, sizeof lab);
    lab_tombs = 0;
    for (unsigned k = 0; k < n; k++) {
        unsigned i = lab_hash(tmp[k].label);
        while (lab[i].state == SLOT_USED)
            i = (i + 1) & (LABEL_SLOTS - 1);
        lab[i].state = SLOT_USED;
        lab[i].label = tmp[k].label;
        lab[i].port = tmp[k].port;
        lab[i].owner = tmp[k].owner;
    }
}

int label_lookup(uint32_t label) {
    int i = lab_find(label);
    return i < 0 ? -1 : lab[i].port;
}

static void lab_erase(int i) {
    lab[i].state = SLOT_TOMB;
    lab_used--;
    lab_tombs++;
}

int label_owner(uint32_t label) {
    int i = lab_find(label);
    return i < 0 ? -1 : lab[i].owner;
}

int label_add(uint32_t label, uint8_t port, struct cmd_err *err) {
    if (label < MPLS_LABEL_MIN || label > MPLS_LABEL_MAX)
        return cmd_fail(err, "bad-syntax", "label must be %d..%d", MPLS_LABEL_MIN, MPLS_LABEL_MAX);
    const struct port *p = port_get(port);
    if (!p)
        return cmd_fail(err, "unknown-port", "no such port");
    if (p->role != PORT_VM)
        return cmd_fail(err, "bad-syntax", "labels map to VM ports, not the underlay");
    if (lab_find(label) >= 0)
        return cmd_fail(err, "exists", "label %u already mapped", label);
    if (lab_used >= LABEL_MAX_MAPPINGS)
        return cmd_fail(err, "table-full", "at most %d labels", LABEL_MAX_MAPPINGS);
    if (lab_tombs > LABEL_SLOTS / 4)
        lab_rehash();
    unsigned i = lab_hash(label);
    while (lab[i].state == SLOT_USED)
        i = (i + 1) & (LABEL_SLOTS - 1);
    if (lab[i].state == SLOT_TOMB)
        lab_tombs--;
    lab[i].state = SLOT_USED;
    lab[i].label = label;
    lab[i].port = port;
    lab[i].owner = (uint8_t)g_owner_ctx;
    lab_used++;
    return 0;
}

int label_del(uint32_t label, struct cmd_err *err) {
    int i = lab_find(label);
    if (i < 0)
        return cmd_fail(err, "not-found", "label %u is not mapped", label);
    lab_erase(i);
    return 0;
}

void label_del_port(uint8_t port) {
    for (unsigned i = 0; i < LABEL_SLOTS; i++)
        if (lab[i].state == SLOT_USED && lab[i].port == port)
            lab_erase((int)i);
}

unsigned label_count(void) {
    return lab_used;
}

unsigned label_count_vrf(unsigned vrf) {
    unsigned n = 0;
    for (unsigned i = 0; i < LABEL_SLOTS; i++) {
        const struct port *p = lab[i].state == SLOT_USED ? port_get(lab[i].port) : NULL;
        n += p && p->vrf == vrf;
    }
    return n;
}

/* Insertion sort: walks run on the control path only, over at most 1,024 keys, and src/dp keeps
 * to freestanding code (no libc allocation or stdlib). */
static void sort_u32(uint32_t *k, unsigned n) {
    for (unsigned i = 1; i < n; i++) {
        uint32_t v = k[i];
        unsigned j = i;
        for (; j > 0 && k[j - 1] > v; j--)
            k[j] = k[j - 1];
        k[j] = v;
    }
}

void label_walk(label_walk_fn fn, void *arg) {
    static uint32_t keys[LABEL_MAX_MAPPINGS];
    unsigned n = 0;
    for (unsigned i = 0; i < LABEL_SLOTS; i++)
        if (lab[i].state == SLOT_USED)
            keys[n++] = lab[i].label;
    sort_u32(keys, n);
    for (unsigned k = 0; k < n; k++)
        fn(keys[k], (uint8_t)label_lookup(keys[k]), arg);
}

/* ---- VNIs: at most 64, linear scan ---- */

static struct {
    bool used;
    uint32_t vni;
    uint8_t vrf;
    uint8_t owner;
} vnis[VNI_MAX_MAPPINGS];

int vni_lookup(uint32_t vni) {
    for (unsigned i = 0; i < VNI_MAX_MAPPINGS; i++)
        if (vnis[i].used && vnis[i].vni == vni)
            return vnis[i].vrf;
    return -1;
}

int vni_owner(uint32_t vni) {
    for (unsigned i = 0; i < VNI_MAX_MAPPINGS; i++)
        if (vnis[i].used && vnis[i].vni == vni)
            return vnis[i].owner;
    return -1;
}

int vni_add(uint32_t vni, unsigned vrf, struct cmd_err *err) {
    if (vni < VNI_MIN || vni > VNI_MAX)
        return cmd_fail(err, "bad-syntax", "VNI must be %d..%d", VNI_MIN, VNI_MAX);
    if (!vrf_by_id(vrf))
        return cmd_fail(err, "unknown-vrf", "no such VRF id %u", vrf);
    if (vni_lookup(vni) >= 0)
        return cmd_fail(err, "exists", "VNI %u already mapped", vni);
    for (unsigned i = 0; i < VNI_MAX_MAPPINGS; i++) {
        if (!vnis[i].used) {
            vnis[i].used = true;
            vnis[i].vni = vni;
            vnis[i].vrf = (uint8_t)vrf;
            vnis[i].owner = (uint8_t)g_owner_ctx;
            return 0;
        }
    }
    return cmd_fail(err, "table-full", "at most %d VNIs", VNI_MAX_MAPPINGS);
}

int vni_del(uint32_t vni, struct cmd_err *err) {
    for (unsigned i = 0; i < VNI_MAX_MAPPINGS; i++)
        if (vnis[i].used && vnis[i].vni == vni) {
            vnis[i].used = false;
            return 0;
        }
    return cmd_fail(err, "not-found", "VNI %u is not mapped", vni);
}

unsigned vni_count(void) {
    unsigned n = 0;
    for (unsigned i = 0; i < VNI_MAX_MAPPINGS; i++)
        n += vnis[i].used;
    return n;
}

unsigned tunnel_vni_count_vrf(unsigned vrf) {
    unsigned n = 0;
    for (unsigned i = 0; i < VNI_MAX_MAPPINGS; i++)
        n += vnis[i].used && vnis[i].vrf == vrf;
    return n;
}

void vni_walk(vni_walk_fn fn, void *arg) {
    static uint32_t keys[VNI_MAX_MAPPINGS];
    unsigned n = 0;
    for (unsigned i = 0; i < VNI_MAX_MAPPINGS; i++)
        if (vnis[i].used)
            keys[n++] = vnis[i].vni;
    sort_u32(keys, n);
    for (unsigned k = 0; k < n; k++)
        fn(keys[k], (unsigned)vni_lookup(keys[k]), arg);
}

void tunnel_reset(void) {
    memset(nodes, 0, sizeof nodes);
    memset(lab, 0, sizeof lab);
    lab_used = lab_tombs = 0;
    memset(vnis, 0, sizeof vnis);
}
