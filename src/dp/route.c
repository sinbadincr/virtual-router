#include "minivr/route.h"

#include <string.h>

#include "minivr/neigh.h"
#include "minivr/tunnel.h"
#include "minivr/vrf.h"

/* Route entries live in a flat array indexed by the trie's value, so a lookup is the trie walk
 * (see lpm.h) plus exactly one entry read. All VRFs share this array and the trie node pool, so
 * 10,000 routes is a total across tenants. Mutation happens between bursts on the same thread;
 * phase 4 will make updates RCU-style and the layout can then be reconsidered. */
static struct route routes[LPM_MAX_RULES];
static uint32_t free_head; /* index+1 of the first free slot, 0 = none */
static uint32_t used_count;
static int inited;

static void ensure_init(void) {
    if (inited)
        return;
    inited = 1;
    memset(routes, 0, sizeof routes);
    free_head = 0;
    for (uint32_t i = LPM_MAX_RULES; i-- > 0;) {
        routes[i].next_free = free_head;
        free_head = i + 1;
    }
    used_count = 0;
}

void route_reset(void) {
    inited = 0;
    ensure_init();
    vrf_reset();
    tunnel_reset();
}

const char *route_origin_name(enum route_origin o) {
    switch (o) {
    case ROUTE_CONNECTED: return "connected";
    case ROUTE_HOST: return "host";
    case ROUTE_REMOTE: return "remote";
    default: return "static";
    }
}

static uint32_t mask_of(uint8_t len) {
    return len == 0 ? 0 : ~0U << (32 - len);
}

static struct route *slot_alloc(uint32_t *idx) {
    if (!free_head)
        return NULL;
    uint32_t i = free_head - 1;
    free_head = routes[i].next_free;
    memset(&routes[i], 0, sizeof routes[i]);
    routes[i].used = 1;
    used_count++;
    *idx = i;
    return &routes[i];
}

static void slot_free(uint32_t idx) {
    routes[idx].used = 0;
    routes[idx].next_free = free_head;
    free_head = idx + 1;
    used_count--;
}

static struct vrf *vrf_or_fail(unsigned vrf, struct cmd_err *err) {
    struct vrf *v = vrf_by_id(vrf);
    if (!v)
        cmd_fail(err, "unknown-vrf", "no such VRF id %u", vrf);
    return v;
}

/* Fields shared by add and replace. */
struct nh {
    enum route_kind kind;
    int port;
    uint32_t gw;
    uint8_t node;
    enum encap_kind encap;
    uint32_t tag;
};

static void fill(struct route *r, const struct nh *nh) {
    r->kind = nh->kind;
    r->port = (int8_t)nh->port;
    r->gateway = nh->gw;
    r->node = nh->node;
    r->encap = nh->encap;
    r->tag = nh->tag;
}

static int insert(struct vrf *v, uint32_t prefix, uint8_t len, const struct nh *nh,
                  enum route_origin origin, struct cmd_err *err) {
    ensure_init();
    uint32_t idx;
    struct route *r = slot_alloc(&idx);
    if (!r)
        return cmd_fail(err, "table-full", "route table full (%d)", LPM_MAX_RULES);
    r->prefix = prefix;
    r->len = len;
    r->vrf = v->id;
    r->origin = origin;
    r->owner = (uint8_t)g_owner_ctx;
    fill(r, nh);
    int rc = lpm_add(vrf_pool(), &v->root, prefix, len, idx);
    if (rc != 0) {
        slot_free(idx);
        return rc == -1 ? cmd_fail(err, "exists", "route already exists")
                        : cmd_fail(err, "table-full", "route table full (%d)", LPM_MAX_RULES);
    }
    return 0;
}

static const struct route *exact(const struct vrf *v, uint32_t prefix, uint8_t len) {
    ensure_init();
    uint32_t idx;
    return lpm_get(vrf_pool(), &v->root, prefix, len, &idx) ? &routes[idx] : NULL;
}

const struct route *route_find(unsigned vrf, uint32_t prefix, uint8_t len) {
    const struct vrf *v = vrf_by_id(vrf);
    return v ? exact(v, prefix, len) : NULL;
}

static unsigned ports_on_prefix(const struct port *except, unsigned vrf, uint32_t prefix,
                                uint8_t len, int *last) {
    unsigned n = 0;
    for (unsigned i = 0; i < MAX_PORTS; i++) {
        const struct port *q = port_get((uint8_t)i);
        if (q && q != except && q->role == PORT_VM && q->vrf == vrf && q->prefix_len == len &&
            (q->ip & port_netmask(q)) == prefix) {
            n++;
            *last = q->id;
        }
    }
    return n;
}

int route_add_connected(const struct port *p, struct cmd_err *err) {
    ensure_init();
    struct vrf *v = vrf_or_fail(p->vrf, err);
    if (!v)
        return -1;
    uint32_t prefix = p->ip & port_netmask(p);
    const struct route *existing = exact(v, prefix, p->prefix_len);
    if (existing) {
        if (existing->origin == ROUTE_CONNECTED) {
            ((struct route *)existing)->port = ROUTE_NO_PORT; /* multi-port subnet */
            return 0;
        }
        return cmd_fail(err, "exists", "a route for the port subnet already exists");
    }
    struct nh nh = {.kind = NH_LOCAL, .port = p->id};
    enum owner saved = g_owner_ctx;
    g_owner_ctx = (enum owner)p->owner;
    int rc = insert(v, prefix, p->prefix_len, &nh, ROUTE_CONNECTED, err);
    g_owner_ctx = saved;
    return rc;
}

/* Undo route_add_connected for `p` in `vrf` (the other ports on the prefix keep it). */
static void connected_remove(const struct port *p, unsigned vrf) {
    struct vrf *v = vrf_by_id(vrf);
    uint32_t prefix = p->ip & port_netmask(p);
    const struct route *r = v ? exact(v, prefix, p->prefix_len) : NULL;
    if (!r || r->origin != ROUTE_CONNECTED)
        return;
    int last = -1;
    unsigned n = ports_on_prefix(p, vrf, prefix, p->prefix_len, &last);
    if (n == 0) {
        uint32_t idx = (uint32_t)(r - routes);
        lpm_del(vrf_pool(), &v->root, prefix, p->prefix_len);
        slot_free(idx);
    } else {
        ((struct route *)r)->port = n == 1 ? (int8_t)last : ROUTE_NO_PORT;
    }
}

int route_add_host(unsigned vrf, uint32_t ip, uint8_t port, struct cmd_err *err) {
    struct vrf *v = vrf_or_fail(vrf, err);
    if (!v)
        return -1;
    struct nh nh = {.kind = NH_LOCAL, .port = port};
    const struct port *pp = port_get(port);
    enum owner saved = g_owner_ctx;
    if (pp)
        g_owner_ctx = (enum owner)pp->owner;
    int rc = insert(v, ip, 32, &nh, ROUTE_HOST, err);
    g_owner_ctx = saved;
    return rc;
}

int route_del_host(unsigned vrf, uint32_t ip) {
    struct vrf *v = vrf_by_id(vrf);
    const struct route *r = v ? exact(v, ip, 32) : NULL;
    if (!r || r->origin != ROUTE_HOST)
        return -1;
    uint32_t idx = (uint32_t)(r - routes);
    lpm_del(vrf_pool(), &v->root, ip, 32);
    slot_free(idx);
    return 0;
}

void route_port_removed(const struct port *p) {
    connected_remove(p, p->vrf);
}

int route_move_port(const struct port *p, uint8_t from, uint8_t to, struct cmd_err *err) {
    struct vrf *dst = vrf_or_fail(to, err);
    if (!dst)
        return -1;
    struct port moved = *p; /* route_add_connected reads the VRF from the port */
    moved.vrf = to;
    if (route_add_connected(&moved, err) != 0)
        return -1;
    uint32_t bip;
    uint8_t bmac[6];
    bool bound = neigh_binding(p->id, &bip, bmac);
    if (bound && route_add_host(to, bip, p->id, err) != 0) {
        connected_remove(&moved, to);
        return -1;
    }
    if (bound)
        route_del_host(from, bip);
    connected_remove(p, from);
    return 0;
}

static int check_local(unsigned vrf, uint32_t prefix, uint8_t len, uint8_t port, uint32_t gw,
                       struct cmd_err *err) {
    struct port *p = port_get(port);
    if (!p || p->role != PORT_VM || p->vrf != vrf)
        return cmd_fail(err, "unknown-port", "no such port in VRF id %u", vrf);
    if (len > 32 || (prefix & ~mask_of(len)))
        return cmd_fail(err, "bad-prefix", "host bits set in prefix");
    if (gw && (gw & port_netmask(p)) != (p->ip & port_netmask(p)))
        return cmd_fail(err, "gw-not-connected", "gateway is not in the subnet of port %s", p->name);
    return 0;
}

static int check_remote(unsigned vrf, uint32_t prefix, uint8_t len, uint8_t node,
                        enum encap_kind encap, uint32_t tag, struct cmd_err *err) {
    if (len > 32 || (prefix & ~mask_of(len)))
        return cmd_fail(err, "bad-prefix", "host bits set in prefix");
    (void)vrf;
    if (!port_underlay())
        return cmd_fail(err, "no-underlay", "no underlay port is configured");
    const struct node *n = node_get(node);
    if (!n)
        return cmd_fail(err, "unknown-node", "no such remote node");
    if (encap == ENCAP_MPLSOUDP) {
        if (tag < MPLS_LABEL_MIN || tag > MPLS_LABEL_MAX)
            return cmd_fail(err, "bad-syntax", "label must be %d..%d", MPLS_LABEL_MIN, MPLS_LABEL_MAX);
    } else {
        if (tag < VNI_MIN || tag > VNI_MAX)
            return cmd_fail(err, "bad-syntax", "VNI must be %d..%d", VNI_MIN, VNI_MAX);
        if (!n->has_rmac)
            return cmd_fail(err, "bad-syntax", "node %s has no rmac (needed for VXLAN)", n->name);
    }
    return 0;
}

int route_add_static(unsigned vrf, uint32_t prefix, uint8_t len, uint8_t port, uint32_t gw,
                     struct cmd_err *err) {
    struct vrf *v = vrf_or_fail(vrf, err);
    if (!v || check_local(vrf, prefix, len, port, gw, err) != 0)
        return -1;
    struct nh nh = {.kind = NH_LOCAL, .port = port, .gw = gw};
    return insert(v, prefix, len, &nh, ROUTE_STATIC, err);
}

int route_add_remote(unsigned vrf, uint32_t prefix, uint8_t len, uint8_t node, enum encap_kind encap,
                     uint32_t tag, struct cmd_err *err) {
    struct vrf *v = vrf_or_fail(vrf, err);
    if (!v || check_remote(vrf, prefix, len, node, encap, tag, err) != 0)
        return -1;
    struct nh nh = {.kind = NH_REMOTE, .node = node, .encap = encap, .tag = tag};
    return insert(v, prefix, len, &nh, ROUTE_REMOTE, err);
}

static struct route *replaceable(struct vrf *v, uint32_t prefix, uint8_t len, struct cmd_err *err) {
    const struct route *r = exact(v, prefix, len);
    if (!r) {
        cmd_fail(err, "not-found", "no such route");
        return NULL;
    }
    if (r->origin != ROUTE_STATIC && r->origin != ROUTE_REMOTE) {
        cmd_fail(err, "immutable", "%s routes cannot be replaced", route_origin_name(r->origin));
        return NULL;
    }
    return (struct route *)r;
}

int route_replace_static(unsigned vrf, uint32_t prefix, uint8_t len, uint8_t port, uint32_t gw,
                         struct cmd_err *err) {
    struct vrf *v = vrf_or_fail(vrf, err);
    if (!v)
        return -1;
    struct route *r = replaceable(v, prefix, len, err);
    if (!r || check_local(vrf, prefix, len, port, gw, err) != 0)
        return -1;
    uint32_t old_gw = r->kind == NH_LOCAL ? r->gateway : 0;
    struct nh nh = {.kind = NH_LOCAL, .port = port, .gw = gw};
    fill(r, &nh);
    r->origin = ROUTE_STATIC;
    if (old_gw && old_gw != gw)
        neigh_gateway_removed(vrf, old_gw);
    return 0;
}

int route_replace_remote(unsigned vrf, uint32_t prefix, uint8_t len, uint8_t node,
                         enum encap_kind encap, uint32_t tag, struct cmd_err *err) {
    struct vrf *v = vrf_or_fail(vrf, err);
    if (!v)
        return -1;
    struct route *r = replaceable(v, prefix, len, err);
    if (!r || check_remote(vrf, prefix, len, node, encap, tag, err) != 0)
        return -1;
    uint32_t old_gw = r->kind == NH_LOCAL ? r->gateway : 0;
    struct nh nh = {.kind = NH_REMOTE, .node = node, .encap = encap, .tag = tag};
    fill(r, &nh);
    r->origin = ROUTE_REMOTE;
    if (old_gw)
        neigh_gateway_removed(vrf, old_gw);
    return 0;
}

int route_del(unsigned vrf, uint32_t prefix, uint8_t len, struct cmd_err *err) {
    struct vrf *v = vrf_or_fail(vrf, err);
    if (!v)
        return -1;
    const struct route *r = exact(v, prefix, len);
    if (!r)
        return cmd_fail(err, "not-found", "no such route");
    if (r->origin != ROUTE_STATIC && r->origin != ROUTE_REMOTE)
        return cmd_fail(err, "immutable", "%s routes cannot be deleted", route_origin_name(r->origin));
    uint32_t gw = r->kind == NH_LOCAL ? r->gateway : 0;
    uint32_t idx = (uint32_t)(r - routes);
    lpm_del(vrf_pool(), &v->root, prefix, len);
    slot_free(idx);
    if (gw)
        neigh_gateway_removed(vrf, gw);
    return 0;
}

const struct route *route_lookup(unsigned vrf, uint32_t ip) {
    ensure_init();
    const struct vrf *v = vrf_by_id(vrf);
    uint32_t idx;
    if (!v || !lpm_lookup(vrf_pool(), &v->root, ip, &idx, NULL))
        return NULL;
    return &routes[idx];
}

unsigned route_count(void) {
    return used_count;
}

unsigned route_count_vrf(unsigned vrf) {
    const struct vrf *v = vrf_by_id(vrf);
    return v ? lpm_count(&v->root) : 0;
}

struct walk_ctx {
    route_walk_fn fn;
    void *arg;
};

static void walk_cb(uint32_t prefix, uint8_t len, uint32_t value, void *arg) {
    (void)prefix;
    (void)len;
    struct walk_ctx *c = arg;
    c->fn(&routes[value], c->arg);
}

void route_walk(unsigned vrf, route_walk_fn fn, void *arg) {
    ensure_init();
    const struct vrf *v = vrf_by_id(vrf);
    if (!v)
        return;
    struct walk_ctx c = {fn, arg};
    lpm_walk(vrf_pool(), &v->root, walk_cb, &c);
}

bool route_port_has_static(unsigned vrf, uint8_t port) {
    ensure_init();
    for (uint32_t i = 0; i < LPM_MAX_RULES; i++)
        if (routes[i].used && routes[i].vrf == vrf && routes[i].origin == ROUTE_STATIC &&
            routes[i].port == port)
            return true;
    return false;
}

bool route_node_in_use(uint8_t node) {
    ensure_init();
    for (uint32_t i = 0; i < LPM_MAX_RULES; i++)
        if (routes[i].used && routes[i].kind == NH_REMOTE && routes[i].node == node)
            return true;
    return false;
}
