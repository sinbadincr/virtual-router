#include "minivr/port.h"

#include <string.h>

#include "minivr/clock.h"
#include "minivr/neigh.h"
#include "minivr/route.h"
#include "minivr/vrf.h"
#include "pio.h"

static struct port ports[MAX_PORTS];
static const struct pio_ops *backend;

void port_set_backend(const struct pio_ops *ops) {
    backend = ops;
}

const struct pio_ops *port_backend(void) {
    return backend;
}

struct port *port_get(uint8_t id) {
    return (id < MAX_PORTS && ports[id].in_use) ? &ports[id] : NULL;
}

struct port *port_find(const char *name) {
    for (unsigned i = 0; i < MAX_PORTS; i++)
        if (ports[i].in_use && strcmp(ports[i].name, name) == 0)
            return &ports[i];
    return NULL;
}

struct port *port_by_ip(unsigned vrf, uint32_t ip) {
    for (unsigned i = 0; i < MAX_PORTS; i++)
        if (ports[i].in_use && ports[i].role == PORT_VM && ports[i].vrf == vrf && ports[i].ip == ip)
            return &ports[i];
    return NULL;
}

struct port *port_underlay(void) {
    for (unsigned i = 0; i < MAX_PORTS; i++)
        if (ports[i].in_use && ports[i].role == PORT_UNDERLAY)
            return &ports[i];
    return NULL;
}

unsigned port_count_in_vrf(unsigned vrf) {
    unsigned n = 0;
    for (unsigned i = 0; i < MAX_PORTS; i++)
        n += ports[i].in_use && ports[i].role == PORT_VM && ports[i].vrf == vrf;
    return n;
}

unsigned port_count(void) {
    unsigned n = 0;
    for (unsigned i = 0; i < MAX_PORTS; i++)
        n += ports[i].in_use;
    return n;
}

uint32_t port_netmask(const struct port *p) {
    return p->prefix_len == 0 ? 0 : ~0U << (32 - p->prefix_len);
}

struct port *port_add(const char *name, const char *ifname, uint32_t ip, uint8_t prefix_len,
                      enum port_role role, unsigned vrf, struct cmd_err *err) {
    if (!backend) {
        cmd_fail(err, "not-found", "no packet I/O backend configured");
        return NULL;
    }
    if (strlen(name) == 0 || strlen(name) > 15 || strlen(ifname) == 0 || strlen(ifname) > 15) {
        cmd_fail(err, "bad-syntax", "name and ifname must be 1..15 characters");
        return NULL;
    }
    if (role == PORT_VM && !vrf_by_id(vrf)) {
        cmd_fail(err, "unknown-vrf", "no such VRF id %u", vrf);
        return NULL;
    }
    if (role == PORT_UNDERLAY && port_underlay()) {
        cmd_fail(err, "exists", "an underlay port already exists");
        return NULL;
    }
    if (port_find(name)) {
        cmd_fail(err, "exists", "port %s already exists", name);
        return NULL;
    }
    struct port *slot = NULL;
    unsigned vm_ports = 0;
    for (unsigned i = 0; i < MAX_PORTS; i++) {
        struct port *p = &ports[i];
        if (!p->in_use) {
            if (!slot)
                slot = p;
            continue;
        }
        if (strcmp(p->ifname, ifname) == 0) {
            cmd_fail(err, "exists", "interface %s already used by port %s", ifname, p->name);
            return NULL;
        }
        vm_ports += p->role == PORT_VM;
        /* the anycast gateway may repeat across VRFs; inside one VRF it needs one prefix */
        if (role == PORT_VM && p->role == PORT_VM && p->vrf == vrf && p->ip == ip &&
            p->prefix_len != prefix_len) {
            cmd_fail(err, "exists", "address shared with port %s but with a different prefix",
                     p->name);
            return NULL;
        }
    }
    if (!slot || (role == PORT_VM && vm_ports >= MAX_VM_PORTS)) {
        cmd_fail(err, "table-full", "at most %d VM ports", MAX_VM_PORTS);
        return NULL;
    }
    void *h = backend->open(ifname);
    if (!h) {
        cmd_fail(err, "not-found", "cannot open interface %s", ifname);
        return NULL;
    }
    uint8_t mac[6];
    int mtu = backend->get_mtu(h);
    if (backend->get_mac(h, mac) != 0 || mtu <= 0 || mtu > 0xffff) {
        backend->close(h);
        cmd_fail(err, "not-found", "cannot read MAC/MTU of %s", ifname);
        return NULL;
    }
    memset(slot, 0, sizeof *slot);
    slot->id = (uint8_t)(slot - ports);
    slot->in_use = true;
    slot->role = role;
    slot->vrf = role == PORT_VM ? (uint8_t)vrf : 0;
    strncpy(slot->name, name, sizeof slot->name - 1);
    strncpy(slot->ifname, ifname, sizeof slot->ifname - 1);
    memcpy(slot->mac, mac, 6);
    slot->ip = ip;
    slot->prefix_len = prefix_len;
    slot->mtu = (uint16_t)mtu;
    slot->admin_up = true;
    slot->oper_up = true;
    slot->pio = h;
    tb_init(&slot->icmp_bucket, ratelimit_rate(), ratelimit_burst(), clock_now_ns());
    if (role == PORT_VM && route_add_connected(slot, err) != 0) {
        backend->close(h);
        memset(slot, 0, sizeof *slot);
        return NULL;
    }
    return slot;
}

int port_set_vrf(struct port *p, unsigned vrf, struct cmd_err *err) {
    if (p->role != PORT_VM)
        return cmd_fail(err, "bad-syntax", "port %s is the underlay and has no VRF", p->name);
    if (!vrf_by_id(vrf))
        return cmd_fail(err, "unknown-vrf", "no such VRF id %u", vrf);
    if (p->vrf == vrf)
        return 0;
    if (route_port_has_static(p->vrf, p->id))
        return cmd_fail(err, "busy", "a static route still uses port %s", p->name);
    for (unsigned i = 0; i < MAX_PORTS; i++) {
        const struct port *q = &ports[i];
        if (q->in_use && q != p && q->role == PORT_VM && q->vrf == vrf && q->ip == p->ip &&
            q->prefix_len != p->prefix_len)
            return cmd_fail(err, "exists", "address shared with port %s but with a different prefix",
                            q->name);
    }
    uint8_t old = p->vrf;
    /* routes first: they refuse (all or nothing) on a clash in the new VRF */
    if (route_move_port(p, old, (uint8_t)vrf, err) != 0)
        return -1;
    neigh_port_set_vrf(p->id, (uint8_t)vrf);
    p->vrf = (uint8_t)vrf;
    return 0;
}

void port_close_all(void) {
    for (unsigned i = 0; i < MAX_PORTS; i++) {
        if (ports[i].in_use && backend) {
            backend->close(ports[i].pio);
            ports[i].pio = NULL;
        }
    }
}

void port_reset(void) {
    port_close_all();
    memset(ports, 0, sizeof ports);
}
