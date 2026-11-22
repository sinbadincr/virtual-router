#include "minivr/neigh.h"

#include <string.h>

#include "minivr/clock.h"
#include "minivr/forward.h"
#include "minivr/pkt.h"
#include "minivr/port.h"
#include "minivr/route.h"
#include "minivr/stats.h"

#define ARP_RETRY_NS (333 * NS_PER_MS)
#define RESOLVE_TIMEOUT_NS NS_PER_SEC
#define FAILED_HOLD_NS NS_PER_SEC

enum { SLOT_EMPTY, SLOT_USED, SLOT_TOMB };

/* Neighbour table: open addressing over 2,048 slots with linear probing, so a lookup normally
 * touches one or two adjacent slots (sequential, prefetch-friendly) and the load factor stays at
 * or below 50% (capacity 1,024). A slot is ~72 bytes, deliberately not padded to a cache line:
 * phase 1 has one thread, so there is no false sharing to avoid. When forwarding moves to several
 * cores (phase 4) the table is read-mostly shared state and gets an RCU/epoch swap rather than
 * per-slot padding; revisit the layout then, with a measurement (docs/perf.md). */
static struct neigh tab[NEIGH_SLOTS];
static unsigned used, tombs;
static struct {
    bool bound;
    uint32_t ip;
    uint8_t mac[6];
} binding[MAX_PORTS];

static unsigned hash(uint8_t table, uint32_t ip) {
    return ((ip ^ ((uint32_t)table * 0x9e3779b9u)) * 2654435761u) >> (32 - 11);
}

/* The neighbour table a port's traffic uses. */
static uint8_t table_of(const struct port *p) {
    return p->role == PORT_UNDERLAY ? NEIGH_UNDERLAY : p->vrf;
}

static struct neigh *find(uint8_t table, uint32_t ip) {
    unsigned i = hash(table, ip);
    for (unsigned n = 0; n < NEIGH_SLOTS; n++, i = (i + 1) & (NEIGH_SLOTS - 1)) {
        if (tab[i].slot == SLOT_EMPTY)
            return NULL;
        if (tab[i].slot == SLOT_USED && tab[i].ip == ip && tab[i].table == table)
            return &tab[i];
    }
    return NULL;
}

static void rehash(void) {
    static struct neigh tmp[NEIGH_CAPACITY];
    unsigned n = 0;
    for (unsigned i = 0; i < NEIGH_SLOTS; i++)
        if (tab[i].slot == SLOT_USED)
            tmp[n++] = tab[i];
    memset(tab, 0, sizeof tab);
    tombs = 0;
    for (unsigned k = 0; k < n; k++) {
        unsigned i = hash(tmp[k].table, tmp[k].ip);
        while (tab[i].slot == SLOT_USED)
            i = (i + 1) & (NEIGH_SLOTS - 1);
        tab[i] = tmp[k];
    }
}

static struct neigh *insert(uint8_t table, uint32_t ip) {
    if (tombs > NEIGH_SLOTS / 4)
        rehash();
    unsigned i = hash(table, ip);
    while (tab[i].slot == SLOT_USED)
        i = (i + 1) & (NEIGH_SLOTS - 1);
    if (tab[i].slot == SLOT_TOMB)
        tombs--;
    memset(&tab[i], 0, sizeof tab[i]);
    tab[i].slot = SLOT_USED;
    tab[i].table = table;
    tab[i].ip = ip;
    tab[i].owner = (uint8_t)g_owner_ctx;
    used++;
    return &tab[i];
}

static void erase(struct neigh *n) {
    n->slot = SLOT_TOMB;
    n->hold_head = n->hold_tail = NULL;
    n->nhold = 0;
    used--;
    tombs++;
}

/* Release held packets, either sending them (mac != NULL) or dropping them. */
static void release_hold(struct neigh *n, const uint8_t *mac, enum drop_reason why, bool icmp) {
    struct mbuf *m = n->hold_head;
    n->hold_head = n->hold_tail = NULL;
    n->nhold = 0;
    while (m) {
        struct mbuf *next = m->next;
        m->next = NULL;
        struct port *eg = port_get(n->port);
        if (mac && eg) {
            uint8_t *f = mbuf_data(m);
            memcpy(f, mac, ETH_ALEN);
            /* underlay: the held frame is already fully encapsulated, only the outer
             * destination MAC was unknown */
            if (n->table != NEIGH_UNDERLAY)
                memcpy(f + 6, eg->mac, ETH_ALEN);
            fwd_tx_now(n->port, m);
        } else {
            stats_drop_port(m->in_port, why);
            if (icmp)
                fwd_icmp_host_unreach(m);
            mbuf_free(m);
        }
        m = next;
    }
}

const struct neigh *neigh_lookup(unsigned table, uint32_t ip) {
    return table > 255 ? NULL : find((uint8_t)table, ip);
}

bool neigh_binding(uint8_t port, uint32_t *ip, uint8_t mac[6]) {
    if (port >= MAX_PORTS || !binding[port].bound)
        return false;
    *ip = binding[port].ip;
    memcpy(mac, binding[port].mac, 6);
    return true;
}

unsigned neigh_count(void) {
    return used;
}

int neigh_add_static(uint32_t ip, const uint8_t mac[6], uint8_t port, struct cmd_err *err) {
    struct port *p = port_get(port);
    if (!p)
        return cmd_fail(err, "unknown-port", "no such port");
    if (p->role != PORT_VM)
        return cmd_fail(err, "bad-syntax", "static neighbours belong to VM ports");
    uint8_t table = table_of(p);
    struct neigh *old = find(table, ip);
    if (old && old->kind == NEIGH_STATIC)
        return cmd_fail(err, "exists", "static neighbour %u.%u.%u.%u already exists", ip >> 24,
                        (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
    if (binding[port].bound)
        return cmd_fail(err, "exists", "port %s already has a static neighbour", p->name);
    if (!old && used >= NEIGH_CAPACITY)
        return cmd_fail(err, "table-full", "neighbour table full (%d)", NEIGH_CAPACITY);
    if (route_add_host(table, ip, port, err) != 0)
        return -1;
    if (old) { /* a learned/incomplete entry is replaced by the static one */
        release_hold(old, NULL, DROP_NEIGHBOUR_UNRESOLVED, false);
        erase(old);
    }
    struct neigh *n = insert(table, ip);
    memcpy(n->mac, mac, 6);
    n->port = port;
    n->kind = NEIGH_STATIC;
    n->state = NEIGH_REACHABLE;
    binding[port].bound = true;
    binding[port].ip = ip;
    memcpy(binding[port].mac, mac, 6);
    return 0;
}

int neigh_del(unsigned table, uint32_t ip, struct cmd_err *err) {
    struct neigh *n = table > 255 ? NULL : find((uint8_t)table, ip);
    if (!n)
        return cmd_fail(err, "not-found", "no such neighbour");
    release_hold(n, NULL, DROP_NEIGHBOUR_UNRESOLVED, false);
    if (n->kind == NEIGH_STATIC) {
        route_del_host(n->table, ip);
        binding[n->port].bound = false;
    }
    erase(n);
    return 0;
}

enum neigh_res neigh_resolve(uint32_t ip, uint8_t port, struct mbuf *m, uint8_t mac[6]) {
    const struct port *ep = port_get(port);
    if (!ep)
        return NEIGH_DROP;
    uint8_t table = table_of(ep);
    struct neigh *n = find(table, ip);
    uint64_t now = clock_now_ns();
    if (n && n->state == NEIGH_REACHABLE) {
        memcpy(mac, n->mac, 6);
        return NEIGH_OK;
    }
    if (n && n->state == NEIGH_FAILED)
        return NEIGH_DROP_UNREACH;
    if (!n) {
        if (used >= NEIGH_CAPACITY) {
            g_stats.neighbour_table_full++;
            return NEIGH_DROP;
        }
        n = insert(table, ip);
        n->owner = OWNER_CONFIG;
        n->port = port;
        n->kind = NEIGH_LEARNED;
        n->state = NEIGH_INCOMPLETE;
        n->deadline = now + RESOLVE_TIMEOUT_NS;
        n->next_arp = now + ARP_RETRY_NS;
        n->arp_tries = 1;
        fwd_send_arp_request(port, ip);
    }
    if (n->nhold >= NEIGH_HOLD_MAX)
        return NEIGH_DROP;
    m->next = NULL;
    if (n->hold_tail)
        n->hold_tail->next = m;
    else
        n->hold_head = m;
    n->hold_tail = m;
    n->nhold++;
    return NEIGH_HELD;
}

void neigh_learn(uint32_t ip, const uint8_t mac[6], uint8_t port) {
    if (ip == 0 || (ip >> 28) == 0xe || ip == 0xffffffffu)
        return;
    const struct port *lp = port_get(port);
    if (!lp)
        return;
    uint8_t table = table_of(lp);
    struct neigh *n = find(table, ip);
    if (n && n->kind == NEIGH_STATIC)
        return; /* learned never overwrites static */
    if (!n) {
        if (used >= NEIGH_CAPACITY) {
            g_stats.neighbour_table_full++;
            return;
        }
        n = insert(table, ip);
        n->owner = OWNER_CONFIG;
        n->kind = NEIGH_LEARNED;
    }
    memcpy(n->mac, mac, 6);
    n->port = port;
    n->state = NEIGH_REACHABLE;
    n->arp_tries = 0;
    if (n->hold_head)
        release_hold(n, n->mac, DROP_NEIGHBOUR_UNRESOLVED, false);
}

void neigh_tick(uint64_t now) {
    for (unsigned i = 0; i < NEIGH_SLOTS; i++) {
        struct neigh *n = &tab[i];
        if (n->slot != SLOT_USED)
            continue;
        if (n->state == NEIGH_INCOMPLETE) {
            if (now >= n->deadline) {
                release_hold(n, NULL, DROP_NEIGHBOUR_UNRESOLVED, true);
                n->state = NEIGH_FAILED;
                n->deadline = now + FAILED_HOLD_NS;
            } else if (n->arp_tries < NEIGH_MAX_TRIES && now >= n->next_arp) {
                fwd_send_arp_request(n->port, n->ip);
                n->arp_tries++;
                n->next_arp += ARP_RETRY_NS;
            }
        } else if (n->state == NEIGH_FAILED && now >= n->deadline) {
            erase(n);
        }
    }
}

void neigh_port_down(uint8_t port) {
    for (unsigned i = 0; i < NEIGH_SLOTS; i++) {
        struct neigh *n = &tab[i];
        if (n->slot != SLOT_USED || n->port != port)
            continue;
        release_hold(n, NULL, DROP_PORT_DOWN, false);
        if (n->kind == NEIGH_LEARNED)
            erase(n);
    }
}

void neigh_port_removed(uint8_t port) {
    for (unsigned i = 0; i < NEIGH_SLOTS; i++) {
        struct neigh *n = &tab[i];
        if (n->slot != SLOT_USED || n->port != port)
            continue;
        release_hold(n, NULL, DROP_PORT_DELETED, false);
        if (n->kind == NEIGH_STATIC)
            route_del_host(n->table, n->ip);
        erase(n);
    }
    binding[port].bound = false;
}

void neigh_gateway_removed(unsigned table, uint32_t gw) {
    struct neigh *n = table > 255 ? NULL : find((uint8_t)table, gw);
    if (n && n->kind == NEIGH_LEARNED && n->state != NEIGH_REACHABLE) {
        release_hold(n, NULL, DROP_NEIGHBOUR_UNRESOLVED, false);
        erase(n);
    }
}

void neigh_port_set_vrf(uint8_t port, uint8_t new_vrf) {
    for (unsigned i = 0; i < NEIGH_SLOTS; i++) {
        struct neigh *n = &tab[i];
        if (n->slot != SLOT_USED || n->port != port)
            continue;
        if (n->kind == NEIGH_LEARNED) {
            release_hold(n, NULL, DROP_NEIGHBOUR_UNRESOLVED, false);
            erase(n);
        }
    }
    /* the static entry is re-keyed: copy it out, erase, insert under the new table */
    uint32_t ip;
    uint8_t mac[6];
    if (!neigh_binding(port, &ip, mac))
        return;
    struct neigh *old = NULL;
    for (unsigned i = 0; i < NEIGH_SLOTS && !old; i++)
        if (tab[i].slot == SLOT_USED && tab[i].port == port && tab[i].kind == NEIGH_STATIC)
            old = &tab[i];
    if (!old)
        return;
    uint8_t old_owner = old->owner;
    erase(old);
    struct neigh *n = insert(new_vrf, ip);
    n->owner = old_owner;
    memcpy(n->mac, mac, 6);
    n->port = port;
    n->kind = NEIGH_STATIC;
    n->state = NEIGH_REACHABLE;
}

void neigh_walk(neigh_walk_fn fn, void *arg) {
    for (unsigned i = 0; i < NEIGH_SLOTS; i++)
        if (tab[i].slot == SLOT_USED)
            fn(&tab[i], arg);
}

void neigh_reset(void) {
    for (unsigned i = 0; i < NEIGH_SLOTS; i++)
        if (tab[i].slot == SLOT_USED) {
            struct mbuf *m = tab[i].hold_head;
            while (m) {
                struct mbuf *next = m->next;
                mbuf_free(m);
                m = next;
            }
        }
    memset(tab, 0, sizeof tab);
    memset(binding, 0, sizeof binding);
    used = tombs = 0;
}
