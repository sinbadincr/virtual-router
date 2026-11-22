#include "minivr/reconcile.h"

#include <string.h>

void rc_init(struct reconciler *rc) {
    memset(rc, 0, sizeof *rc);
    ns_init(&rc->want, rc->want_s, RC_CAP);
    ns_init(&rc->pending, rc->pending_s, RC_CAP);
    ns_init(&rc->foreign, rc->foreign_s, RC_CAP);
}

void rc_sync_begin(struct reconciler *rc, uint32_t gen) {
    ns_clear(&rc->pending);
    rc->syncing = true;
    rc->gen = gen;
}

int rc_update(struct reconciler *rc, const struct nentry *dels, unsigned ndels,
              const struct nentry *adds, unsigned nadds) {
    struct nstate *dst = rc->syncing ? &rc->pending : &rc->want;
    for (unsigned i = 0; i < ndels; i++)
        ns_del(dst, &dels[i]);
    for (unsigned i = 0; i < nadds; i++)
        if (ns_put(dst, &adds[i]) != 0)
            return -1;
    return 0;
}

int rc_sync_end(struct reconciler *rc, uint32_t gen) {
    if (!rc->syncing || gen != rc->gen)
        return -1;
    ns_copy(&rc->want, &rc->pending);
    ns_clear(&rc->pending);
    rc->syncing = false;
    rc->want_valid = true;
    return 0;
}

void rc_session_lost(struct reconciler *rc) {
    ns_clear(&rc->pending);
    rc->syncing = false;
}

void backoff_reset(struct backoff *b) {
    b->ms = 500;
}

unsigned backoff_next(struct backoff *b) {
    if (b->ms == 0)
        b->ms = 500;
    unsigned now = b->ms;
    b->ms = b->ms >= 4000 ? 5000 : b->ms * 2;
    return now;
}

/* ---- text rendering without stdio ---- */

struct sb {
    char *p;
    size_t cap, len;
    bool over;
};

static void sb_s(struct sb *b, const char *s) {
    size_t n = strlen(s);
    if (b->len + n + 1 > b->cap) {
        b->over = true;
        return;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = 0;
}

static void sb_u(struct sb *b, uint64_t v) {
    char t[24];
    int i = 23;
    t[i] = 0;
    do {
        t[--i] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    sb_s(b, t + i);
}

static void sb_ip(struct sb *b, uint32_t ip) {
    char t[16];
    ne_ip_str(ip, t);
    sb_s(b, t);
}

static void sb_prefix(struct sb *b, uint32_t ip, uint8_t len) {
    char t[20];
    ne_prefix_str(ip, len, t);
    sb_s(b, t);
}

static void sb_mac(struct sb *b, const uint8_t m[6]) {
    char t[18];
    ne_mac_str(m, t);
    sb_s(b, t);
}

/* "prefix of the route as a.b.c.d/len" */
static void render_add(struct rc_cmd *c, const struct nentry *e, bool replace) {
    struct sb b = {c->text, sizeof c->text, 0, false};
    c->text[0] = 0;
    c->is_del = false;
    c->is_port_add = false;
    c->entry = *e;
    switch (e->kind) {
    case NE_VRF:
        sb_s(&b, "vrf add ");
        sb_s(&b, e->name);
        sb_s(&b, " id ");
        sb_u(&b, e->id);
        break;
    case NE_VNI:
        sb_s(&b, "vni add ");
        sb_u(&b, e->vni);
        sb_s(&b, " vrf ");
        sb_s(&b, e->vrf);
        break;
    case NE_NODE:
        if (replace) { /* only the rmac changed */
            sb_s(&b, "node set ");
            sb_s(&b, e->name);
            sb_s(&b, " rmac ");
            sb_mac(&b, e->rmac);
        } else {
            sb_s(&b, "node add ");
            sb_s(&b, e->name);
            sb_s(&b, " ip ");
            sb_ip(&b, e->ip);
            sb_s(&b, " rmac ");
            sb_mac(&b, e->rmac);
        }
        break;
    case NE_PORT:
        sb_s(&b, "port add ");
        sb_s(&b, e->name);
        sb_s(&b, " ifname ");
        sb_s(&b, e->name);
        sb_s(&b, " ip ");
        sb_prefix(&b, e->prefix, e->plen);
        sb_s(&b, " vrf ");
        sb_s(&b, e->vrf);
        sb_s(&b, " fd");
        c->is_port_add = true;
        break;
    case NE_NEIGH:
        sb_s(&b, "neigh add ");
        sb_ip(&b, e->ip);
        sb_s(&b, " lladdr ");
        sb_mac(&b, e->mac);
        sb_s(&b, " dev ");
        sb_s(&b, e->port);
        break;
    case NE_LABEL:
        sb_s(&b, "label add ");
        sb_u(&b, e->label);
        sb_s(&b, " port ");
        sb_s(&b, e->port);
        break;
    case NE_ROUTE:
        sb_s(&b, replace ? "route replace " : "route add ");
        sb_prefix(&b, e->prefix, e->plen);
        sb_s(&b, " vrf ");
        sb_s(&b, e->vrf);
        sb_s(&b, " node ");
        sb_s(&b, e->node);
        if (e->encap == NE_ENCAP_VXLAN) {
            sb_s(&b, " encap vxlan vni ");
        } else {
            sb_s(&b, " encap mplsoudp label ");
        }
        sb_u(&b, e->tag);
        break;
    }
}

static void render_del(struct rc_cmd *c, const struct nentry *e) {
    struct sb b = {c->text, sizeof c->text, 0, false};
    c->text[0] = 0;
    c->is_del = true;
    c->is_port_add = false;
    c->entry = *e;
    switch (e->kind) {
    case NE_VRF: sb_s(&b, "vrf del "); sb_s(&b, e->name); break;
    case NE_VNI: sb_s(&b, "vni del "); sb_u(&b, e->vni); break;
    case NE_NODE: sb_s(&b, "node del "); sb_s(&b, e->name); break;
    case NE_PORT: sb_s(&b, "port del "); sb_s(&b, e->name); break;
    case NE_NEIGH:
        sb_s(&b, "neigh del ");
        sb_ip(&b, e->ip);
        sb_s(&b, " vrf ");
        sb_s(&b, e->vrf);
        break;
    case NE_LABEL: sb_s(&b, "label del "); sb_u(&b, e->label); break;
    case NE_ROUTE:
        sb_s(&b, "route del ");
        sb_prefix(&b, e->prefix, e->plen);
        sb_s(&b, " vrf ");
        sb_s(&b, e->vrf);
        break;
    }
}

static int del_tier(unsigned kind) {
    switch (kind) {
    case NE_ROUTE: return 0;
    case NE_LABEL: case NE_VNI: return 1;
    case NE_NEIGH: return 2;
    case NE_PORT: return 3;
    case NE_NODE: return 4;
    default: return 5; /* VRF */
    }
}

static int add_tier(unsigned kind) {
    switch (kind) {
    case NE_VRF: return 0;
    case NE_NODE: return 1;
    case NE_PORT: return 2;
    case NE_NEIGH: return 3;
    case NE_LABEL: case NE_VNI: return 4;
    default: return 5; /* ROUTE */
    }
}

/* Does `dep` depend on the entry `base` (so that replacing base removes and re-adds dep)? */
static bool depends_on(const struct nentry *dep, const struct nentry *base) {
    switch (base->kind) {
    case NE_PORT:
        return (dep->kind == NE_NEIGH || dep->kind == NE_LABEL) && strcmp(dep->port, base->name) == 0;
    case NE_NODE:
        return dep->kind == NE_ROUTE && strcmp(dep->node, base->name) == 0;
    case NE_VRF:
        return (dep->kind == NE_PORT || dep->kind == NE_VNI || dep->kind == NE_NEIGH ||
                dep->kind == NE_ROUTE) && strcmp(dep->vrf, base->name) == 0;
    default:
        return false;
    }
}

/* Replacing PORT, VRF, NEIGH, LABEL, VNI needs del + add (the forwarder has no in-place update);
 * ROUTE is replaced in place; NODE with only a changed rmac uses `node set`. */
static bool needs_del_add(const struct nentry *old, const struct nentry *now) {
    switch (now->kind) {
    case NE_ROUTE: return false;
    case NE_NODE: return old->ip != now->ip;
    default: return true;
    }
}

static struct nentry dels_s[RC_CAP], adds_s[RC_CAP];
static unsigned char mark_del[RC_CAP], mark_add[RC_CAP], in_have_marked[RC_CAP];

int rc_plan(const struct reconciler *rc, const struct nstate *have, struct rc_cmd *out,
            unsigned cap, struct rc_conflict *conf, unsigned conf_cap, unsigned *nconf) {
    *nconf = 0;
    if (!rc->want_valid)
        return 0;
    /* 1. plain difference */
    struct ndiff d = {dels_s, adds_s, 0, 0, RC_CAP, RC_CAP};
    if (ns_diff(have, &rc->want, &d) != 0)
        return -1;
    memset(mark_del, 1, d.ndels);
    memset(mark_add, 1, d.nadds);

    /* 2. changed entries that cannot be updated in place become del + add (the old value is
     * deleted too), and their dependents are cycled with them */
    unsigned base_n = d.nadds;
    for (unsigned i = 0; i < base_n; i++) {
        const struct nentry *old = ns_get(have, &adds_s[i]);
        if (!old || !needs_del_add(old, &adds_s[i]))
            continue;
        if (d.ndels >= RC_CAP)
            return -1;
        dels_s[d.ndels] = *old;
        mark_del[d.ndels++] = 2; /* 2: cycled, the add below is a plain add */
        mark_add[i] = 2;
    }
    /* dependents of every deleted-and-re-added PORT, NODE or VRF */
    for (unsigned i = 0; i < d.nadds; i++) {
        if (mark_add[i] != 2 || (adds_s[i].kind != NE_PORT && adds_s[i].kind != NE_NODE &&
                                 adds_s[i].kind != NE_VRF))
            continue;
        for (unsigned h = 0; h < have->n; h++) {
            const struct nentry *dep = &have->e[h];
            if (!depends_on(dep, &adds_s[i]))
                continue;
            bool already = false;
            for (unsigned k = 0; k < d.ndels && !already; k++)
                already = ne_key_cmp(&dels_s[k], dep) == 0;
            if (!already) {
                if (d.ndels >= RC_CAP)
                    return -1;
                dels_s[d.ndels] = *dep;
                mark_del[d.ndels++] = 2;
            }
        }
        for (unsigned w = 0; w < rc->want.n; w++) {
            const struct nentry *dep = &rc->want.e[w];
            if (!depends_on(dep, &adds_s[i]))
                continue;
            bool already = false;
            for (unsigned k = 0; k < d.nadds && !already; k++)
                already = ne_key_cmp(&adds_s[k], dep) == 0;
            if (!already) {
                if (d.nadds >= RC_CAP)
                    return -1;
                adds_s[d.nadds] = *dep;
                mark_add[d.nadds++] = 2;
            }
        }
    }
    (void)in_have_marked;

    /* 3. adds for keys the forwarder holds for config/cli are conflicts, never commands */
    unsigned nc = 0;
    for (unsigned i = 0; i < d.nadds; i++) {
        if (ns_get(&rc->foreign, &adds_s[i])) {
            if (nc < conf_cap)
                conf[nc].entry = adds_s[i];
            nc++;
            mark_add[i] = 0;
        }
    }
    *nconf = nc < conf_cap ? nc : conf_cap;

    /* 4. emit: deletes by tier, then adds by tier */
    unsigned n = 0;
    for (int tier = 0; tier <= 5; tier++)
        for (unsigned i = 0; i < d.ndels; i++) {
            if (!mark_del[i] || del_tier(dels_s[i].kind) != tier)
                continue;
            if (n >= cap)
                return -1;
            render_del(&out[n++], &dels_s[i]);
        }
    for (int tier = 0; tier <= 5; tier++)
        for (unsigned i = 0; i < d.nadds; i++) {
            if (!mark_add[i] || add_tier(adds_s[i].kind) != tier)
                continue;
            if (n >= cap)
                return -1;
            const struct nentry *old = ns_get(have, &adds_s[i]);
            bool replace = mark_add[i] == 1 && old != NULL; /* in-place: route replace, node set */
            render_add(&out[n++], &adds_s[i], replace);
        }
    return (int)n;
}
