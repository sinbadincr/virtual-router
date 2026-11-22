#include "minivr/nodestate.h"

#include <string.h>

const char *ne_kind_name(unsigned kind) {
    switch (kind) {
    case NE_VRF: return "vrf";
    case NE_VNI: return "vni";
    case NE_NODE: return "node";
    case NE_PORT: return "port";
    case NE_NEIGH: return "neigh";
    case NE_LABEL: return "label";
    case NE_ROUTE: return "route";
    default: return "?";
    }
}

bool ne_name_ok(const char *s) {
    size_t n = 0;
    for (; s[n]; n++) {
        char c = s[n];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return false;
        if (n >= NE_NAME - 1)
            return false;
    }
    return n >= 1;
}

static int cmp_u32(uint32_t a, uint32_t b) {
    return a < b ? -1 : a > b ? 1 : 0;
}

int ne_key_cmp(const struct nentry *a, const struct nentry *b) {
    int c = cmp_u32(a->kind, b->kind);
    if (c)
        return c;
    switch (a->kind) {
    case NE_VRF:
    case NE_NODE:
    case NE_PORT:
        return strcmp(a->name, b->name);
    case NE_VNI:
        return cmp_u32(a->vni, b->vni);
    case NE_NEIGH:
        if ((c = strcmp(a->vrf, b->vrf)))
            return c;
        return cmp_u32(a->ip, b->ip);
    case NE_LABEL:
        return cmp_u32(a->label, b->label);
    case NE_ROUTE:
        if ((c = strcmp(a->vrf, b->vrf)))
            return c;
        if ((c = cmp_u32(a->prefix, b->prefix)))
            return c;
        return cmp_u32(a->plen, b->plen);
    default:
        return 0;
    }
}

bool ne_val_eq(const struct nentry *a, const struct nentry *b) {
    if (a->kind != b->kind)
        return false;
    switch (a->kind) {
    case NE_VRF:
        return a->id == b->id;
    case NE_VNI:
        return strcmp(a->vrf, b->vrf) == 0;
    case NE_NODE:
        return a->ip == b->ip && memcmp(a->rmac, b->rmac, 6) == 0;
    case NE_PORT:
        return strcmp(a->vrf, b->vrf) == 0 && a->prefix == b->prefix && a->plen == b->plen;
    case NE_NEIGH:
        return memcmp(a->mac, b->mac, 6) == 0 && strcmp(a->port, b->port) == 0;
    case NE_LABEL:
        return strcmp(a->port, b->port) == 0;
    case NE_ROUTE:
        return strcmp(a->node, b->node) == 0 && a->encap == b->encap && a->tag == b->tag;
    default:
        return true;
    }
}

void ns_init(struct nstate *s, struct nentry *storage, unsigned cap) {
    s->e = storage;
    s->n = 0;
    s->cap = cap;
}

void ns_clear(struct nstate *s) {
    s->n = 0;
}

/* first index whose key is >= e's; *found tells whether it is equal */
static unsigned lower_bound(const struct nstate *s, const struct nentry *e, bool *found) {
    unsigned lo = 0, hi = s->n;
    while (lo < hi) {
        unsigned mid = (lo + hi) / 2;
        if (ne_key_cmp(&s->e[mid], e) < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    *found = lo < s->n && ne_key_cmp(&s->e[lo], e) == 0;
    return lo;
}

int ns_put(struct nstate *s, const struct nentry *e) {
    bool found;
    unsigned i = lower_bound(s, e, &found);
    if (found) {
        s->e[i] = *e;
        return 0;
    }
    if (s->n >= s->cap)
        return -1;
    memmove(&s->e[i + 1], &s->e[i], (s->n - i) * sizeof s->e[0]);
    s->e[i] = *e;
    s->n++;
    return 0;
}

int ns_del(struct nstate *s, const struct nentry *key) {
    bool found;
    unsigned i = lower_bound(s, key, &found);
    if (!found)
        return -1;
    memmove(&s->e[i], &s->e[i + 1], (s->n - i - 1) * sizeof s->e[0]);
    s->n--;
    return 0;
}

const struct nentry *ns_get(const struct nstate *s, const struct nentry *key) {
    bool found;
    unsigned i = lower_bound(s, key, &found);
    return found ? &s->e[i] : NULL;
}

unsigned ns_count(const struct nstate *s) {
    return s->n;
}

const struct nentry *ns_at(const struct nstate *s, unsigned i) {
    return i < s->n ? &s->e[i] : NULL;
}

bool ns_equal(const struct nstate *a, const struct nstate *b) {
    if (a->n != b->n)
        return false;
    for (unsigned i = 0; i < a->n; i++)
        if (ne_key_cmp(&a->e[i], &b->e[i]) != 0 || !ne_val_eq(&a->e[i], &b->e[i]))
            return false;
    return true;
}

int ns_copy(struct nstate *dst, const struct nstate *src) {
    if (src->n > dst->cap)
        return -1;
    memcpy(dst->e, src->e, src->n * sizeof src->e[0]);
    dst->n = src->n;
    return 0;
}

int ns_diff(const struct nstate *have, const struct nstate *want, struct ndiff *out) {
    out->ndels = out->nadds = 0;
    unsigned i = 0, j = 0;
    while (i < have->n || j < want->n) {
        int c = i >= have->n ? 1 : j >= want->n ? -1 : ne_key_cmp(&have->e[i], &want->e[j]);
        if (c < 0) {
            if (out->ndels >= out->dcap)
                return -1;
            out->dels[out->ndels++] = have->e[i++];
        } else if (c > 0) {
            if (out->nadds >= out->acap)
                return -1;
            out->adds[out->nadds++] = want->e[j++];
        } else {
            if (!ne_val_eq(&have->e[i], &want->e[j])) {
                if (out->nadds >= out->acap)
                    return -1;
                out->adds[out->nadds++] = want->e[j];
            }
            i++;
            j++;
        }
    }
    return 0;
}

int ns_apply(struct nstate *s, const struct ndiff *d) {
    for (unsigned i = 0; i < d->ndels; i++)
        ns_del(s, &d->dels[i]);
    for (unsigned i = 0; i < d->nadds; i++)
        if (ns_put(s, &d->adds[i]) != 0)
            return -1;
    return 0;
}
