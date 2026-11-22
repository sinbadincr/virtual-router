/* Controller model: intent, bindings, label allocator (data-model §1-2). Pure. */
#include <string.h>

#include "minivr/ctl_model.h"

static uint32_t netmask(uint8_t plen) {
    return plen == 0 ? 0 : ~0U << (32 - plen);
}

static void cpy(char *dst, const char *src) { /* dst is NE_NAME bytes, src already validated */
    strncpy(dst, src, NE_NAME - 1);
    dst[NE_NAME - 1] = 0;
}

void cm_init(struct cmodel *m) {
    memset(m, 0, sizeof *m);
}

static bool name_ok(const char *s) {
    return ne_name_ok(s) && s[0] >= 'a' && s[0] <= 'z';
}

int cm_tenant_idx(const struct cmodel *m, const char *name) {
    for (int i = 0; i < CM_MAX_TENANTS; i++)
        if (m->tenants[i].used && strcmp(m->tenants[i].name, name) == 0)
            return i;
    return -1;
}

int cm_node_idx(const struct cmodel *m, const char *name) {
    for (int i = 0; i < CM_MAX_NODES; i++)
        if (m->nodes[i].used && strcmp(m->nodes[i].name, name) == 0)
            return i;
    return -1;
}

int cm_vmi_idx(const struct cmodel *m, const char *name) {
    for (int i = 0; i < CM_MAX_VMIS; i++)
        if (m->vmis[i].used && strcmp(m->vmis[i].name, name) == 0)
            return i;
    return -1;
}

const struct cm_subnet *cm_vmi_subnet(const struct cmodel *m, const struct cm_vmi *v) {
    for (int i = 0; i < CM_MAX_SUBNETS; i++) {
        const struct cm_subnet *s = &m->subnets[i];
        if (s->used && s->tenant == v->tenant && (v->ip & netmask(s->plen)) == s->prefix)
            return s;
    }
    return NULL;
}

/* ---- tenants ---- */

int cm_tenant_add(struct cmodel *m, const char *name, unsigned id, uint32_t vni, unsigned encap,
                  struct cmd_err *err) {
    if (!name_ok(name) || strcmp(name, "default") == 0)
        return cmd_fail(err, "bad-syntax",
                        "tenant name must be 1..15 of [a-z0-9_-], start with a letter, not 'default'");
    if (id < 1 || id > 63)
        return cmd_fail(err, "bad-syntax", "tenant id must be 1..63");
    if (vni < 1 || vni > 16777215u)
        return cmd_fail(err, "bad-syntax", "tenant vni must be 1..16777215");
    if (encap != NE_ENCAP_MPLSOUDP && encap != NE_ENCAP_VXLAN)
        return cmd_fail(err, "bad-syntax", "encap must be mplsoudp or vxlan");
    int slot = -1;
    for (int i = 0; i < CM_MAX_TENANTS; i++) {
        const struct cm_tenant *t = &m->tenants[i];
        if (!t->used) {
            if (slot < 0)
                slot = i;
            continue;
        }
        if (strcmp(t->name, name) == 0)
            return cmd_fail(err, "exists", "tenant %s already exists", name);
        if (t->id == id)
            return cmd_fail(err, "exists", "tenant id %u is used by %s", id, t->name);
        if (t->vni == vni)
            return cmd_fail(err, "exists", "vni %u is used by tenant %s", vni, t->name);
    }
    if (slot < 0)
        return cmd_fail(err, "table-full", "at most %d tenants", CM_MAX_TENANTS);
    struct cm_tenant *t = &m->tenants[slot];
    memset(t, 0, sizeof *t);
    t->used = true;
    cpy(t->name, name);
    t->id = (uint8_t)id;
    t->vni = vni;
    t->encap = (uint8_t)encap;
    m->gen++;
    return 0;
}

int cm_tenant_set_encap(struct cmodel *m, const char *name, unsigned encap, struct cmd_err *err) {
    int t = cm_tenant_idx(m, name);
    if (t < 0)
        return cmd_fail(err, "unknown-tenant", "no such tenant '%s'", name);
    if (encap != NE_ENCAP_MPLSOUDP && encap != NE_ENCAP_VXLAN)
        return cmd_fail(err, "bad-syntax", "encap must be mplsoudp or vxlan");
    if (m->tenants[t].encap != encap) {
        m->tenants[t].encap = (uint8_t)encap;
        m->gen++;
    }
    return 0;
}

int cm_tenant_del(struct cmodel *m, const char *name, struct cmd_err *err) {
    int t = cm_tenant_idx(m, name);
    if (t < 0)
        return cmd_fail(err, "unknown-tenant", "no such tenant '%s'", name);
    unsigned subs = 0, vmis = 0;
    for (int i = 0; i < CM_MAX_SUBNETS; i++)
        subs += m->subnets[i].used && m->subnets[i].tenant == t;
    for (int i = 0; i < CM_MAX_VMIS; i++)
        vmis += m->vmis[i].used && m->vmis[i].tenant == t;
    if (subs || vmis)
        return cmd_fail(err, "busy", "tenant %s still has %u subnet(s) and %u VM interface(s)", name,
                        subs, vmis);
    memset(&m->tenants[t], 0, sizeof m->tenants[t]);
    m->gen++;
    return 0;
}

/* ---- subnets ---- */

int cm_subnet_add(struct cmodel *m, const char *tenant, uint32_t prefix, uint8_t plen, uint32_t gw,
                  struct cmd_err *err) {
    int t = cm_tenant_idx(m, tenant);
    if (t < 0)
        return cmd_fail(err, "unknown-tenant", "no such tenant '%s'", tenant);
    if (plen < 8 || plen > 30)
        return cmd_fail(err, "bad-prefix", "subnet prefix length must be 8..30");
    if (prefix & ~netmask(plen))
        return cmd_fail(err, "bad-prefix", "subnet has host bits set");
    uint32_t bcast = prefix | ~netmask(plen);
    if ((gw & netmask(plen)) != prefix || gw == prefix || gw == bcast)
        return cmd_fail(err, "bad-address", "gateway must be a host address inside the subnet");
    int slot = -1;
    for (int i = 0; i < CM_MAX_SUBNETS; i++) {
        const struct cm_subnet *s = &m->subnets[i];
        if (!s->used) {
            if (slot < 0)
                slot = i;
            continue;
        }
        if (s->tenant != t)
            continue; /* other tenants may overlap */
        uint8_t shorter = s->plen < plen ? s->plen : plen;
        if ((s->prefix & netmask(shorter)) == (prefix & netmask(shorter)))
            return cmd_fail(err, "overlap", "overlaps subnet %u.%u.%u.%u/%u of tenant %s",
                            s->prefix >> 24, (s->prefix >> 16) & 255, (s->prefix >> 8) & 255,
                            s->prefix & 255, s->plen, tenant);
    }
    if (slot < 0)
        return cmd_fail(err, "table-full", "at most %d subnets", CM_MAX_SUBNETS);
    struct cm_subnet *s = &m->subnets[slot];
    s->used = true;
    s->tenant = (uint8_t)t;
    s->prefix = prefix;
    s->plen = plen;
    s->gw = gw;
    m->gen++;
    return 0;
}

int cm_subnet_del(struct cmodel *m, const char *tenant, uint32_t prefix, uint8_t plen,
                  struct cmd_err *err) {
    int t = cm_tenant_idx(m, tenant);
    if (t < 0)
        return cmd_fail(err, "unknown-tenant", "no such tenant '%s'", tenant);
    struct cm_subnet *s = NULL;
    for (int i = 0; i < CM_MAX_SUBNETS && !s; i++)
        if (m->subnets[i].used && m->subnets[i].tenant == t && m->subnets[i].prefix == prefix &&
            m->subnets[i].plen == plen)
            s = &m->subnets[i];
    if (!s)
        return cmd_fail(err, "not-found", "no such subnet");
    for (int i = 0; i < CM_MAX_VMIS; i++) {
        const struct cm_vmi *v = &m->vmis[i];
        if (v->used && v->tenant == t && (v->ip & netmask(plen)) == prefix)
            return cmd_fail(err, "busy", "VM interface %s has an address in this subnet", v->name);
    }
    memset(s, 0, sizeof *s);
    m->gen++;
    return 0;
}

/* ---- nodes ---- */

int cm_node_add(struct cmodel *m, const char *name, struct cmd_err *err) {
    if (!name_ok(name))
        return cmd_fail(err, "bad-syntax",
                        "node name must be 1..15 of [a-z0-9_-] and start with a letter");
    int slot = -1;
    for (int i = 0; i < CM_MAX_NODES; i++) {
        if (!m->nodes[i].used) {
            if (slot < 0)
                slot = i;
        } else if (strcmp(m->nodes[i].name, name) == 0) {
            return cmd_fail(err, "exists", "node %s already exists", name);
        }
    }
    if (slot < 0)
        return cmd_fail(err, "table-full", "at most %d nodes", CM_MAX_NODES);
    memset(&m->nodes[slot], 0, sizeof m->nodes[slot]);
    m->nodes[slot].used = true;
    cpy(m->nodes[slot].name, name);
    m->gen++;
    return 0;
}

unsigned cm_bound_count(const struct cmodel *m, unsigned node) {
    unsigned n = 0;
    for (int i = 0; i < CM_MAX_VMIS; i++)
        n += m->vmis[i].used && m->vmis[i].node == (int8_t)node;
    return n;
}

unsigned cm_quarantine_count(const struct cmodel *m, unsigned node) {
    unsigned n = 0;
    for (int i = 0; i < CM_MAX_QUARANTINE; i++)
        n += m->quar[i].used && m->quar[i].node == node;
    return n;
}

int cm_node_del(struct cmodel *m, const char *name, struct cmd_err *err) {
    int n = cm_node_idx(m, name);
    if (n < 0)
        return cmd_fail(err, "unknown-node", "no such node '%s'", name);
    if (cm_bound_count(m, (unsigned)n))
        return cmd_fail(err, "busy", "node %s still has %u binding(s); use node forget", name,
                        cm_bound_count(m, (unsigned)n));
    if (m->nodes[n].connected)
        return cmd_fail(err, "busy", "node %s has a live session", name);
    for (int i = 0; i < CM_MAX_QUARANTINE; i++)
        if (m->quar[i].used && m->quar[i].node == n)
            memset(&m->quar[i], 0, sizeof m->quar[i]);
    memset(&m->nodes[n], 0, sizeof m->nodes[n]);
    m->gen++;
    return 0;
}

int cm_node_forget(struct cmodel *m, const char *name, struct cmd_err *err) {
    int n = cm_node_idx(m, name);
    if (n < 0)
        return cmd_fail(err, "unknown-node", "no such node '%s'", name);
    if (m->nodes[n].connected)
        return cmd_fail(err, "busy", "node %s has a live session", name);
    for (int i = 0; i < CM_MAX_VMIS; i++)
        if (m->vmis[i].used && m->vmis[i].node == n) {
            m->vmis[i].node = -1;
            m->vmis[i].port[0] = 0;
            m->vmis[i].label = 0;
        }
    for (int i = 0; i < CM_MAX_QUARANTINE; i++)
        if (m->quar[i].used && m->quar[i].node == n)
            memset(&m->quar[i], 0, sizeof m->quar[i]);
    m->nodes[n].addr_known = false;
    m->gen++;
    return 0;
}

void cm_node_learn(struct cmodel *m, unsigned node, uint32_t underlay_ip, const uint8_t rmac[6]) {
    struct cm_node *n = &m->nodes[node];
    if (!n->addr_known || n->underlay_ip != underlay_ip || memcmp(n->rmac, rmac, 6) != 0) {
        n->addr_known = true;
        n->underlay_ip = underlay_ip;
        memcpy(n->rmac, rmac, 6);
        m->gen++;
    }
}

/* ---- VM interfaces ---- */

int cm_vmi_add(struct cmodel *m, const char *name, const char *tenant, uint32_t ip,
               const uint8_t mac[6], struct cmd_err *err) {
    if (!name_ok(name))
        return cmd_fail(err, "bad-syntax",
                        "VM interface name must be 1..15 of [a-z0-9_-] and start with a letter");
    int t = cm_tenant_idx(m, tenant);
    if (t < 0)
        return cmd_fail(err, "unknown-tenant", "no such tenant '%s'", tenant);
    if (mac[0] & 1)
        return cmd_fail(err, "bad-mac", "VM MAC must be unicast");
    struct cm_vmi probe;
    memset(&probe, 0, sizeof probe);
    probe.tenant = (uint8_t)t;
    probe.ip = ip;
    const struct cm_subnet *s = cm_vmi_subnet(m, &probe);
    if (!s)
        return cmd_fail(err, "no-subnet", "address is inside no subnet of tenant %s", tenant);
    if (ip == s->gw || ip == s->prefix || ip == (s->prefix | ~netmask(s->plen)))
        return cmd_fail(err, "bad-address", "address is the gateway, network or broadcast address");
    int slot = -1;
    for (int i = 0; i < CM_MAX_VMIS; i++) {
        const struct cm_vmi *v = &m->vmis[i];
        if (!v->used) {
            if (slot < 0)
                slot = i;
            continue;
        }
        if (strcmp(v->name, name) == 0)
            return cmd_fail(err, "exists", "VM interface %s already exists", name);
        if (v->tenant == t && v->ip == ip)
            return cmd_fail(err, "exists", "address already used by %s in tenant %s", v->name, tenant);
        if (v->tenant == t && memcmp(v->mac, mac, 6) == 0)
            return cmd_fail(err, "exists", "MAC already used by %s in tenant %s", v->name, tenant);
    }
    if (slot < 0)
        return cmd_fail(err, "table-full", "at most %d VM interfaces", CM_MAX_VMIS);
    struct cm_vmi *v = &m->vmis[slot];
    memset(v, 0, sizeof *v);
    v->used = true;
    cpy(v->name, name);
    v->tenant = (uint8_t)t;
    v->ip = ip;
    memcpy(v->mac, mac, 6);
    v->node = -1;
    m->gen++;
    return 0;
}

int cm_vmi_del(struct cmodel *m, const char *name, struct cmd_err *err) {
    int i = cm_vmi_idx(m, name);
    if (i < 0)
        return cmd_fail(err, "not-found", "no such VM interface '%s'", name);
    if (m->vmis[i].node >= 0)
        return cmd_fail(err, "busy", "VM interface %s is bound on node %s", name,
                        m->nodes[m->vmis[i].node].name);
    memset(&m->vmis[i], 0, sizeof m->vmis[i]);
    m->gen++;
    return 0;
}

