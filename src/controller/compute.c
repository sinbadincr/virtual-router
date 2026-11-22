/* compute(intent, bindings, node): the whole node state in one pure function (data-model §3, R4). */
#include <string.h>

#include "minivr/ctl_model.h"

static void cpy(char *dst, const char *src) {
    strncpy(dst, src, NE_NAME - 1);
    dst[NE_NAME - 1] = 0;
}

int cm_compute(const struct cmodel *m, unsigned node, struct nstate *out) {
    ns_clear(out);
    bool present[CM_MAX_TENANTS] = {false};
    for (int i = 0; i < CM_MAX_VMIS; i++)
        if (m->vmis[i].used && m->vmis[i].node == (int8_t)node)
            present[m->vmis[i].tenant] = true;

    struct nentry e;
    for (int t = 0; t < CM_MAX_TENANTS; t++) {
        if (!present[t])
            continue;
        const struct cm_tenant *tn = &m->tenants[t];
        memset(&e, 0, sizeof e);
        e.kind = NE_VRF;
        cpy(e.name, tn->name);
        e.id = tn->id;
        if (ns_put(out, &e) != 0)
            return -1;
        /* the VNI is installed whatever the tenant's encap, so an encap change is hitless on
         * receive */
        memset(&e, 0, sizeof e);
        e.kind = NE_VNI;
        e.vni = tn->vni;
        cpy(e.vrf, tn->name);
        if (ns_put(out, &e) != 0)
            return -1;
    }

    /* local interfaces */
    for (int i = 0; i < CM_MAX_VMIS; i++) {
        const struct cm_vmi *v = &m->vmis[i];
        if (!v->used || v->node != (int8_t)node)
            continue;
        const struct cm_tenant *tn = &m->tenants[v->tenant];
        const struct cm_subnet *s = cm_vmi_subnet(m, v);
        memset(&e, 0, sizeof e);
        e.kind = NE_PORT;
        cpy(e.name, v->port);
        cpy(e.vrf, tn->name);
        e.prefix = s ? s->gw : 0;
        e.plen = s ? s->plen : 24;
        if (ns_put(out, &e) != 0)
            return -1;
        memset(&e, 0, sizeof e);
        e.kind = NE_NEIGH;
        cpy(e.vrf, tn->name);
        e.ip = v->ip;
        memcpy(e.mac, v->mac, 6);
        cpy(e.port, v->port);
        if (ns_put(out, &e) != 0)
            return -1;
        memset(&e, 0, sizeof e);
        e.kind = NE_LABEL;
        e.label = v->label;
        cpy(e.port, v->port);
        if (ns_put(out, &e) != 0)
            return -1;
    }

    /* remote interfaces of the tenants present here */
    for (int i = 0; i < CM_MAX_VMIS; i++) {
        const struct cm_vmi *v = &m->vmis[i];
        if (!v->used || v->node < 0 || v->node == (int8_t)node || !present[v->tenant])
            continue;
        const struct cm_node *rn = &m->nodes[v->node];
        if (!rn->addr_known)
            continue; /* not a NODE, so no route through it */
        const struct cm_tenant *tn = &m->tenants[v->tenant];
        memset(&e, 0, sizeof e);
        e.kind = NE_NODE;
        cpy(e.name, rn->name);
        e.ip = rn->underlay_ip;
        memcpy(e.rmac, rn->rmac, 6);
        if (ns_put(out, &e) != 0)
            return -1;
        memset(&e, 0, sizeof e);
        e.kind = NE_ROUTE;
        cpy(e.vrf, tn->name);
        e.prefix = v->ip;
        e.plen = 32;
        cpy(e.node, rn->name);
        e.encap = tn->encap;
        e.tag = tn->encap == NE_ENCAP_MPLSOUDP ? v->label : tn->vni;
        if (ns_put(out, &e) != 0)
            return -1;
    }
    return 0;
}
